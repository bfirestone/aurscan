use crate::types::{
    BundleCoverage, BundleLimits, CoverageMode, RecipeBundle, RecipeBundleBuilder, RecipeFile,
};
use anyhow::{anyhow, bail, Context};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultRecipeBundleBuilder;

impl RecipeBundleBuilder for DefaultRecipeBundleBuilder {
    fn build(
        &self,
        root: &Path,
        pkgbase: &str,
        limits: BundleLimits,
    ) -> anyhow::Result<RecipeBundle> {
        let root = root
            .canonicalize()
            .with_context(|| format!("cannot resolve recipe root {}", root.display()))?;
        if !root.is_dir() {
            bail!("recipe root is not a directory: {}", root.display());
        }

        let git_backed = root.join(".git").exists();
        let paths = if git_backed {
            git_tracked_paths(&root)?
        } else {
            conservative_paths(&root)?
        };
        let mut excluded_binary_files = Vec::new();
        let mut excluded_symlinks = Vec::new();
        let mut files = Vec::new();
        let mut total_bytes = 0usize;

        for relative_path in paths {
            let normalized = normalize_relative_path(&relative_path)?;
            if normalized
                .rsplit('/')
                .next()
                .is_some_and(|name| name == ".SRCINFO")
            {
                continue;
            }
            let full_path = root.join(path_from_normalized(&normalized));
            let metadata = fs::symlink_metadata(&full_path)
                .with_context(|| format!("cannot inspect tracked file {normalized}"))?;
            if metadata.file_type().is_symlink() {
                excluded_symlinks.push(normalized);
                continue;
            }
            if !metadata.is_file() {
                bail!("eligible recipe path is not a regular file: {normalized}");
            }
            if metadata.len() > limits.max_file_bytes as u64 {
                bail!(
                    "per-file byte limit exceeded by {normalized}: {} > {}",
                    metadata.len(),
                    limits.max_file_bytes
                );
            }

            let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
            fs::File::open(&full_path)
                .with_context(|| format!("cannot open recipe file {normalized}"))?
                .take(limits.max_file_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .with_context(|| format!("cannot read recipe file {normalized}"))?;
            if bytes.len() > limits.max_file_bytes {
                bail!(
                    "per-file byte limit exceeded by {normalized}: {} > {}",
                    bytes.len(),
                    limits.max_file_bytes
                );
            }
            if bytes.contains(&0) {
                excluded_binary_files.push(normalized);
                continue;
            }
            let Ok(content) = String::from_utf8(bytes) else {
                excluded_binary_files.push(normalized);
                continue;
            };

            if files.len() == limits.max_files {
                bail!("file count limit exceeded: more than {}", limits.max_files);
            }
            total_bytes = total_bytes
                .checked_add(content.len())
                .ok_or_else(|| anyhow!("aggregate bundle byte count overflow"))?;
            if total_bytes > limits.max_bundle_bytes {
                bail!(
                    "aggregate bundle byte limit exceeded: {total_bytes} > {}",
                    limits.max_bundle_bytes
                );
            }
            files.push(RecipeFile {
                path: normalized,
                content,
            });
        }

        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        excluded_binary_files.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        excluded_symlinks.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if !files.iter().any(|file| file.path == "PKGBUILD") {
            bail!("required regular UTF-8 PKGBUILD is missing");
        }

        let mut hasher = blake3::Hasher::new();
        for file in &files {
            let path_bytes = file.path.as_bytes();
            let content_bytes = file.content.as_bytes();
            hasher.update(&(path_bytes.len() as u64).to_le_bytes());
            hasher.update(path_bytes);
            hasher.update(&(content_bytes.len() as u64).to_le_bytes());
            hasher.update(content_bytes);
        }

        let coverage = BundleCoverage {
            mode: if git_backed {
                CoverageMode::GitTracked
            } else {
                CoverageMode::ConservativeLocal
            },
            included_files: files.len(),
            excluded_binary_files,
            excluded_symlinks,
        };

        Ok(RecipeBundle {
            pkgbase: pkgbase.to_owned(),
            aur_commit: git_backed.then(|| git_head(&root)).flatten(),
            content_hash: *hasher.finalize().as_bytes(),
            files,
            coverage,
        })
    }
}

fn git_tracked_paths(root: &Path) -> anyhow::Result<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--"])
        .output()
        .context("failed to run git ls-files")?;
    if !output.status.success() {
        bail!("git ls-files failed for recipe root");
    }
    let mut paths = Vec::new();
    for raw in output.stdout.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        paths.push(
            String::from_utf8(raw.to_vec())
                .map_err(|_| anyhow!("tracked recipe path is not valid UTF-8"))?,
        );
    }
    Ok(paths)
}

fn git_head(root: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    (!commit.is_empty()).then(|| commit.to_owned())
}

fn conservative_paths(root: &Path) -> anyhow::Result<Vec<String>> {
    fn visit(root: &Path, directory: &Path, paths: &mut Vec<String>) -> anyhow::Result<()> {
        for entry in fs::read_dir(directory)
            .with_context(|| format!("cannot read recipe directory {}", directory.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                visit(root, &path, paths)?;
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| anyhow!("recipe path escaped its root"))?;
            let normalized = normalize_path(relative)?;
            if is_conservative_candidate(&normalized) {
                paths.push(normalized);
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    visit(root, root, &mut paths)?;
    Ok(paths)
}

fn is_conservative_candidate(path: &str) -> bool {
    path == "PKGBUILD"
        || path.ends_with(".install")
        || path.ends_with(".patch")
        || path.ends_with(".diff")
}

fn normalize_relative_path(path: &str) -> anyhow::Result<String> {
    if path.contains('\\') {
        bail!("recipe path is not normalized: {path}");
    }
    normalize_path(Path::new(path))
}

fn normalize_path(path: &Path) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| anyhow!("recipe path is not valid UTF-8"))?,
            ),
            _ => bail!("recipe path escapes its root or is not normalized"),
        }
    }
    if parts.is_empty() {
        bail!("empty recipe path");
    }
    Ok(parts.join("/"))
}

fn path_from_normalized(path: &str) -> PathBuf {
    path.split('/').collect()
}
