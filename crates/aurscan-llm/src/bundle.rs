use crate::types::{
    BundleCoverage, BundleLimits, CoverageMode, RecipeBundle, RecipeBundleBuilder, RecipeFile,
};
use anyhow::{anyhow, bail, Context};
use std::fs;
use std::io::Read;
use std::path::{Component, Path};
use std::process::Command;

#[cfg(target_os = "linux")]
use std::ffi::{CString, OsStr};
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

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

        let root_directory = open_root_directory(&root)?;
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
            let mut opened = match open_file_beneath(&root_directory, &normalized) {
                Ok(file) => file,
                Err(SecureOpenError::FinalSymlink) => {
                    excluded_symlinks.push(normalized);
                    continue;
                }
                Err(error) => {
                    return Err(anyhow!(
                        "cannot securely open recipe file {normalized}: {error}"
                    ));
                }
            };
            let metadata = opened
                .metadata()
                .with_context(|| format!("cannot inspect opened recipe file {normalized}"))?;
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
            opened
                .by_ref()
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

#[derive(Debug)]
enum SecureOpenError {
    UnsafeAncestor(std::io::Error),
    FinalSymlink,
    FinalComponent(std::io::Error),
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
}

impl std::fmt::Display for SecureOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeAncestor(error) => write!(
                formatter,
                "path has a missing, non-directory, or symlinked ancestor: {error}"
            ),
            Self::FinalSymlink => formatter.write_str("final path component is a symlink"),
            Self::FinalComponent(error) => {
                write!(formatter, "cannot open final path component: {error}")
            }
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => formatter.write_str(
                "race-resistant path-beneath file opening is unavailable on this platform",
            ),
        }
    }
}

#[cfg(target_os = "linux")]
const O_CLOEXEC: i32 = 0o2_000_000;
#[cfg(target_os = "linux")]
const O_DIRECTORY: i32 = 0o200_000;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4_000;
#[cfg(target_os = "linux")]
const ELOOP: i32 = 40;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn openat(directory_fd: i32, path: *const std::ffi::c_char, flags: i32, mode: u32) -> i32;
}

#[cfg(target_os = "linux")]
fn open_root_directory(root: &Path) -> anyhow::Result<File> {
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW)
        .open("/")
        .context("cannot open filesystem root for path-beneath traversal")?;
    for component in root.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat_component(
                    &directory,
                    name,
                    O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK,
                )
                .with_context(|| {
                    format!(
                        "cannot securely open recipe-root component {}",
                        name.to_string_lossy()
                    )
                })?;
            }
            _ => bail!("canonical recipe root contains a non-normal path component"),
        }
    }
    Ok(directory)
}

#[cfg(not(target_os = "linux"))]
fn open_root_directory(_root: &Path) -> anyhow::Result<std::fs::File> {
    Err(anyhow!(SecureOpenError::UnsupportedPlatform))
}

#[cfg(target_os = "linux")]
fn open_file_beneath(root: &File, normalized: &str) -> Result<File, SecureOpenError> {
    let mut components = normalized.split('/').peekable();
    let Some(first) = components.next() else {
        return Err(SecureOpenError::FinalComponent(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty path",
        )));
    };
    let mut directory = root.try_clone().map_err(SecureOpenError::UnsafeAncestor)?;
    let mut component = first;

    loop {
        if components.peek().is_none() {
            return match openat_component(
                &directory,
                OsStr::new(component),
                O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
            ) {
                Ok(file) => Ok(file),
                Err(error) if error.raw_os_error() == Some(ELOOP) => {
                    Err(SecureOpenError::FinalSymlink)
                }
                Err(error) => Err(SecureOpenError::FinalComponent(error)),
            };
        }

        directory = openat_component(
            &directory,
            OsStr::new(component),
            O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK,
        )
        .map_err(SecureOpenError::UnsafeAncestor)?;
        component = components.next().expect("peek proved a component exists");
    }
}

#[cfg(not(target_os = "linux"))]
fn open_file_beneath(
    _root: &std::fs::File,
    _normalized: &str,
) -> Result<std::fs::File, SecureOpenError> {
    Err(SecureOpenError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn openat_component(directory: &File, component: &OsStr, flags: i32) -> std::io::Result<File> {
    let component = CString::new(component.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains a NUL byte",
        )
    })?;
    // SAFETY: `component` is a live NUL-terminated C string, `directory` owns a
    // valid descriptor for the duration of the call, and no creation flag is
    // supplied, so the zero mode argument is ignored by `openat`.
    let descriptor = unsafe { openat(directory.as_raw_fd(), component.as_ptr(), flags, 0) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a nonnegative result from `openat` is a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}
