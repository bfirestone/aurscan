//! Target expansion: turn on-disk artifacts (AUR clone dirs, downloaded
//! sources, built package archives) into the `ScanTarget`s detectors consume.

use crate::types::{ScanTarget, ScriptKind, SourceOrigin};
use std::io::Read;
use std::path::Path;

const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;

/// Inputs discovered without executing packaging code. Generated entries may be
/// whole pruned directories; they are recorded for future source-analysis stages,
/// not granted trust or passed to packaging detectors.
#[derive(Debug, Default)]
pub struct ScanInputInventory {
    pub packaging: Vec<ScanTarget>,
    pub sources: Vec<ScanTarget>,
    pub generated: Vec<std::path::PathBuf>,
}

/// Discover packaging files and preserve explicit source routing. Only root-level
/// src/ and pkg/ are conventional build output; tracked files override that rule.
/// Download exclusions are paths relative to the scan root, never basenames.
pub fn scan_input_inventory(
    dir: &Path,
    source_files: &[(std::path::PathBuf, SourceOrigin)],
) -> anyhow::Result<ScanInputInventory> {
    use anyhow::Context;
    let tracked = tracked_files(dir)?;
    let mut inventory = ScanInputInventory::default();
    let root = std::fs::canonicalize(dir)?;
    inventory.sources = expand_source_files(source_files);
    // Fetch discovery also returns untracked local files. LocalFile is not
    // evidence of an upstream download: retain packaging checks for helpers.
    let sources: Vec<_> = source_files
        .iter()
        .filter(|(_, origin)| !matches!(origin, SourceOrigin::LocalFile))
        .map(|(path, _)| std::fs::canonicalize(path))
        .collect::<std::io::Result<_>>()?;
    let mut entries = walkdir::WalkDir::new(dir).into_iter();
    while let Some(entry) = entries.next() {
        let entry =
            entry.with_context(|| format!("discovering scan inputs in {}", dir.display()))?;
        let path = entry.path();
        let relative = path.strip_prefix(dir)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_name() == ".git" {
            if entry.file_type().is_dir() {
                entries.skip_current_dir();
            }
            continue;
        }
        let reserved = matches!(relative.components().next(), Some(c) if c.as_os_str() == "src" || c.as_os_str() == "pkg");
        if reserved && !tracked.contains(relative) {
            if entry.file_type().is_dir() && tracked.iter().any(|p| p.starts_with(relative)) {
                continue;
            }
            inventory.generated.push(path.to_path_buf());
            if entry.file_type().is_dir() {
                entries.skip_current_dir();
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        let kind = script_kind(&name);
        if !tracked.contains(relative)
            && kind == ScriptKind::Other
            && sources.iter().any(|p| p == &root.join(relative))
        {
            continue;
        }
        if kind == ScriptKind::Other && entry.metadata()?.len() >= 1_048_576 {
            continue;
        }
        inventory.packaging.push(ScanTarget::BuildScript {
            path: path.to_path_buf(),
            kind,
        });
    }
    Ok(inventory)
}

fn script_kind(name: &str) -> ScriptKind {
    match () {
        _ if name == "PKGBUILD" => ScriptKind::Pkgbuild,
        _ if name.ends_with(".install") => ScriptKind::InstallScript,
        _ if name == ".SRCINFO" => ScriptKind::SrcInfo,
        _ if name.ends_with(".patch") || name.ends_with(".diff") => ScriptKind::Patch,
        _ => ScriptKind::Other,
    }
}

/// Read the index of the scan-root checkout, including linked worktrees. A
/// present but broken repository is an error: silently treating it as non-Git
/// would lose the tracked-file exception. Git environment overrides are removed
/// so an ambient GIT_DIR/GIT_INDEX_FILE cannot redirect this discovery.
fn tracked_files(dir: &Path) -> anyhow::Result<std::collections::HashSet<std::path::PathBuf>> {
    use anyhow::Context;
    use std::os::unix::ffi::OsStringExt;
    let root = std::fs::canonicalize(dir)?;
    let repo = &root;
    match repo.join(".git").symlink_metadata() {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(error) => return Err(error).context("discovering scan-root Git metadata"),
    }
    let mut command = std::process::Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    let output = command
        .arg("--git-dir")
        .arg(repo.join(".git"))
        .arg("--work-tree")
        .arg(repo)
        .current_dir(&root)
        .args(["ls-files", "--cached", "-z", "--", "."])
        .output()
        .with_context(|| format!("discovering tracked packaging files in {}", dir.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "discovering tracked packaging files in {}: git failed: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| std::path::PathBuf::from(std::ffi::OsString::from_vec(p.to_vec())))
        .collect())
}

/// Packaging-only convenience wrapper for local checks and paru hooks.
pub fn expand_build_dir(dir: &Path) -> anyhow::Result<Vec<ScanTarget>> {
    Ok(scan_input_inventory(dir, &[])?.packaging)
}

/// Wrap downloaded source files (post `makepkg --verifysource`) as SourceFile targets.
pub fn expand_source_files(files: &[(std::path::PathBuf, SourceOrigin)]) -> Vec<ScanTarget> {
    files
        .iter()
        .map(|(p, o)| ScanTarget::SourceFile {
            path: p.clone(),
            origin: o.clone(),
        })
        .collect()
}

/// List members of a .pkg.tar.zst as PackageFile targets (no extraction).
pub fn expand_archive(pkg: &Path) -> anyhow::Result<Vec<ScanTarget>> {
    let f = std::fs::File::open(pkg)?;
    let mut ar = tar::Archive::new(zstd::Decoder::new(f)?);
    let mut out = Vec::new();
    for entry in ar.entries()? {
        let e = entry?;
        if e.header().entry_type().is_file() {
            out.push(ScanTarget::PackageFile {
                archive: pkg.to_path_buf(),
                member: e.path()?.to_string_lossy().into_owned(),
            });
        }
    }
    Ok(out)
}

/// Read one archive member, bounded. Shared helper for archive-aware detectors.
pub fn read_archive_member(archive: &Path, member: &str, cap: u64) -> anyhow::Result<Vec<u8>> {
    let f = std::fs::File::open(archive)?;
    let mut ar = tar::Archive::new(zstd::Decoder::new(f)?);
    for entry in ar.entries()? {
        let mut e = entry?;
        if e.path()?.to_string_lossy() == member {
            let n = e.header().size()?.min(cap.min(MAX_MEMBER_BYTES));
            let mut buf = Vec::with_capacity(n as usize);
            e.by_ref().take(n).read_to_end(&mut buf)?;
            return Ok(buf);
        }
    }
    anyhow::bail!("member not found: {member} in {}", archive.display())
}

/// Cache fingerprint includes all detector-visible target/context fields as well
/// as content. Serialization failure disables caching rather than losing identity.
pub fn scan_hash(
    target: &ScanTarget,
    context: &crate::detector::ScanContext,
) -> anyhow::Result<[u8; 32]> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"aurscan-scan-identity-v2\0");
    hash.update(&content_hash(target)?);
    hash.update(&serde_json::to_vec(&(target, context))?);
    Ok(*hash.finalize().as_bytes())
}

/// blake3 of the target's identity content, for cache keys.
/// Files hash their bytes; PackageFile hashes archive-file bytes + member name.
pub fn content_hash(target: &ScanTarget) -> anyhow::Result<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    match target {
        ScanTarget::BuildScript { path, .. }
        | ScanTarget::SourceFile { path, .. }
        | ScanTarget::HostArtifact { path } => {
            h.update_mmap(path)?;
        }
        ScanTarget::PackageFile { archive, member } => {
            h.update_mmap(archive)?;
            h.update(member.as_bytes());
        }
    }
    Ok(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_build_dir_finds_expected_kinds_and_skips_git() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), b"pkgname=x\n").unwrap();
        std::fs::write(dir.path().join("foo.install"), b"post_install() {}\n").unwrap();
        std::fs::write(dir.path().join(".SRCINFO"), b"pkgbase = x\n").unwrap();
        std::fs::write(dir.path().join("x.patch"), b"--- a\n+++ b\n").unwrap();
        assert!(std::process::Command::new("git")
            .args(["init", "-q"])
            .arg(dir.path())
            .status()
            .unwrap()
            .success());
        std::fs::write(dir.path().join(".git").join("hidden"), b"hidden\n").unwrap();

        let targets = expand_build_dir(dir.path()).unwrap();
        assert_eq!(targets.len(), 4);

        let kind_of = |name: &str| {
            targets
                .iter()
                .find_map(|t| match t {
                    ScanTarget::BuildScript { path, kind } if path.file_name().unwrap() == name => {
                        Some(*kind)
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing target for {name}"))
        };
        assert_eq!(kind_of("PKGBUILD"), ScriptKind::Pkgbuild);
        assert_eq!(kind_of("foo.install"), ScriptKind::InstallScript);
        assert_eq!(kind_of(".SRCINFO"), ScriptKind::SrcInfo);
        assert_eq!(kind_of("x.patch"), ScriptKind::Patch);

        assert!(targets.iter().all(|t| match t {
            ScanTarget::BuildScript { path, .. } => {
                !path.components().any(|c| c.as_os_str() == ".git")
            }
            _ => true,
        }));
    }

    #[test]
    fn generated_trees_are_excluded_without_git_but_normal_helpers_remain() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "PKGBUILD",
            "helpers/run.sh",
            "src/upstream/test.sh",
            "pkg/usr/bin/run",
        ] {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "echo x").unwrap();
        }
        let targets = expand_build_dir(dir.path()).unwrap();
        assert_eq!(targets.len(), 2, "{targets:?}");
    }

    #[test]
    fn downloaded_exclusions_match_relative_path_not_basename() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("helpers")).unwrap();
        for name in ["upstream.sh", "helpers/upstream.sh"] {
            std::fs::write(dir.path().join(name), "echo x").unwrap();
        }
        let targets = scan_input_inventory(
            dir.path(),
            &[(
                dir.path().join("upstream.sh"),
                SourceOrigin::Url("https://example.com/upstream.sh".into()),
            )],
        )
        .unwrap()
        .packaging;
        assert_eq!(targets.len(), 1, "{targets:?}");
    }

    fn git(dir: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn tracked_reserved_helpers_survive_in_regular_and_linked_worktrees() {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        for name in ["PKGBUILD", "src/packaging/helper.sh", "pkg/helper.install"] {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "echo x").unwrap();
        }
        git(dir.path(), &["add", "."]);
        git(
            dir.path(),
            &[
                "-c",
                "user.name=Test",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "fixture",
            ],
        );
        let linked_parent = tempfile::tempdir().unwrap();
        let linked = linked_parent.path().join("linked");
        git(
            dir.path(),
            &["worktree", "add", "--detach", linked.to_str().unwrap()],
        );
        for root in [dir.path(), linked.as_path()] {
            std::fs::create_dir_all(root.join("src/generated")).unwrap();
            std::fs::write(root.join("src/generated/runtime.install"), "echo x").unwrap();
            std::fs::write(root.join("untracked.sh"), "echo x").unwrap();
            let inventory = scan_input_inventory(root, &[]).unwrap();
            assert_eq!(inventory.packaging.len(), 4, "{inventory:?}");
            assert!(!inventory.generated.is_empty());
        }
    }

    #[test]
    fn broken_git_metadata_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".git"), "gitdir: missing\n").unwrap();
        assert!(scan_input_inventory(dir.path(), &[])
            .unwrap_err()
            .to_string()
            .contains("git failed"));
    }

    #[test]
    fn explicit_sources_keep_routing_with_generated_and_tracked_inputs() {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        std::fs::create_dir(dir.path().join("src")).unwrap();
        for name in ["src/source.sh", "helper.sh", "hook.install", "download.sh"] {
            std::fs::write(dir.path().join(name), "echo x").unwrap();
        }
        git(dir.path(), &["add", "helper.sh"]);
        let sources: Vec<_> = ["src/source.sh", "helper.sh", "hook.install", "download.sh"]
            .into_iter()
            .map(|p| {
                (
                    dir.path().join(".").join(p),
                    SourceOrigin::Url("https://example.com/x".into()),
                )
            })
            .collect();
        let inventory = scan_input_inventory(&dir.path().join("."), &sources).unwrap();
        assert_eq!(inventory.sources.len(), 4);
        assert_eq!(inventory.packaging.len(), 2, "{inventory:?}");
        let link_root = tempfile::tempdir().unwrap();
        let link = link_root.path().join("clone");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert_eq!(
            scan_input_inventory(&link, &sources)
                .unwrap()
                .packaging
                .len(),
            2
        );
    }

    #[test]
    fn scan_hash_distinguishes_target_variants_and_source_origins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("same");
        std::fs::write(&path, "same bytes").unwrap();
        let context = crate::ScanContext {
            package: "x".into(),
            version: "1".into(),
            aur_meta: None,
        };
        let targets = [
            ScanTarget::BuildScript {
                path: path.clone(),
                kind: ScriptKind::Other,
            },
            ScanTarget::SourceFile {
                path: path.clone(),
                origin: SourceOrigin::LocalFile,
            },
            ScanTarget::SourceFile {
                path: path.clone(),
                origin: SourceOrigin::Url("https://one.example".into()),
            },
            ScanTarget::SourceFile {
                path: path.clone(),
                origin: SourceOrigin::Url("https://two.example".into()),
            },
            ScanTarget::SourceFile {
                path: path.clone(),
                origin: SourceOrigin::Vcs("https://one.example".into()),
            },
            ScanTarget::HostArtifact { path: path.clone() },
            ScanTarget::PackageFile {
                archive: path.clone(),
                member: "one".into(),
            },
            ScanTarget::PackageFile {
                archive: path,
                member: "two".into(),
            },
        ];
        let hashes: std::collections::HashSet<_> = targets
            .iter()
            .map(|t| scan_hash(t, &context).unwrap())
            .collect();
        assert_eq!(hashes.len(), targets.len());
    }

    fn make_pkg() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.pkg.tar.zst");
        let f = std::fs::File::create(&path).unwrap();
        let enc = zstd::Encoder::new(f, 0).unwrap().auto_finish();
        let mut ar = tar::Builder::new(enc);
        let mut h = tar::Header::new_gnu();
        h.set_size(9);
        h.set_mode(0o644);
        h.set_cksum();
        ar.append_data(&mut h, ".PKGINFO", &b"pkgname=x"[..])
            .unwrap();
        ar.finish().unwrap();
        (dir, path)
    }

    #[test]
    fn expand_archive_lists_file_members() {
        let (_dir, path) = make_pkg();
        let targets = expand_archive(&path).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(matches!(
            &targets[0],
            ScanTarget::PackageFile { member, .. } if member == ".PKGINFO"
        ));
    }
}
