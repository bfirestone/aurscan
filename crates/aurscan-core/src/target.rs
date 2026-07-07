//! Target expansion: turn on-disk artifacts (AUR clone dirs, downloaded
//! sources, built package archives) into the `ScanTarget`s detectors consume.

use crate::types::{ScanTarget, ScriptKind, SourceOrigin};
use std::io::Read;
use std::path::Path;

const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;

/// Expand an AUR clone dir into BuildScript targets:
/// PKGBUILD, *.install, .SRCINFO, *.patch/*.diff, plus any other regular
/// file <1MB as ScriptKind::Other (helper scripts ride in clones).
/// Skips .git and skips files matched as downloaded sources when
/// `exclude` names are given (the check flow passes source filenames).
pub fn expand_build_dir(dir: &Path, exclude: &[String]) -> Vec<ScanTarget> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        let p = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if p.components().any(|c| c.as_os_str() == ".git") {
            continue;
        }
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        if exclude.iter().any(|e| e == name.as_ref()) {
            continue;
        }
        let kind = match () {
            _ if name == "PKGBUILD" => ScriptKind::Pkgbuild,
            _ if name.ends_with(".install") => ScriptKind::InstallScript,
            _ if name == ".SRCINFO" => ScriptKind::SrcInfo,
            _ if name.ends_with(".patch") || name.ends_with(".diff") => ScriptKind::Patch,
            _ if entry
                .metadata()
                .map(|m| m.len() < 1_048_576)
                .unwrap_or(false) =>
            {
                ScriptKind::Other
            }
            _ => continue,
        };
        out.push(ScanTarget::BuildScript {
            path: p.to_path_buf(),
            kind,
        });
    }
    out
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
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git").join("config"), b"[core]\n").unwrap();

        let targets = expand_build_dir(dir.path(), &[]);
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
