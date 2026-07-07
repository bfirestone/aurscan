//! Clone/pull AUR pkgbases into paru's clone dir and materialize their
//! upstream sources via `makepkg --verifysource`, without ever building or
//! installing anything.

use anyhow::Context;
use aurscan_core::SourceOrigin;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// paru's default clone dir: `$XDG_CACHE_HOME/paru/clone`, else `~/.cache/paru/clone`.
pub fn clone_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("paru/clone")
}

/// Clone `base`'s AUR git repo into paru's clone dir if it isn't there yet,
/// else fast-forward it. Returns the checkout directory.
pub fn sync_pkgbase(base: &str) -> anyhow::Result<PathBuf> {
    let dir = clone_dir().join(base);
    if dir.join(".git").is_dir() {
        run(Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["pull", "--ff-only"]))?;
    } else {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating clone dir {}", parent.display()))?;
        }
        run(Command::new("git")
            .arg("clone")
            .arg(format!("https://aur.archlinux.org/{base}.git"))
            .arg(&dir))?;
    }
    Ok(dir)
}

/// The checkout's current `HEAD` commit.
pub fn head_commit(dir: &Path) -> anyhow::Result<String> {
    let out = run(Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"]))?;
    Ok(out.trim().to_string())
}

/// Run `makepkg --verifysource --noconfirm` in `dir` (downloads sources,
/// executes nothing), then list the newly-materialized source files: every
/// regular file in `dir` that isn't tracked by git and isn't a build script,
/// paired with a `SourceOrigin` inferred from `.SRCINFO`'s `source =` lines.
pub fn verifysource(dir: &Path) -> anyhow::Result<Vec<(PathBuf, SourceOrigin)>> {
    if which("makepkg").is_none() {
        anyhow::bail!(
            "makepkg not found on PATH; install base-devel to check or install AUR packages"
        );
    }
    run(Command::new("makepkg")
        .args(["--verifysource", "--noconfirm"])
        .current_dir(dir))?;

    let tracked = git_tracked_files(dir)?;
    let origins = srcinfo_origins(dir);

    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if tracked.contains(&name) || is_build_script(&name) {
            continue;
        }
        let origin = origins
            .get(&name)
            .cloned()
            .unwrap_or(SourceOrigin::LocalFile);
        out.push((entry.path(), origin));
    }
    Ok(out)
}

fn git_tracked_files(dir: &Path) -> anyhow::Result<HashSet<String>> {
    let out = run(Command::new("git").arg("-C").arg(dir).args(["ls-files"]))?;
    Ok(out.lines().map(str::to_string).collect())
}

fn is_build_script(name: &str) -> bool {
    name == "PKGBUILD"
        || name == ".SRCINFO"
        || name.ends_with(".install")
        || name.ends_with(".patch")
        || name.ends_with(".diff")
}

/// Map each `.SRCINFO` `source =`/`source_<arch> =` entry's local filename to
/// its inferred origin. Missing/unreadable `.SRCINFO` yields an empty map, so
/// callers fall back to `SourceOrigin::LocalFile`.
fn srcinfo_origins(dir: &Path) -> HashMap<String, SourceOrigin> {
    let Ok(content) = std::fs::read_to_string(dir.join(".SRCINFO")) else {
        return HashMap::new();
    };
    parse_srcinfo_sources(&content)
        .into_iter()
        .map(|raw| (source_filename(&raw), classify_origin(&raw)))
        .collect()
}

/// Extract `source`/`source_<arch>` values from a `.SRCINFO` (one per line;
/// no bash array parsing needed since `.SRCINFO` is already flattened).
fn parse_srcinfo_sources(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once('=')?;
            let key = key.trim();
            (key == "source" || key.starts_with("source_")).then(|| value.trim().to_string())
        })
        .collect()
}

/// A `name::url` source value uses `::` to separate the local filename from
/// the fetch URL; without it, the local name is the URL's last path segment.
fn source_filename(raw_value: &str) -> String {
    if let Some((name, _)) = raw_value.split_once("::") {
        return name.to_string();
    }
    let stripped = raw_value.strip_prefix("git+").unwrap_or(raw_value);
    if !stripped.contains("://") {
        return raw_value.to_string();
    }
    stripped
        .rsplit('/')
        .next()
        .unwrap_or(stripped)
        .split(['?', '#'])
        .next()
        .unwrap_or(stripped)
        .to_string()
}

/// Classify a `.SRCINFO` source value as VCS (`git+`/`hg+`/`svn+`/`bzr+`),
/// a plain URL, or a bare local file bundled alongside the PKGBUILD.
fn classify_origin(raw_value: &str) -> SourceOrigin {
    let url = match raw_value.split_once("::") {
        Some((_, url)) => url,
        None => raw_value,
    };
    if ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|p| url.starts_with(p))
    {
        SourceOrigin::Vcs(url.to_string())
    } else if url.contains("://") {
        SourceOrigin::Url(url.to_string())
    } else {
        SourceOrigin::LocalFile
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).find_map(|dir| {
        let candidate = dir.join(bin);
        candidate.is_file().then_some(candidate)
    })
}

/// Run a command, bubbling its stderr into the error on non-zero exit.
fn run(cmd: &mut Command) -> anyhow::Result<String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let output = cmd
        .output()
        .with_context(|| format!("failed to spawn `{program}`"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`{program}` failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_filename_uses_name_before_double_colon() {
        assert_eq!(
            source_filename("foo.tar.gz::https://example.com/dl?x=1"),
            "foo.tar.gz"
        );
    }

    #[test]
    fn source_filename_falls_back_to_url_basename() {
        assert_eq!(
            source_filename("https://example.com/dist/foo-1.0.tar.gz"),
            "foo-1.0.tar.gz"
        );
    }

    #[test]
    fn source_filename_strips_query_string() {
        assert_eq!(
            source_filename("https://example.com/foo.tar.gz?token=abc"),
            "foo.tar.gz"
        );
    }

    #[test]
    fn source_filename_bare_value_is_itself() {
        assert_eq!(source_filename("local-patch.diff"), "local-patch.diff");
    }

    #[test]
    fn classify_origin_detects_git_plus() {
        assert!(matches!(
            classify_origin("git+https://github.com/o/r.git#tag=v1"),
            SourceOrigin::Vcs(_)
        ));
    }

    #[test]
    fn classify_origin_detects_named_vcs_source() {
        assert!(matches!(
            classify_origin("repo::git+https://github.com/o/r.git"),
            SourceOrigin::Vcs(_)
        ));
    }

    #[test]
    fn classify_origin_detects_plain_url() {
        assert!(matches!(
            classify_origin("https://example.com/foo.tar.gz"),
            SourceOrigin::Url(_)
        ));
    }

    #[test]
    fn classify_origin_bare_value_is_local() {
        assert!(matches!(
            classify_origin("local-patch.diff"),
            SourceOrigin::LocalFile
        ));
    }

    #[test]
    fn parse_srcinfo_sources_collects_arch_specific_entries() {
        let content = "pkgbase = x\n\tsource = https://example.com/a.tar.gz\n\tsource_x86_64 = https://example.com/b.tar.gz\n\tdepends = glibc\n";
        let sources = parse_srcinfo_sources(content);
        assert_eq!(
            sources,
            vec![
                "https://example.com/a.tar.gz".to_string(),
                "https://example.com/b.tar.gz".to_string()
            ]
        );
    }

    #[test]
    fn is_build_script_recognizes_all_kinds() {
        assert!(is_build_script("PKGBUILD"));
        assert!(is_build_script(".SRCINFO"));
        assert!(is_build_script("foo.install"));
        assert!(is_build_script("fix.patch"));
        assert!(is_build_script("fix.diff"));
        assert!(!is_build_script("upstream-1.0.tar.gz"));
    }

    #[test]
    fn which_finds_a_binary_known_to_exist_on_path() {
        // `sh` is POSIX-guaranteed and present on every CI/dev box this
        // workspace targets.
        assert!(which("sh").is_some());
    }

    #[test]
    fn which_returns_none_for_a_bogus_binary() {
        assert!(which("definitely-not-a-real-binary-xyz").is_none());
    }
}
