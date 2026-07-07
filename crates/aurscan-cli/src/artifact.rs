//! `scan-artifact`: scan already-built `.pkg.tar.zst` archives before
//! install, plus the ALPM `PreTransaction` hook entry point (`--hook`) that
//! reads target archive/package identifiers from stdin (the `NeedsTargets`
//! contract) and aborts the transaction on a Block verdict.

use crate::ack::AckStore;
use crate::config::Config;
use crate::registry;
use crate::report;
use aurscan_core::target::expand_archive;
use aurscan_core::PackageJob;
use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};

/// pacman's built-package cache, where `--hook` resolves bare `pkgname`
/// stdin lines to their built archive.
const PACMAN_CACHE_DIR: &str = "/var/cache/pacman/pkg";

/// `scan-artifact <pkg>...`: expand each built archive into `PackageFile`
/// targets, scan them through the full engine, render, and return the worst
/// exit code.
pub fn scan_files(
    paths: &[PathBuf],
    cfg: &Config,
    json: bool,
    no_color: bool,
    verbose: bool,
) -> i32 {
    let engine = match registry::build_engine(cfg) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 3;
        }
    };

    let mut jobs = Vec::new();
    for path in paths {
        match expand_archive(path) {
            Ok(targets) => jobs.push(PackageJob {
                name: archive_name(path),
                version: String::new(),
                aur_meta: None,
                targets,
            }),
            Err(e) => eprintln!("warning: {} could not be scanned: {e:#}", path.display()),
        }
    }

    let mut reports = engine.scan(&jobs);
    if !cfg.record_features {
        for r in &mut reports {
            r.features.clear();
        }
    }

    let acks = AckStore::load();
    if json {
        let value = report::render_json(&reports);
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    } else {
        let color = !no_color && std::io::stdout().is_terminal();
        print!("{}", report::render_text(&reports, &acks, verbose, color));
    }

    report::worst_exit_code(&reports)
}

/// The ALPM hook entry point: read target lines from stdin, scan whatever
/// resolves to an existing built archive, and exit non-interactively (no
/// prompts -- stdin is consumed by the hook contract, not a tty).
pub fn hook_main() -> i32 {
    let cfg = Config::load();
    let lines: Vec<String> = std::io::stdin()
        .lock()
        .lines()
        .map_while(Result::ok)
        .collect();
    hook_scan_paths(&lines, &cfg)
}

/// Stdin-free seam for `hook_main`: resolve each of `lines` to a built
/// archive (an absolute `.pkg.tar.zst` path is used as-is; anything else is
/// treated as a `pkgname` and resolved against pacman's package cache) and
/// scan whatever resolves. Exits `0` with nothing scanned if nothing
/// resolves -- this is "nothing to check", not an error.
pub fn hook_scan_paths(lines: &[String], cfg: &Config) -> i32 {
    let cache_dir = Path::new(PACMAN_CACHE_DIR);
    let paths: Vec<PathBuf> = lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter_map(|l| resolve_target(l, cache_dir))
        .collect();

    if paths.is_empty() {
        return 0;
    }
    scan_files(&paths, cfg, false, true, false)
}

/// Resolve one hook stdin line to a scannable, existing `.pkg.tar.zst`
/// path: pass an absolute archive path through as-is; otherwise treat the
/// line as a `pkgname` and pick the newest matching `<pkgname>-*.pkg.tar.zst`
/// out of `cache_dir`.
fn resolve_target(line: &str, cache_dir: &Path) -> Option<PathBuf> {
    let candidate = Path::new(line);
    if candidate.is_absolute() {
        return (is_pkg_archive(candidate) && candidate.is_file()).then(|| candidate.to_path_buf());
    }

    let prefix = format!("{line}-");
    let mut matches: Vec<PathBuf> = std::fs::read_dir(cache_dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| is_pkg_archive(p) && file_name(p).starts_with(&prefix))
        .collect();
    matches.sort();
    matches.pop()
}

fn is_pkg_archive(path: &Path) -> bool {
    file_name(path).ends_with(".pkg.tar.zst")
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The package name for a report: the archive's filename stem, up to (but
/// not including) `.pkg.tar`.
fn archive_name(path: &Path) -> String {
    let name = file_name(path);
    name.split(".pkg.tar").next().unwrap_or(&name).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkg(members: &[(&str, u32, &[u8])], file_name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(file_name);
        let f = std::fs::File::create(&path).unwrap();
        let enc = zstd::Encoder::new(f, 0).unwrap().auto_finish();
        let mut ar = tar::Builder::new(enc);
        for (name, mode, data) in members {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_cksum();
            ar.append_data(&mut h, name, *data).unwrap();
        }
        ar.finish().unwrap();
        (dir, path)
    }

    fn make_malicious_pkg() -> (tempfile::TempDir, PathBuf) {
        make_pkg(
            &[
                (".PKGINFO", 0o644, b"pkgname=evil\n" as &[u8]),
                ("usr/bin/evil", 0o4755, b"\x7fELFxx" as &[u8]),
            ],
            "evil-1.0-1-x86_64.pkg.tar.zst",
        )
    }

    fn test_cfg() -> Config {
        Config {
            no_cache: true,
            ..Default::default()
        }
    }

    #[test]
    fn scan_files_blocks_on_a_setuid_binary_in_a_built_archive() {
        let (_dir, path) = make_malicious_pkg();
        let code = scan_files(&[path], &test_cfg(), false, true, false);
        assert_eq!(code, 2, "a setuid binary dropped into usr/bin must block");
    }

    #[test]
    fn scan_files_clean_archive_yields_exit_0() {
        let (_dir, path) = make_pkg(
            &[
                (".PKGINFO", 0o644, b"pkgname=hello\n" as &[u8]),
                ("usr/bin/hello", 0o755, b"\x7fELFxx" as &[u8]),
            ],
            "hello-1.0-1-x86_64.pkg.tar.zst",
        );
        let code = scan_files(&[path], &test_cfg(), false, true, false);
        assert_eq!(code, 0);
    }

    #[test]
    fn archive_name_strips_pkg_tar_suffix() {
        assert_eq!(
            archive_name(Path::new("/tmp/evil-1.0-1-x86_64.pkg.tar.zst")),
            "evil-1.0-1-x86_64"
        );
    }

    #[test]
    fn hook_scan_paths_resolves_absolute_archive_paths_and_blocks() {
        let (_dir, path) = make_malicious_pkg();
        let lines = vec![path.display().to_string()];
        assert_eq!(hook_scan_paths(&lines, &test_cfg()), 2);
    }

    #[test]
    fn hook_scan_paths_exits_zero_when_nothing_resolves() {
        let lines = vec!["no-such-package".to_string()];
        assert_eq!(hook_scan_paths(&lines, &test_cfg()), 0);
    }

    #[test]
    fn hook_scan_paths_ignores_blank_lines() {
        let lines = vec![String::new(), "  ".to_string()];
        assert_eq!(hook_scan_paths(&lines, &test_cfg()), 0);
    }

    #[test]
    fn resolve_target_rejects_relative_non_pkgname_paths_that_dont_exist_in_cache() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(resolve_target("some-pkgname", dir.path()), None);
    }

    #[test]
    fn resolve_target_picks_newest_matching_cache_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo-1.0-1-x86_64.pkg.tar.zst"), b"").unwrap();
        std::fs::write(dir.path().join("foo-2.0-1-x86_64.pkg.tar.zst"), b"").unwrap();
        std::fs::write(dir.path().join("foobar-1.0-1-x86_64.pkg.tar.zst"), b"").unwrap();

        let resolved = resolve_target("foo", dir.path()).unwrap();
        assert_eq!(file_name(&resolved), "foo-2.0-1-x86_64.pkg.tar.zst");
    }
}
