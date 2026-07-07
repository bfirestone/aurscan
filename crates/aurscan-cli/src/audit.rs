//! `aurscan audit` — the installed-system audit. Ports the legacy Python
//! scanner's role: enumerate foreign (AUR) packages straight from pacman's
//! local DB, scan their cached PKGBUILDs, and run the persistence /
//! host-artifact / payload-hash checks through the engine. See
//! `legacy/aurscan.py` (`read_local_db`, `_parse_desc`, `find_pkgbuild_files`,
//! `scan_systemd_persistence`, `scan_host_artifacts`, `hunt_payload_files`)
//! for the ported behavior.

use crate::ack::AckStore;
use crate::config::Config;
use crate::registry;
use crate::report;
use aurscan_core::{PackageJob, ScanTarget, ScriptKind};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Directories AUR helpers cache cloned PKGBUILDs in, ported verbatim from
/// legacy `AUR_CACHE_DIRS`.
const AUR_CACHE_DIRS: &[&str] = &[
    "~/.cache/yay",
    "~/.cache/paru/clone",
    "~/.cache/aurutils",
    "~/.cache/pikaur/aur_repos",
    "/var/cache/pacman/aur",
];

/// One foreign (AUR) package read straight out of pacman's local DB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignPkg {
    pub name: String,
    pub version: String,
    pub install_date: Option<i64>,
}

/// Enumerate foreign (AUR) packages from `{root}/var/lib/pacman/local/*/desc`.
/// Foreign == a `%VALIDATION%` field that is missing/empty or `none`
/// (case-insensitive) -- i.e. not validated by a signature from a sync DB.
/// Ported from legacy `read_local_db`.
pub fn read_local_db(root: &Path) -> anyhow::Result<Vec<ForeignPkg>> {
    let local = root.join("var/lib/pacman/local");
    if !local.is_dir() {
        anyhow::bail!("pacman local DB not found at {}", local.display());
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(&local)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();

    let mut pkgs = Vec::new();
    for entry in entries {
        let desc = entry.join("desc");
        if !desc.is_file() {
            continue;
        }
        let fields = parse_desc(&desc)?;

        let validation = fields
            .get("VALIDATION")
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if validation != "none" && !validation.is_empty() {
            continue;
        }

        let name = fields.get("NAME").map(|v| v.trim().to_string()).unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        let install_date = fields
            .get("INSTALLDATE")
            .map(|v| v.trim())
            .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()))
            .and_then(|v| v.parse::<i64>().ok());

        pkgs.push(ForeignPkg {
            name,
            version: fields.get("VERSION").map(|v| v.trim().to_string()).unwrap_or_default(),
            install_date,
        });
    }
    Ok(pkgs)
}

/// Parse a pacman `desc` file (`%KEY%\nvalue\n\n`) into a flat map. Ported
/// from legacy `_parse_desc`.
fn parse_desc(path: &Path) -> anyhow::Result<HashMap<String, String>> {
    let bytes = std::fs::read(path)?;
    let content = String::from_utf8_lossy(&bytes);

    let mut out: HashMap<String, String> = HashMap::new();
    let mut key: Option<String> = None;
    for line in content.lines() {
        if line.starts_with('%') && line.ends_with('%') {
            let k = line.trim_matches('%').to_string();
            out.insert(k.clone(), String::new());
            key = Some(k);
        } else if let Some(k) = &key {
            if !line.is_empty() {
                let entry = out.entry(k.clone()).or_default();
                *entry = if entry.is_empty() {
                    line.to_string()
                } else {
                    format!("{entry}\n{line}").trim().to_string()
                };
            }
        }
    }
    Ok(out)
}

/// Locate cached PKGBUILD/.install/.SRCINFO files for the given package
/// names across AUR-helper caches (this user's and, when readable, every
/// user's under `/home`). Maps package name -> build-script paths. Ported
/// from legacy `find_pkgbuild_files`.
pub fn find_cached_pkgbuilds(names: &[String]) -> HashMap<String, Vec<PathBuf>> {
    let mut roots: Vec<PathBuf> = AUR_CACHE_DIRS.iter().map(|d| expand_home(d)).collect();
    if let Ok(entries) = std::fs::read_dir("/home") {
        for home in entries.filter_map(Result::ok).map(|e| e.path()) {
            roots.push(home.join(".cache/yay"));
            roots.push(home.join(".cache/paru/clone"));
        }
    }

    let mut found: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        for name in names {
            let pkgdir = root.join(name);
            if !pkgdir.is_dir() {
                continue;
            }
            for entry in walkdir::WalkDir::new(&pkgdir)
                .into_iter()
                .filter_map(Result::ok)
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let fname = entry.file_name().to_string_lossy();
                if fname == "PKGBUILD" || fname == ".SRCINFO" || fname.ends_with(".install") {
                    found
                        .entry(name.clone())
                        .or_default()
                        .push(entry.path().to_path_buf());
                }
            }
        }
    }
    found
}

/// Collect host-side candidate `ScanTarget::HostArtifact`s: systemd unit
/// files (root units + every user's session units), eBPF rootkit pins under
/// `/sys/fs/bpf`, and payload-hunt files under the npm/bun caches and
/// `/var/lib` (so the engine's `payload_hashes` detector can hash them).
/// `root` prefixes every absolute path, honoring `--root` for offline-image
/// scans. Ported from legacy `scan_systemd_persistence`, `scan_host_artifacts`,
/// and the `hunt_payload_files` root list.
pub fn host_artifact_targets(root: &Path) -> Vec<ScanTarget> {
    let mut targets = Vec::new();

    // systemd units: root units + every user's session units.
    let mut unit_dirs = vec![reroot(root, Path::new("/etc/systemd/system"))];
    let home_root = reroot(root, Path::new("/home"));
    if let Ok(entries) = std::fs::read_dir(&home_root) {
        for home in entries.filter_map(Result::ok).map(|e| e.path()) {
            unit_dirs.push(home.join(".config/systemd/user"));
        }
    }
    for udir in &unit_dirs {
        let Ok(entries) = std::fs::read_dir(udir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let is_service = path.extension().and_then(|e| e.to_str()) == Some("service");
            if is_service && entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                targets.push(ScanTarget::HostArtifact { path });
            }
        }
    }

    // eBPF rootkit pins.
    let bpf_dir = reroot(root, Path::new("/sys/fs/bpf"));
    if let Ok(entries) = std::fs::read_dir(&bpf_dir) {
        for entry in entries.filter_map(Result::ok) {
            if entry.file_name().to_string_lossy().starts_with("hidden_") {
                targets.push(ScanTarget::HostArtifact { path: entry.path() });
            }
        }
    }

    // Payload-hunt files: npm/bun package caches + /var/lib.
    let mut hunt_roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        hunt_roots.push(reroot(root, &home.join(".npm/_cacache")));
        hunt_roots.push(reroot(root, &home.join(".bun/install/cache")));
    }
    hunt_roots.push(reroot(root, Path::new("/var/lib")));
    if let Ok(entries) = std::fs::read_dir(&home_root) {
        for home in entries.filter_map(Result::ok).map(|e| e.path()) {
            hunt_roots.push(home.join(".npm/_cacache"));
            hunt_roots.push(home.join(".bun/install/cache"));
        }
    }
    for hroot in hunt_roots {
        if !hroot.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&hroot).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                targets.push(ScanTarget::HostArtifact {
                    path: entry.path().to_path_buf(),
                });
            }
        }
    }

    targets
}

/// Expand a `~/`-prefixed cache-dir constant against the real home dir;
/// pass absolute paths through unchanged.
fn expand_home(dir: &str) -> PathBuf {
    match dir.strip_prefix("~/") {
        Some(rest) => dirs::home_dir()
            .map(|h| h.join(rest))
            .unwrap_or_else(|| PathBuf::from(dir)),
        None => PathBuf::from(dir),
    }
}

/// Re-root an absolute path under `root` (a no-op when `root` is `/`), so
/// offline-image `--root` scans honor the fixture tree instead of the live
/// filesystem.
fn reroot(root: &Path, abs: &Path) -> PathBuf {
    if root == Path::new("/") {
        return abs.to_path_buf();
    }
    match abs.strip_prefix("/") {
        Ok(rel) => root.join(rel),
        Err(_) => root.join(abs),
    }
}

/// Wrap a cached build-script path as a `BuildScript` target, inferring its
/// `ScriptKind` from the filename (mirrors `registry::wrap_file`).
fn wrap_build_script(path: &Path) -> ScanTarget {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let kind = if name == "PKGBUILD" {
        ScriptKind::Pkgbuild
    } else if name.ends_with(".install") {
        ScriptKind::InstallScript
    } else if name == ".SRCINFO" {
        ScriptKind::SrcInfo
    } else {
        ScriptKind::Other
    };
    ScanTarget::BuildScript {
        path: path.to_path_buf(),
        kind,
    }
}

/// `aurscan audit --root <root>`: enumerate foreign packages from the local
/// pacman DB, scan their cached build scripts and host-artifact locations
/// through the engine, print a legacy-parity summary, and return the worst
/// exit code.
pub fn run_audit(root: &Path, cfg: &Config) -> i32 {
    let engine = match registry::build_engine(cfg) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 3;
        }
    };

    let foreign = match read_local_db(root) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 3;
        }
    };

    let names: Vec<String> = foreign.iter().map(|p| p.name.clone()).collect();
    let cached = find_cached_pkgbuilds(&names);

    let mut jobs: Vec<PackageJob> = foreign
        .iter()
        .map(|pkg| PackageJob {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            aur_meta: None,
            targets: cached
                .get(&pkg.name)
                .map(|paths| paths.iter().map(|p| wrap_build_script(p)).collect())
                .unwrap_or_default(),
        })
        .collect();

    jobs.push(PackageJob {
        name: "<host>".to_string(),
        version: String::new(),
        aur_meta: None,
        targets: host_artifact_targets(root),
    });

    let mut reports = engine.scan(&jobs);
    if !cfg.record_features {
        for r in &mut reports {
            r.features.clear();
        }
    }

    println!("Scanned {} foreign (AUR) package(s).", foreign.len());
    let acks = AckStore::load();
    print!("{}", report::render_text(&reports, &acks, false, false));

    report::worst_exit_code(&reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(p: &std::path::Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    #[test]
    fn reads_only_foreign_packages() {
        let root = tempfile::tempdir().unwrap();
        write(
            &root.path().join("var/lib/pacman/local/evil-1.0/desc"),
            "%NAME%\nevil\n\n%VERSION%\n1.0\n\n%VALIDATION%\nNone\n\n%INSTALLDATE%\n1718000000\n",
        );
        write(
            &root.path().join("var/lib/pacman/local/coreutils-9/desc"),
            "%NAME%\ncoreutils\n\n%VERSION%\n9\n\n%VALIDATION%\npgp\n\n",
        );
        let pkgs = read_local_db(root.path()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "evil");
    }

    #[test]
    fn parse_desc_multivalue() {
        let dir = tempfile::tempdir().unwrap();
        let desc = dir.path().join("desc");
        write(&desc, "%NAME%\nfoo\n\n%DEPENDS%\nbar\nbaz\n\n");

        let fields = parse_desc(&desc).unwrap();
        assert_eq!(fields.get("NAME").map(String::as_str), Some("foo"));
        assert_eq!(fields.get("DEPENDS").map(String::as_str), Some("bar\nbaz"));
    }

    #[test]
    fn ebpf_pin_becomes_host_target() {
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("sys/fs/bpf/hidden_x"), "");

        let targets = host_artifact_targets(root.path());
        let expected = root.path().join("sys/fs/bpf/hidden_x");
        assert!(targets
            .iter()
            .any(|t| matches!(t, ScanTarget::HostArtifact { path } if path == &expected)));
    }

    #[test]
    fn run_audit_reports_missing_local_db_as_error_exit() {
        let root = tempfile::tempdir().unwrap();
        let cfg = Config {
            no_cache: true,
            ..Default::default()
        };
        assert_eq!(run_audit(root.path(), &cfg), 3);
    }

    #[test]
    fn run_audit_returns_clean_exit_for_a_foreign_package_with_no_findings() {
        let root = tempfile::tempdir().unwrap();
        write(
            &root.path().join("var/lib/pacman/local/evil-1.0/desc"),
            "%NAME%\nevil\n\n%VERSION%\n1.0\n\n%VALIDATION%\nNone\n\n",
        );
        let cfg = Config {
            no_cache: true,
            ..Default::default()
        };
        assert_eq!(run_audit(root.path(), &cfg), 0);
    }
}
