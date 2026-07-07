//! Fetch -> scan -> gate pipeline for name-based `check <name>` and
//! `install`: resolves the AUR dependency tree, clones each pkgbase, scans
//! build scripts and verified sources, then (for `install`) gates on the
//! verdict before delegating to `paru -S`.

use crate::ack::AckStore;
use crate::aur_rpc::{self, AurInfo};
use crate::config::Config;
use crate::fetch;
use crate::gate::{self, GateOutcome};
use crate::registry;
use crate::report;
use aurscan_core::target::{expand_build_dir, expand_source_files};
use aurscan_core::{AurMetadata, PackageJob, PackageReport, SourceOrigin};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Scan an already-cloned pkgbase directory: its build scripts, then any
/// already-materialized `source_files` (from `fetch::verifysource`). Pure
/// aside from reading `dir`/`source_files` off disk -- no git, makepkg, or
/// network calls, so it's the piece exercised directly by tests.
pub fn scan_dir_pipeline(
    dir: &Path,
    name: &str,
    version: &str,
    meta: Option<AurMetadata>,
    source_files: &[(PathBuf, SourceOrigin)],
    cfg: &Config,
) -> anyhow::Result<Vec<PackageReport>> {
    let engine = registry::build_engine(cfg)?;

    let build_job = PackageJob {
        name: name.to_string(),
        version: version.to_string(),
        aur_meta: meta.clone(),
        targets: expand_build_dir(dir, &[]),
    };
    let mut reports = vec![engine.scan_package(&build_job)];

    let source_targets = expand_source_files(source_files);
    if !source_targets.is_empty() {
        let source_job = PackageJob {
            name: name.to_string(),
            version: version.to_string(),
            aur_meta: meta,
            targets: source_targets,
        };
        reports.push(engine.scan_package(&source_job));
    }

    Ok(reports)
}

/// Clone `info`'s pkgbase, verify its sources, and scan both through
/// `scan_dir_pipeline`. Records the scanned commit best-effort for the
/// ALPM-hook task's TOCTOU check.
fn fetch_and_scan(info: &AurInfo, cfg: &Config) -> anyhow::Result<Vec<PackageReport>> {
    let dir = fetch::sync_pkgbase(&info.package_base)?;
    record_scanned_commit(&info.package_base, &dir);
    let source_files = fetch::verifysource(&dir)?;
    scan_dir_pipeline(
        &dir,
        &info.name,
        &info.version,
        Some(info.to_metadata()),
        &source_files,
        cfg,
    )
}

/// `check <name>...`: resolve the AUR dependency tree, clone each pkgbase,
/// scan build scripts + verified sources, and report without installing.
pub fn run_check_names(
    names: &[&str],
    cfg: &Config,
    hook: bool,
    json: bool,
    no_color: bool,
    verbose: bool,
) -> i32 {
    let _ = hook; // reserved: `check` never gates/prompts, only reports.

    let infos = match aur_rpc::resolve_aur_deps(names) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 3;
        }
    };

    let mut reports = Vec::new();
    for info in &infos {
        match fetch_and_scan(info, cfg) {
            Ok(r) => reports.extend(r),
            Err(e) => eprintln!("warning: {} could not be fetched/scanned: {e:#}", info.name),
        }
    }

    render(&reports, json, no_color, verbose);
    report::worst_exit_code(&reports)
}

/// `install <name>...`: same scan as `check`, then gate on the verdicts --
/// abort on Block/declined-Advisory, or delegate to `paru -S`.
pub fn run_install(
    names: &[&str],
    allow: &[String],
    cfg: &Config,
    json: bool,
    no_color: bool,
    verbose: bool,
) -> i32 {
    let infos = match aur_rpc::resolve_aur_deps(names) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 3;
        }
    };

    let mut reports = Vec::new();
    for info in &infos {
        match fetch_and_scan(info, cfg) {
            Ok(r) => reports.extend(r),
            Err(e) => {
                eprintln!("error: {} could not be fetched/scanned: {e:#}", info.name);
                return 3;
            }
        }
    }

    render(&reports, json, no_color, verbose);

    match gate::decide(&reports, allow, true, false) {
        GateOutcome::Proceed => run_paru_install(names),
        GateOutcome::Abort => {
            eprintln!("aborted: blocked or declined-advisory findings for one or more packages");
            2
        }
    }
}

fn render(reports: &[PackageReport], json: bool, no_color: bool, verbose: bool) {
    let acks = AckStore::load();
    if json {
        let value = report::render_json(reports);
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    } else {
        let color = !no_color && std::io::stdout().is_terminal();
        print!("{}", report::render_text(reports, &acks, verbose, color));
    }
}

fn run_paru_install(names: &[&str]) -> i32 {
    match Command::new("paru").arg("-S").args(names).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("error: failed to launch paru: {e:#}");
            3
        }
    }
}

/// Best-effort record of `pkgbase`'s scanned `HEAD` commit, consumed by the
/// ALPM hook's TOCTOU check. Failures (unwritable cache dir, git error) are
/// silently ignored -- this is advisory bookkeeping, not part of the gate.
fn record_scanned_commit(pkgbase: &str, dir: &Path) {
    let Ok(commit) = fetch::head_commit(dir) else {
        return;
    };
    let Some(path) = dirs::cache_dir().map(|d| d.join("aurscan/scanned_commits.json")) else {
        return;
    };
    let mut commits: std::collections::HashMap<String, String> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    commits.insert(pkgbase.to_string(), commit);

    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    if let Ok(json) = serde_json::to_string_pretty(&commits) {
        let _ = std::fs::write(&path, json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::Verdict;

    #[test]
    fn scan_dir_pipeline_blocks_on_a_planted_ioc_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("PKGBUILD"),
            b"pkgname=evil\nbuild() {\n  npm install atomic-lockfile\n}\n",
        )
        .unwrap();

        let cfg = Config {
            no_cache: true,
            ..Default::default()
        };
        let reports = scan_dir_pipeline(dir.path(), "evil", "1.0-1", None, &[], &cfg).unwrap();

        assert!(
            reports
                .iter()
                .any(|r| matches!(r.verdict, Verdict::Block(_))),
            "expected a Block verdict from the planted token, got: {reports:?}"
        );
    }

    #[test]
    fn scan_dir_pipeline_scans_source_files_separately_from_build_scripts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), b"pkgname=x\npkgver=1.0\n").unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = src_dir.path().join("upstream.tar.gz");
        std::fs::write(&src_path, b"npm install atomic-lockfile\n").unwrap();

        let cfg = Config {
            no_cache: true,
            ..Default::default()
        };
        let source_files = vec![(
            src_path,
            SourceOrigin::Url("https://example.com/upstream.tar.gz".into()),
        )];
        let reports = scan_dir_pipeline(dir.path(), "x", "1.0", None, &source_files, &cfg).unwrap();

        assert_eq!(
            reports.len(),
            2,
            "expected a build-script report and a source-file report"
        );
        assert!(matches!(reports[0].verdict, Verdict::Clean));
        assert!(matches!(reports[1].verdict, Verdict::Block(_)));
    }

    #[test]
    fn scan_dir_pipeline_clean_dir_yields_one_clean_report() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("PKGBUILD"),
            b"pkgname=hello\npkgver=1.0\nsource=(\"https://example.com/hello-1.0.tar.gz\")\n",
        )
        .unwrap();

        let cfg = Config {
            no_cache: true,
            ..Default::default()
        };
        let reports = scan_dir_pipeline(dir.path(), "hello", "1.0", None, &[], &cfg).unwrap();

        assert_eq!(reports.len(), 1);
        assert!(matches!(reports[0].verdict, Verdict::Clean));
    }
}
