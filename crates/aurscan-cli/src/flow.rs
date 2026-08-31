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
/// `scan_dir_pipeline` -- unless the AUR's current commit already scanned
/// Clean under the current ruleset + detector epoch, in which case one
/// `git ls-remote` round-trip replaces the whole fetch. The clone and
/// `makepkg --verifysource` are where a repeat scan's network and
/// wall-clock cost live; the redb result cache cannot help there because
/// you must *have* the content to hash it.
fn fetch_and_scan(info: &AurInfo, cfg: &Config) -> anyhow::Result<Vec<PackageReport>> {
    let mut ledger = crate::commit_ledger::CommitLedger::load();
    let (ruleset_version, detector_epoch) = registry::cache_identity();

    let remote_head = if cfg.no_cache {
        None
    } else {
        fetch::remote_head(&info.package_base).ok()
    };
    if let Some(head) = &remote_head {
        if ledger.clean_at(&info.package_base, head, ruleset_version, detector_epoch) {
            eprintln!(
                "==> aurscan: {} unchanged since its last clean scan ({}), fetch skipped",
                info.name,
                &head[..7.min(head.len())]
            );
            return Ok(vec![PackageReport {
                package: info.name.clone(),
                verdict: aurscan_core::Verdict::Clean,
                findings: Vec::new(),
                features: Vec::new(),
            }]);
        }
    }

    let dir = fetch::sync_pkgbase(&info.package_base)?;
    let source_files = fetch::verifysource(&dir)?;
    let reports = scan_dir_pipeline(
        &dir,
        &info.name,
        &info.version,
        Some(info.to_metadata()),
        &source_files,
        cfg,
    )?;

    // Record *after* scanning, with the verdict: the pre-ledger version of
    // this wrote the commit before the scan ran, so it could never say
    // whether the commit was safe to skip.
    if let Ok(commit) = fetch::head_commit(&dir) {
        ledger.record(
            &info.package_base,
            crate::commit_ledger::Entry {
                commit,
                verdict: worst_verdict_label(&reports).to_string(),
                ruleset_version,
                detector_epoch,
            },
        );
    }
    Ok(reports)
}

/// The worst verdict across `reports`, as the ledger's label.
fn worst_verdict_label(reports: &[PackageReport]) -> &'static str {
    match report::worst_exit_code(reports) {
        2 => "block",
        1 => "advisory",
        _ => "clean",
    }
}

/// `check <name>...`: resolve the AUR dependency tree, clone each pkgbase,
/// scan build scripts + verified sources, and report without installing.
pub fn run_check_names(
    names: &[&str],
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
            Err(e) => eprintln!("warning: {} could not be fetched/scanned: {e:#}", info.name),
        }
    }

    crate::ack::apply_acks(&mut reports, &AckStore::load(), &cfg.policy());
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

    // Acked findings must not gate: without this, an acknowledged advisory
    // still prompted on every install.
    crate::ack::apply_acks(&mut reports, &AckStore::load(), &cfg.policy());
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
