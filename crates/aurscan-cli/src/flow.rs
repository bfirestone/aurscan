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

#[derive(Debug)]
pub(crate) struct ScannedAurPackage {
    pub info: AurInfo,
    pub checkout: Option<PathBuf>,
    pub reports: Vec<PackageReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchPlan {
    SkipWithoutCheckout,
    EnsureCheckoutAndSkipSources,
    FullScan,
}

fn fetch_plan(clean_at_remote_head: bool, require_checkout: bool) -> FetchPlan {
    match (clean_at_remote_head, require_checkout) {
        (true, false) => FetchPlan::SkipWithoutCheckout,
        (true, true) => FetchPlan::EnsureCheckoutAndSkipSources,
        (false, _) => FetchPlan::FullScan,
    }
}

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
pub(crate) fn fetch_and_scan(
    info: &AurInfo,
    cfg: &Config,
    require_checkout: bool,
) -> anyhow::Result<ScannedAurPackage> {
    let mut ledger = crate::commit_ledger::CommitLedger::load();
    let (ruleset_version, detector_epoch) = registry::cache_identity();

    let remote_head = if cfg.no_cache {
        None
    } else {
        fetch::remote_head(&info.package_base).ok()
    };
    let clean_at_remote_head = remote_head.as_ref().is_some_and(|head| {
        ledger.clean_at(&info.package_base, head, ruleset_version, detector_epoch)
    });
    let plan = fetch_plan(clean_at_remote_head, require_checkout);

    match plan {
        FetchPlan::SkipWithoutCheckout => {
            let head = remote_head.as_deref().expect("clean remote head exists");
            eprintln!(
                "==> aurscan: {} unchanged since its last clean scan ({}), fetch skipped",
                report::terminal_safe(&info.name),
                &head[..7.min(head.len())]
            );
            Ok(ScannedAurPackage {
                info: info.clone(),
                checkout: None,
                reports: clean_reports(info),
            })
        }
        FetchPlan::EnsureCheckoutAndSkipSources => {
            let dir = fetch::sync_pkgbase(&info.package_base)?;
            let expected_head = remote_head.as_deref().expect("clean remote head exists");
            if fetch::checkout_matches_clean_head(&dir, expected_head).unwrap_or(false) {
                eprintln!(
                    "==> aurscan: {} checkout synchronized at {}, source verification skipped",
                    report::terminal_safe(&info.name),
                    &expected_head[..7.min(expected_head.len())]
                );
                return Ok(ScannedAurPackage {
                    info: info.clone(),
                    checkout: Some(dir),
                    reports: clean_reports(info),
                });
            }

            // The remote may have advanced between ls-remote and sync, or a
            // checkout may contain tracked changes. Scan this exact already-
            // synchronized directory rather than trusting the stale ledger.
            full_scan_synchronized_checkout(
                &dir,
                info,
                cfg,
                &mut ledger,
                ruleset_version,
                detector_epoch,
            )
        }
        FetchPlan::FullScan => {
            let dir = fetch::sync_pkgbase(&info.package_base)?;
            full_scan_synchronized_checkout(
                &dir,
                info,
                cfg,
                &mut ledger,
                ruleset_version,
                detector_epoch,
            )
        }
    }
}

fn clean_reports(info: &AurInfo) -> Vec<PackageReport> {
    vec![PackageReport {
        package: info.name.clone(),
        verdict: aurscan_core::Verdict::Clean,
        findings: Vec::new(),
        features: Vec::new(),
    }]
}

fn full_scan_synchronized_checkout(
    dir: &Path,
    info: &AurInfo,
    cfg: &Config,
    ledger: &mut crate::commit_ledger::CommitLedger,
    ruleset_version: u32,
    detector_epoch: u32,
) -> anyhow::Result<ScannedAurPackage> {
    // Bind the scan to a clean HEAD before it starts and verify the same state
    // again afterward. A dirty tree is scanned for safety but can never update
    // the commit ledger, even if it is later cleaned while scanning.
    let scanned_head = fetch::head_commit(dir).ok();
    let clean_before_scan = scanned_head
        .as_deref()
        .is_some_and(|head| fetch::checkout_matches_clean_head(dir, head).unwrap_or(false));
    let source_files = fetch::verifysource(dir)?;
    let scan_result = scan_dir_pipeline(
        dir,
        &info.name,
        &info.version,
        Some(info.to_metadata()),
        &source_files,
        cfg,
    );
    let reports = after_completed_scan(scan_result, |reports| {
        let clean_after_scan = scanned_head
            .as_deref()
            .is_some_and(|head| fetch::checkout_matches_clean_head(dir, head).unwrap_or(false));
        if can_record_scanned_checkout(scanned_head.as_deref(), clean_before_scan, clean_after_scan)
        {
            ledger.record(
                &info.package_base,
                ledger_entry(
                    scanned_head.expect("recordable checkout has a scanned HEAD"),
                    reports,
                    ruleset_version,
                    detector_epoch,
                ),
            );
        }
    })?;
    Ok(ScannedAurPackage {
        info: info.clone(),
        checkout: Some(dir.to_path_buf()),
        reports,
    })
}

fn can_record_scanned_checkout(
    scanned_head: Option<&str>,
    clean_before_scan: bool,
    clean_after_scan: bool,
) -> bool {
    scanned_head.is_some() && clean_before_scan && clean_after_scan
}

fn after_completed_scan(
    scan_result: anyhow::Result<Vec<PackageReport>>,
    record: impl FnOnce(&[PackageReport]),
) -> anyhow::Result<Vec<PackageReport>> {
    let reports = scan_result?;
    record(&reports);
    Ok(reports)
}

fn ledger_entry(
    commit: String,
    reports: &[PackageReport],
    ruleset_version: u32,
    detector_epoch: u32,
) -> crate::commit_ledger::Entry {
    crate::commit_ledger::Entry {
        commit,
        verdict: worst_verdict_label(reports).to_string(),
        ruleset_version,
        detector_epoch,
    }
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
        match fetch_and_scan(info, cfg, false) {
            Ok(scanned) => reports.extend(scanned.reports),
            Err(e) => eprintln!(
                "warning: {} could not be fetched/scanned: {e:#}",
                report::terminal_safe(&info.name)
            ),
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
        match fetch_and_scan(info, cfg, false) {
            Ok(scanned) => reports.extend(scanned.reports),
            Err(e) => {
                eprintln!(
                    "error: {} could not be fetched/scanned: {e:#}",
                    report::terminal_safe(&info.name)
                );
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

    #[test]
    fn fetch_plan_covers_clean_ledger_and_checkout_requirements() {
        let cases = [
            (true, false, FetchPlan::SkipWithoutCheckout),
            (true, true, FetchPlan::EnsureCheckoutAndSkipSources),
            (false, false, FetchPlan::FullScan),
            (false, true, FetchPlan::FullScan),
        ];
        for (clean, require_checkout, expected) in cases {
            assert_eq!(fetch_plan(clean, require_checkout), expected);
        }
    }

    #[test]
    fn ledger_entry_preserves_identity_and_maps_worst_verdict() {
        for (verdict, expected_label) in [
            (Verdict::Clean, "clean"),
            (Verdict::Advisory(vec![]), "advisory"),
            (Verdict::Block(vec![]), "block"),
        ] {
            let reports = vec![PackageReport {
                package: "pkg".into(),
                verdict,
                findings: vec![],
                features: vec![],
            }];

            let entry = ledger_entry("abc123".into(), &reports, 17, 23);
            assert_eq!(entry.commit, "abc123");
            assert_eq!(entry.verdict, expected_label);
            assert_eq!(entry.ruleset_version, 17);
            assert_eq!(entry.detector_epoch, 23);
        }
    }

    #[test]
    fn ledger_recording_happens_only_after_a_completed_scan() {
        let mut recorded = 0;
        let failed: anyhow::Result<Vec<PackageReport>> = Err(anyhow::anyhow!("scan failed"));
        assert!(after_completed_scan(failed, |_| recorded += 1).is_err());
        assert_eq!(recorded, 0);

        let completed = vec![PackageReport {
            package: "p".into(),
            verdict: Verdict::Clean,
            findings: vec![],
            features: vec![],
        }];
        let reports = after_completed_scan(Ok(completed), |_| recorded += 1).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(recorded, 1);
    }

    #[test]
    fn full_scan_ledger_recording_requires_bound_clean_content_before_and_after_scan() {
        assert!(can_record_scanned_checkout(Some("commit"), true, true));
        assert!(!can_record_scanned_checkout(None, true, true));
        assert!(!can_record_scanned_checkout(Some("commit"), false, true));
        assert!(!can_record_scanned_checkout(Some("commit"), true, false));
        assert!(!can_record_scanned_checkout(None, false, false));
    }
}
