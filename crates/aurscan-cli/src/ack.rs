//! Acknowledgement store: lets a user silence a specific finding on a specific
//! package without suppressing the detector globally. Keyed by
//! `(package, detector, blake3(location + excerpt))` so re-running against the
//! same evidence stays quiet, while any change in the matched content resurfaces.

use aurscan_core::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

pub struct AckStore {
    acked: HashSet<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct AckFile {
    #[serde(default)]
    acknowledged: Vec<String>,
}

impl AckStore {
    /// Load `~/.config/aurscan/acknowledged.toml`; empty on missing/invalid.
    pub fn load() -> Self {
        let acked = Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str::<AckFile>(&s).ok())
            .map(|f| f.acknowledged.into_iter().collect())
            .unwrap_or_default();
        Self { acked }
    }

    /// Stable acknowledgement key for a finding.
    ///
    /// Stability is the point: an ack must survive a pkgver bump (the user
    /// judged the *finding*, not one release of it) but expire when the
    /// matched content changes. The excerpt pins the content; package and
    /// location are normalized because both embed versions -- artifact
    /// reports are named after the archive stem
    /// (`zen-browser-bin-1.21.16b-1-x86_64`) and their locations carry the
    /// full versioned archive path. Un-normalized, every upgrade un-acked
    /// everything, so the same four browser advisories re-prompted forever.
    pub fn key(f: &Finding) -> String {
        let is_llm = matches!(&f.confidence, aurscan_core::Confidence::Llm);
        let location = if is_llm {
            stable_llm_location(&f.evidence.location)
        } else {
            stable_location(&f.evidence.location)
        };
        let package = if is_llm {
            f.package.clone()
        } else {
            stable_package(&f.package)
        };
        let h = blake3::hash(format!("{}|{}", location, f.evidence.excerpt).as_bytes());
        format!("{}:{}:{}", package, f.detector.0, &h.to_hex()[..16])
    }

    pub fn is_acked(&self, f: &Finding) -> bool {
        self.acked.contains(&Self::key(f))
    }

    /// Record and persist a reviewed batch with one acknowledgement-file write.
    pub fn add_batch_and_persist(&mut self, findings: &[&Finding]) -> anyhow::Result<()> {
        self.acked
            .extend(findings.iter().map(|finding| Self::key(finding)));
        self.persist()
    }

    /// Record and persist an acknowledgement for a finding.
    #[cfg(test)]
    pub fn add(&mut self, f: &Finding) -> anyhow::Result<()> {
        self.add_batch_and_persist(&[f])
    }

    fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("aurscan/acknowledged.toml"))
    }

    fn persist(&self) -> anyhow::Result<()> {
        let Some(path) = Self::path() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut acknowledged: Vec<String> = self.acked.iter().cloned().collect();
        acknowledged.sort();
        std::fs::write(&path, toml::to_string_pretty(&AckFile { acknowledged })?)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_keys<I: IntoIterator<Item = String>>(keys: I) -> Self {
        Self {
            acked: keys.into_iter().collect(),
        }
    }
}

/// The location, version-invariant. `archive!member` keeps only the member
/// path (already version-free inside the archive). `path:line` drops the
/// line number (they shift between releases while the excerpt pins the
/// content) and keeps only the file's basename (clone/cache prefixes vary
/// by invocation).
fn stable_llm_location(location: &str) -> String {
    match location.rsplit_once(':') {
        Some((path, suffix)) if is_line_or_range(suffix) => path.to_string(),
        _ => location.to_string(),
    }
}

fn is_line_or_range(suffix: &str) -> bool {
    let mut bounds = suffix.split('-');
    let valid = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    match (bounds.next(), bounds.next(), bounds.next()) {
        (Some(line), None, None) => valid(line),
        (Some(start), Some(end), None) => valid(start) && valid(end),
        _ => false,
    }
}

fn stable_location(location: &str) -> String {
    if let Some((_, member)) = location.rsplit_once('!') {
        return member.to_string();
    }
    let path = match location.rsplit_once(':') {
        Some((p, line)) if !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()) => p,
        _ => location,
    };
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// Strip `-pkgver-pkgrel-arch` off an archive-stem package name. Applied
/// only when the trailing three dash-fields actually look like Arch version
/// metadata, so ordinary package names pass through untouched.
fn stable_package(package: &str) -> String {
    let mut it = package.rsplitn(4, '-');
    let (Some(arch), Some(rel), Some(ver), Some(name)) =
        (it.next(), it.next(), it.next(), it.next())
    else {
        return package.to_string();
    };
    let archish = matches!(
        arch,
        "x86_64"
            | "aarch64"
            | "any"
            | "i686"
            | "pentium4"
            | "armv7h"
            | "armv6h"
            | "arm"
            | "riscv64"
    );
    let relish = !rel.is_empty() && rel.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    let verish = ver
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    if archish && relish && verish {
        name.to_string()
    } else {
        package.to_string()
    }
}

/// Recompute each report's verdict from its *unacknowledged* findings only.
///
/// Without this, an ack was cosmetic: the finding disappeared from text
/// output while the verdict (and therefore the exit code, the paru y/N
/// prompt, and the ALPM AbortOnFail gate) still counted it. Findings are
/// left in place so reports and JSON stay a full record of what was seen.
pub fn apply_acks(
    reports: &mut [aurscan_core::PackageReport],
    acks: &AckStore,
    policy: &aurscan_core::VerdictPolicy,
) {
    for r in reports.iter_mut() {
        if r.findings.iter().any(|f| acks.is_acked(f)) {
            let live: Vec<Finding> = r
                .findings
                .iter()
                .filter(|f| !acks.is_acked(f))
                .cloned()
                .collect();
            r.verdict = aurscan_core::compute_verdict(live, policy);
        }
    }
}

/// `aurscan ack <target>...`: scan the targets, show the live (unacked)
/// Medium-or-above findings, and record acknowledgements after a y/N
/// confirm (`--yes` skips it, and is required when stdin is not a tty).
///
/// A target is a build directory, a built `.pkg.tar.zst`, or a bare package
/// name -- names resolve through the same search the ALPM hook uses (paru
/// clone cache, pacman cache, PKGDEST), covering both the recipe and the
/// built artifact, so one `aurscan ack zen-browser-bin` silences what both
/// gates just showed.
pub fn run_ack(targets: &[String], yes: bool, cfg: &crate::config::Config) -> i32 {
    use std::io::IsTerminal;

    let mut dir_targets: Vec<String> = Vec::new();
    let mut archive_targets: Vec<std::path::PathBuf> = Vec::new();
    let search = crate::artifact::HookSearchDirs::detect();
    for t in targets {
        let path = std::path::Path::new(t);
        if path.is_dir() {
            dir_targets.push(t.clone());
        } else if path.is_file() {
            archive_targets.push(path.to_path_buf());
        } else {
            let mut found = false;
            if let Some(archive) = crate::artifact::resolve_target(t, &search) {
                archive_targets.push(archive);
                found = true;
            }
            if let Some(clone) = search.paru_clone.as_ref().map(|c| c.join(t)) {
                if clone.join("PKGBUILD").is_file() {
                    dir_targets.push(clone.display().to_string());
                    found = true;
                }
            }
            if !found {
                eprintln!(
                    "aurscan: nothing found to acknowledge for `{}`",
                    crate::report::terminal_safe(t)
                );
            }
        }
    }

    let mut reports = Vec::new();
    if !dir_targets.is_empty() {
        match crate::registry::run_check(&dir_targets, cfg) {
            Ok((r, _)) => reports.extend(r),
            Err(e) => {
                eprintln!("error: {e:#}");
                return 3;
            }
        }
    }
    if !archive_targets.is_empty() {
        match crate::artifact::collect_reports(&archive_targets, cfg, false) {
            Ok(r) => reports.extend(r),
            Err(e) => {
                eprintln!("error: {e:#}");
                return 3;
            }
        }
    }

    let mut store = AckStore::load();
    let pending: Vec<&Finding> = reports
        .iter()
        .flat_map(|r| r.findings.iter())
        .filter(|f| f.severity >= aurscan_core::Severity::Medium && !store.is_acked(f))
        .collect();

    if pending.is_empty() {
        println!("aurscan: nothing to acknowledge (no unacked findings at Medium or above)");
        return 0;
    }

    for f in &pending {
        println!(
            "{}: [{:?}] {}",
            crate::report::terminal_safe(&f.package),
            f.severity,
            crate::report::terminal_safe(&f.reason)
        );
        println!(
            "    \u{21b3} {}",
            crate::report::terminal_safe(&f.evidence.location)
        );
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            eprintln!("aurscan: not a terminal; rerun with --yes to acknowledge");
            return 1;
        }
        print!(
            "Acknowledge {} finding(s)? They stop prompting and gating until \
             their matched content changes. [y/N] ",
            pending.len()
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut line = String::new();
        let ok = std::io::stdin().read_line(&mut line).is_ok()
            && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        if !ok {
            println!("aurscan: nothing acknowledged");
            return 1;
        }
    }

    let count = pending.len();
    if let Err(e) = store.add_batch_and_persist(&pending) {
        eprintln!("error: could not persist acknowledgements: {e:#}");
        return 3;
    }
    println!("aurscan: acknowledged {count} finding(s)");
    0
}

pub(crate) fn run_llm_ack(
    targets: &[String],
    yes: bool,
    cfg: &crate::config::Config,
    llm: &aurscan_llm::ValidatedLlmConfig,
) -> i32 {
    use std::io::IsTerminal;

    let collection = match crate::deep_scan::collect(targets, false, cfg, llm) {
        Ok(collection) => collection,
        Err(error) => {
            eprintln!(
                "error: {}",
                crate::report::terminal_safe(&format!("{error:#}"))
            );
            return 3;
        }
    };
    let mut store = AckStore::load();
    let pending = match pending_llm_findings(&collection.run, &store) {
        Ok(pending) => pending,
        Err(error) => {
            eprintln!("aurscan: {error}; no LLM acknowledgements were persisted");
            return 3;
        }
    };
    if pending.is_empty() {
        println!("aurscan: nothing to acknowledge (no unacked LLM findings at Medium or above)");
        return 0;
    }

    for finding in &pending {
        println!(
            "{}: [{:?}] [LLM; Advisory ceiling] {}",
            crate::report::terminal_safe(&finding.package),
            finding.severity,
            crate::report::terminal_safe(&finding.reason),
        );
        println!(
            "    \u{21b3} {}",
            crate::report::terminal_safe(&finding.evidence.location)
        );
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            eprintln!("aurscan: not a terminal; rerun with --yes to acknowledge");
            return 1;
        }
        print!(
            "Acknowledge {} finding(s)? They stop prompting and gating until \
             their matched content changes. [y/N] ",
            pending.len()
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut line = String::new();
        let ok = std::io::stdin().read_line(&mut line).is_ok()
            && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        if !ok {
            println!("aurscan: nothing acknowledged");
            return 1;
        }
    }

    let count = pending.len();
    if let Err(error) = store.add_batch_and_persist(&pending) {
        eprintln!("error: could not persist acknowledgements: {error:#}");
        return 3;
    }
    println!("aurscan: acknowledged {count} LLM finding(s)");
    0
}

fn pending_llm_findings<'a>(
    run: &'a crate::deep_scan::DeepRun,
    store: &AckStore,
) -> anyhow::Result<Vec<&'a Finding>> {
    if run
        .packages
        .iter()
        .any(|package| package.analysis.status != aurscan_llm::AnalysisStatus::Completed)
    {
        anyhow::bail!("one or more requested LLM analyses did not complete");
    }
    Ok(run
        .packages
        .iter()
        .flat_map(|package| package.combined.findings.iter())
        .filter(|finding| {
            matches!(&finding.confidence, aurscan_core::Confidence::Llm)
                && finding.severity >= aurscan_core::Severity::Medium
                && !store.is_acked(finding)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::{Confidence, DetectorId, Evidence, Severity};

    fn finding(pkg: &str, det: &'static str, loc: &str, excerpt: &str) -> Finding {
        Finding {
            severity: Severity::High,
            confidence: Confidence::Exact,
            detector: DetectorId(det),
            package: pkg.into(),
            reason: "r".into(),
            evidence: Evidence {
                location: loc.into(),
                excerpt: excerpt.into(),
            },
        }
    }

    #[test]
    fn artifact_ack_survives_a_version_bump() {
        // Regression: package and location both embedded the version, so
        // every upgrade un-acked everything and the same four browser
        // advisories re-prompted forever.
        let old = finding(
            "zen-browser-bin-1.21.16b-1-x86_64",
            "elf_inspect",
            "/home/u/.cache/paru/clone/zen-browser-bin/zen-browser-bin-1.21.16b-1-x86_64.pkg.tar.zst!opt/zen-browser-bin/pingsender",
            "dynamic import combo",
        );
        let new = finding(
            "zen-browser-bin-1.22.0-1-x86_64",
            "elf_inspect",
            "/home/u/.cache/paru/clone/zen-browser-bin/zen-browser-bin-1.22.0-1-x86_64.pkg.tar.zst!opt/zen-browser-bin/pingsender",
            "dynamic import combo",
        );
        assert_eq!(AckStore::key(&old), AckStore::key(&new));
        // ...but a different member is a different finding.
        let other_member = finding(
            "zen-browser-bin-1.22.0-1-x86_64",
            "elf_inspect",
            "/home/u/.cache/paru/clone/zen-browser-bin/zen-browser-bin-1.22.0-1-x86_64.pkg.tar.zst!opt/zen-browser-bin/zen",
            "dynamic import combo",
        );
        assert_ne!(AckStore::key(&new), AckStore::key(&other_member));
    }

    #[test]
    fn pkgbuild_ack_survives_line_moves_and_path_prefixes() {
        // The excerpt pins the content; the line number and the clone-dir
        // prefix vary by release and by invocation.
        let a = finding("p", "pkgbuild_static", "./PKGBUILD:39", "eval \"cat <<EOF");
        let b = finding(
            "p",
            "pkgbuild_static",
            "/home/u/.cache/paru/clone/p/PKGBUILD:42",
            "eval \"cat <<EOF",
        );
        assert_eq!(AckStore::key(&a), AckStore::key(&b));
    }

    #[test]
    fn stable_package_leaves_ordinary_names_alone() {
        assert_eq!(stable_package("zen-browser-bin"), "zen-browser-bin");
        assert_eq!(stable_package("brave-bin-1:1.92.139-1-x86_64"), "brave-bin");
        assert_eq!(stable_package("a-b-c"), "a-b-c");
    }

    #[test]
    fn apply_acks_downgrades_a_fully_acked_advisory_to_clean() {
        use aurscan_core::{compute_verdict, PackageReport, Verdict, VerdictPolicy};
        let f = finding("p", "ioc", "PKGBUILD:1", "eval thing");
        let policy = VerdictPolicy::default();
        let mut reports = vec![PackageReport {
            package: "p".into(),
            verdict: compute_verdict(vec![f.clone()], &policy),
            findings: vec![f.clone()],
            features: vec![],
        }];
        assert!(matches!(reports[0].verdict, Verdict::Block(_)));

        let acks = AckStore::from_keys([AckStore::key(&f)]);
        apply_acks(&mut reports, &acks, &policy);
        assert!(
            matches!(reports[0].verdict, Verdict::Clean),
            "acked findings must stop gating"
        );
        assert_eq!(reports[0].findings.len(), 1, "findings stay for display");
    }

    #[test]
    fn key_changes_with_evidence() {
        let a = finding("p", "ioc", "PKGBUILD:1", "one");
        let b = finding("p", "ioc", "PKGBUILD:1", "two");
        assert_ne!(AckStore::key(&a), AckStore::key(&b));
    }

    #[test]
    fn is_acked_matches_stored_key() {
        let f = finding("p", "ioc", "PKGBUILD:1", "npm install atomic-lockfile");
        let store = AckStore::from_keys([AckStore::key(&f)]);
        assert!(store.is_acked(&f));
        let other = finding("q", "ioc", "PKGBUILD:1", "npm install atomic-lockfile");
        assert!(!store.is_acked(&other));
    }

    #[test]
    fn add_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", dir.path());

        let f = finding("p", "ioc", "PKGBUILD:1", "malware");
        let mut store = AckStore::load();
        assert!(!store.is_acked(&f));
        store.add(&f).unwrap();

        let reloaded = AckStore::load();
        assert!(reloaded.is_acked(&f));
    }

    fn llm_finding(loc: &str, excerpt: &str) -> Finding {
        let mut finding = finding("canonical-base", "llm_download_execute", loc, excerpt);
        finding.confidence = Confidence::Llm;
        finding
    }

    #[test]
    fn deterministic_key_bytes_remain_on_the_legacy_normalization_path() {
        let f = finding(
            "zen-browser-bin-1.22.0-1-x86_64",
            "elf_inspect",
            "/cache/archive.pkg.tar.zst!opt/zen/pingsender",
            "dynamic import combo",
        );
        let hash = blake3::hash(
            format!(
                "{}|{}",
                stable_location(&f.evidence.location),
                f.evidence.excerpt
            )
            .as_bytes(),
        );
        let legacy = format!(
            "{}:{}:{}",
            stable_package(&f.package),
            f.detector.0,
            &hash.to_hex()[..16]
        );
        assert_eq!(AckStore::key(&f), legacy);
    }

    #[test]
    fn llm_keys_keep_full_relative_paths_but_ignore_line_movement() {
        let first = llm_finding("helpers/one/install.sh:3", "curl x | sh");
        let moved = llm_finding("helpers/one/install.sh:19-21", "curl x | sh");
        let same_name_elsewhere = llm_finding("helpers/two/install.sh:3", "curl x | sh");

        assert_eq!(AckStore::key(&first), AckStore::key(&moved));
        assert_ne!(AckStore::key(&first), AckStore::key(&same_name_elsewhere));
    }

    #[test]
    fn llm_keys_keep_the_exact_canonical_pkgbase_component() {
        let canonical = llm_finding("PKGBUILD:4", "download payload");
        let mut archive_shaped = canonical.clone();
        archive_shaped.package = "canonical-base-1-1-x86_64".into();
        assert_ne!(AckStore::key(&canonical), AckStore::key(&archive_shaped));
    }

    #[test]
    fn llm_keys_invalidate_when_relative_path_or_evidence_changes() {
        let original = llm_finding("scripts/prepare.sh:4", "download payload");
        let moved_file = llm_finding("scripts/build.sh:4", "download payload");
        let changed_evidence = llm_finding("scripts/prepare.sh:4", "download other payload");

        assert_ne!(AckStore::key(&original), AckStore::key(&moved_file));
        assert_ne!(AckStore::key(&original), AckStore::key(&changed_evidence));
    }

    #[test]
    fn llm_ack_selection_refuses_incomplete_analysis_before_returning_findings() {
        use crate::deep_scan::{DeepPackageReport, DeepRun};
        use aurscan_core::{PackageReport, Verdict};
        use aurscan_llm::{AnalysisOutcome, AnalysisStatus, BundleCoverage, CoverageMode};
        let llm = llm_finding("PKGBUILD:3", "suspicious command");
        let run = DeepRun {
            packages: vec![DeepPackageReport {
                pkgbase: "base".into(),
                requested_packages: vec!["base".into()],
                combined: PackageReport {
                    package: "base".into(),
                    verdict: Verdict::Advisory(vec![]),
                    findings: vec![llm],
                    features: vec![],
                },
                analysis: AnalysisOutcome {
                    status: AnalysisStatus::Incomplete,
                    source: None,
                    findings: vec![],
                    identity: None,
                    usage: None,
                    reason: Some("truncated".into()),
                },
                coverage: BundleCoverage {
                    mode: CoverageMode::GitTracked,
                    included_files: 1,
                    excluded_binary_files: vec![],
                    excluded_symlinks: vec![],
                },
            }],
            exit_code: 3,
        };
        assert!(pending_llm_findings(&run, &AckStore::from_keys([])).is_err());
    }

    #[test]
    fn llm_ack_selection_includes_only_live_medium_or_higher_llm_findings() {
        use crate::deep_scan::{DeepPackageReport, DeepRun};
        use aurscan_core::{PackageReport, Verdict};
        use aurscan_llm::{AnalysisOutcome, AnalysisStatus, BundleCoverage, CoverageMode};
        let selected = llm_finding("PKGBUILD:3", "selected");
        let mut info = llm_finding("PKGBUILD:4", "info");
        info.severity = Severity::Info;
        let deterministic = finding("base", "static", "PKGBUILD:5", "deterministic");
        let run = DeepRun {
            packages: vec![DeepPackageReport {
                pkgbase: "base".into(),
                requested_packages: vec!["base".into()],
                combined: PackageReport {
                    package: "base".into(),
                    verdict: Verdict::Advisory(vec![]),
                    findings: vec![selected.clone(), info, deterministic],
                    features: vec![],
                },
                analysis: AnalysisOutcome {
                    status: AnalysisStatus::Completed,
                    source: None,
                    findings: vec![],
                    identity: None,
                    usage: None,
                    reason: None,
                },
                coverage: BundleCoverage {
                    mode: CoverageMode::GitTracked,
                    included_files: 1,
                    excluded_binary_files: vec![],
                    excluded_symlinks: vec![],
                },
            }],
            exit_code: 1,
        };
        let pending = pending_llm_findings(&run, &AckStore::from_keys([])).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].evidence.excerpt, selected.evidence.excerpt);
    }
}
