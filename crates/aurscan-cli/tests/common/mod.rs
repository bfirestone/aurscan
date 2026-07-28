//! End-to-end test harness. `aurscan` (the CLI crate) is a binary-only crate,
//! so integration tests cannot import its internal modules. Instead we drive
//! the *compiled* binary — Cargo hands us its path via `CARGO_BIN_EXE_aurscan`
//! — with `check --json`, parse the structured report the `report` module
//! emits (T10 schema), and assert on verdicts, severities, detector
//! provenance, and the process exit code. This is a truer end-to-end test
//! than calling internals: it exercises the same path a user's shell hits.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// The benign top-package corpus, by fixture directory name. Modeled on real
/// popular AUR packages (release-tarball `-bin`, a `-git` VCS package, and
/// plain source builds). The false-positive floor is asserted over this set.
pub const BENIGN_FIXTURES: &[&str] = &[
    "ripgrep-bin",
    "fd-bin",
    "bat-cli-bin",
    "hello-greeter-git",
    "libwidget",
    "miniplayer-theme",
    "fastcat-bin",
    "worktrunk-bin",
];

/// Severity mirror of `aurscan_core::Severity`, ordered for threshold checks.
/// Deserialized from the lowercase strings the JSON report emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn parse(s: &str) -> Severity {
        match s {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Info,
        }
    }
}

/// Verdict mirror of `aurscan_core::Verdict`, without the carried findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Advisory,
    Block,
}

impl Verdict {
    fn parse(s: &str) -> Verdict {
        match s {
            "block" => Verdict::Block,
            "advisory" => Verdict::Advisory,
            _ => Verdict::Clean,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Verdict::Clean => 0,
            Verdict::Advisory => 1,
            Verdict::Block => 2,
        }
    }
}

/// One finding, flattened out of the per-package reports.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub detector: String,
    pub reason: String,
}

/// The parsed outcome of scanning one fixture directory.
pub struct ScanResult {
    pub verdicts: Vec<Verdict>,
    pub findings: Vec<Finding>,
    pub exit_code: i32,
}

/// Absolute path to the `tests/fixtures/` tree, located relative to this
/// crate's manifest so it resolves no matter the working directory.
pub fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// The vendored real-AUR snapshot package names, read off disk and sorted.
///
/// Enumerated rather than hardcoded like `BENIGN_FIXTURES`: the set turns over
/// whenever `scripts/refresh_benign_snapshot.py` reruns, and a stale constant
/// would silently stop testing packages that are still on disk.
pub fn snapshot_packages() -> Vec<String> {
    let root = fixtures_root().join("benign-snapshot");
    let mut names: Vec<String> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", root.display()))
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(
        !names.is_empty(),
        "benign snapshot is empty; run scripts/refresh_benign_snapshot.py"
    );
    names
}

/// Run the compiled binary over `fixtures/<rel>`, sharing `cache_home` as the
/// redb result-cache root. All user directories are redirected into hermetic
/// temp roots so the scan uses the embedded ruleset and never touches (or is
/// influenced by) the developer's real config/cache/data.
fn run(rel: &str, cache_home: &std::path::Path, isolate_home: &std::path::Path) -> ScanResult {
    let dir = fixtures_root().join(rel);
    assert!(dir.exists(), "fixture directory missing: {}", dir.display());

    let output = Command::new(env!("CARGO_BIN_EXE_aurscan"))
        .args(["--json", "--no-color", "check"])
        .arg(&dir)
        .env("HOME", isolate_home)
        .env("XDG_CACHE_HOME", cache_home)
        .env("XDG_CONFIG_HOME", isolate_home.join("config"))
        .env("XDG_DATA_HOME", isolate_home.join("data"))
        .output()
        .expect("failed to launch aurscan binary");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "expected JSON report on stdout, got parse error {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });

    let reports = value["reports"].as_array().cloned().unwrap_or_default();
    let mut verdicts = Vec::new();
    let mut findings = Vec::new();
    for report in &reports {
        verdicts.push(Verdict::parse(
            report["verdict"].as_str().unwrap_or("clean"),
        ));
        for f in report["findings"].as_array().into_iter().flatten() {
            findings.push(Finding {
                severity: Severity::parse(f["severity"].as_str().unwrap_or("info")),
                detector: f["detector"].as_str().unwrap_or_default().to_string(),
                reason: f["reason"].as_str().unwrap_or_default().to_string(),
            });
        }
    }

    ScanResult {
        verdicts,
        findings,
        exit_code,
    }
}

/// Scan a fixture directory through the binary with a throwaway, isolated
/// cache — the common case for the corpora assertions.
pub fn scan_fixture_dir(rel: &str) -> ScanResult {
    let home = tempfile::tempdir().expect("tempdir");
    let cache = tempfile::tempdir().expect("tempdir");
    run(rel, cache.path(), home.path())
}

/// Scan `rel` twice through a *shared* cache directory and return the wall
/// time of the second (warm) pass. Guards the cache wiring end-to-end.
pub fn timed_warm_rescan(rel: &str) -> Duration {
    let home = tempfile::tempdir().expect("tempdir");
    let cache = tempfile::tempdir().expect("tempdir");
    // Cold pass populates the redb cache under `cache`.
    let _ = run(rel, cache.path(), home.path());
    // Warm pass reuses it.
    let start = Instant::now();
    let _ = run(rel, cache.path(), home.path());
    start.elapsed()
}

/// The worst verdict across a result's per-package reports.
pub fn worst(result: &ScanResult) -> Verdict {
    result
        .verdicts
        .iter()
        .copied()
        .max_by_key(|v| v.rank())
        .unwrap_or(Verdict::Clean)
}

/// The highest severity across all findings (`Info` when there are none).
pub fn max_severity(result: &ScanResult) -> Severity {
    result
        .findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info)
}

/// True when any finding was produced by the named detector.
pub fn has_finding_from(result: &ScanResult, detector: &str) -> bool {
    result.findings.iter().any(|f| f.detector == detector)
}

/// Total number of findings across all of the result's reports.
pub fn finding_count(result: &ScanResult) -> usize {
    result.findings.len()
}
