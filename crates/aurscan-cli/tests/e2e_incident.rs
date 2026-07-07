//! Incident-regression corpus: samples drawn from confirmed real-world AUR/npm
//! supply-chain incidents must Block via an *Exact* detector (literal IOC token
//! or confirmed-compromised package name). If any of these ever stops Blocking,
//! a signature path has regressed.

mod common;

use common::{Severity, Verdict};

#[test]
fn atomic_lockfile_victim_is_blocked() {
    let r = common::scan_fixture_dir("incident/atomic-lockfile-victim");
    assert_eq!(common::worst(&r), Verdict::Block, "must Block on the IOC token");
    assert!(
        common::has_finding_from(&r, "ioc_tokens"),
        "the atomic-lockfile injection command is a literal IOC token"
    );
    assert_eq!(r.exit_code, 2, "Block maps to exit code 2");
    assert_eq!(common::max_severity(&r), Severity::Critical);
}

#[test]
fn known_bad_name_is_blocked() {
    let r = common::scan_fixture_dir("incident/runescape-launcher");
    assert_eq!(common::worst(&r), Verdict::Block, "must Block on the bad name");
    assert!(
        common::has_finding_from(&r, "known_bad_names"),
        "the package name is on the confirmed-compromised list"
    );
    assert_eq!(r.exit_code, 2, "Block maps to exit code 2");
}

/// Coarse cache-wiring guard (not a benchmark): a warm rescan of the handful of
/// incident files — reusing a tempdir-backed redb cache — completes well within
/// a generous, machine-independent bound.
#[test]
fn warm_cache_rescan_is_fast() {
    let elapsed = common::timed_warm_rescan("incident/atomic-lockfile-victim");
    assert!(
        elapsed.as_millis() < 250,
        "warm rescan took {elapsed:?}, expected < 250ms"
    );
}
