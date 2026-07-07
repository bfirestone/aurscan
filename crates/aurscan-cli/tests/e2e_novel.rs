//! Novel-attack synthetic corpus: samples crafted to exhibit malicious *shape*
//! while sharing ZERO literal overlap with the signature lists — no known IOC
//! token, no known payload hash, no listed bad name, and (deliberately) not even
//! the curl/base64/raw-IP regex signatures that ride in the `ioc_tokens`
//! detector. Each must still be caught, purely by the structural/heuristic
//! detectors (`pkgbuild_static`, `source_provenance`). This proves the engine
//! generalizes rather than memorizes.

mod common;

use common::Severity;

/// No finding in a novel sample may come from a memorization detector —
/// otherwise the sample isn't testing generalization.
fn assert_no_signature_findings(r: &common::ScanResult) {
    assert!(
        !common::has_finding_from(r, "ioc_tokens"),
        "novel sample must not match a literal/regex IOC signature"
    );
    assert!(
        !common::has_finding_from(r, "payload_hashes"),
        "novel sample must not match a known payload hash"
    );
    assert!(
        !common::has_finding_from(r, "known_bad_names"),
        "novel sample must not match a listed bad name"
    );
}

#[test]
fn curl_pipe_flagged_by_heuristics_only() {
    // A remote-code dropper piped into a shell, via an interpreter the curl/wget
    // regex does not cover — only the AST-level pipe-to-shell heuristic catches it.
    let r = common::scan_fixture_dir("novel/curl-pipe");
    assert!(common::max_severity(&r) >= Severity::High);
    assert!(common::has_finding_from(&r, "pkgbuild_static"));
    assert_no_signature_findings(&r);
}

#[test]
fn b64_eval_flagged_by_heuristics_only() {
    // `eval` of decoded content, arranged so the `eval "$(base64` regex misses
    // it but the structural eval-of-decoded heuristic fires.
    let r = common::scan_fixture_dir("novel/b64-eval");
    assert!(common::max_severity(&r) >= Severity::High);
    assert!(common::has_finding_from(&r, "pkgbuild_static"));
    assert_no_signature_findings(&r);
}

#[test]
fn install_daemon_flagged_by_heuristics_only() {
    // A root-time `.install` hook that enables a systemd daemon.
    let r = common::scan_fixture_dir("novel/install-daemon");
    assert!(common::max_severity(&r) >= Severity::High);
    assert!(common::has_finding_from(&r, "pkgbuild_static"));
    assert_no_signature_findings(&r);
}

#[test]
fn typosquat_source_flagged_by_heuristics_only() {
    // A `github.co` typosquat of `github.com` in `.SRCINFO` sources.
    let r = common::scan_fixture_dir("novel/typosquat-src");
    assert!(common::max_severity(&r) >= Severity::High);
    assert!(common::has_finding_from(&r, "source_provenance"));
    assert_no_signature_findings(&r);
}
