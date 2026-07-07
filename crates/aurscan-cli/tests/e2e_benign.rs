//! Benign top-package corpus: the false-positive floor. These fixtures are
//! modeled on genuinely clean, popular AUR packaging patterns — release-tarball
//! `-bin` installs, a `-git` VCS package, and plain source builds. None may
//! Block, and the whole corpus must stay within a tight total-findings budget.
//! If one of these Blocks or blows the budget, a detector's precision has
//! regressed — do NOT loosen the assertion; investigate the detector.

mod common;

use common::Verdict;

#[test]
fn no_benign_fixture_is_blocked() {
    for name in common::BENIGN_FIXTURES {
        let r = common::scan_fixture_dir(&format!("benign/{name}"));
        assert_ne!(
            common::worst(&r),
            Verdict::Block,
            "benign fixture `{name}` was blocked (detector false positive)"
        );
        assert_ne!(
            r.exit_code, 2,
            "benign fixture `{name}` exited with Block code 2"
        );
    }
}

#[test]
fn benign_advisory_findings_are_few() {
    let total: usize = common::BENIGN_FIXTURES
        .iter()
        .map(|name| common::finding_count(&common::scan_fixture_dir(&format!("benign/{name}"))))
        .sum();
    assert!(
        total <= 5,
        "too many benign findings across the corpus: {total} (budget is 5)"
    );
}
