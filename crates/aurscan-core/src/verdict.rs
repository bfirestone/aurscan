//! Tiered verdict policy generalizing the legacy `assess_package()` logic.
//!
//! 1. Any `Exact` finding at `Critical` -> Block, unconditionally.
//! 2. Any block-eligible finding >= `block_heuristic_at` -> Block.
//! 3. Escalation: >= 3 block-eligible findings at >= `advisory_at` from >= 3
//!    distinct detectors -> Block (weak signals co-occurring is the incident pattern).
//! 4. Any finding >= `advisory_at` -> Advisory.
//! 5. Otherwise Clean (Info findings ride along in reports, not verdicts).

use crate::types::{Confidence, Finding, Severity, Verdict};

#[derive(Debug, Clone)]
pub struct VerdictPolicy {
    pub block_heuristic_at: Severity,
    pub advisory_at: Severity,
}

impl Default for VerdictPolicy {
    fn default() -> Self {
        Self {
            block_heuristic_at: Severity::High,
            advisory_at: Severity::Medium,
        }
    }
}

pub fn compute_verdict(findings: Vec<Finding>, policy: &VerdictPolicy) -> Verdict {
    let exact_critical = findings
        .iter()
        .any(|f| f.severity == Severity::Critical && f.confidence == Confidence::Exact);
    let block_eligible: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.confidence.block_eligible())
        .collect();
    let heuristic_block = block_eligible
        .iter()
        .any(|finding| finding.severity >= policy.block_heuristic_at);
    let escalation: Vec<&&Finding> = block_eligible
        .iter()
        .filter(|finding| finding.severity >= policy.advisory_at)
        .collect();
    let distinct: std::collections::HashSet<_> =
        escalation.iter().map(|finding| finding.detector).collect();
    let advisories: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.severity >= policy.advisory_at)
        .collect();

    if exact_critical || heuristic_block || (escalation.len() >= 3 && distinct.len() >= 3) {
        Verdict::Block(findings)
    } else if !advisories.is_empty() {
        Verdict::Advisory(findings)
    } else {
        Verdict::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DetectorId, Evidence};

    fn finding(sev: Severity, conf: Confidence, det: &'static str) -> Finding {
        Finding {
            severity: sev,
            confidence: conf,
            detector: DetectorId(det),
            package: "p".into(),
            reason: "r".into(),
            evidence: Evidence {
                location: "l".into(),
                excerpt: "e".into(),
            },
        }
    }

    #[test]
    fn exact_critical_blocks() {
        let v = compute_verdict(
            vec![finding(Severity::Critical, Confidence::Exact, "a")],
            &VerdictPolicy::default(),
        );
        assert!(matches!(v, Verdict::Block(_)));
    }

    #[test]
    fn heuristic_high_blocks_by_default_policy() {
        let v = compute_verdict(
            vec![finding(Severity::High, Confidence::Heuristic, "a")],
            &VerdictPolicy::default(),
        );
        assert!(matches!(v, Verdict::Block(_)));
    }

    #[test]
    fn single_medium_is_advisory() {
        let v = compute_verdict(
            vec![finding(Severity::Medium, Confidence::Heuristic, "a")],
            &VerdictPolicy::default(),
        );
        assert!(matches!(v, Verdict::Advisory(_)));
    }

    #[test]
    fn co_occurring_mediums_from_distinct_detectors_escalate_to_block() {
        let v = compute_verdict(
            vec![
                finding(Severity::Medium, Confidence::Heuristic, "a"),
                finding(Severity::Medium, Confidence::Heuristic, "b"),
                finding(Severity::Medium, Confidence::Heuristic, "c"),
            ],
            &VerdictPolicy::default(),
        );
        assert!(matches!(v, Verdict::Block(_)));
    }

    #[test]
    fn info_only_is_clean() {
        let v = compute_verdict(
            vec![finding(Severity::Info, Confidence::Heuristic, "a")],
            &VerdictPolicy::default(),
        );
        assert!(matches!(v, Verdict::Clean));
    }

    #[test]
    fn llm_findings_are_advisory_max_at_every_severity() {
        for severity in [
            Severity::Info,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let verdict = compute_verdict(
                vec![finding(severity, Confidence::Llm, "llm_other_semantic")],
                &VerdictPolicy::default(),
            );
            assert!(!matches!(verdict, Verdict::Block(_)));
        }
    }

    #[test]
    fn llm_does_not_complete_distinct_detector_escalation() {
        let verdict = compute_verdict(
            vec![
                finding(Severity::Medium, Confidence::Heuristic, "a"),
                finding(Severity::Medium, Confidence::Heuristic, "b"),
                finding(Severity::Medium, Confidence::Llm, "llm_other_semantic"),
            ],
            &VerdictPolicy::default(),
        );
        assert!(matches!(verdict, Verdict::Advisory(_)));
    }
}
