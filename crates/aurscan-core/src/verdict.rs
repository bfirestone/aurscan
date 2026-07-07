//! Tiered verdict policy generalizing the legacy `assess_package()` logic.
//!
//! 1. Any `Exact` finding at `Critical` -> Block, unconditionally.
//! 2. Any finding >= `block_heuristic_at` -> Block.
//! 3. Escalation: >= 3 findings at >= `advisory_at` from >= 3 distinct
//!    detectors -> Block (weak signals co-occurring is the incident pattern).
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
    let heuristic_block = findings.iter().any(|f| f.severity >= policy.block_heuristic_at);
    let advisories: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= policy.advisory_at)
        .collect();
    let distinct: std::collections::HashSet<_> = advisories.iter().map(|f| f.detector).collect();

    if exact_critical || heuristic_block || (advisories.len() >= 3 && distinct.len() >= 3) {
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
}
