//! Checks the package name being scanned against the curated list of
//! confirmed-compromised AUR package names.

use aurscan_core::{
    Confidence, Detector, DetectorId, DetectorResult, Evidence, Finding, ScanContext, ScanTarget,
    ScriptKind, Severity,
};
use std::collections::HashSet;

pub struct KnownBadNamesDetector {
    names: HashSet<String>,
}

impl KnownBadNamesDetector {
    pub fn new(rules: &crate::rules::RuleSet) -> Self {
        Self {
            names: rules.bad_names.clone(),
        }
    }
}

impl Detector for KnownBadNamesDetector {
    fn id(&self) -> DetectorId {
        DetectorId("known_bad_names")
    }

    fn wants(&self, target: &ScanTarget) -> bool {
        matches!(
            target,
            ScanTarget::BuildScript {
                kind: ScriptKind::Pkgbuild,
                ..
            }
        )
    }

    fn scan(&self, _target: &ScanTarget, ctx: &ScanContext) -> DetectorResult {
        if !self.names.contains(&ctx.package) {
            return DetectorResult::default();
        }
        DetectorResult {
            findings: vec![Finding {
                severity: Severity::Critical,
                confidence: Confidence::Exact,
                detector: self.id(),
                package: ctx.package.clone(),
                reason: "package is on the confirmed-compromised list".to_string(),
                evidence: Evidence {
                    location: ctx.package.clone(),
                    excerpt: format!("version {}", ctx.version),
                },
            }],
            features: None,
        }
    }
}

// --- Contract assertions ---
const _: fn() = || {
    fn is_detector<T: aurscan_core::Detector>() {}
    is_detector::<KnownBadNamesDetector>();
};

#[cfg(test)]
mod tests {
    use aurscan_core::{Confidence, Detector, ScanContext, ScanTarget, ScriptKind, Severity};

    use super::KnownBadNamesDetector;

    fn target() -> ScanTarget {
        ScanTarget::BuildScript {
            path: "PKGBUILD".into(),
            kind: ScriptKind::Pkgbuild,
        }
    }

    #[test]
    fn listed_name_fires() {
        let rules = crate::rules::RuleSet::embedded().unwrap();
        let det = KnownBadNamesDetector::new(&rules);
        let ctx = ScanContext {
            package: "runescape-launcher".into(),
            version: "1".into(),
            aur_meta: None,
        };
        let res = det.scan(&target(), &ctx);
        assert_eq!(res.findings.len(), 1);
        assert_eq!(res.findings[0].severity, Severity::Critical);
        assert_eq!(res.findings[0].confidence, Confidence::Exact);
    }

    #[test]
    fn unlisted_name_no_findings() {
        let rules = crate::rules::RuleSet::embedded().unwrap();
        let det = KnownBadNamesDetector::new(&rules);
        let ctx = ScanContext {
            package: "ripgrep".into(),
            version: "1".into(),
            aur_meta: None,
        };
        let res = det.scan(&target(), &ctx);
        assert!(res.findings.is_empty());
    }
}
