use aurscan_core::{
    Confidence, Detector, DetectorId, DetectorResult, Evidence, Finding, ScanContext, ScanTarget,
    ScriptKind, Severity,
};

const DAY: i64 = 86_400;

/// Cross-signal detector over AUR RPC metadata: corroborating evidence such
/// as an adopted-orphan pattern, a brand-new package, or an orphan package
/// that was somehow just modified. These are deliberately Medium/Info —
/// they corroborate content findings rather than stand alone.
pub struct AurMetadataDetector {
    now: i64,
}

impl AurMetadataDetector {
    pub fn new(now_epoch: i64) -> Self {
        Self { now: now_epoch }
    }
}

impl Detector for AurMetadataDetector {
    fn id(&self) -> DetectorId {
        DetectorId("aur_metadata")
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
        let mut findings = Vec::new();

        if let Some(meta) = &ctx.aur_meta {
            let age_since_submit = self.now - meta.first_submitted;
            let age_since_modified = self.now - meta.last_modified;

            // R1: adopted-orphan pattern — old, unpopular package modified very recently.
            if age_since_submit > 180 * DAY
                && meta.popularity < 0.5
                && meta.num_votes < 10
                && age_since_modified <= 14 * DAY
            {
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::Heuristic,
                    detector: self.id(),
                    package: ctx.package.clone(),
                    reason: "old low-popularity package modified very recently".to_string(),
                    evidence: Evidence {
                        location: ctx.package.clone(),
                        excerpt: format!(
                            "first_submitted={} last_modified={} popularity={} num_votes={}",
                            meta.first_submitted,
                            meta.last_modified,
                            meta.popularity,
                            meta.num_votes
                        ),
                    },
                });
            }

            // R2: brand-new package.
            if age_since_submit <= 7 * DAY {
                findings.push(Finding {
                    severity: Severity::Info,
                    confidence: Confidence::Heuristic,
                    detector: self.id(),
                    package: ctx.package.clone(),
                    reason: "package is new to the AUR".to_string(),
                    evidence: Evidence {
                        location: ctx.package.clone(),
                        excerpt: format!("first_submitted={}", meta.first_submitted),
                    },
                });
            }

            // R3: orphan just modified — orphans can't be legitimately updated;
            // either someone pushed as co-maintainer or the RPC lagged an
            // adoption. Either way, look.
            if meta.maintainer.is_none() && age_since_modified <= 14 * DAY {
                findings.push(Finding {
                    severity: Severity::Medium,
                    confidence: Confidence::Heuristic,
                    detector: self.id(),
                    package: ctx.package.clone(),
                    reason: "orphaned package was modified within the last 14 days".to_string(),
                    evidence: Evidence {
                        location: ctx.package.clone(),
                        excerpt: format!("last_modified={}", meta.last_modified),
                    },
                });
            }
        }

        DetectorResult {
            findings,
            features: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::AurMetadata;
    use std::path::PathBuf;

    fn pkgbuild_target() -> ScanTarget {
        ScanTarget::BuildScript {
            path: PathBuf::from("PKGBUILD"),
            kind: ScriptKind::Pkgbuild,
        }
    }

    fn ctx_with(meta: AurMetadata) -> ScanContext {
        ScanContext {
            package: "x".into(),
            version: "1".into(),
            aur_meta: Some(meta),
        }
    }

    fn base_meta(now: i64) -> AurMetadata {
        AurMetadata {
            maintainer: Some("m".into()),
            first_submitted: now - 400 * DAY,
            last_modified: now - 100 * DAY,
            out_of_date: None,
            popularity: 3.0,
            num_votes: 50,
        }
    }

    fn is_detector<T: Detector>() {}

    #[test]
    fn aur_metadata_detector_satisfies_detector_contract() {
        is_detector::<AurMetadataDetector>();
    }

    #[test]
    fn recently_modified_old_unpopular_package_is_medium() {
        // classic adopted-orphan pattern: old package, near-zero popularity,
        // modified in the last 14 days
        let now = 1_800_000_000;
        let det = AurMetadataDetector::new(now);
        let meta = AurMetadata {
            popularity: 0.02,
            num_votes: 3,
            last_modified: now - 3 * DAY,
            ..base_meta(now)
        };
        let r = det.scan(&pkgbuild_target(), &ctx_with(meta));
        assert!(r.findings.iter().any(|f| f.severity >= Severity::Medium));
    }

    #[test]
    fn brand_new_package_is_info() {
        let now = 1_800_000_000;
        let det = AurMetadataDetector::new(now);
        let meta = AurMetadata {
            first_submitted: now - 2 * DAY,
            last_modified: now - DAY,
            ..base_meta(now)
        };
        let r = det.scan(&pkgbuild_target(), &ctx_with(meta));
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity == Severity::Info && f.reason.contains("new")));
    }

    #[test]
    fn unmaintained_but_stale_is_quiet() {
        let now = 1_800_000_000;
        let det = AurMetadataDetector::new(now);
        let meta = AurMetadata {
            maintainer: None,
            ..base_meta(now)
        };
        assert!(det
            .scan(&pkgbuild_target(), &ctx_with(meta))
            .findings
            .is_empty());
    }

    #[test]
    fn no_metadata_no_findings() {
        let det = AurMetadataDetector::new(1_800_000_000);
        let ctx = ScanContext {
            package: "x".into(),
            version: "1".into(),
            aur_meta: None,
        };
        assert!(det.scan(&pkgbuild_target(), &ctx).findings.is_empty());
    }
}
