//! Scan engine: fans the target × detector matrix out across rayon, with
//! blake3-content-keyed cache lookups guarding each detector invocation.

use crate::cache::{CacheKey, ResultCache};
use crate::detector::{Detector, ScanContext};
use crate::types::{FeatureVector, Finding, PackageJob, PackageReport};
use crate::verdict::{compute_verdict, VerdictPolicy};
use rayon::prelude::*;
use std::sync::Arc;

pub struct Engine {
    pub detectors: Vec<Box<dyn Detector>>,
    pub cache: Arc<dyn ResultCache>,
    pub policy: VerdictPolicy,
    pub ruleset_version: u32,
}

impl Engine {
    pub fn scan(&self, jobs: &[PackageJob]) -> Vec<PackageReport> {
        jobs.par_iter().map(|j| self.scan_package(j)).collect()
    }

    pub fn scan_package(&self, job: &PackageJob) -> PackageReport {
        let ctx = ScanContext {
            package: job.name.clone(),
            version: job.version.clone(),
            aur_meta: job.aur_meta.clone(),
        };
        let (findings, features): (Vec<Vec<Finding>>, Vec<Option<FeatureVector>>) = job
            .targets
            .par_iter()
            .flat_map_iter(|t| {
                self.detectors
                    .iter()
                    .filter(|d| d.wants(t))
                    .map(move |d| (t, d))
            })
            .map(|(t, d)| {
                let key = crate::target::content_hash(t)
                    .ok()
                    .map(|content_hash| CacheKey {
                        content_hash,
                        detector: d.id(),
                        ruleset_version: self.ruleset_version,
                    });
                if let Some(k) = &key {
                    if let Some(hit) = self.cache.get(k) {
                        return (hit.findings, hit.features);
                    }
                }
                let res = d.scan(t, &ctx);
                if let Some(k) = &key {
                    self.cache.put(k, &res);
                }
                (res.findings, res.features)
            })
            .unzip();
        let findings: Vec<Finding> = findings.into_iter().flatten().collect();
        let features: Vec<FeatureVector> = features.into_iter().flatten().collect();
        let verdict = compute_verdict(findings.clone(), &self.policy);
        PackageReport {
            package: job.name.clone(),
            verdict,
            findings,
            features,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::NoopCache;
    use crate::detector::DetectorResult;
    use crate::types::{DetectorId, ScanTarget, ScriptKind, Verdict};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingDetector(Arc<AtomicUsize>);

    impl Detector for CountingDetector {
        fn id(&self) -> DetectorId {
            DetectorId("counting")
        }
        fn wants(&self, t: &ScanTarget) -> bool {
            matches!(t, ScanTarget::BuildScript { .. })
        }
        fn scan(&self, _t: &ScanTarget, _ctx: &ScanContext) -> DetectorResult {
            self.0.fetch_add(1, Ordering::SeqCst);
            DetectorResult::default()
        }
    }

    #[test]
    fn routes_only_wanted_targets_and_reports_clean() {
        let dir = tempfile::tempdir().unwrap();
        let pkgbuild = dir.path().join("PKGBUILD");
        std::fs::write(&pkgbuild, b"pkgname=x\n").unwrap();
        let host_artifact = dir.path().join("some-binary");
        std::fs::write(&host_artifact, b"\x7fELF").unwrap();

        let scan_count = Arc::new(AtomicUsize::new(0));
        let engine = Engine {
            detectors: vec![Box::new(CountingDetector(scan_count.clone()))],
            cache: Arc::new(NoopCache),
            policy: VerdictPolicy::default(),
            ruleset_version: 1,
        };

        let job = PackageJob {
            name: "x".into(),
            version: "1".into(),
            aur_meta: None,
            targets: vec![
                ScanTarget::BuildScript {
                    path: pkgbuild,
                    kind: ScriptKind::Pkgbuild,
                },
                ScanTarget::HostArtifact { path: host_artifact },
            ],
        };

        let report = engine.scan_package(&job);
        assert_eq!(scan_count.load(Ordering::SeqCst), 1);
        assert!(matches!(report.verdict, Verdict::Clean));
    }
}
