//! Scan engine: fans the target × detector matrix out across rayon, with
//! content/target/context-keyed cache lookups guarding each detector invocation.

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
    /// See `CacheKey::detector_epoch`.
    pub detector_epoch: u32,
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
                let key = crate::target::scan_hash(t, &ctx)
                    .ok()
                    .map(|content_hash| CacheKey {
                        content_hash,
                        detector: d.id(),
                        ruleset_version: self.ruleset_version,
                        detector_epoch: self.detector_epoch,
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
    fn cache_distinguishes_target_path_kind_and_package_context() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, "same bytes").unwrap();
        std::fs::write(&b, "same bytes").unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let engine = Engine {
            detectors: vec![Box::new(CountingDetector(count.clone()))],
            cache: Arc::new(crate::RedbCache::open(&dir.path().join("cache.redb")).unwrap()),
            policy: VerdictPolicy::default(),
            ruleset_version: 1,
            detector_epoch: 1,
        };
        let mut job = PackageJob {
            name: "x".into(),
            version: "1".into(),
            aur_meta: None,
            targets: vec![ScanTarget::BuildScript {
                path: a,
                kind: ScriptKind::Pkgbuild,
            }],
        };
        engine.scan_package(&job);
        engine.scan_package(&job);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        job.targets = vec![ScanTarget::BuildScript {
            path: b.clone(),
            kind: ScriptKind::Pkgbuild,
        }];
        engine.scan_package(&job);
        assert_eq!(count.load(Ordering::SeqCst), 2, "different path must miss");
        job.targets = vec![ScanTarget::BuildScript {
            path: b,
            kind: ScriptKind::InstallScript,
        }];
        engine.scan_package(&job);
        assert_eq!(count.load(Ordering::SeqCst), 3, "different kind must miss");
        job.name = "y".into();
        engine.scan_package(&job);
        assert_eq!(
            count.load(Ordering::SeqCst),
            4,
            "different package must miss"
        );
        job.version = "2".into();
        engine.scan_package(&job);
        assert_eq!(
            count.load(Ordering::SeqCst),
            5,
            "different version must miss"
        );
        job.aur_meta = Some(crate::AurMetadata {
            maintainer: None,
            first_submitted: 1,
            last_modified: 2,
            out_of_date: None,
            popularity: 0.0,
            num_votes: 0,
        });
        engine.scan_package(&job);
        assert_eq!(
            count.load(Ordering::SeqCst),
            6,
            "different metadata must miss"
        );
        job.aur_meta.as_mut().unwrap().num_votes = 42;
        engine.scan_package(&job);
        assert_eq!(
            count.load(Ordering::SeqCst),
            7,
            "changed metadata must miss"
        );
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
            detector_epoch: 1,
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
                ScanTarget::HostArtifact {
                    path: host_artifact,
                },
            ],
        };

        let report = engine.scan_package(&job);
        assert_eq!(scan_count.load(Ordering::SeqCst), 1);
        assert!(matches!(report.verdict, Verdict::Clean));
    }
}
