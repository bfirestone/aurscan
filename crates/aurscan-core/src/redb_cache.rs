//! Persistent `ResultCache` backed by `redb`, keyed by content hash, detector
//! id, and ruleset version so unchanged targets are never re-scanned across
//! runs. Findings are stored as JSON via `Stored*` mirror types because
//! `DetectorId(&'static str)` cannot `Deserialize`.

use crate::cache::{CacheKey, ResultCache};
use crate::detector::DetectorResult;
use crate::types::{Confidence, DetectorId, Evidence, FeatureVector, Finding, Severity};
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("results_v1");

#[derive(Serialize, Deserialize)]
struct StoredEvidence {
    location: String,
    excerpt: String,
}

#[derive(Serialize, Deserialize)]
struct StoredFinding {
    severity: u8,
    confidence_kind: u8,
    confidence_score: f32,
    detector: String,
    package: String,
    reason: String,
    evidence: StoredEvidence,
}

#[derive(Serialize, Deserialize)]
struct StoredResult {
    findings: Vec<StoredFinding>,
    features: Option<(u16, Vec<(u32, f32)>)>,
}

fn severity_to_u8(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

fn severity_from_u8(v: u8) -> Severity {
    match v {
        0 => Severity::Info,
        1 => Severity::Medium,
        2 => Severity::High,
        _ => Severity::Critical,
    }
}

fn confidence_to_parts(c: &Confidence) -> (u8, f32) {
    match c {
        Confidence::Exact => (0, 0.0),
        Confidence::Heuristic => (1, 0.0),
        Confidence::Model(score) => (2, *score),
        Confidence::Llm => (3, 0.0),
    }
}

fn confidence_from_parts(kind: u8, score: f32) -> Confidence {
    match kind {
        0 => Confidence::Exact,
        1 => Confidence::Heuristic,
        2 => Confidence::Model(score),
        3 => Confidence::Llm,
        _ => Confidence::Model(score),
    }
}

fn to_stored(result: &DetectorResult) -> StoredResult {
    let findings = result
        .findings
        .iter()
        .map(|f| {
            let (confidence_kind, confidence_score) = confidence_to_parts(&f.confidence);
            StoredFinding {
                severity: severity_to_u8(f.severity),
                confidence_kind,
                confidence_score,
                detector: f.detector.0.to_string(),
                package: f.package.clone(),
                reason: f.reason.clone(),
                evidence: StoredEvidence {
                    location: f.evidence.location.clone(),
                    excerpt: f.evidence.excerpt.clone(),
                },
            }
        })
        .collect();
    let features = result.features.as_ref().map(|fv| {
        (
            fv.schema_version,
            fv.values.iter().map(|(id, v)| (id.0, *v)).collect(),
        )
    });
    StoredResult { findings, features }
}

fn from_stored(stored: StoredResult) -> DetectorResult {
    let findings = stored
        .findings
        .into_iter()
        .map(|f| {
            let detector: &'static str = Box::leak(f.detector.into_boxed_str());
            Finding {
                severity: severity_from_u8(f.severity),
                confidence: confidence_from_parts(f.confidence_kind, f.confidence_score),
                detector: DetectorId(detector),
                package: f.package,
                reason: f.reason,
                evidence: Evidence {
                    location: f.evidence.location,
                    excerpt: f.evidence.excerpt,
                },
            }
        })
        .collect();
    let features = stored
        .features
        .map(|(schema_version, values)| FeatureVector {
            schema_version,
            values: values
                .into_iter()
                .map(|(id, v)| (crate::types::FeatureId(id), v))
                .collect(),
        });
    DetectorResult { findings, features }
}

pub struct RedbCache {
    db: Database,
}

impl RedbCache {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self {
            db: Database::create(path)?,
        })
    }

    pub fn default_path() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("aurscan/results.redb")
    }

    fn key_bytes(key: &CacheKey) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 8 + key.detector.0.len());
        v.extend_from_slice(&key.content_hash);
        v.extend_from_slice(&key.ruleset_version.to_le_bytes());
        v.extend_from_slice(&key.detector_epoch.to_le_bytes());
        v.extend_from_slice(key.detector.0.as_bytes());
        v
    }
}

impl ResultCache for RedbCache {
    fn get(&self, key: &CacheKey) -> Option<DetectorResult> {
        let tx = self.db.begin_read().ok()?;
        let table = tx.open_table(TABLE).ok()?;
        let raw = table.get(Self::key_bytes(key).as_slice()).ok()??;
        let stored: StoredResult = serde_json::from_slice(raw.value()).ok()?;
        Some(from_stored(stored))
    }

    fn put(&self, key: &CacheKey, result: &DetectorResult) {
        let stored = to_stored(result);
        let Ok(bytes) = serde_json::to_vec(&stored) else {
            return;
        };
        let Ok(tx) = self.db.begin_write() else {
            return;
        };
        {
            let Ok(mut table) = tx.open_table(TABLE) else {
                return;
            };
            let _ = table.insert(Self::key_bytes(key).as_slice(), bytes.as_slice());
        }
        // Cache writes are best-effort; scan correctness never depends on them.
        let _ = tx.commit();
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::{CacheKey, ResultCache};
    use crate::detector::DetectorResult;
    use crate::types::{Confidence, DetectorId, Evidence, Finding, Severity};

    #[test]
    fn put_then_get_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let cache = super::RedbCache::open(&dir.path().join("t.redb")).unwrap();
        let key = CacheKey {
            content_hash: [7u8; 32],
            detector: DetectorId("ioc_tokens"),
            ruleset_version: 1,
            detector_epoch: 1,
        };
        let res = DetectorResult {
            findings: vec![Finding {
                severity: Severity::Critical,
                confidence: Confidence::Exact,
                detector: DetectorId("ioc_tokens"),
                package: "evil".into(),
                reason: "token".into(),
                evidence: Evidence {
                    location: "PKGBUILD:3".into(),
                    excerpt: "atomic-lockfile".into(),
                },
            }],
            features: None,
        };
        cache.put(&key, &res);
        let hit = cache.get(&key).expect("hit");
        assert_eq!(hit.findings.len(), 1);
        assert_eq!(hit.findings[0].detector.0, "ioc_tokens");
        assert_eq!(hit.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn llm_confidence_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let cache = super::RedbCache::open(&dir.path().join("t.redb")).unwrap();
        let key = CacheKey {
            content_hash: [8u8; 32],
            detector: DetectorId("llm_other_semantic"),
            ruleset_version: 1,
            detector_epoch: 1,
        };
        let result = DetectorResult {
            findings: vec![Finding {
                severity: Severity::Medium,
                confidence: Confidence::Llm,
                detector: DetectorId("llm_other_semantic"),
                package: "package".into(),
                reason: "semantic finding".into(),
                evidence: Evidence {
                    location: "PKGBUILD:1".into(),
                    excerpt: "content".into(),
                },
            }],
            features: None,
        };

        cache.put(&key, &result);
        let hit = cache.get(&key).expect("hit");

        assert_eq!(hit.findings[0].confidence, Confidence::Llm);
    }

    #[test]
    fn confidence_encoding_remains_backward_compatible() {
        assert_eq!(super::confidence_to_parts(&Confidence::Exact), (0, 0.0));
        assert_eq!(super::confidence_to_parts(&Confidence::Heuristic), (1, 0.0));
        assert_eq!(
            super::confidence_to_parts(&Confidence::Model(0.75)),
            (2, 0.75)
        );
        assert_eq!(super::confidence_to_parts(&Confidence::Llm), (3, 0.0));

        assert_eq!(super::confidence_from_parts(0, 0.0), Confidence::Exact);
        assert_eq!(super::confidence_from_parts(1, 0.0), Confidence::Heuristic);
        assert_eq!(
            super::confidence_from_parts(2, 0.75),
            Confidence::Model(0.75)
        );
        assert_eq!(super::confidence_from_parts(3, 0.0), Confidence::Llm);
        assert_eq!(
            super::confidence_from_parts(4, 0.25),
            Confidence::Model(0.25)
        );
    }

    #[test]
    fn ruleset_version_bump_misses() {
        let dir = tempfile::tempdir().unwrap();
        let cache = super::RedbCache::open(&dir.path().join("t.redb")).unwrap();
        let k1 = CacheKey {
            content_hash: [1u8; 32],
            detector: DetectorId("d"),
            ruleset_version: 1,
            detector_epoch: 1,
        };
        let k2 = CacheKey {
            ruleset_version: 2,
            detector_epoch: 1,
            ..k1.clone()
        };
        cache.put(&k1, &DetectorResult::default());
        assert!(cache.get(&k2).is_none());
    }

    #[test]
    fn detector_epoch_bump_misses() {
        // A detector logic change must not serve verdicts computed by the
        // previous logic. Without this, fixing a false positive leaves every
        // already-scanned package still blocked, and a newly added detection
        // never re-examines anything.
        let dir = tempfile::tempdir().unwrap();
        let cache = super::RedbCache::open(&dir.path().join("t.redb")).unwrap();
        let k1 = CacheKey {
            content_hash: [7u8; 32],
            detector: DetectorId("pkgbuild_static"),
            ruleset_version: 3,
            detector_epoch: 1,
        };
        let k2 = CacheKey {
            detector_epoch: 2,
            ..k1.clone()
        };
        cache.put(&k1, &DetectorResult::default());
        assert!(
            cache.get(&k1).is_some(),
            "same epoch must still hit, or caching is pointless"
        );
        assert!(cache.get(&k2).is_none(), "epoch bump must invalidate");
    }
}
