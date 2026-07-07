use crate::detector::DetectorResult;
use crate::types::DetectorId;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub content_hash: [u8; 32], // blake3 of target content
    pub detector: DetectorId,
    pub ruleset_version: u32,
}

pub trait ResultCache: Send + Sync {
    fn get(&self, key: &CacheKey) -> Option<DetectorResult>;
    fn put(&self, key: &CacheKey, result: &DetectorResult);
}

/// Cache that never hits — the engine's default until the redb cache task lands.
pub struct NoopCache;

impl ResultCache for NoopCache {
    fn get(&self, _key: &CacheKey) -> Option<DetectorResult> {
        None
    }
    fn put(&self, _key: &CacheKey, _result: &DetectorResult) {}
}
