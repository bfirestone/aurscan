use crate::types::{DetectorId, FeatureVector, Finding, ScanTarget};

#[derive(Debug, Default)]
pub struct DetectorResult {
    pub findings: Vec<Finding>,
    pub features: Option<FeatureVector>,
}

/// Subset of AUR RPC v5 info the detectors consume.
#[derive(Debug, Clone)]
pub struct AurMetadata {
    pub maintainer: Option<String>,
    pub first_submitted: i64,   // epoch
    pub last_modified: i64,     // epoch
    pub out_of_date: Option<i64>,
    pub popularity: f64,
    pub num_votes: u32,
}

/// Package metadata available to every detector during a scan.
pub struct ScanContext {
    pub package: String,
    pub version: String,
    pub aur_meta: Option<AurMetadata>,   // None when offline / audit mode
}

pub trait Detector: Send + Sync {
    fn id(&self) -> DetectorId;
    fn wants(&self, target: &ScanTarget) -> bool;
    fn scan(&self, target: &ScanTarget, ctx: &ScanContext) -> DetectorResult;
}
