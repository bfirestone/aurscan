use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Exact,      // hash / literal IOC match
    Heuristic,  // rule-based inference
    Model(f32), // phase-2 ONNX score in [0,1]
    Llm,        // untrusted semantic analysis; Advisory ceiling
}

impl Confidence {
    pub fn block_eligible(&self) -> bool {
        !matches!(self, Self::Llm)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptKind {
    Pkgbuild,
    InstallScript,
    SrcInfo,
    Patch,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub enum SourceOrigin {
    Url(String),
    LocalFile,
    Vcs(String),
}

#[derive(Debug, Clone, Serialize)]
pub enum ScanTarget {
    BuildScript { path: PathBuf, kind: ScriptKind },
    SourceFile { path: PathBuf, origin: SourceOrigin },
    PackageFile { archive: PathBuf, member: String },
    HostArtifact { path: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct DetectorId(pub &'static str);

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub location: String, // "path:line" or "archive!member@offset"
    pub excerpt: String,  // grounded content, bounded by the producing detector/analyzer
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub confidence: Confidence,
    pub detector: DetectorId,
    pub package: String,
    pub reason: String,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct FeatureId(pub u32);

#[derive(Debug, Clone, Serialize)]
pub struct FeatureVector {
    pub schema_version: u16,
    pub values: Vec<(FeatureId, f32)>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase", tag = "verdict", content = "findings")]
pub enum Verdict {
    Clean,
    Advisory(Vec<Finding>),
    Block(Vec<Finding>),
}

/// One package's scan input: metadata + the expanded targets to examine.
#[derive(Debug, Clone)]
pub struct PackageJob {
    pub name: String,
    pub version: String,
    pub aur_meta: Option<crate::detector::AurMetadata>,
    pub targets: Vec<ScanTarget>,
}

/// One package's scan output.
#[derive(Debug, Clone, Serialize)]
pub struct PackageReport {
    pub package: String,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<FeatureVector>,
}

// --- Contract assertions ---
// These verify the approved design spec. Do NOT modify without updating the plan.

#[cfg(test)]
mod contract {
    use super::*;

    // Severity must be totally ordered for verdict thresholds.
    const _: fn() = || {
        fn ord<T: Ord>() {}
        ord::<Severity>();
    };

    // Detector must be object-safe: the engine holds Vec<Box<dyn Detector>>.
    fn _assert_object_safe(_: &dyn crate::detector::Detector) {}

    // Finding must be Clone + Send for rayon fan-out.
    const _: fn() = || {
        fn ok<T: Clone + Send>() {}
        ok::<Finding>();
    };

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Info);
    }

    #[test]
    fn llm_confidence_serializes_stably() {
        assert_eq!(
            serde_json::to_value(Confidence::Llm).unwrap(),
            serde_json::json!("llm")
        );
        assert!(!Confidence::Llm.block_eligible());
        assert!(Confidence::Exact.block_eligible());
        assert!(Confidence::Heuristic.block_eligible());
        assert!(Confidence::Model(0.5).block_eligible());
    }
}
