use aurscan_core::{DetectorId, Finding};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const PROVIDER_PROTOCOL_VERSION: u16 = 1;
pub const PROMPT_VERSION: u32 = 1;
pub const RESPONSE_SCHEMA_VERSION: u16 = 1;
pub const LLM_ANALYSIS_EPOCH: u32 = 1;
pub const REVIEW_STRATEGY_ID: &str = "findings_first_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmFindingKind {
    ObfuscatedExecution,
    DownloadExecute,
    CredentialAccess,
    PersistencePrivilege,
    DataExfiltration,
    BuildInstallBoundary,
    SupplyChainAnomaly,
    OtherSemantic,
}

impl LlmFindingKind {
    pub const ALL: [Self; 8] = [
        Self::ObfuscatedExecution,
        Self::DownloadExecute,
        Self::CredentialAccess,
        Self::PersistencePrivilege,
        Self::DataExfiltration,
        Self::BuildInstallBoundary,
        Self::SupplyChainAnomaly,
        Self::OtherSemantic,
    ];

    pub const fn detector_id(self) -> DetectorId {
        DetectorId(match self {
            Self::ObfuscatedExecution => "llm_obfuscated_execution",
            Self::DownloadExecute => "llm_download_execute",
            Self::CredentialAccess => "llm_credential_access",
            Self::PersistencePrivilege => "llm_persistence_privilege",
            Self::DataExfiltration => "llm_data_exfiltration",
            Self::BuildInstallBoundary => "llm_build_install_boundary",
            Self::SupplyChainAnomaly => "llm_supply_chain_anomaly",
            Self::OtherSemantic => "llm_other_semantic",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageMode {
    GitTracked,
    ConservativeLocal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleCoverage {
    pub mode: CoverageMode,
    pub included_files: usize,
    pub excluded_binary_files: Vec<String>,
    pub excluded_symlinks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeBundle {
    pub pkgbase: String,
    pub aur_commit: Option<String>,
    pub content_hash: [u8; 32],
    pub files: Vec<RecipeFile>,
    pub coverage: BundleCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleLimits {
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_bundle_bytes: usize,
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self {
            max_files: 32,
            max_file_bytes: 65_536,
            max_bundle_bytes: 131_072,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    JsonSchema,
    JsonObject,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LlmConfig {
    pub endpoint: String,
    pub model: String,
    pub response_format: ResponseFormat,
    pub api_key_env: Option<String>,
    pub allow_remote: bool,
    pub allow_large_requests: bool,
    pub timeout_seconds: u64,
    pub max_output_tokens: u32,
    pub max_requests_per_run: usize,
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_bundle_bytes: usize,
    pub max_request_bytes: usize,
    pub max_findings: usize,
    pub max_evidence_lines: usize,
    pub max_excerpt_bytes: usize,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            model: String::new(),
            response_format: ResponseFormat::JsonSchema,
            api_key_env: None,
            allow_remote: false,
            allow_large_requests: false,
            timeout_seconds: 90,
            max_output_tokens: 2_048,
            max_requests_per_run: 10,
            max_files: 32,
            max_file_bytes: 65_536,
            max_bundle_bytes: 131_072,
            max_request_bytes: 524_288,
            max_findings: 32,
            max_evidence_lines: 8,
            max_excerpt_bytes: 200,
        }
    }
}

impl LlmConfig {
    pub fn bundle_limits(&self) -> BundleLimits {
        BundleLimits {
            max_files: self.max_files,
            max_file_bytes: self.max_file_bytes,
            max_bundle_bytes: self.max_bundle_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct AnalysisIdentity {
    pub bundle_hash: [u8; 32],
    pub provider_protocol_version: u16,
    pub endpoint_origin_fingerprint: [u8; 32],
    pub model_id: String,
    pub review_strategy_id: String,
    pub request_profile_fingerprint: [u8; 32],
    pub prompt_version: u32,
    pub prompt_hash: [u8; 32],
    pub response_schema_version: u16,
    pub response_schema_hash: [u8; 32],
    pub analysis_epoch: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Completed,
    Unavailable,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSource {
    Provider,
    Cache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone)]
pub struct AnalysisOutcome {
    pub status: AnalysisStatus,
    pub source: Option<AnalysisSource>,
    pub findings: Vec<Finding>,
    pub identity: Option<AnalysisIdentity>,
    pub usage: Option<TokenUsage>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalyzeOptions {
    pub refresh: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPreflight {
    pub original_bytes: usize,
    pub encoded_request_bytes: usize,
}

pub trait RecipeBundleBuilder: Send + Sync {
    fn build(
        &self,
        root: &Path,
        pkgbase: &str,
        limits: BundleLimits,
    ) -> anyhow::Result<RecipeBundle>;
}

pub trait PackageAnalyzer: Send + Sync {
    fn analyze(&self, bundle: &RecipeBundle, options: AnalyzeOptions) -> AnalysisOutcome;
}
