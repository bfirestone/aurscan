use crate::cache::{AnalysisCache, CompletedClaims, RedbAnalysisCache};
use crate::config::ValidatedLlmConfig;
use crate::grounding::{ground_response, materialize_claims};
use crate::prompt::{build_request, prompt_hash, response_schema_hash, ProviderRequest};
use crate::provider::{load_api_key, ModelProvider, OpenAiCompatibleProvider};
use crate::types::{
    AnalysisIdentity, AnalysisOutcome, AnalysisSource, AnalysisStatus, AnalyzeOptions,
    PackageAnalyzer, RecipeBundle, LLM_ANALYSIS_EPOCH, PROMPT_VERSION, PROVIDER_PROTOCOL_VERSION,
    RESPONSE_SCHEMA_VERSION, REVIEW_STRATEGY_ID,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Analyzer {
    config: ValidatedLlmConfig,
    provider: Box<dyn ModelProvider>,
    cache: Box<dyn AnalysisCache>,
}

pub fn build_analyzer(config: ValidatedLlmConfig) -> anyhow::Result<Analyzer> {
    Analyzer::with_cache_path(config, RedbAnalysisCache::default_path()?)
}

impl Analyzer {
    pub fn with_cache_path(
        config: ValidatedLlmConfig,
        cache_path: PathBuf,
    ) -> anyhow::Result<Self> {
        let provider = OpenAiCompatibleProvider::new(&config);
        let cache = RedbAnalysisCache::open(&cache_path)?;
        Ok(Self {
            config,
            provider: Box::new(provider),
            cache: Box::new(cache),
        })
    }

    pub fn analysis_identity(&self, bundle: &RecipeBundle) -> AnalysisIdentity {
        analysis_identity(bundle, &self.config)
    }

    pub fn analyze_batch(
        &self,
        bundles: &[RecipeBundle],
        options: AnalyzeOptions,
    ) -> Vec<AnalysisOutcome> {
        let mut outcomes = vec![None; bundles.len()];
        let mut pending = Vec::new();

        for (index, bundle) in bundles.iter().enumerate() {
            let identity = self.analysis_identity(bundle);
            if !options.refresh {
                if let Some(completed) = self.cache.get(&identity) {
                    outcomes[index] = Some(completed_outcome(
                        bundle,
                        identity,
                        completed,
                        AnalysisSource::Cache,
                    ));
                    continue;
                }
            }
            match prepare_request(bundle, &self.config, identity.clone()) {
                Ok(request) => pending.push(PendingRequest {
                    index,
                    identity,
                    request: request.0,
                    encoded_body: request.1,
                }),
                Err(error) => {
                    outcomes[index] = Some(failure_outcome(
                        AnalysisStatus::Incomplete,
                        None,
                        identity,
                        error.to_string(),
                    ));
                }
            }
        }

        let miss_count = pending.len()
            + outcomes
                .iter()
                .filter(|outcome| {
                    matches!(
                        outcome,
                        Some(AnalysisOutcome {
                            source: None,
                            status: AnalysisStatus::Incomplete,
                            ..
                        })
                    )
                })
                .count();
        if miss_count > self.config.max_requests_per_run {
            for pending_request in pending {
                outcomes[pending_request.index] = Some(failure_outcome(
                    AnalysisStatus::Incomplete,
                    None,
                    pending_request.identity,
                    format!(
                        "cache miss count {miss_count} exceeds request cap {}",
                        self.config.max_requests_per_run
                    ),
                ));
            }
            return finish_outcomes(outcomes);
        }

        let mut sendable = Vec::new();
        for pending_request in pending {
            if pending_request.encoded_body.len() > self.config.max_request_bytes {
                outcomes[pending_request.index] = Some(failure_outcome(
                    AnalysisStatus::Incomplete,
                    None,
                    pending_request.identity,
                    format!(
                        "encoded request size {} exceeds byte limit {}",
                        pending_request.encoded_body.len(),
                        self.config.max_request_bytes
                    ),
                ));
            } else {
                sendable.push(pending_request);
            }
        }

        let api_key = if sendable.is_empty() {
            None
        } else {
            match load_api_key(&self.config) {
                Ok(api_key) => api_key,
                Err(error) => {
                    let reason = error.to_string();
                    for pending_request in sendable {
                        outcomes[pending_request.index] = Some(failure_outcome(
                            AnalysisStatus::Unavailable,
                            None,
                            pending_request.identity,
                            reason.clone(),
                        ));
                    }
                    return finish_outcomes(outcomes);
                }
            }
        };

        for pending_request in sendable {
            let provider_response = self.provider.send(
                &self.config,
                &pending_request.request,
                &pending_request.encoded_body,
                api_key.as_ref(),
            );
            let response = match provider_response {
                Ok(response) => response,
                Err(error) => {
                    outcomes[pending_request.index] = Some(failure_outcome(
                        AnalysisStatus::Unavailable,
                        Some(AnalysisSource::Provider),
                        pending_request.identity,
                        error.to_string(),
                    ));
                    continue;
                }
            };

            let grounded = match ground_response(
                &response.content,
                &bundles[pending_request.index],
                self.config.max_findings,
                self.config.max_evidence_lines,
                self.config.max_excerpt_bytes,
            ) {
                Ok(grounded) => grounded,
                Err(reason) => {
                    let reason = if response.finish_reason == "stop" {
                        reason
                    } else {
                        format!(
                            "provider finish_reason {:?} was incomplete; {reason}",
                            response.finish_reason
                        )
                    };
                    outcomes[pending_request.index] = Some(AnalysisOutcome {
                        status: AnalysisStatus::Incomplete,
                        source: Some(AnalysisSource::Provider),
                        findings: Vec::new(),
                        identity: Some(pending_request.identity),
                        usage: response.usage,
                        reason: Some(reason),
                    });
                    continue;
                }
            };

            let finish_complete = response.finish_reason == "stop";
            let fully_grounded = grounded.rejected_reasons.is_empty();
            let findings =
                materialize_claims(&grounded.claims, &bundles[pending_request.index].pkgbase);
            if finish_complete && fully_grounded {
                let completed = CompletedClaims {
                    identity: pending_request.identity.clone(),
                    claims: grounded.claims,
                    usage: response.usage,
                    analysed_at: analysed_at(),
                };
                self.cache.put(&pending_request.identity, &completed);
                outcomes[pending_request.index] = Some(AnalysisOutcome {
                    status: AnalysisStatus::Completed,
                    source: Some(AnalysisSource::Provider),
                    findings,
                    identity: Some(pending_request.identity),
                    usage: response.usage,
                    reason: None,
                });
            } else {
                let mut reasons = Vec::new();
                if !finish_complete {
                    reasons.push(format!(
                        "provider finish_reason {:?} was incomplete",
                        response.finish_reason
                    ));
                }
                reasons.extend(grounded.rejected_reasons);
                outcomes[pending_request.index] = Some(AnalysisOutcome {
                    status: AnalysisStatus::Incomplete,
                    source: Some(AnalysisSource::Provider),
                    findings,
                    identity: Some(pending_request.identity),
                    usage: response.usage,
                    reason: Some(reasons.join("; ")),
                });
            }
        }

        finish_outcomes(outcomes)
    }
}

impl PackageAnalyzer for Analyzer {
    fn analyze(&self, bundle: &RecipeBundle, options: AnalyzeOptions) -> AnalysisOutcome {
        self.analyze_batch(std::slice::from_ref(bundle), options)
            .into_iter()
            .next()
            .expect("one input bundle produces one analysis outcome")
    }
}

struct PendingRequest {
    index: usize,
    identity: AnalysisIdentity,
    request: ProviderRequest,
    encoded_body: Vec<u8>,
}

fn prepare_request(
    bundle: &RecipeBundle,
    config: &ValidatedLlmConfig,
    identity: AnalysisIdentity,
) -> anyhow::Result<(ProviderRequest, Vec<u8>)> {
    let request = build_request(bundle, config, identity)?;
    let encoded_body = request.encoded_body()?;
    Ok((request, encoded_body))
}

fn completed_outcome(
    bundle: &RecipeBundle,
    identity: AnalysisIdentity,
    completed: CompletedClaims,
    source: AnalysisSource,
) -> AnalysisOutcome {
    AnalysisOutcome {
        status: AnalysisStatus::Completed,
        source: Some(source),
        findings: materialize_claims(&completed.claims, &bundle.pkgbase),
        identity: Some(identity),
        usage: completed.usage,
        reason: None,
    }
}

fn failure_outcome(
    status: AnalysisStatus,
    source: Option<AnalysisSource>,
    identity: AnalysisIdentity,
    reason: String,
) -> AnalysisOutcome {
    AnalysisOutcome {
        status,
        source,
        findings: Vec::new(),
        identity: Some(identity),
        usage: None,
        reason: Some(reason),
    }
}

fn finish_outcomes(outcomes: Vec<Option<AnalysisOutcome>>) -> Vec<AnalysisOutcome> {
    outcomes
        .into_iter()
        .map(|outcome| outcome.expect("every input bundle receives an analysis outcome"))
        .collect()
}

fn analysis_identity(bundle: &RecipeBundle, config: &ValidatedLlmConfig) -> AnalysisIdentity {
    let endpoint_origin_fingerprint = *blake3::hash(config.endpoint_origin.as_bytes()).as_bytes();
    AnalysisIdentity {
        bundle_hash: bundle.content_hash,
        provider_protocol_version: PROVIDER_PROTOCOL_VERSION,
        endpoint_origin_fingerprint,
        model_id: config.model.clone(),
        review_strategy_id: REVIEW_STRATEGY_ID.to_owned(),
        request_profile_fingerprint: request_profile_fingerprint(config),
        prompt_version: PROMPT_VERSION,
        prompt_hash: prompt_hash(),
        response_schema_version: RESPONSE_SCHEMA_VERSION,
        response_schema_hash: response_schema_hash(),
        analysis_epoch: LLM_ANALYSIS_EPOCH,
    }
}

fn request_profile_fingerprint(config: &ValidatedLlmConfig) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    append_framed(&mut hasher, REVIEW_STRATEGY_ID.as_bytes());
    append_framed(
        &mut hasher,
        match config.response_format {
            crate::types::ResponseFormat::JsonSchema => b"json_schema",
            crate::types::ResponseFormat::JsonObject => b"json_object",
        },
    );
    hasher.update(&config.max_output_tokens.to_le_bytes());
    hasher.update(&(config.max_findings as u64).to_le_bytes());
    hasher.update(&(config.max_evidence_lines as u64).to_le_bytes());
    hasher.update(&(config.max_excerpt_bytes as u64).to_le_bytes());
    append_framed(&mut hasher, b"temperature=0");
    append_framed(&mut hasher, b"n=1");
    append_framed(&mut hasher, b"max_tokens");
    append_framed(&mut hasher, b"one_raw_user_message_per_file");
    append_framed(&mut hasher, b"reason_max_bytes=500");
    *hasher.finalize().as_bytes()
}

fn append_framed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn analysed_at() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
