use crate::cache::{AnalysisCache, CompletedClaims, RedbAnalysisCache};
use crate::config::ValidatedLlmConfig;
use crate::grounding::{ground_response, materialize_claims};
use crate::prompt::{build_request, prompt_hash, response_schema_hash, ProviderRequest};
use crate::provider::{load_api_key, ModelProvider, OpenAiCompatibleProvider};
use crate::types::{
    AnalysisIdentity, AnalysisOutcome, AnalysisSource, AnalysisStatus, AnalyzeOptions,
    PackageAnalyzer, RecipeBundle, RequestPreflight, LLM_ANALYSIS_EPOCH, PROMPT_VERSION,
    PROVIDER_PROTOCOL_VERSION, RESPONSE_SCHEMA_VERSION, REVIEW_STRATEGY_ID,
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

    pub fn preflight_batch(
        &self,
        bundles: &[RecipeBundle],
    ) -> anyhow::Result<Vec<RequestPreflight>> {
        let mut preflight = Vec::with_capacity(bundles.len());
        for bundle in bundles {
            let original_bytes = bundle.files.iter().try_fold(0_usize, |total, file| {
                total
                    .checked_add(file.content.len())
                    .ok_or_else(|| anyhow::anyhow!("original recipe byte count overflow"))
            })?;
            let encoded_request_bytes = {
                let identity = analysis_identity(bundle, &self.config);
                let (_, encoded_body) = prepare_request(bundle, &self.config, identity)
                    .map_err(|_| anyhow::anyhow!("request rendering failed"))?;
                encoded_body.len()
            };
            preflight.push(RequestPreflight {
                original_bytes,
                encoded_request_bytes,
            });
        }
        Ok(preflight)
    }

    pub fn analyze_batch(
        &self,
        bundles: &[RecipeBundle],
        options: AnalyzeOptions,
    ) -> Vec<AnalysisOutcome> {
        let mut outcomes = vec![None; bundles.len()];
        let mut misses = Vec::new();

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
            misses.push(PendingMiss { index, identity });
        }

        if misses.len() > self.config.max_requests_per_run {
            let miss_count = misses.len();
            for pending in misses {
                outcomes[pending.index] = Some(failure_outcome(
                    AnalysisStatus::Incomplete,
                    None,
                    pending.identity,
                    format!(
                        "cache miss count {miss_count} exceeds request cap {}",
                        self.config.max_requests_per_run
                    ),
                ));
            }
            return finish_outcomes(outcomes);
        }

        let mut api_key = None;
        let mut misses = misses.into_iter();
        while let Some(pending) = misses.next() {
            let (request, encoded_body) = match prepare_request(
                &bundles[pending.index],
                &self.config,
                pending.identity.clone(),
            ) {
                Ok(prepared) => prepared,
                Err(_) => {
                    outcomes[pending.index] = Some(failure_outcome(
                        AnalysisStatus::Incomplete,
                        None,
                        pending.identity,
                        "request rendering failed".into(),
                    ));
                    continue;
                }
            };
            if encoded_body.len() > self.config.max_request_bytes {
                outcomes[pending.index] = Some(failure_outcome(
                    AnalysisStatus::Incomplete,
                    None,
                    pending.identity,
                    format!(
                        "encoded request size {} exceeds byte limit {}",
                        encoded_body.len(),
                        self.config.max_request_bytes
                    ),
                ));
                continue;
            }

            if api_key.is_none() {
                match load_api_key(&self.config) {
                    Ok(loaded) => api_key = Some(loaded),
                    Err(error) => {
                        let reason = error.to_string();
                        outcomes[pending.index] = Some(failure_outcome(
                            AnalysisStatus::Unavailable,
                            None,
                            pending.identity,
                            reason.clone(),
                        ));
                        for remaining in misses {
                            outcomes[remaining.index] = Some(failure_outcome(
                                AnalysisStatus::Unavailable,
                                None,
                                remaining.identity,
                                reason.clone(),
                            ));
                        }
                        return finish_outcomes(outcomes);
                    }
                }
            }

            let response = match self.provider.send(
                &self.config,
                &request,
                &encoded_body,
                api_key.as_ref().and_then(Option::as_ref),
            ) {
                Ok(response) => response,
                Err(error) => {
                    outcomes[pending.index] = Some(failure_outcome(
                        AnalysisStatus::Unavailable,
                        Some(AnalysisSource::Provider),
                        pending.identity,
                        error.to_string(),
                    ));
                    continue;
                }
            };

            let finish_complete = response.finish_reason == "stop";
            let grounded = match ground_response(
                &response.content,
                &bundles[pending.index],
                self.config.max_findings,
                self.config.max_evidence_lines,
                self.config.max_excerpt_bytes,
            ) {
                Ok(grounded) => grounded,
                Err(reason) => {
                    outcomes[pending.index] = Some(AnalysisOutcome {
                        status: AnalysisStatus::Incomplete,
                        source: Some(AnalysisSource::Provider),
                        findings: Vec::new(),
                        identity: Some(pending.identity),
                        usage: response.usage,
                        reason: Some(if finish_complete {
                            reason
                        } else {
                            "provider response was incomplete".into()
                        }),
                    });
                    continue;
                }
            };

            let fully_grounded = grounded.rejected_reasons.is_empty();
            let findings = materialize_claims(&grounded.claims, &bundles[pending.index].pkgbase);
            if finish_complete && fully_grounded {
                let completed = CompletedClaims {
                    identity: pending.identity.clone(),
                    claims: grounded.claims,
                    usage: response.usage,
                    analysed_at: analysed_at(),
                };
                self.cache.put(&pending.identity, &completed);
                outcomes[pending.index] = Some(AnalysisOutcome {
                    status: AnalysisStatus::Completed,
                    source: Some(AnalysisSource::Provider),
                    findings,
                    identity: Some(pending.identity),
                    usage: response.usage,
                    reason: None,
                });
            } else {
                let reason = if !finish_complete {
                    "provider response was incomplete".into()
                } else {
                    grounded.rejected_reasons.join("; ")
                };
                outcomes[pending.index] = Some(AnalysisOutcome {
                    status: AnalysisStatus::Incomplete,
                    source: Some(AnalysisSource::Provider),
                    findings,
                    identity: Some(pending.identity),
                    usage: response.usage,
                    reason: Some(reason),
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

struct PendingMiss {
    index: usize,
    identity: AnalysisIdentity,
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

#[cfg(test)]
mod tests {
    use crate::types::{BundleCoverage, CoverageMode, LlmConfig, RecipeFile};

    fn bundle(hash: u8) -> crate::types::RecipeBundle {
        crate::types::RecipeBundle {
            pkgbase: format!("package-{hash}"),
            aur_commit: None,
            content_hash: [hash; 32],
            files: vec![RecipeFile {
                path: "PKGBUILD".into(),
                content: "x".repeat(1024 * 1024),
            }],
            coverage: BundleCoverage {
                mode: CoverageMode::GitTracked,
                included_files: 1,
                excluded_binary_files: vec![],
                excluded_symlinks: vec![],
            },
        }
    }

    #[test]
    fn over_cap_preflight_does_not_render_requests() {
        let config = LlmConfig {
            endpoint: "http://127.0.0.1:9/v1".into(),
            model: "test".into(),
            max_requests_per_run: 1,
            ..LlmConfig::default()
        };
        let directory = tempfile::tempdir().unwrap();
        let analyzer = super::Analyzer::with_cache_path(
            crate::config::validate_config(&config).unwrap(),
            directory.path().join("cache.redb"),
        )
        .unwrap();
        crate::prompt::reset_render_count();

        let outcomes = analyzer.analyze_batch(
            &[bundle(1), bundle(2)],
            crate::types::AnalyzeOptions { refresh: false },
        );

        assert_eq!(crate::prompt::render_count(), 0);
        assert!(outcomes
            .iter()
            .all(|outcome| outcome.status == crate::types::AnalysisStatus::Incomplete));
    }
}
