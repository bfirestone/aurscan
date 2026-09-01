use aurscan_llm::{
    AnalysisStatus, BundleLimits, LlmConfig, LlmFindingKind, PackageAnalyzer, RecipeBundleBuilder,
    ResponseFormat, REVIEW_STRATEGY_ID,
};
use std::collections::HashSet;

#[test]
fn public_traits_are_object_safe() {
    fn assert_send_sync<T: Send + Sync + ?Sized>() {}

    assert_send_sync::<dyn RecipeBundleBuilder>();
    assert_send_sync::<dyn PackageAnalyzer>();
}

#[test]
fn llm_detector_ids_are_unique() {
    let detector_ids: HashSet<_> = LlmFindingKind::ALL
        .into_iter()
        .map(|kind| kind.detector_id().0)
        .collect();

    assert_eq!(LlmFindingKind::ALL.len(), 8);
    assert_eq!(detector_ids.len(), 8);
}

#[test]
fn default_limits_are_stable() {
    let limits = BundleLimits::default();
    assert_eq!(limits.max_files, 32);
    assert_eq!(limits.max_file_bytes, 65_536);
    assert_eq!(limits.max_bundle_bytes, 131_072);

    let config = LlmConfig::default();
    assert_eq!(config.response_format, ResponseFormat::JsonSchema);
    assert_eq!(config.timeout_seconds, 90);
    assert_eq!(config.max_output_tokens, 2_048);
    assert_eq!(config.max_requests_per_run, 10);
    assert_eq!(config.max_files, 32);
    assert_eq!(config.max_file_bytes, 65_536);
    assert_eq!(config.max_bundle_bytes, 131_072);
    assert_eq!(config.max_request_bytes, 524_288);
    assert_eq!(config.max_findings, 32);
    assert_eq!(config.max_evidence_lines, 8);
    assert_eq!(config.max_excerpt_bytes, 200);
    assert_eq!(config.bundle_limits(), limits);
}

#[test]
fn review_strategy_id_is_stable() {
    assert_eq!(REVIEW_STRATEGY_ID, "findings_first_v1");
}

#[test]
fn analysis_status_variants_serialize_stably() {
    assert_eq!(
        serde_json::to_value(AnalysisStatus::Completed).unwrap(),
        serde_json::json!("completed")
    );
    assert_eq!(
        serde_json::to_value(AnalysisStatus::Unavailable).unwrap(),
        serde_json::json!("unavailable")
    );
    assert_eq!(
        serde_json::to_value(AnalysisStatus::Incomplete).unwrap(),
        serde_json::json!("incomplete")
    );
}
