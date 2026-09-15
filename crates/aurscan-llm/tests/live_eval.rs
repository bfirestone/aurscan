#[path = "live_eval/mod.rs"]
mod live_eval;

#[test]
fn manifest_and_harness_contract_compiles() -> anyhow::Result<()> {
    live_eval::offline_contract()
}

#[test]
#[ignore = "requires explicitly configured revision-pinned LLM"]
fn live_calibration_evaluation() -> anyhow::Result<()> {
    live_eval::run_calibration()
}

#[test]
#[ignore = "requires explicitly configured revision-pinned LLM"]
fn live_reference_evaluation() -> anyhow::Result<()> {
    live_eval::run_qualification()
}
