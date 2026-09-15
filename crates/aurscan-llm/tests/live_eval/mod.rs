mod corpus;
mod diagnostic;
mod runner;

pub(super) fn offline_contract() -> anyhow::Result<()> {
    corpus::offline_contract()?;
    diagnostic::offline_contract()?;
    runner::offline_contract()
}

pub(super) fn run_calibration() -> anyhow::Result<()> {
    runner::run_calibration()
}

pub(super) fn run_qualification() -> anyhow::Result<()> {
    runner::run_qualification()
}
