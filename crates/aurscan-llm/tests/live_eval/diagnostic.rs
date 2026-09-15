use super::corpus::validate_relative_path;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const DIAGNOSTIC_OUTPUT_ENV: &str = "AURSCAN_LLM_EVAL_DIAGNOSTIC_OUTPUT";
const FORBIDDEN_KEYS: [&str; 11] = [
    "endpoint",
    "api_key",
    "api_key_env",
    "authorization",
    "raw_response",
    "raw_prompt",
    "prompt",
    "content",
    "reason",
    "location",
    "excerpt",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunKind {
    Calibration,
    Qualification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunOutcome {
    Passed,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiagnosticStatus {
    Completed,
    Unavailable,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvaluationMetrics {
    pub(crate) semantic_expected_kind_rate: f64,
    pub(crate) grounding_rate: f64,
    pub(crate) paired_injection_delta_percentage_points: f64,
    pub(crate) benign_unlabelled_advisory_rate: f64,
    pub(crate) llm_block_count: usize,
    pub(crate) invalid_or_incomplete_rate: f64,
    pub(crate) request_count: usize,
    pub(crate) cache_hit_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output_tokens: Option<u64>,
    pub(crate) latency_ms: u64,
    pub(crate) completed_count: usize,
    pub(crate) unavailable_count: usize,
    pub(crate) incomplete_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiagnosticUsage {
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiagnosticFindingRef {
    pub(crate) kind: String,
    pub(crate) severity: String,
    pub(crate) relative_file: String,
    pub(crate) start_line: usize,
    pub(crate) end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiagnosticCaseResult {
    pub(crate) id: String,
    pub(crate) category: String,
    pub(crate) expected_hit: bool,
    pub(crate) expected_kinds: Vec<String>,
    pub(crate) accepted_findings: Vec<DiagnosticFindingRef>,
    pub(crate) grounded: bool,
    pub(crate) status: DiagnosticStatus,
    pub(crate) latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) usage: Option<DiagnosticUsage>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiagnosticReport {
    pub(crate) schema_version: u32,
    pub(crate) run_kind: RunKind,
    pub(crate) outcome: RunOutcome,
    pub(crate) failed_threshold_ids: Vec<String>,
    pub(crate) generated_at: u64,
    pub(crate) git_commit: String,
    pub(crate) model_id: String,
    pub(crate) endpoint_origin_fingerprint: String,
    pub(crate) request_profile: String,
    pub(crate) request_profile_fingerprint: String,
    pub(crate) review_strategy_id: String,
    pub(crate) prompt_version: u32,
    pub(crate) prompt_hash: String,
    pub(crate) response_schema_version: u16,
    pub(crate) response_schema_hash: String,
    pub(crate) analysis_epoch: u32,
    pub(crate) corpus_manifest_hash: String,
    pub(crate) oracle_hash: String,
    pub(crate) analysis_contract_hash: String,
    pub(crate) selected_case_ids: Vec<String>,
    pub(crate) metrics: EvaluationMetrics,
    pub(crate) case_results: Vec<DiagnosticCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnalysisContractIdentity {
    pub(crate) model_id: String,
    pub(crate) request_profile: String,
    pub(crate) request_profile_fingerprint: String,
    pub(crate) prompt_version: u32,
    pub(crate) prompt_hash: String,
    pub(crate) response_schema_version: u16,
    pub(crate) response_schema_hash: String,
    pub(crate) analysis_epoch: u32,
    pub(crate) review_strategy_id: String,
    pub(crate) corpus_manifest_hash: String,
    pub(crate) oracle_hash: String,
}

#[derive(Debug)]
pub(crate) struct PreparedDiagnosticPath {
    path: PathBuf,
}

impl PreparedDiagnosticPath {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn offline_contract() -> Result<()> {
    ensure!(
        sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 implementation changed"
    );
    ensure_no_forbidden_keys(&serde_json::json!({
        "safe": [{"relative_file": "PKGBUILD", "start_line": 1, "end_line": 1}]
    }))?;
    ensure!(
        ensure_no_forbidden_keys(&serde_json::json!({"safe": [{"ReAsOn": "raw"}]})).is_err(),
        "recursive diagnostic secrecy check changed"
    );
    Ok(())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub(crate) fn analysis_contract_hash(identity: &AnalysisContractIdentity) -> String {
    let mut hasher = Sha256::new();
    append_framed(&mut hasher, identity.model_id.as_bytes());
    append_framed(&mut hasher, identity.request_profile.as_bytes());
    append_framed(&mut hasher, identity.request_profile_fingerprint.as_bytes());
    append_framed(&mut hasher, &identity.prompt_version.to_le_bytes());
    append_framed(&mut hasher, identity.prompt_hash.as_bytes());
    append_framed(&mut hasher, &identity.response_schema_version.to_le_bytes());
    append_framed(&mut hasher, identity.response_schema_hash.as_bytes());
    append_framed(&mut hasher, &identity.analysis_epoch.to_le_bytes());
    append_framed(&mut hasher, identity.review_strategy_id.as_bytes());
    append_framed(&mut hasher, identity.corpus_manifest_hash.as_bytes());
    append_framed(&mut hasher, identity.oracle_hash.as_bytes());
    hex(&hasher.finalize())
}

fn append_framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

pub(crate) fn contract_identity(report: &DiagnosticReport) -> AnalysisContractIdentity {
    AnalysisContractIdentity {
        model_id: report.model_id.clone(),
        request_profile: report.request_profile.clone(),
        request_profile_fingerprint: report.request_profile_fingerprint.clone(),
        prompt_version: report.prompt_version,
        prompt_hash: report.prompt_hash.clone(),
        response_schema_version: report.response_schema_version,
        response_schema_hash: report.response_schema_hash.clone(),
        analysis_epoch: report.analysis_epoch,
        review_strategy_id: report.review_strategy_id.clone(),
        corpus_manifest_hash: report.corpus_manifest_hash.clone(),
        oracle_hash: report.oracle_hash.clone(),
    }
}

pub(crate) fn configured_output_path() -> Result<PreparedDiagnosticPath> {
    let state_home = state_home()?;
    let configured = env::var_os(DIAGNOSTIC_OUTPUT_ENV).ok_or_else(|| {
        anyhow!("{DIAGNOSTIC_OUTPUT_ENV} must name a private diagnostic JSON path")
    })?;
    prepare_new_diagnostic_path(&state_home, Path::new(&configured))
}

pub(crate) fn configured_existing_path(variable: &str) -> Result<PathBuf> {
    let state_home = state_home()?;
    let configured = env::var_os(variable)
        .ok_or_else(|| anyhow!("{variable} must name an existing private diagnostic JSON path"))?;
    validate_existing_diagnostic_path(&state_home, Path::new(&configured))
}

fn state_home() -> Result<PathBuf> {
    let state_home = env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| anyhow!("XDG_STATE_HOME or HOME is required for evaluation diagnostics"))?;
    validate_absolute_without_traversal(&state_home, "state home")?;
    Ok(state_home)
}

fn diagnostic_root(state_home: &Path) -> PathBuf {
    state_home.join("aurscan/eval-runs")
}

pub(crate) fn prepare_new_diagnostic_path(
    state_home: &Path,
    configured: &Path,
) -> Result<PreparedDiagnosticPath> {
    validate_diagnostic_location(state_home, configured)?;
    ensure!(
        fs::symlink_metadata(configured)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "diagnostic target already exists or cannot be inspected"
    );
    ensure_private_state_home(state_home)?;
    let parent = configured
        .parent()
        .ok_or_else(|| anyhow!("diagnostic path has no parent directory"))?;
    create_private_directories(state_home, parent)?;
    reject_symlinks(configured)?;
    ensure!(!configured.exists(), "diagnostic target already exists");
    Ok(PreparedDiagnosticPath {
        path: configured.to_path_buf(),
    })
}

pub(crate) fn validate_existing_diagnostic_path(
    state_home: &Path,
    configured: &Path,
) -> Result<PathBuf> {
    validate_diagnostic_location(state_home, configured)?;
    reject_symlinks(configured)?;
    let metadata = fs::metadata(configured).context("promotion diagnostic does not exist")?;
    ensure!(
        metadata.is_file(),
        "promotion diagnostic is not a regular file"
    );
    Ok(configured.to_path_buf())
}

fn validate_diagnostic_location(state_home: &Path, configured: &Path) -> Result<()> {
    validate_absolute_without_traversal(state_home, "state home")?;
    validate_absolute_without_traversal(configured, "diagnostic path")?;
    let root = diagnostic_root(state_home);
    ensure!(
        configured.starts_with(&root) && configured != root,
        "diagnostic path must be beneath {}",
        root.display()
    );
    ensure!(
        configured.extension() == Some(OsStr::new("json"))
            && configured.file_stem().is_some_and(|stem| !stem.is_empty()),
        "diagnostic target must have a non-empty .json filename"
    );
    let reference_reports = Path::new(env!("CARGO_MANIFEST_DIR")).join("eval/reference-reports");
    ensure!(
        !configured.starts_with(reference_reports),
        "diagnostics may not be written under reference-reports"
    );
    reject_symlinks(configured)
}

fn validate_absolute_without_traversal(path: &Path, label: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{label} must be absolute");
    ensure!(
        path.components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir)),
        "{label} contains traversal"
    );
    ensure!(
        !path.to_string_lossy().chars().any(is_terminal_control),
        "{label} contains a terminal control character"
    );
    Ok(())
}

fn reject_symlinks(path: &Path) -> Result<()> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "diagnostic path contains symlink {}",
                prefix.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect diagnostic path {}", prefix.display())
                })
            }
        }
    }
    Ok(())
}

fn ensure_private_state_home(state_home: &Path) -> Result<()> {
    reject_symlinks(state_home)?;
    let created = match fs::symlink_metadata(state_home) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "state home is not a real directory"
            );
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(state_home).context("cannot create state home")?;
            true
        }
        Err(error) => return Err(error).context("cannot inspect state home"),
    };
    reject_symlinks(state_home)?;
    if created {
        set_directory_mode(state_home)?;
    }
    Ok(())
}

fn create_private_directories(state_home: &Path, parent: &Path) -> Result<()> {
    ensure!(
        parent.starts_with(state_home),
        "diagnostic parent escapes state home"
    );
    let mut current = state_home.to_path_buf();
    ensure!(current.is_dir(), "state home must exist and be a directory");
    for component in parent
        .strip_prefix(state_home)
        .context("diagnostic parent escapes state home")?
        .components()
    {
        let Component::Normal(part) = component else {
            bail!("diagnostic parent contains traversal");
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink() && metadata.is_dir(),
                    "diagnostic parent {} is not a real directory",
                    current.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| {
                    format!(
                        "cannot create private diagnostic directory {}",
                        current.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect diagnostic directory {}", current.display())
                })
            }
        }
        set_directory_mode(&current)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_directory_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot set private mode on {}", path.display()))
}

#[cfg(not(unix))]
fn set_directory_mode(_path: &Path) -> Result<()> {
    Ok(())
}

pub(crate) fn persist_diagnostic(
    prepared: PreparedDiagnosticPath,
    report: &DiagnosticReport,
) -> Result<()> {
    validate_report(report)?;
    let value = serde_json::to_value(report).context("cannot inspect diagnostic JSON")?;
    ensure_no_forbidden_keys(&value)?;
    let mut bytes =
        serde_json::to_vec_pretty(report).context("cannot serialize diagnostic JSON")?;
    bytes.push(b'\n');

    let path = prepared.path;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("diagnostic path has no parent directory"))?;
    reject_symlinks(&path)?;
    ensure!(!path.exists(), "diagnostic target already exists");
    let mut temporary = tempfile::Builder::new()
        .prefix(".aurscan-eval-")
        .tempfile_in(parent)
        .context("cannot create same-directory diagnostic temporary file")?;
    set_file_mode(temporary.as_file())?;
    temporary
        .as_file_mut()
        .write_all(&bytes)
        .context("cannot write diagnostic temporary file")?;
    temporary
        .as_file_mut()
        .flush()
        .context("cannot flush diagnostic temporary file")?;
    temporary
        .as_file()
        .sync_all()
        .context("cannot sync diagnostic temporary file")?;
    temporary
        .persist_noclobber(&path)
        .map_err(|error| error.error)
        .context("cannot atomically publish diagnostic without clobbering")?;
    sync_directory(parent).context("cannot sync diagnostic directory")?;
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("cannot set private diagnostic file mode")
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .context("cannot sync directory")
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

pub(crate) fn validate_report(report: &DiagnosticReport) -> Result<()> {
    ensure!(report.schema_version == 1, "diagnostic schema changed");
    ensure!(
        (report.outcome == RunOutcome::Passed && report.failed_threshold_ids.is_empty())
            || (report.outcome == RunOutcome::Rejected && !report.failed_threshold_ids.is_empty()),
        "diagnostic outcome and failed thresholds disagree"
    );
    ensure!(
        report.analysis_contract_hash == analysis_contract_hash(&contract_identity(report)),
        "diagnostic analysis contract hash does not recompute"
    );
    for (label, digest) in [
        (
            "endpoint origin",
            report.endpoint_origin_fingerprint.as_str(),
        ),
        (
            "request profile",
            report.request_profile_fingerprint.as_str(),
        ),
        ("prompt", report.prompt_hash.as_str()),
        ("response schema", report.response_schema_hash.as_str()),
        ("corpus manifest", report.corpus_manifest_hash.as_str()),
        ("oracle", report.oracle_hash.as_str()),
        ("analysis contract", report.analysis_contract_hash.as_str()),
    ] {
        ensure!(
            is_lower_hex_digest(digest),
            "{label} hash is not a lowercase 32-byte digest"
        );
    }
    ensure!(
        !report.model_id.is_empty()
            && !report.request_profile.is_empty()
            && !report.review_strategy_id.is_empty(),
        "diagnostic identity string is empty"
    );
    let selected = report
        .selected_case_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        selected.len() == report.selected_case_ids.len(),
        "diagnostic selection contains duplicate IDs"
    );
    ensure!(
        report.case_results.len() == report.selected_case_ids.len()
            && report
                .case_results
                .iter()
                .map(|case| case.id.as_str())
                .eq(report.selected_case_ids.iter().map(String::as_str)),
        "diagnostic case results do not match selected ID order"
    );
    for case in &report.case_results {
        for finding in &case.accepted_findings {
            validate_relative_path(&finding.relative_file)
                .context("diagnostic finding path is unsafe")?;
            ensure!(
                finding.start_line > 0 && finding.start_line <= finding.end_line,
                "diagnostic finding line range is invalid"
            );
            ensure!(
                matches!(
                    finding.severity.as_str(),
                    "info" | "medium" | "high" | "critical"
                ),
                "diagnostic finding severity is invalid"
            );
        }
    }
    for percentage in [
        report.metrics.semantic_expected_kind_rate,
        report.metrics.grounding_rate,
        report.metrics.paired_injection_delta_percentage_points,
        report.metrics.benign_unlabelled_advisory_rate,
        report.metrics.invalid_or_incomplete_rate,
    ] {
        ensure!(percentage.is_finite(), "diagnostic metric is not finite");
    }
    Ok(())
}

pub(crate) fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn ensure_no_forbidden_keys(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                ensure!(
                    !FORBIDDEN_KEYS
                        .iter()
                        .any(|forbidden| key.eq_ignore_ascii_case(forbidden)),
                    "diagnostic JSON contains forbidden key {key}"
                );
                ensure_no_forbidden_keys(nested)?;
            }
        }
        Value::Array(array) => {
            for nested in array {
                ensure_no_forbidden_keys(nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn terminal_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        if is_terminal_control(character) {
            use std::fmt::Write;
            write!(&mut escaped, "\\u{{{:04x}}}", character as u32)
                .expect("writing into String cannot fail");
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn is_terminal_control(character: char) -> bool {
    let code = character as u32;
    character.is_control()
        || (0x7f..=0x9f).contains(&code)
        || matches!(
            code,
            0x061c
                | 0x200e
                | 0x200f
                | 0x2028
                | 0x2029
                | 0x202a..=0x202e
                | 0x2066..=0x206f
        )
}

pub(crate) fn stdout_summary(report: &DiagnosticReport, path: &Path) -> String {
    let failures = if report.failed_threshold_ids.is_empty() {
        "none".to_owned()
    } else {
        report
            .failed_threshold_ids
            .iter()
            .map(|value| terminal_escape(value))
            .collect::<Vec<_>>()
            .join(",")
    };
    let cases = report
        .case_results
        .iter()
        .map(|case| {
            let expected_kinds = case
                .expected_kinds
                .iter()
                .map(|kind| terminal_escape(kind))
                .collect::<Vec<_>>()
                .join("+");
            let accepted_findings = case
                .accepted_findings
                .iter()
                .map(|finding| {
                    format!(
                        "{}:{}@{}:{}-{}",
                        terminal_escape(&finding.kind),
                        terminal_escape(&finding.severity),
                        terminal_escape(&finding.relative_file),
                        finding.start_line,
                        finding.end_line
                    )
                })
                .collect::<Vec<_>>()
                .join("+");
            let usage = case.usage.as_ref().map_or_else(
                || "none".to_owned(),
                |usage| format!("{}+{}", usage.input_tokens, usage.output_tokens),
            );
            format!(
                "{}({}):expected={}/{}:accepted={}:grounded={}:status={:?}:latency_ms={}:usage={}",
                terminal_escape(&case.id),
                terminal_escape(&case.category),
                case.expected_hit,
                expected_kinds,
                accepted_findings,
                case.grounded,
                case.status,
                case.latency_ms,
                usage
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "diagnostic={} run={:?} outcome={:?} model={} profile={} failed_thresholds={} cases={}",
        terminal_escape(&path.to_string_lossy()),
        report.run_kind,
        report.outcome,
        terminal_escape(&report.model_id),
        terminal_escape(&report.request_profile),
        failures,
        cases
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").expect("writing into String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn identity() -> AnalysisContractIdentity {
        AnalysisContractIdentity {
            model_id: "gpt-5.6-sol".to_owned(),
            request_profile: "openai_reasoning_none".to_owned(),
            request_profile_fingerprint: "11".repeat(32),
            prompt_version: 2,
            prompt_hash: "22".repeat(32),
            response_schema_version: 1,
            response_schema_hash: "33".repeat(32),
            analysis_epoch: 1,
            review_strategy_id: "findings_first_v1".to_owned(),
            corpus_manifest_hash: "44".repeat(32),
            oracle_hash: "55".repeat(32),
        }
    }

    fn report() -> DiagnosticReport {
        let identity = identity();
        DiagnosticReport {
            schema_version: 1,
            run_kind: RunKind::Calibration,
            outcome: RunOutcome::Passed,
            failed_threshold_ids: Vec::new(),
            generated_at: 1,
            git_commit: "a".repeat(40),
            model_id: identity.model_id.clone(),
            endpoint_origin_fingerprint: "66".repeat(32),
            request_profile: identity.request_profile.clone(),
            request_profile_fingerprint: identity.request_profile_fingerprint.clone(),
            review_strategy_id: identity.review_strategy_id.clone(),
            prompt_version: identity.prompt_version,
            prompt_hash: identity.prompt_hash.clone(),
            response_schema_version: identity.response_schema_version,
            response_schema_hash: identity.response_schema_hash.clone(),
            analysis_epoch: identity.analysis_epoch,
            corpus_manifest_hash: identity.corpus_manifest_hash.clone(),
            oracle_hash: identity.oracle_hash.clone(),
            analysis_contract_hash: analysis_contract_hash(&identity),
            selected_case_ids: vec!["case-one".to_owned()],
            metrics: EvaluationMetrics {
                semantic_expected_kind_rate: 100.0,
                grounding_rate: 100.0,
                paired_injection_delta_percentage_points: 0.0,
                benign_unlabelled_advisory_rate: 0.0,
                llm_block_count: 0,
                invalid_or_incomplete_rate: 0.0,
                request_count: 1,
                cache_hit_count: 0,
                input_tokens: Some(10),
                output_tokens: Some(5),
                latency_ms: 2,
                completed_count: 1,
                unavailable_count: 0,
                incomplete_count: 0,
            },
            case_results: vec![DiagnosticCaseResult {
                id: "case-one".to_owned(),
                category: "test-category".to_owned(),
                expected_hit: true,
                expected_kinds: vec!["download_execute".to_owned()],
                accepted_findings: vec![DiagnosticFindingRef {
                    kind: "download_execute".to_owned(),
                    severity: "high".to_owned(),
                    relative_file: "PKGBUILD".to_owned(),
                    start_line: 7,
                    end_line: 8,
                }],
                grounded: true,
                status: DiagnosticStatus::Completed,
                latency_ms: 2,
                usage: Some(DiagnosticUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                }),
            }],
        }
    }

    #[test]
    fn sha256_contract_is_available_for_diagnostic_identity() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn every_analysis_contract_field_changes_the_length_framed_hash() {
        let base = identity();
        let expected = analysis_contract_hash(&base);
        let mut mutations = Vec::new();
        let mut changed = base.clone();
        changed.model_id.push('x');
        mutations.push(changed);
        let mut changed = base.clone();
        changed.request_profile.push('x');
        mutations.push(changed);
        let mut changed = base.clone();
        changed.request_profile_fingerprint.replace_range(0..1, "2");
        mutations.push(changed);
        let mut changed = base.clone();
        changed.prompt_version += 1;
        mutations.push(changed);
        let mut changed = base.clone();
        changed.prompt_hash.replace_range(0..1, "3");
        mutations.push(changed);
        let mut changed = base.clone();
        changed.response_schema_version += 1;
        mutations.push(changed);
        let mut changed = base.clone();
        changed.response_schema_hash.replace_range(0..1, "4");
        mutations.push(changed);
        let mut changed = base.clone();
        changed.analysis_epoch += 1;
        mutations.push(changed);
        let mut changed = base.clone();
        changed.review_strategy_id.push('x');
        mutations.push(changed);
        let mut changed = base.clone();
        changed.corpus_manifest_hash.replace_range(0..1, "5");
        mutations.push(changed);
        let mut changed = base;
        changed.oracle_hash.replace_range(0..1, "6");
        mutations.push(changed);

        for mutation in mutations {
            assert_ne!(analysis_contract_hash(&mutation), expected);
        }

        let mut left = identity();
        left.model_id = "ab".to_owned();
        left.request_profile = "c".to_owned();
        let mut right = identity();
        right.model_id = "a".to_owned();
        right.request_profile = "bc".to_owned();
        assert_ne!(
            analysis_contract_hash(&left),
            analysis_contract_hash(&right)
        );
    }

    #[test]
    fn git_commit_selection_and_endpoint_do_not_change_analysis_contract_hash() {
        let original = report();
        let expected = analysis_contract_hash(&contract_identity(&original));
        let mut changed = original;
        changed.git_commit = "b".repeat(40);
        changed.selected_case_ids = vec!["different-case".to_owned()];
        changed.endpoint_origin_fingerprint = "77".repeat(32);
        assert_eq!(
            analysis_contract_hash(&contract_identity(&changed)),
            expected
        );
    }

    #[test]
    fn diagnostic_schema_recursively_rejects_every_forbidden_key() {
        let value = serde_json::to_value(report()).unwrap();
        ensure_no_forbidden_keys(&value).unwrap();
        for key in FORBIDDEN_KEYS {
            assert!(ensure_no_forbidden_keys(&json!({key: "secret"})).is_err());
            let uppercase = key.to_ascii_uppercase();
            assert!(ensure_no_forbidden_keys(&json!({"safe": [{uppercase: "secret"}]})).is_err());
        }
    }

    #[test]
    fn unsafe_finding_paths_are_rejected_before_json() {
        for relative_file in ["../secret", "/etc/shadow", "bad\u{1b}[2J"] {
            let mut unsafe_report = report();
            unsafe_report.case_results[0].accepted_findings[0].relative_file =
                relative_file.to_owned();
            assert!(validate_report(&unsafe_report).is_err());
        }
    }

    #[test]
    fn empty_xdg_state_home_falls_back_to_home_local_state() {
        let _environment = ENV_LOCK.lock().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let previous_xdg_state_home = env::var_os("XDG_STATE_HOME");
        let previous_home = env::var_os("HOME");
        env::set_var("XDG_STATE_HOME", "");
        env::set_var("HOME", temporary.path());

        let resolved = state_home();

        if let Some(value) = previous_xdg_state_home {
            env::set_var("XDG_STATE_HOME", value);
        } else {
            env::remove_var("XDG_STATE_HOME");
        }
        if let Some(value) = previous_home {
            env::set_var("HOME", value);
        } else {
            env::remove_var("HOME");
        }

        assert_eq!(resolved.unwrap(), temporary.path().join(".local/state"));
    }

    #[test]
    fn diagnostic_path_creates_a_missing_private_state_tree() {
        let temporary = tempfile::tempdir().unwrap();
        let state_home = temporary.path().join("new-state-home");
        let target = state_home.join("aurscan/eval-runs/calibration.json");
        let prepared = prepare_new_diagnostic_path(&state_home, &target).unwrap();
        persist_diagnostic(prepared, &report()).unwrap();
        assert!(target.is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&state_home).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn rejected_diagnostics_are_persisted_as_non_reference_artifacts() {
        let temporary = tempfile::tempdir().unwrap();
        let state_home = temporary.path();
        let target = state_home.join("aurscan/eval-runs/rejected.json");
        let mut rejected = report();
        rejected.outcome = RunOutcome::Rejected;
        rejected.failed_threshold_ids = vec!["semantic_expected_kind_rate".to_owned()];
        let prepared = prepare_new_diagnostic_path(state_home, &target).unwrap();
        persist_diagnostic(prepared, &rejected).unwrap();
        let persisted: DiagnosticReport =
            serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(persisted.outcome, RunOutcome::Rejected);
        assert_eq!(
            persisted.failed_threshold_ids,
            ["semantic_expected_kind_rate"]
        );
        assert!(!target.to_string_lossy().contains("reference-reports"));
    }

    #[test]
    fn diagnostic_path_is_private_atomic_and_never_overwrites() {
        let temporary = tempfile::tempdir().unwrap();
        let state_home = temporary.path();
        let target = state_home.join("aurscan/eval-runs/nested/calibration.json");
        let prepared = prepare_new_diagnostic_path(state_home, &target).unwrap();
        persist_diagnostic(prepared, &report()).unwrap();
        let bytes = fs::read(&target).unwrap();
        let mut expected = serde_json::to_vec_pretty(&report()).unwrap();
        expected.push(b'\n');
        assert_eq!(bytes, expected);
        assert!(prepare_new_diagnostic_path(state_home, &target).is_err());

        let raced_target = state_home.join("aurscan/eval-runs/nested/raced.json");
        let prepared = prepare_new_diagnostic_path(state_home, &raced_target).unwrap();
        fs::write(&raced_target, b"racing-writer\n").unwrap();
        assert!(persist_diagnostic(prepared, &report()).is_err());
        assert_eq!(fs::read(&raced_target).unwrap(), b"racing-writer\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(target.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(state_home.join("aurscan/eval-runs"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn diagnostic_paths_reject_relative_traversal_non_json_and_outside_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let state_home = temporary.path();
        for target in [
            PathBuf::from("relative.json"),
            state_home.join("aurscan/eval-runs/../escape.json"),
            state_home.join("aurscan/eval-runs/report.txt"),
            state_home.join("aurscan/eval-runs/report.JSON"),
            state_home.join("aurscan/eval-runs/bad\nname.json"),
            state_home.join("outside.json"),
        ] {
            assert!(
                prepare_new_diagnostic_path(state_home, &target).is_err(),
                "accepted {}",
                target.display()
            );
        }
    }

    #[test]
    fn diagnostic_paths_never_target_reference_reports() {
        let state_home = Path::new(env!("CARGO_MANIFEST_DIR")).join("eval/reference-reports");
        let target = state_home.join("aurscan/eval-runs/rejected.json");
        assert!(prepare_new_diagnostic_path(&state_home, &target).is_err());
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_paths_reject_symlink_parents_and_targets() {
        use std::os::unix::fs::symlink;
        let temporary = tempfile::tempdir().unwrap();
        let state_home = temporary.path();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(state_home.join("aurscan")).unwrap();
        symlink(outside.path(), state_home.join("aurscan/eval-runs")).unwrap();
        let escaped = state_home.join("aurscan/eval-runs/report.json");
        assert!(prepare_new_diagnostic_path(state_home, &escaped).is_err());

        fs::remove_file(state_home.join("aurscan/eval-runs")).unwrap();
        fs::create_dir(state_home.join("aurscan/eval-runs")).unwrap();
        let target = state_home.join("aurscan/eval-runs/report.json");
        symlink(outside.path().join("missing"), &target).unwrap();
        assert!(prepare_new_diagnostic_path(state_home, &target).is_err());
    }

    #[test]
    fn terminal_output_escapes_control_and_directional_characters() {
        let escaped = terminal_escape("safe\n\u{1b}[31m\u{202e}tail");
        assert_eq!(escaped, "safe\\u{000a}\\u{001b}[31m\\u{202e}tail");
        assert!(!escaped.contains('\n'));

        let mut hostile = report();
        hostile.outcome = RunOutcome::Rejected;
        hostile.failed_threshold_ids = vec!["failure\n\u{1b}".to_owned()];
        hostile.model_id = "model\n\u{202e}".to_owned();
        hostile.request_profile = "profile\u{1b}".to_owned();
        hostile.case_results[0].id = "id\n".to_owned();
        hostile.case_results[0].category = "category\u{202e}".to_owned();
        hostile.case_results[0].expected_kinds = vec!["expected\u{1b}".to_owned()];
        hostile.case_results[0].accepted_findings[0].kind = "kind\n".to_owned();
        hostile.case_results[0].accepted_findings[0].severity = "severity\u{202e}".to_owned();
        hostile.case_results[0].accepted_findings[0].relative_file = "path\u{1b}".to_owned();
        let summary = stdout_summary(&hostile, Path::new("/state/bad\n\u{1b}.json"));
        assert!(!summary.chars().any(is_terminal_control));
        assert!(summary.contains("\\u{000a}"));
        assert!(summary.contains("\\u{001b}"));
        assert!(summary.contains("\\u{202e}"));
    }
}
