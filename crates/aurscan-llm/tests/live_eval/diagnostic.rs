use super::corpus::validate_relative_path;
use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

const DIAGNOSTIC_OUTPUT_ENV: &str = "AURSCAN_LLM_EVAL_DIAGNOSTIC_OUTPUT";
const MAX_PROMOTION_DIAGNOSTIC_BYTES: u64 = 8 * 1024 * 1024;
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
    pub(crate) corpus_content_hash: String,
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
    pub(crate) corpus_content_hash: String,
}

#[derive(Debug)]
struct RetainedDirectoryPath {
    path: PathBuf,
    descriptors: Vec<File>,
}

impl RetainedDirectoryPath {
    fn directory(&self) -> &File {
        self.descriptors
            .last()
            .expect("an absolute directory walk always retains the root descriptor")
    }
}

#[derive(Debug)]
pub(crate) struct PreparedDiagnosticPath {
    path: PathBuf,
    parent: RetainedDirectoryPath,
    file_name: OsString,
}

impl PreparedDiagnosticPath {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
pub(crate) struct OpenedDiagnosticPath {
    path: PathBuf,
    _parent: RetainedDirectoryPath,
    file: File,
}

impl OpenedDiagnosticPath {
    pub(crate) fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let length = self
            .file
            .metadata()
            .context("cannot inspect promotion diagnostic size")?
            .len();
        ensure!(
            length <= MAX_PROMOTION_DIAGNOSTIC_BYTES,
            "promotion diagnostic exceeds the safe size limit"
        );
        self.file
            .seek(std::io::SeekFrom::Start(0))
            .context("cannot seek promotion diagnostic")?;
        let capacity =
            usize::try_from(length).context("promotion diagnostic size cannot fit in memory")?;
        let mut bytes = Vec::with_capacity(capacity);
        Read::by_ref(&mut self.file)
            .take(MAX_PROMOTION_DIAGNOSTIC_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("cannot read promotion diagnostic")?;
        ensure!(
            bytes.len() as u64 <= MAX_PROMOTION_DIAGNOSTIC_BYTES,
            "promotion diagnostic grew beyond the safe size limit"
        );
        Ok(bytes)
    }

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
    append_framed(&mut hasher, identity.corpus_content_hash.as_bytes());
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
        corpus_content_hash: report.corpus_content_hash.clone(),
    }
}

pub(crate) fn configured_output_path() -> Result<PreparedDiagnosticPath> {
    let state_home = state_home()?;
    let configured = env::var_os(DIAGNOSTIC_OUTPUT_ENV).ok_or_else(|| {
        anyhow!("{DIAGNOSTIC_OUTPUT_ENV} must name a private diagnostic JSON path")
    })?;
    prepare_new_diagnostic_path(&state_home, Path::new(&configured))
}

pub(crate) fn configured_existing_path(variable: &str) -> Result<OpenedDiagnosticPath> {
    let state_home = state_home()?;
    let configured = env::var_os(variable)
        .ok_or_else(|| anyhow!("{variable} must name an existing private diagnostic JSON path"))?;
    open_existing_diagnostic_path(&state_home, Path::new(&configured))
}

fn state_home() -> Result<PathBuf> {
    let xdg = env::var_os("XDG_STATE_HOME");
    let home = env::var_os("HOME");
    state_home_from(xdg.as_deref(), home.as_deref())
}

fn state_home_from(xdg: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf> {
    let state_home = xdg
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.map(|value| PathBuf::from(value).join(".local/state")))
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
    prepare_new_diagnostic_path_inner(state_home, configured, |_| {})
}

#[cfg(test)]
fn prepare_new_diagnostic_path_with_hook(
    state_home: &Path,
    configured: &Path,
    hook: impl FnMut(&Path),
) -> Result<PreparedDiagnosticPath> {
    prepare_new_diagnostic_path_inner(state_home, configured, hook)
}

fn prepare_new_diagnostic_path_inner(
    state_home: &Path,
    configured: &Path,
    hook: impl FnMut(&Path),
) -> Result<PreparedDiagnosticPath> {
    validate_diagnostic_location(state_home, configured)?;
    let parent_path = configured
        .parent()
        .ok_or_else(|| anyhow!("diagnostic path has no parent directory"))?;
    let parent = open_absolute_directory_tree(parent_path, true, Some(state_home), hook)
        .context("cannot securely prepare diagnostic parent directory")?;
    let file_name = configured
        .file_name()
        .ok_or_else(|| anyhow!("diagnostic path has no file name"))?
        .to_os_string();
    let anchored_target = anchored_child_path(parent.directory(), &parent.path, &file_name);
    ensure!(
        fs::symlink_metadata(&anchored_target)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "diagnostic target already exists or cannot be inspected"
    );
    Ok(PreparedDiagnosticPath {
        path: configured.to_path_buf(),
        parent,
        file_name,
    })
}

pub(crate) fn open_existing_diagnostic_path(
    state_home: &Path,
    configured: &Path,
) -> Result<OpenedDiagnosticPath> {
    open_existing_diagnostic_path_inner(state_home, configured, |_| {})
}

#[cfg(test)]
fn open_existing_diagnostic_path_with_hook(
    state_home: &Path,
    configured: &Path,
    hook: impl FnMut(&Path),
) -> Result<OpenedDiagnosticPath> {
    open_existing_diagnostic_path_inner(state_home, configured, hook)
}

fn open_existing_diagnostic_path_inner(
    state_home: &Path,
    configured: &Path,
    hook: impl FnMut(&Path),
) -> Result<OpenedDiagnosticPath> {
    validate_diagnostic_location(state_home, configured)?;
    let parent_path = configured
        .parent()
        .ok_or_else(|| anyhow!("diagnostic path has no parent directory"))?;
    let parent = open_absolute_directory_tree(parent_path, false, None, hook)
        .context("cannot securely retain promotion diagnostic parent directory")?;
    let file_name = configured
        .file_name()
        .ok_or_else(|| anyhow!("promotion diagnostic path has no file name"))?;
    let anchored = anchored_child_path(parent.directory(), &parent.path, file_name);
    let file = open_regular_file_nofollow(&anchored)
        .context("cannot securely open promotion diagnostic")?;
    ensure!(
        file.metadata()
            .context("cannot inspect promotion diagnostic")?
            .is_file(),
        "promotion diagnostic is not a regular file"
    );
    Ok(OpenedDiagnosticPath {
        path: configured.to_path_buf(),
        _parent: parent,
        file,
    })
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
    Ok(())
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

fn open_absolute_directory_tree(
    path: &Path,
    create_missing: bool,
    private_root: Option<&Path>,
    mut after_open: impl FnMut(&Path),
) -> Result<RetainedDirectoryPath> {
    validate_absolute_without_traversal(path, "directory path")?;
    let mut current_path = PathBuf::new();
    let mut descriptors = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current_path.push(prefix.as_os_str()),
            Component::RootDir => {
                current_path.push(component.as_os_str());
                let root = open_directory_nofollow(&current_path).with_context(|| {
                    format!("cannot securely open directory {}", current_path.display())
                })?;
                descriptors.push(root);
                after_open(&current_path);
            }
            Component::Normal(part) => {
                let parent = descriptors
                    .last()
                    .ok_or_else(|| anyhow!("absolute directory path has no opened root"))?;
                let child = anchored_child_path(parent, &current_path, part);
                let mut created = false;
                let opened = match open_directory_nofollow(&child) {
                    Ok(opened) => opened,
                    Err(error)
                        if create_missing && error.kind() == std::io::ErrorKind::NotFound =>
                    {
                        match create_private_directory(&child) {
                            Ok(()) => created = true,
                            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                            Err(error) => {
                                return Err(error).with_context(|| {
                                    format!(
                                        "cannot create private diagnostic directory {}",
                                        current_path.join(part).display()
                                    )
                                })
                            }
                        }
                        open_directory_nofollow(&child).with_context(|| {
                            format!(
                                "cannot securely open diagnostic directory {} after creation",
                                current_path.join(part).display()
                            )
                        })?
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "cannot securely open diagnostic directory {}",
                                current_path.join(part).display()
                            )
                        })
                    }
                };
                current_path.push(part);
                if created
                    || private_root.is_some_and(|root| {
                        current_path.starts_with(root) && current_path.as_path() != root
                    })
                {
                    set_open_directory_private(&opened).with_context(|| {
                        format!("cannot set private mode on {}", current_path.display())
                    })?;
                }
                descriptors.push(opened);
                after_open(&current_path);
            }
            Component::CurDir | Component::ParentDir => {
                return Err(anyhow!("directory path contains traversal"));
            }
        }
    }
    ensure!(
        !descriptors.is_empty(),
        "absolute directory path has no opened root"
    );
    Ok(RetainedDirectoryPath {
        path: current_path,
        descriptors,
    })
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn set_open_directory_private(directory: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .context("cannot set private directory permissions")
}

#[cfg(not(unix))]
fn set_open_directory_private(_directory: &File) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_directory_nofollow(path: &Path) -> std::io::Result<File> {
    const O_DIRECTORY: i32 = 0o200000;
    const O_NOFOLLOW: i32 = 0o400000;
    OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_directory_nofollow(path: &Path) -> std::io::Result<File> {
    let file = File::open(path)?;
    if file.metadata()?.is_dir() {
        Ok(file)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            "opened path is not a directory",
        ))
    }
}

#[cfg(target_os = "linux")]
fn open_regular_file_nofollow(path: &Path) -> Result<File> {
    const O_NOFOLLOW: i32 = 0o400000;
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot securely open file {}", path.display()))
}

#[cfg(not(target_os = "linux"))]
fn open_regular_file_nofollow(path: &Path) -> Result<File> {
    File::open(path).with_context(|| format!("cannot open file {}", path.display()))
}

#[cfg(target_os = "linux")]
fn anchored_child_path(parent: &File, _parent_path: &Path, name: &OsStr) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(name)
}

#[cfg(not(target_os = "linux"))]
fn anchored_child_path(_parent: &File, parent_path: &Path, name: &OsStr) -> PathBuf {
    parent_path.join(name)
}

#[cfg(target_os = "linux")]
fn anchored_directory_path(parent: &RetainedDirectoryPath) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", parent.directory().as_raw_fd()))
}

#[cfg(not(target_os = "linux"))]
fn anchored_directory_path(parent: &RetainedDirectoryPath) -> PathBuf {
    parent.path.clone()
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

    let parent = anchored_directory_path(&prepared.parent);
    let target = anchored_child_path(
        prepared.parent.directory(),
        &prepared.parent.path,
        &prepared.file_name,
    );
    ensure!(
        fs::symlink_metadata(&target)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "diagnostic target already exists or cannot be inspected"
    );
    let mut temporary = tempfile::Builder::new()
        .prefix(".aurscan-eval-")
        .tempfile_in(&parent)
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
        .persist_noclobber(&target)
        .map_err(|error| error.error)
        .context("cannot atomically publish diagnostic without clobbering")?;
    prepared
        .parent
        .directory()
        .sync_all()
        .context("cannot sync diagnostic directory")?;
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
        ("corpus content", report.corpus_content_hash.as_str()),
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
            corpus_content_hash: "66".repeat(32),
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
            endpoint_origin_fingerprint: "77".repeat(32),
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
            corpus_content_hash: identity.corpus_content_hash.clone(),
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
        let mut changed = base.clone();
        changed.oracle_hash.replace_range(0..1, "6");
        mutations.push(changed);
        let mut changed = base;
        changed.corpus_content_hash.replace_range(0..1, "7");
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
        changed.endpoint_origin_fingerprint = "88".repeat(32);
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
    fn state_home_resolution_falls_back_from_empty_xdg_and_rejects_relative_roots() {
        assert_eq!(
            state_home_from(Some(OsStr::new("")), Some(OsStr::new("/home/test"))).unwrap(),
            Path::new("/home/test/.local/state")
        );
        assert_eq!(
            state_home_from(
                Some(OsStr::new("/var/lib/aurscan-state")),
                Some(OsStr::new("/home/test")),
            )
            .unwrap(),
            Path::new("/var/lib/aurscan-state")
        );
        for (xdg, home) in [
            (Some(OsStr::new("relative")), Some(OsStr::new("/home/test"))),
            (Some(OsStr::new("")), Some(OsStr::new("relative"))),
            (Some(OsStr::new("/tmp/../escape")), None),
        ] {
            assert!(state_home_from(xdg, home).is_err());
        }
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

    #[cfg(target_os = "linux")]
    #[test]
    fn diagnostic_publication_is_anchored_when_parent_path_is_replaced() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let state_home = temporary.path();
        let parent = state_home.join("aurscan/eval-runs/nested");
        let target = parent.join("report.json");
        let prepared = prepare_new_diagnostic_path(state_home, &target).unwrap();
        let retained_parent = state_home.join("retained-parent");
        fs::rename(&parent, &retained_parent).unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), &parent).unwrap();

        persist_diagnostic(prepared, &report()).unwrap();

        assert!(retained_parent.join("report.json").is_file());
        assert!(!outside.path().join("report.json").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn promotion_read_is_anchored_when_parent_path_is_replaced() {
        let temporary = tempfile::tempdir().unwrap();
        let state_home = temporary.path();
        let parent = state_home.join("aurscan/eval-runs");
        fs::create_dir_all(&parent).unwrap();
        let target = parent.join("promotion.json");
        fs::write(&target, b"original\n").unwrap();
        let mut opened = open_existing_diagnostic_path(state_home, &target).unwrap();
        let retained_parent = state_home.join("retained-parent");
        fs::rename(&parent, &retained_parent).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(&target, b"replacement\n").unwrap();

        assert_eq!(opened.read_bytes().unwrap(), b"original\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_final_ancestor_swaps_cannot_escape_diagnostic_reads_or_writes() {
        use std::os::unix::fs::symlink;

        let write_area = tempfile::tempdir().unwrap();
        let write_state = write_area.path().join("state");
        let original_ancestor = write_state.join("aurscan");
        fs::create_dir_all(&original_ancestor).unwrap();
        let retained_ancestor = write_state.join("retained-aurscan");
        let outside_write = tempfile::tempdir().unwrap();
        let write_target = original_ancestor.join("eval-runs/nested/report.json");
        let mut swapped = false;
        let prepared =
            prepare_new_diagnostic_path_with_hook(&write_state, &write_target, |opened_path| {
                if !swapped && opened_path == original_ancestor {
                    fs::rename(&original_ancestor, &retained_ancestor).unwrap();
                    symlink(outside_write.path(), &original_ancestor).unwrap();
                    swapped = true;
                }
            })
            .unwrap();
        assert!(swapped);
        persist_diagnostic(prepared, &report()).unwrap();
        assert!(retained_ancestor
            .join("eval-runs/nested/report.json")
            .is_file());
        assert!(!outside_write
            .path()
            .join("eval-runs/nested/report.json")
            .exists());

        let read_area = tempfile::tempdir().unwrap();
        let read_state = read_area.path().join("state");
        let original_ancestor = read_state.join("aurscan");
        let original_target = original_ancestor.join("eval-runs/promotion.json");
        fs::create_dir_all(original_target.parent().unwrap()).unwrap();
        fs::write(&original_target, b"trusted\n").unwrap();
        let outside_read = tempfile::tempdir().unwrap();
        let outside_target = outside_read.path().join("eval-runs/promotion.json");
        fs::create_dir_all(outside_target.parent().unwrap()).unwrap();
        fs::write(&outside_target, b"escaped\n").unwrap();
        let retained_ancestor = read_state.join("retained-aurscan");
        let mut swapped = false;
        let mut opened =
            open_existing_diagnostic_path_with_hook(&read_state, &original_target, |opened_path| {
                if !swapped && opened_path == original_ancestor {
                    fs::rename(&original_ancestor, &retained_ancestor).unwrap();
                    symlink(outside_read.path(), &original_ancestor).unwrap();
                    swapped = true;
                }
            })
            .unwrap();
        assert!(swapped);
        assert_eq!(opened.read_bytes().unwrap(), b"trusted\n");
        assert_eq!(fs::read(&outside_target).unwrap(), b"escaped\n");
    }

    #[test]
    fn promotion_reads_are_capped_above_a_bounded_57_case_diagnostic() {
        let mut bounded = report();
        let case = bounded.case_results[0].clone();
        bounded.selected_case_ids = (0..57).map(|index| format!("case-{index:02}")).collect();
        bounded.case_results = bounded
            .selected_case_ids
            .iter()
            .map(|id| {
                let mut case = case.clone();
                case.id = id.clone();
                case.accepted_findings =
                    (0..32).map(|_| case.accepted_findings[0].clone()).collect();
                case
            })
            .collect();
        let bounded_bytes = serde_json::to_vec_pretty(&bounded).unwrap();
        assert!(
            bounded_bytes.len() as u64 * 4 < MAX_PROMOTION_DIAGNOSTIC_BYTES,
            "promotion cap has insufficient headroom for the bounded 57-case artifact"
        );

        let temporary = tempfile::tempdir().unwrap();
        let state_home = temporary.path();
        let target = state_home.join("aurscan/eval-runs/oversized.json");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let file = File::create(&target).unwrap();
        file.set_len(MAX_PROMOTION_DIAGNOSTIC_BYTES + 1).unwrap();
        drop(file);
        let mut opened = open_existing_diagnostic_path(state_home, &target).unwrap();
        assert!(opened.read_bytes().is_err());
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
