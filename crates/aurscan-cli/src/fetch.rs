//! Clone/pull AUR pkgbases into paru's clone dir and materialize their
//! upstream sources via `makepkg --verifysource`, without ever building or
//! installing anything.

use anyhow::Context;
use aurscan_core::SourceOrigin;
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

/// paru's default clone dir: `$XDG_CACHE_HOME/paru/clone`, else `~/.cache/paru/clone`.
pub fn clone_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("paru/clone")
}

/// Clone `base`'s AUR git repo into paru's clone dir if it isn't there yet,
/// else fast-forward it. Returns the checkout directory.
pub fn sync_pkgbase(base: &str) -> anyhow::Result<PathBuf> {
    let dir = clone_dir().join(base);
    if dir.join(".git").is_dir() {
        run(Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["pull", "--ff-only"]))?;
    } else {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating clone dir {}", parent.display()))?;
        }
        run(Command::new("git")
            .arg("clone")
            .arg(format!("https://aur.archlinux.org/{base}.git"))
            .arg(&dir))?;
    }
    Ok(dir)
}

/// The AUR repo's current remote `HEAD` for `base`, via one `git ls-remote`
/// round-trip -- no clone, no fetch. This is the cheap question the skip
/// path asks before paying for `sync_pkgbase` + `verifysource`. Trusting it
/// is the same assumption as cloning from the same host, so it adds no new
/// exposure; the caller must still never skip unless the recorded verdict
/// was Clean.
pub fn remote_head(base: &str) -> anyhow::Result<String> {
    let output = run_sanitized_git_bounded(
        None,
        &[
            "ls-remote",
            &format!("https://aur.archlinux.org/{base}.git"),
            "HEAD",
        ],
        MAX_SINGLE_GIT_OUTPUT_BYTES,
    )?;
    let out = String::from_utf8(output).context("git ls-remote returned non-UTF-8 output")?;
    out.split_whitespace()
        .next()
        .filter(|sha| valid_object_id(sha))
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("unexpected ls-remote output for {base}: {out:?}"))
}

/// The checkout's current `HEAD` commit, read with repository overrides and
/// ambient Git configuration disabled.
pub fn head_commit(dir: &Path) -> anyhow::Result<String> {
    let canonical = dir
        .canonicalize()
        .with_context(|| format!("cannot canonicalize checkout {}", dir.display()))?;
    let root = SecureRoot::open_canonical(&canonical)?;
    exact_head(&root)
}

const MAX_CHECKOUT_TRACKED_FILES: usize = 4096;
const MAX_CHECKOUT_PATH_BYTES: usize = 2 * 1024 * 1024;
const MAX_CHECKOUT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHECKOUT_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GIT_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_SINGLE_GIT_OUTPUT_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrackedEntry {
    mode: u32,
    object_id: String,
    path: Vec<u8>,
}

/// Whether the checkout is byte-for-byte identical to the authorized commit.
///
/// This does not use `status`, worktree stat caches, clean filters, or external
/// diff drivers. It compares the commit tree with the stage-0 index, rejects
/// index inspection-suppressing flags, then opens and hashes each tracked file
/// relative to one held checkout-root descriptor. Untracked source downloads
/// remain intentionally outside this identity check.
pub fn checkout_matches_clean_head(dir: &Path, expected_head: &str) -> anyhow::Result<bool> {
    if !valid_object_id(expected_head) {
        return Ok(false);
    }
    let canonical = dir
        .canonicalize()
        .with_context(|| format!("cannot canonicalize checkout {}", dir.display()))?;
    let root = SecureRoot::open_canonical(&canonical)?;

    if exact_head(&root)? != expected_head {
        return Ok(false);
    }
    let Some(tree) = read_head_tree(&root, expected_head)? else {
        return Ok(false);
    };
    let Some(raw_index_before) = read_safe_raw_index(&root, expected_head.len() / 2)? else {
        return Ok(false);
    };
    let Some(index_before) = read_stage_zero_index(&root)? else {
        return Ok(false);
    };
    if tree != index_before {
        return Ok(false);
    }
    if !worktree_files_match(&root, &tree)? {
        return Ok(false);
    }

    // Re-read all mutable Git metadata after hashing. This does not mutate or
    // lock the user's index, but it prevents a state changed during inspection
    // from authorizing reuse unless the complete snapshots still agree.
    let Some(index_after) = read_stage_zero_index(&root)? else {
        return Ok(false);
    };
    let Some(raw_index_after) = read_safe_raw_index(&root, expected_head.len() / 2)? else {
        return Ok(false);
    };
    if index_after != index_before || raw_index_after != raw_index_before {
        return Ok(false);
    }
    Ok(exact_head(&root)? == expected_head)
}

fn exact_head(root: &SecureRoot) -> anyhow::Result<String> {
    let output = run_sanitized_git_bounded(
        Some(root),
        &["rev-parse", "--verify", "HEAD^{commit}"],
        MAX_SINGLE_GIT_OUTPUT_BYTES,
    )?;
    let head = std::str::from_utf8(&output)
        .context("git rev-parse returned non-UTF-8 output")?
        .trim();
    if !valid_object_id(head) {
        anyhow::bail!("git rev-parse returned an invalid object ID");
    }
    Ok(head.to_string())
}

fn read_head_tree(
    root: &SecureRoot,
    expected_head: &str,
) -> anyhow::Result<Option<Vec<TrackedEntry>>> {
    let output = run_sanitized_git_bounded(
        Some(root),
        &["ls-tree", "-rz", "--full-tree", expected_head],
        MAX_GIT_METADATA_BYTES,
    )?;
    parse_tree_entries(&output)
}

fn parse_tree_entries(output: &[u8]) -> anyhow::Result<Option<Vec<TrackedEntry>>> {
    let records = nul_records(output)?;
    let mut budget = PathBudget::default();
    let mut entries = Vec::with_capacity(records.len());
    let mut previous = None;
    for record in records {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            anyhow::bail!("malformed git ls-tree record");
        };
        let metadata =
            std::str::from_utf8(&record[..tab]).context("git ls-tree metadata was not UTF-8")?;
        let fields: Vec<&str> = metadata.split(' ').collect();
        if fields.len() != 3 || fields[1] != "blob" || !valid_object_id(fields[2]) {
            return Ok(None);
        }
        let mode = parse_git_mode(fields[0])?;
        if !matches!(mode, 0o100644 | 0o100755) {
            return Ok(None);
        }
        let path = record[tab + 1..].to_vec();
        budget.add(&path)?;
        validate_git_path(&path)?;
        if previous
            .as_ref()
            .is_some_and(|prior: &Vec<u8>| prior >= &path)
        {
            anyhow::bail!("git ls-tree paths were duplicated or out of order");
        }
        previous = Some(path.clone());
        entries.push(TrackedEntry {
            mode,
            object_id: fields[2].to_string(),
            path,
        });
    }
    Ok(Some(entries))
}

fn read_stage_zero_index(root: &SecureRoot) -> anyhow::Result<Option<Vec<TrackedEntry>>> {
    let output = run_sanitized_git_bounded(
        Some(root),
        &["ls-files", "--stage", "-z", "--"],
        MAX_GIT_METADATA_BYTES,
    )?;
    parse_index_entries(&output)
}

fn parse_index_entries(output: &[u8]) -> anyhow::Result<Option<Vec<TrackedEntry>>> {
    let records = nul_records(output)?;
    let mut budget = PathBudget::default();
    let mut entries = Vec::with_capacity(records.len());
    let mut previous = None;
    for record in records {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            anyhow::bail!("malformed git ls-files --stage record");
        };
        let metadata =
            std::str::from_utf8(&record[..tab]).context("git index metadata was not UTF-8")?;
        let fields: Vec<&str> = metadata.split(' ').collect();
        if fields.len() != 3 || fields[2] != "0" || !valid_object_id(fields[1]) {
            return Ok(None);
        }
        let mode = parse_git_mode(fields[0])?;
        if !matches!(mode, 0o100644 | 0o100755) || fields[1].bytes().all(|byte| byte == b'0') {
            return Ok(None);
        }
        let path = record[tab + 1..].to_vec();
        budget.add(&path)?;
        validate_git_path(&path)?;
        if previous
            .as_ref()
            .is_some_and(|prior: &Vec<u8>| prior >= &path)
        {
            anyhow::bail!("git index paths were duplicated or out of order");
        }
        previous = Some(path.clone());
        entries.push(TrackedEntry {
            mode,
            object_id: fields[1].to_string(),
            path,
        });
    }
    Ok(Some(entries))
}

fn read_safe_raw_index(
    root: &SecureRoot,
    object_id_bytes: usize,
) -> anyhow::Result<Option<Vec<u8>>> {
    if !matches!(object_id_bytes, 20 | 32) {
        return Ok(None);
    }
    let mut file = match root.open_regular_file(Path::new(".git/index")) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let metadata = file.metadata()?;
    if metadata.len() > MAX_GIT_METADATA_BYTES as u64 {
        anyhow::bail!("Git index exceeds the inspection byte limit");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_GIT_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_GIT_METADATA_BYTES {
        anyhow::bail!("Git index exceeds the inspection byte limit");
    }
    parse_raw_index_safety(&bytes, object_id_bytes).map(|safe| safe.then_some(bytes))
}

fn parse_raw_index_safety(index: &[u8], object_id_bytes: usize) -> anyhow::Result<bool> {
    const HEADER_BYTES: usize = 12;
    const STAT_BYTES: usize = 40;
    const FLAG_BYTES: usize = 2;
    const CE_NAME_MASK: u16 = 0x0fff;
    const CE_STAGE_MASK: u16 = 0x3000;
    const CE_EXTENDED: u16 = 0x4000;
    const CE_VALID: u16 = 0x8000;

    if index.len() < HEADER_BYTES + object_id_bytes || &index[..4] != b"DIRC" {
        anyhow::bail!("Git index has a malformed header");
    }
    let version = read_be_u32(index, 4)?;
    if !matches!(version, 2 | 3) {
        return Ok(false);
    }
    let entry_count = read_be_u32(index, 8)? as usize;
    if entry_count > MAX_CHECKOUT_TRACKED_FILES {
        anyhow::bail!("Git index exceeds the tracked-file count limit");
    }
    let content_end = index
        .len()
        .checked_sub(object_id_bytes)
        .ok_or_else(|| anyhow::anyhow!("Git index is shorter than its checksum"))?;
    let mut offset = HEADER_BYTES;
    let mut path_budget = PathBudget::default();
    for _ in 0..entry_count {
        let entry_start = offset;
        let flags_offset = offset
            .checked_add(STAT_BYTES + object_id_bytes)
            .ok_or_else(|| anyhow::anyhow!("Git index entry offset overflow"))?;
        let flags = read_be_u16(index, flags_offset)?;
        if flags & (CE_STAGE_MASK | CE_VALID) != 0 {
            return Ok(false);
        }
        offset = flags_offset + FLAG_BYTES;
        if flags & CE_EXTENDED != 0 {
            let extended_flags = read_be_u16(index, offset)?;
            // Every currently persisted extended flag changes index inspection
            // semantics (intent-to-add or skip-worktree). Unknown future flags
            // are rejected rather than guessed safe.
            if extended_flags != 0 {
                return Ok(false);
            }
            offset += 2;
        }
        if offset >= content_end {
            anyhow::bail!("Git index entry is truncated before its path");
        }
        let path_end = index[offset..content_end]
            .iter()
            .position(|byte| *byte == 0)
            .map(|relative| offset + relative)
            .ok_or_else(|| anyhow::anyhow!("Git index entry path is unterminated"))?;
        let path = &index[offset..path_end];
        path_budget.add(path)?;
        validate_git_path(path)?;
        let encoded_name_len = usize::from(flags & CE_NAME_MASK);
        if encoded_name_len != CE_NAME_MASK as usize && encoded_name_len != path.len() {
            anyhow::bail!("Git index entry path length is inconsistent");
        }
        let unpadded_len = path_end
            .checked_add(1)
            .and_then(|end| end.checked_sub(entry_start))
            .ok_or_else(|| anyhow::anyhow!("Git index entry length overflow"))?;
        let padded_len = unpadded_len
            .checked_add(7)
            .map(|length| length & !7)
            .ok_or_else(|| anyhow::anyhow!("Git index entry padding overflow"))?;
        offset = entry_start
            .checked_add(padded_len)
            .ok_or_else(|| anyhow::anyhow!("Git index entry offset overflow"))?;
        if offset > content_end || index[path_end + 1..offset].iter().any(|byte| *byte != 0) {
            anyhow::bail!("Git index entry has malformed padding");
        }
    }

    while offset < content_end {
        if content_end - offset < 8 {
            anyhow::bail!("Git index extension header is truncated");
        }
        let signature = &index[offset..offset + 4];
        let extension_len = read_be_u32(index, offset + 4)? as usize;
        offset = offset
            .checked_add(8)
            .ok_or_else(|| anyhow::anyhow!("Git index extension offset overflow"))?;
        let extension_end = offset
            .checked_add(extension_len)
            .ok_or_else(|| anyhow::anyhow!("Git index extension length overflow"))?;
        if extension_end > content_end {
            anyhow::bail!("Git index extension exceeds the index boundary");
        }
        // TREE is only a derived cache. Reject fsmonitor, untracked-cache,
        // split-index, resolve-undo, sparse-index, and unknown future state.
        if signature != b"TREE" {
            return Ok(false);
        }
        offset = extension_end;
    }
    Ok(offset == content_end)
}

fn read_be_u16(bytes: &[u8], offset: usize) -> anyhow::Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow::anyhow!("Git index field is truncated"))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("Git index field is truncated"))?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn worktree_files_match(root: &SecureRoot, entries: &[TrackedEntry]) -> anyhow::Result<bool> {
    let mut total_bytes = 0u64;
    for entry in entries {
        let path = path_from_git_bytes(&entry.path)?;
        let mut file = match root.open_regular_file(&path) {
            Ok(file) => file,
            Err(_) => return Ok(false),
        };
        let before = file.metadata()?;
        if !descriptor_mode_matches(&before, entry.mode) {
            return Ok(false);
        }
        if before.len() > MAX_CHECKOUT_FILE_BYTES {
            anyhow::bail!("tracked checkout file exceeds the per-file byte limit");
        }

        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(MAX_CHECKOUT_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CHECKOUT_FILE_BYTES {
            anyhow::bail!("tracked checkout file exceeds the per-file byte limit");
        }
        total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("tracked checkout byte count overflow"))?;
        if total_bytes > MAX_CHECKOUT_TOTAL_BYTES {
            anyhow::bail!("tracked checkout exceeds the aggregate byte limit");
        }

        let after = file.metadata()?;
        if !descriptor_metadata_stable(&before, &after, bytes.len() as u64)
            || !descriptor_mode_matches(&after, entry.mode)
        {
            return Ok(false);
        }
        if hash_blob(root, &bytes)? != entry.object_id {
            return Ok(false);
        }
    }
    Ok(true)
}

fn hash_blob(root: &SecureRoot, bytes: &[u8]) -> anyhow::Result<String> {
    let mut command = sanitized_git_command(Some(root));
    command
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = ReapingChild::new(
        command
            .spawn()
            .context("failed to spawn `git hash-object`")?,
    );
    let mut stdin = child
        .take_stdin()
        .ok_or_else(|| anyhow::anyhow!("git hash-object stdin was unavailable"))?;
    stdin
        .write_all(bytes)
        .context("cannot stream tracked file bytes to git hash-object")?;
    drop(stdin);
    let output = collect_child_output(child, MAX_SINGLE_GIT_OUTPUT_BYTES, "git hash-object")?;
    let object_id = std::str::from_utf8(&output)
        .context("git hash-object returned non-UTF-8 output")?
        .trim();
    if !valid_object_id(object_id) {
        anyhow::bail!("git hash-object returned an invalid object ID");
    }
    Ok(object_id.to_string())
}

fn parse_git_mode(mode: &str) -> anyhow::Result<u32> {
    if mode.len() != 6 || !mode.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        anyhow::bail!("Git returned an invalid tracked-file mode");
    }
    u32::from_str_radix(mode, 8).context("Git returned an invalid tracked-file mode")
}

fn valid_object_id(object_id: &str) -> bool {
    matches!(object_id.len(), 40 | 64)
        && object_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn nul_records(output: &[u8]) -> anyhow::Result<Vec<&[u8]>> {
    if output.is_empty() {
        return Ok(Vec::new());
    }
    if output.last() != Some(&0) {
        anyhow::bail!("Git returned an unterminated NUL-delimited record");
    }
    Ok(output[..output.len() - 1]
        .split(|byte| *byte == 0)
        .collect())
}

#[derive(Default)]
struct PathBudget {
    files: usize,
    bytes: usize,
}

impl PathBudget {
    fn add(&mut self, path: &[u8]) -> anyhow::Result<()> {
        self.files = self
            .files
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("tracked-file count overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(path.len())
            .ok_or_else(|| anyhow::anyhow!("tracked path-byte count overflow"))?;
        if self.files > MAX_CHECKOUT_TRACKED_FILES {
            anyhow::bail!("tracked checkout exceeds the file-count limit");
        }
        if self.bytes > MAX_CHECKOUT_PATH_BYTES {
            anyhow::bail!("tracked checkout exceeds the path-byte limit");
        }
        Ok(())
    }
}

fn validate_git_path(path: &[u8]) -> anyhow::Result<()> {
    if path.is_empty()
        || path.starts_with(b"/")
        || path.ends_with(b"/")
        || path
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || matches!(part, b"." | b".."))
    {
        anyhow::bail!("Git returned a path that is not safely relative");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn path_from_git_bytes(path: &[u8]) -> anyhow::Result<PathBuf> {
    validate_git_path(path)?;
    Ok(PathBuf::from(OsString::from_vec(path.to_vec())))
}

#[cfg(not(target_os = "linux"))]
fn path_from_git_bytes(_path: &[u8]) -> anyhow::Result<PathBuf> {
    anyhow::bail!("race-resistant checkout inspection is unavailable on this platform")
}

#[cfg(target_os = "linux")]
fn descriptor_mode_matches(metadata: &std::fs::Metadata, git_mode: u32) -> bool {
    let executable = metadata.mode() & 0o111 != 0;
    executable == (git_mode == 0o100755)
}

#[cfg(not(target_os = "linux"))]
fn descriptor_mode_matches(_metadata: &std::fs::Metadata, _git_mode: u32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn descriptor_metadata_stable(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
    bytes_read: u64,
) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.len() == bytes_read
        && after.len() == bytes_read
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(target_os = "linux"))]
fn descriptor_metadata_stable(
    _before: &std::fs::Metadata,
    _after: &std::fs::Metadata,
    _bytes_read: u64,
) -> bool {
    false
}

#[derive(Debug)]
pub(crate) enum SecureOpenError {
    UnsafeAncestor(std::io::Error),
    Absent,
    FinalSymlink,
    FinalComponent(std::io::Error),
    NotRegular,
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
}

impl std::fmt::Display for SecureOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeAncestor(error) => write!(
                formatter,
                "path has a missing, non-directory, or symlinked ancestor: {error}"
            ),
            Self::Absent => formatter.write_str("final path component is absent"),
            Self::FinalSymlink => formatter.write_str("final path component is a symlink"),
            Self::FinalComponent(error) => {
                write!(formatter, "cannot open final path component: {error}")
            }
            Self::NotRegular => formatter.write_str("final path component is not a regular file"),
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => formatter.write_str(
                "race-resistant path-beneath file opening is unavailable on this platform",
            ),
        }
    }
}

impl std::error::Error for SecureOpenError {}

pub(crate) struct SecureRoot {
    directory: File,
}

impl SecureRoot {
    /// Open an absolute, already-canonical directory one component at a time.
    /// Each component is resolved relative to the previously held descriptor,
    /// with symlink following disabled.
    #[cfg(target_os = "linux")]
    pub(crate) fn open_canonical(root: &Path) -> anyhow::Result<Self> {
        if !root.is_absolute() {
            anyhow::bail!("secure root must be an absolute canonical path");
        }
        let mut directory = OpenOptions::new()
            .read(true)
            .custom_flags(O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK)
            .open("/")
            .context("cannot open filesystem root for secure traversal")?;
        for component in root.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    directory = openat_component(
                        &directory,
                        name,
                        O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK,
                    )
                    .with_context(|| {
                        format!(
                            "cannot securely open root component {}",
                            name.to_string_lossy()
                        )
                    })?;
                }
                _ => anyhow::bail!("secure root contains a non-normal path component"),
            }
        }
        Ok(Self { directory })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open_canonical(_root: &Path) -> anyhow::Result<Self> {
        Err(anyhow::anyhow!(SecureOpenError::UnsupportedPlatform))
    }

    /// Open a regular file beneath this root without following any ancestor or
    /// final-component symlink. `O_NONBLOCK` ensures a special file cannot hang
    /// inspection before descriptor metadata rejects it.
    #[cfg(target_os = "linux")]
    pub(crate) fn open_regular_file(&self, relative: &Path) -> Result<File, SecureOpenError> {
        let components: Vec<&OsStr> = relative
            .components()
            .map(|component| match component {
                Component::Normal(name) => Ok(name),
                _ => Err(SecureOpenError::FinalComponent(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path is not safely relative",
                ))),
            })
            .collect::<Result<_, _>>()?;
        let Some((final_component, ancestors)) = components.split_last() else {
            return Err(SecureOpenError::FinalComponent(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path is empty",
            )));
        };

        let mut directory = self
            .directory
            .try_clone()
            .map_err(SecureOpenError::UnsafeAncestor)?;
        for component in ancestors {
            directory = openat_component(
                &directory,
                component,
                O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK,
            )
            .map_err(SecureOpenError::UnsafeAncestor)?;
        }
        let file = match openat_component(
            &directory,
            final_component,
            O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        ) {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(ENOENT) => {
                return Err(SecureOpenError::Absent)
            }
            Err(error) if error.raw_os_error() == Some(ELOOP) => {
                return Err(SecureOpenError::FinalSymlink)
            }
            Err(error) => return Err(SecureOpenError::FinalComponent(error)),
        };
        match file.metadata() {
            Ok(metadata) if metadata.is_file() => Ok(file),
            Ok(_) => Err(SecureOpenError::NotRegular),
            Err(error) => Err(SecureOpenError::FinalComponent(error)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open_regular_file(&self, _relative: &Path) -> Result<File, SecureOpenError> {
        Err(SecureOpenError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    #[cfg(not(target_os = "linux"))]
    fn proc_path(&self) -> PathBuf {
        PathBuf::new()
    }
}

#[cfg(target_os = "linux")]
const O_CLOEXEC: i32 = 0o2_000_000;
#[cfg(target_os = "linux")]
const O_DIRECTORY: i32 = 0o200_000;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4_000;
#[cfg(target_os = "linux")]
const ENOENT: i32 = 2;
#[cfg(target_os = "linux")]
const ELOOP: i32 = 40;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn openat(directory_fd: i32, path: *const std::ffi::c_char, flags: i32, mode: u32) -> i32;
}

#[cfg(target_os = "linux")]
fn openat_component(directory: &File, component: &OsStr, flags: i32) -> std::io::Result<File> {
    let component = CString::new(component.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains a NUL byte",
        )
    })?;
    // SAFETY: `component` is a live NUL-terminated C string, `directory` owns
    // a valid descriptor for this call, and no creation flag is supplied, so
    // the zero mode argument is ignored by `openat`.
    let descriptor = unsafe { openat(directory.as_raw_fd(), component.as_ptr(), flags, 0) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a nonnegative result from `openat` is a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn sanitized_git_command(root: Option<&SecureRoot>) -> Command {
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .args([
            "-c",
            "color.ui=false",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "diff.external=",
            "-c",
            "protocol.ext.allow=never",
        ]);
    match root {
        Some(root) => {
            command.current_dir(root.proc_path());
        }
        None => {
            // Avoid inheriting the caller's repository-local configuration for
            // non-repository operations such as `ls-remote`.
            command.current_dir("/");
        }
    }
    command
}

fn run_sanitized_git_bounded(
    root: Option<&SecureRoot>,
    arguments: &[&str],
    max_output_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut command = sanitized_git_command(root);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let child = command.spawn().context("failed to spawn sanitized `git`")?;
    collect_child_output(
        ReapingChild::new(child),
        max_output_bytes,
        "sanitized git command",
    )
}

fn collect_child_output(
    mut child: ReapingChild,
    max_output_bytes: usize,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let stdout = child
        .take_stdout()
        .ok_or_else(|| anyhow::anyhow!("{label} stdout was unavailable"))?;
    let read_limit = max_output_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("{label} output limit overflow"))?;
    let mut output = Vec::new();
    stdout
        .take(read_limit as u64)
        .read_to_end(&mut output)
        .with_context(|| format!("cannot read {label} output"))?;
    if output.len() > max_output_bytes {
        anyhow::bail!("{label} exceeded its output limit");
    }
    let status = child
        .wait()
        .with_context(|| format!("cannot reap {label}"))?;
    if !status.success() {
        anyhow::bail!("{label} failed ({status})");
    }
    Ok(output)
}

struct ReapingChild {
    child: Child,
    reaped: bool,
}

impl ReapingChild {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    fn wait(mut self) -> std::io::Result<ExitStatus> {
        let result = self.child.wait();
        self.reaped = result.is_ok();
        result
    }
}

impl Drop for ReapingChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        loop {
            match self.child.wait() {
                Ok(_) => {
                    self.reaped = true;
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }
    }
}

/// Run `makepkg --verifysource --noconfirm` in `dir` (downloads sources,
/// executes nothing), then list the newly-materialized source files: every
/// regular file in `dir` that isn't tracked by git and isn't a build script,
/// paired with a `SourceOrigin` inferred from `.SRCINFO`'s `source =` lines.
pub fn verifysource(dir: &Path) -> anyhow::Result<Vec<(PathBuf, SourceOrigin)>> {
    if which("makepkg").is_none() {
        anyhow::bail!(
            "makepkg not found on PATH; install base-devel to check or install AUR packages"
        );
    }
    run(Command::new("makepkg")
        .args(["--verifysource", "--noconfirm"])
        .current_dir(dir))?;

    let tracked = git_tracked_files(dir)?;
    let origins = srcinfo_origins(dir);

    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if tracked.contains(&name) || is_build_script(&name) {
            continue;
        }
        let origin = origins
            .get(&name)
            .cloned()
            .unwrap_or(SourceOrigin::LocalFile);
        out.push((entry.path(), origin));
    }
    Ok(out)
}

fn git_tracked_files(dir: &Path) -> anyhow::Result<HashSet<String>> {
    let out = run(Command::new("git").arg("-C").arg(dir).args(["ls-files"]))?;
    Ok(out.lines().map(str::to_string).collect())
}

fn is_build_script(name: &str) -> bool {
    name == "PKGBUILD"
        || name == ".SRCINFO"
        || name.ends_with(".install")
        || name.ends_with(".patch")
        || name.ends_with(".diff")
}

/// Map each `.SRCINFO` `source =`/`source_<arch> =` entry's local filename to
/// its inferred origin. Missing/unreadable `.SRCINFO` yields an empty map, so
/// callers fall back to `SourceOrigin::LocalFile`.
fn srcinfo_origins(dir: &Path) -> HashMap<String, SourceOrigin> {
    let Ok(content) = std::fs::read_to_string(dir.join(".SRCINFO")) else {
        return HashMap::new();
    };
    parse_srcinfo_sources(&content)
        .into_iter()
        .map(|raw| (source_filename(&raw), classify_origin(&raw)))
        .collect()
}

/// Extract `source`/`source_<arch>` values from a `.SRCINFO` (one per line;
/// no bash array parsing needed since `.SRCINFO` is already flattened).
fn parse_srcinfo_sources(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once('=')?;
            let key = key.trim();
            (key == "source" || key.starts_with("source_")).then(|| value.trim().to_string())
        })
        .collect()
}

/// A `name::url` source value uses `::` to separate the local filename from
/// the fetch URL; without it, the local name is the URL's last path segment.
fn source_filename(raw_value: &str) -> String {
    if let Some((name, _)) = raw_value.split_once("::") {
        return name.to_string();
    }
    let stripped = raw_value.strip_prefix("git+").unwrap_or(raw_value);
    if !stripped.contains("://") {
        return raw_value.to_string();
    }
    stripped
        .rsplit('/')
        .next()
        .unwrap_or(stripped)
        .split(['?', '#'])
        .next()
        .unwrap_or(stripped)
        .to_string()
}

/// Classify a `.SRCINFO` source value as VCS (`git+`/`hg+`/`svn+`/`bzr+`),
/// a plain URL, or a bare local file bundled alongside the PKGBUILD.
fn classify_origin(raw_value: &str) -> SourceOrigin {
    let url = match raw_value.split_once("::") {
        Some((_, url)) => url,
        None => raw_value,
    };
    if ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|p| url.starts_with(p))
    {
        SourceOrigin::Vcs(url.to_string())
    } else if url.contains("://") {
        SourceOrigin::Url(url.to_string())
    } else {
        SourceOrigin::LocalFile
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).find_map(|dir| {
        let candidate = dir.join(bin);
        candidate.is_file().then_some(candidate)
    })
}

/// Run a command, bubbling its stderr into the error on non-zero exit.
fn run(cmd: &mut Command) -> anyhow::Result<String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let output = cmd
        .output()
        .with_context(|| format!("failed to spawn `{program}`"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`{program}` failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_filename_uses_name_before_double_colon() {
        assert_eq!(
            source_filename("foo.tar.gz::https://example.com/dl?x=1"),
            "foo.tar.gz"
        );
    }

    #[test]
    fn source_filename_falls_back_to_url_basename() {
        assert_eq!(
            source_filename("https://example.com/dist/foo-1.0.tar.gz"),
            "foo-1.0.tar.gz"
        );
    }

    #[test]
    fn source_filename_strips_query_string() {
        assert_eq!(
            source_filename("https://example.com/foo.tar.gz?token=abc"),
            "foo.tar.gz"
        );
    }

    #[test]
    fn source_filename_bare_value_is_itself() {
        assert_eq!(source_filename("local-patch.diff"), "local-patch.diff");
    }

    #[test]
    fn classify_origin_detects_git_plus() {
        assert!(matches!(
            classify_origin("git+https://github.com/o/r.git#tag=v1"),
            SourceOrigin::Vcs(_)
        ));
    }

    #[test]
    fn classify_origin_detects_named_vcs_source() {
        assert!(matches!(
            classify_origin("repo::git+https://github.com/o/r.git"),
            SourceOrigin::Vcs(_)
        ));
    }

    #[test]
    fn classify_origin_detects_plain_url() {
        assert!(matches!(
            classify_origin("https://example.com/foo.tar.gz"),
            SourceOrigin::Url(_)
        ));
    }

    #[test]
    fn classify_origin_bare_value_is_local() {
        assert!(matches!(
            classify_origin("local-patch.diff"),
            SourceOrigin::LocalFile
        ));
    }

    #[test]
    fn parse_srcinfo_sources_collects_arch_specific_entries() {
        let content = "pkgbase = x\n\tsource = https://example.com/a.tar.gz\n\tsource_x86_64 = https://example.com/b.tar.gz\n\tdepends = glibc\n";
        let sources = parse_srcinfo_sources(content);
        assert_eq!(
            sources,
            vec![
                "https://example.com/a.tar.gz".to_string(),
                "https://example.com/b.tar.gz".to_string()
            ]
        );
    }

    #[test]
    fn is_build_script_recognizes_all_kinds() {
        assert!(is_build_script("PKGBUILD"));
        assert!(is_build_script(".SRCINFO"));
        assert!(is_build_script("foo.install"));
        assert!(is_build_script("fix.patch"));
        assert!(is_build_script("fix.diff"));
        assert!(!is_build_script("upstream-1.0.tar.gz"));
    }

    #[test]
    fn which_finds_a_binary_known_to_exist_on_path() {
        // `sh` is POSIX-guaranteed and present on every CI/dev box this
        // workspace targets.
        assert!(which("sh").is_some());
    }

    #[test]
    fn which_returns_none_for_a_bogus_binary() {
        assert!(which("definitely-not-a-real-binary-xyz").is_none());
    }

    fn committed_checkout() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        run(Command::new("git").arg("init").arg(dir.path())).unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=demo\n").unwrap();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "-c",
            "user.name=aurscan test",
            "-c",
            "user.email=aurscan@example.invalid",
            "add",
            "PKGBUILD",
        ]))
        .unwrap();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "-c",
            "user.name=aurscan test",
            "-c",
            "user.email=aurscan@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "-m",
            "initial",
        ]))
        .unwrap();
        let head = head_commit(dir.path()).unwrap();
        (dir, head)
    }

    #[test]
    fn checkout_state_accepts_a_matching_clean_head() {
        let (dir, head) = committed_checkout();
        assert!(checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[test]
    fn checkout_state_rejects_a_mismatched_head() {
        let (dir, _) = committed_checkout();
        assert!(!checkout_matches_clean_head(dir.path(), "0".repeat(40).as_str()).unwrap());
    }

    #[test]
    fn checkout_state_rejects_a_staged_tracked_modification() {
        let (dir, head) = committed_checkout();
        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=changed\n").unwrap();
        run(Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["add", "PKGBUILD"]))
        .unwrap();
        assert!(!checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[test]
    fn checkout_state_rejects_an_unstaged_tracked_modification() {
        let (dir, head) = committed_checkout();
        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=changed\n").unwrap();
        assert!(!checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[test]
    fn checkout_state_rejects_assume_unchanged_index_entries() {
        let (dir, head) = committed_checkout();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "update-index",
            "--assume-unchanged",
            "PKGBUILD",
        ]))
        .unwrap();

        assert!(!checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[test]
    fn checkout_state_rejects_skip_worktree_index_entries() {
        let (dir, head) = committed_checkout();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "update-index",
            "--skip-worktree",
            "PKGBUILD",
        ]))
        .unwrap();

        assert!(!checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[test]
    fn checkout_state_rejects_fsmonitor_valid_index_entries() {
        let (dir, head) = committed_checkout();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "config",
            "core.fsmonitor",
            "true",
        ]))
        .unwrap();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "update-index",
            "--fsmonitor-valid",
            "PKGBUILD",
        ]))
        .unwrap();

        assert!(!checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn checkout_state_rejects_an_executable_bit_change() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, head) = committed_checkout();
        let path = dir.path().join("PKGBUILD");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(!checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn checkout_state_rejects_tracked_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        run(Command::new("git").arg("init").arg(dir.path())).unwrap();
        symlink("elsewhere", dir.path().join("PKGBUILD")).unwrap();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "-c",
            "user.name=aurscan test",
            "-c",
            "user.email=aurscan@example.invalid",
            "add",
            "PKGBUILD",
        ]))
        .unwrap();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "-c",
            "user.name=aurscan test",
            "-c",
            "user.email=aurscan@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "-m",
            "symlink",
        ]))
        .unwrap();
        let head = head_commit(dir.path()).unwrap();

        assert!(!checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[test]
    fn checkout_state_rejects_unmerged_index_entries() {
        let (dir, head) = committed_checkout();
        let blob = run(Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["rev-parse", "HEAD:PKGBUILD"]))
        .unwrap();
        let blob = blob.trim();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "update-index",
            "--force-remove",
            "PKGBUILD",
        ]))
        .unwrap();
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(dir.path())
            .args(["update-index", "--index-info"])
            .stdin(Stdio::piped());
        let mut child = command.spawn().unwrap();
        write!(
            child.stdin.take().unwrap(),
            "100644 {blob} 1\tPKGBUILD\n100644 {blob} 2\tPKGBUILD\n"
        )
        .unwrap();
        assert!(child.wait().unwrap().success());

        assert!(!checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[test]
    fn checkout_state_rejects_tracked_gitlinks() {
        let (dir, first_head) = committed_checkout();
        let cache_info = format!("160000,{first_head},vendor");
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "update-index",
            "--add",
            "--cacheinfo",
            &cache_info,
        ]))
        .unwrap();
        run(Command::new("git").arg("-C").arg(dir.path()).args([
            "-c",
            "user.name=aurscan test",
            "-c",
            "user.email=aurscan@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "-m",
            "gitlink",
        ]))
        .unwrap();
        let head = head_commit(dir.path()).unwrap();

        assert!(!checkout_matches_clean_head(dir.path(), &head).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checkout_state_ignores_ambient_repository_overrides() {
        let (dir, head) = committed_checkout();
        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=changed\n").unwrap();
        let alternate_worktree = tempfile::tempdir().unwrap();
        std::fs::write(alternate_worktree.path().join("PKGBUILD"), "pkgname=demo\n").unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fetch::tests::ambient_repository_overrides_child",
            ])
            .env("AURSCAN_TEST_CHECKOUT", dir.path())
            .env("AURSCAN_TEST_EXPECTED_HEAD", &head)
            .env("GIT_DIR", dir.path().join(".git"))
            .env("GIT_WORK_TREE", alternate_worktree.path())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn ambient_repository_overrides_child() {
        let Some(dir) = std::env::var_os("AURSCAN_TEST_CHECKOUT") else {
            return;
        };
        let head = std::env::var("AURSCAN_TEST_EXPECTED_HEAD").unwrap();
        assert!(!checkout_matches_clean_head(Path::new(&dir), &head).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checkout_state_does_not_invoke_configured_fsmonitor_diff_or_filter_programs() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, head) = committed_checkout();
        let marker = dir.path().join("ambient-program-ran");
        let program = dir.path().join("ambient-program");
        std::fs::write(
            &program,
            format!("#!/bin/sh\n: > '{}'\nexit 1\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            dir.path().join(".gitattributes"),
            "PKGBUILD diff=ambient filter=ambient\n",
        )
        .unwrap();
        for (key, value) in [
            ("core.fsmonitor", program.to_string_lossy().into_owned()),
            ("diff.external", program.to_string_lossy().into_owned()),
            (
                "filter.ambient.clean",
                program.to_string_lossy().into_owned(),
            ),
        ] {
            run(Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(["config", key, &value]))
            .unwrap();
        }

        assert!(checkout_matches_clean_head(dir.path(), &head).unwrap());
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secure_open_rejects_symlinked_ancestors_and_final_components() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/file"), b"content").unwrap();
        symlink("real", dir.path().join("linked")).unwrap();
        symlink("real/file", dir.path().join("final")).unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        let root = SecureRoot::open_canonical(&canonical).unwrap();

        assert!(matches!(
            root.open_regular_file(Path::new("linked/file")),
            Err(SecureOpenError::UnsafeAncestor(_))
        ));
        assert!(matches!(
            root.open_regular_file(Path::new("final")),
            Err(SecureOpenError::FinalSymlink)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secure_open_descriptor_survives_a_final_path_swap() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("metadata"), b"original").unwrap();
        std::fs::write(dir.path().join("replacement"), b"replacement").unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        let root = SecureRoot::open_canonical(&canonical).unwrap();
        let mut opened = root.open_regular_file(Path::new("metadata")).unwrap();

        std::fs::rename(dir.path().join("metadata"), dir.path().join("old-metadata")).unwrap();
        symlink("replacement", dir.path().join("metadata")).unwrap();
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secure_open_distinguishes_absent_files_and_rejects_special_files() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let _socket = UnixListener::bind(dir.path().join("special")).unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        let root = SecureRoot::open_canonical(&canonical).unwrap();

        assert!(matches!(
            root.open_regular_file(Path::new("missing")),
            Err(SecureOpenError::Absent)
        ));
        assert!(root.open_regular_file(Path::new("special")).is_err());
    }
}
