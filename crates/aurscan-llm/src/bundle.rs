use crate::types::{
    BundleCoverage, BundleLimits, CoverageMode, RecipeBundle, RecipeBundleBuilder, RecipeFile,
};
use anyhow::{anyhow, bail, Context};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Component, Path};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
static GIT_SPAWN_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "linux")]
use std::ffi::{CString, OsStr};
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultRecipeBundleBuilder;

impl RecipeBundleBuilder for DefaultRecipeBundleBuilder {
    fn build(
        &self,
        root: &Path,
        pkgbase: &str,
        limits: BundleLimits,
    ) -> anyhow::Result<RecipeBundle> {
        let root = root
            .canonicalize()
            .with_context(|| format!("cannot resolve recipe root {}", root.display()))?;
        if !root.is_dir() {
            bail!("recipe root is not a directory: {}", root.display());
        }

        let root_directory = open_root_directory(&root)?;
        let git_backed = root.join(".git").exists();
        let paths = if git_backed {
            git_tracked_paths(&root, limits)?
        } else {
            conservative_paths(&root, limits)?
        };
        let mut excluded_binary_files = Vec::new();
        let mut excluded_symlinks = Vec::new();
        let mut files = Vec::new();
        let mut total_bytes = 0usize;

        for normalized in paths {
            let mut opened = match open_file_beneath(&root_directory, &normalized) {
                Ok(file) => file,
                Err(SecureOpenError::FinalSymlink) => {
                    excluded_symlinks.push(normalized);
                    continue;
                }
                Err(error) => {
                    return Err(anyhow!(
                        "cannot securely open recipe file {normalized}: {error}"
                    ));
                }
            };
            let metadata = opened
                .metadata()
                .with_context(|| format!("cannot inspect opened recipe file {normalized}"))?;
            if !metadata.is_file() {
                bail!("eligible recipe path is not a regular file: {normalized}");
            }
            if metadata.len() > limits.max_file_bytes as u64 {
                bail!(
                    "per-file byte limit exceeded by {normalized}: {} > {}",
                    metadata.len(),
                    limits.max_file_bytes
                );
            }

            let projected_bytes = total_bytes
                .checked_add(metadata.len() as usize)
                .ok_or_else(|| anyhow!("aggregate bundle byte count overflow"))?;
            if projected_bytes > limits.max_bundle_bytes {
                bail!(
                    "aggregate bundle byte limit exceeded: {projected_bytes} > {}",
                    limits.max_bundle_bytes
                );
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
            opened
                .by_ref()
                .take(limits.max_file_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .with_context(|| format!("cannot read recipe file {normalized}"))?;
            if bytes.len() > limits.max_file_bytes {
                bail!(
                    "per-file byte limit exceeded by {normalized}: {} > {}",
                    bytes.len(),
                    limits.max_file_bytes
                );
            }
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| anyhow!("aggregate bundle byte count overflow"))?;
            if total_bytes > limits.max_bundle_bytes {
                bail!(
                    "aggregate bundle byte limit exceeded: {total_bytes} > {}",
                    limits.max_bundle_bytes
                );
            }
            if bytes.contains(&0) {
                excluded_binary_files.push(normalized);
                continue;
            }
            let Ok(content) = String::from_utf8(bytes) else {
                excluded_binary_files.push(normalized);
                continue;
            };

            files.push(RecipeFile {
                path: normalized,
                content,
            });
        }

        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        excluded_binary_files.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        excluded_symlinks.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if !files.iter().any(|file| file.path == "PKGBUILD") {
            bail!("required regular UTF-8 PKGBUILD is missing");
        }

        let mut hasher = blake3::Hasher::new();
        for file in &files {
            let path_bytes = file.path.as_bytes();
            let content_bytes = file.content.as_bytes();
            hasher.update(&(path_bytes.len() as u64).to_le_bytes());
            hasher.update(path_bytes);
            hasher.update(&(content_bytes.len() as u64).to_le_bytes());
            hasher.update(content_bytes);
        }

        let coverage = BundleCoverage {
            mode: if git_backed {
                CoverageMode::GitTracked
            } else {
                CoverageMode::ConservativeLocal
            },
            included_files: files.len(),
            excluded_binary_files,
            excluded_symlinks,
        };

        Ok(RecipeBundle {
            pkgbase: pkgbase.to_owned(),
            aur_commit: git_backed.then(|| git_head(&root)).flatten(),
            content_hash: *hasher.finalize().as_bytes(),
            files,
            coverage,
        })
    }
}

const PROCESS_MAX_CANDIDATES: usize = 256;
const PROCESS_MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
const PROCESS_MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
const PROCESS_MAX_PATH_BYTES: usize = 2 * 1024 * 1024;
const PROCESS_MAX_DISCOVERED_ENTRIES: usize = 4096;
const PROCESS_MAX_DISCOVERY_PATH_BYTES: usize = 8 * 1024 * 1024;

struct CollectionBudget {
    max_candidates: usize,
    max_selected_path_bytes: usize,
    candidates: usize,
    selected_path_bytes: usize,
    discovered_entries: usize,
    discovery_path_bytes: usize,
}

impl CollectionBudget {
    fn new(limits: BundleLimits) -> anyhow::Result<Self> {
        if limits.max_files > PROCESS_MAX_CANDIDATES {
            bail!("file count limit exceeds process maximum {PROCESS_MAX_CANDIDATES}");
        }
        if limits.max_file_bytes > PROCESS_MAX_FILE_BYTES {
            bail!("per-file limit exceeds process maximum {PROCESS_MAX_FILE_BYTES}");
        }
        if limits.max_bundle_bytes > PROCESS_MAX_BUNDLE_BYTES {
            bail!("bundle limit exceeds process maximum {PROCESS_MAX_BUNDLE_BYTES}");
        }
        Ok(Self {
            max_candidates: limits.max_files,
            max_selected_path_bytes: PROCESS_MAX_DISCOVERY_PATH_BYTES,
            candidates: 0,
            selected_path_bytes: 0,
            discovered_entries: 0,
            discovery_path_bytes: 0,
        })
    }

    fn discover(&mut self, path_bytes: usize) -> anyhow::Result<()> {
        if path_bytes > PROCESS_MAX_PATH_BYTES {
            bail!("recipe path exceeds process path-byte limit");
        }
        self.discovered_entries += 1;
        self.discovery_path_bytes = self
            .discovery_path_bytes
            .checked_add(path_bytes)
            .ok_or_else(|| anyhow!("discovery path-byte count overflow"))?;
        if self.discovered_entries > PROCESS_MAX_DISCOVERED_ENTRIES
            || self.discovery_path_bytes > PROCESS_MAX_DISCOVERY_PATH_BYTES
        {
            bail!("recipe discovery exceeds process-safety limits");
        }
        Ok(())
    }

    fn select(&mut self, path_bytes: usize) -> anyhow::Result<()> {
        self.candidates += 1;
        self.selected_path_bytes = self
            .selected_path_bytes
            .checked_add(path_bytes)
            .ok_or_else(|| anyhow!("selected path-byte count overflow"))?;
        if self.candidates > self.max_candidates {
            bail!(
                "file count limit exceeded: more than {}",
                self.max_candidates
            );
        }
        if self.selected_path_bytes > self.max_selected_path_bytes {
            bail!("selected recipe paths exceed aggregate path-byte limit");
        }
        Ok(())
    }
}

fn git_tracked_paths(root: &Path, limits: BundleLimits) -> anyhow::Result<Vec<String>> {
    let mut budget = CollectionBudget::new(limits)?;
    let mut child =
        ReapingChild::new(spawn_git_ls_files(root).context("failed to run git ls-files")?);
    let stdout = child
        .take_stdout()
        .ok_or_else(|| anyhow!("git ls-files stdout was unavailable"))?;
    let mut reader = BufReader::new(stdout);
    let mut raw = Vec::new();
    let mut paths = Vec::new();
    let collected = (|| -> anyhow::Result<()> {
        while read_bounded_nul_record(&mut reader, &mut raw)? {
            if raw.is_empty() {
                continue;
            }
            budget.discover(raw.len())?;
            let path = std::str::from_utf8(&raw)
                .map_err(|_| anyhow!("tracked recipe path is not valid UTF-8"))?;
            let normalized = normalize_relative_path(path)?;
            if is_srcinfo(&normalized) {
                continue;
            }
            budget.select(normalized.len())?;
            paths.push(normalized);
        }
        Ok(())
    })();
    collected?;
    if !child.wait()?.success() {
        bail!("git ls-files failed for recipe root");
    }
    Ok(paths)
}

fn read_bounded_nul_record(
    reader: &mut impl BufRead,
    record: &mut Vec<u8>,
) -> anyhow::Result<bool> {
    record.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(!record.is_empty());
        }
        let delimiter = available.iter().position(|byte| *byte == 0);
        let take = delimiter.unwrap_or(available.len());
        if record.len() + take > PROCESS_MAX_PATH_BYTES {
            bail!("tracked recipe path exceeds process path-byte limit");
        }
        record.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(delimiter.is_some()));
        if delimiter.is_some() {
            return Ok(true);
        }
    }
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

    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    fn wait(mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait();
        self.reaped = status.is_ok();
        status
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

fn spawn_git_ls_files(root: &Path) -> std::io::Result<Child> {
    #[cfg(test)]
    GIT_SPAWN_ATTEMPTS.fetch_add(1, Ordering::SeqCst);

    sanitized_git_command(root)
        .args(["ls-files", "-z", "--"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

fn sanitized_git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
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
            "-C",
        ])
        .arg(root);
    command
}

fn git_head(root: &Path) -> Option<String> {
    let output = sanitized_git_command(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    (!commit.is_empty()).then(|| commit.to_owned())
}

fn conservative_paths(root: &Path, limits: BundleLimits) -> anyhow::Result<Vec<String>> {
    fn visit(
        root: &Path,
        directory: &Path,
        paths: &mut Vec<String>,
        budget: &mut CollectionBudget,
    ) -> anyhow::Result<()> {
        for entry in fs::read_dir(directory)
            .with_context(|| format!("cannot read recipe directory {}", directory.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| anyhow!("recipe path escaped its root"))?;
            let normalized = normalize_path(relative)?;
            budget.discover(normalized.len())?;
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                visit(root, &path, paths, budget)?;
                continue;
            }
            if is_conservative_candidate(&normalized) {
                budget.select(normalized.len())?;
                paths.push(normalized);
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    let mut budget = CollectionBudget::new(limits)?;
    visit(root, root, &mut paths, &mut budget)?;
    Ok(paths)
}

fn is_srcinfo(path: &str) -> bool {
    path.rsplit('/').next() == Some(".SRCINFO")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_process_limits_do_not_start_git() {
        GIT_SPAWN_ATTEMPTS.store(0, Ordering::SeqCst);
        let result = git_tracked_paths(
            Path::new("."),
            BundleLimits {
                max_files: PROCESS_MAX_CANDIDATES + 1,
                max_file_bytes: 1,
                max_bundle_bytes: 1,
            },
        );

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("file count limit exceeds process maximum"));
        assert_eq!(GIT_SPAWN_ATTEMPTS.load(Ordering::SeqCst), 0);
    }
}

fn is_conservative_candidate(path: &str) -> bool {
    path == "PKGBUILD"
        || path.ends_with(".install")
        || path.ends_with(".patch")
        || path.ends_with(".diff")
}

fn normalize_relative_path(path: &str) -> anyhow::Result<String> {
    if path.contains('\\') {
        bail!("recipe path is not normalized: {path}");
    }
    normalize_path(Path::new(path))
}

fn normalize_path(path: &Path) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| anyhow!("recipe path is not valid UTF-8"))?,
            ),
            _ => bail!("recipe path escapes its root or is not normalized"),
        }
    }
    if parts.is_empty() {
        bail!("empty recipe path");
    }
    Ok(parts.join("/"))
}

#[derive(Debug)]
enum SecureOpenError {
    UnsafeAncestor(std::io::Error),
    FinalSymlink,
    FinalComponent(std::io::Error),
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
            Self::FinalSymlink => formatter.write_str("final path component is a symlink"),
            Self::FinalComponent(error) => {
                write!(formatter, "cannot open final path component: {error}")
            }
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => formatter.write_str(
                "race-resistant path-beneath file opening is unavailable on this platform",
            ),
        }
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
const ELOOP: i32 = 40;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn openat(directory_fd: i32, path: *const std::ffi::c_char, flags: i32, mode: u32) -> i32;
}

#[cfg(target_os = "linux")]
fn open_root_directory(root: &Path) -> anyhow::Result<File> {
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW)
        .open("/")
        .context("cannot open filesystem root for path-beneath traversal")?;
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
                        "cannot securely open recipe-root component {}",
                        name.to_string_lossy()
                    )
                })?;
            }
            _ => bail!("canonical recipe root contains a non-normal path component"),
        }
    }
    Ok(directory)
}

#[cfg(not(target_os = "linux"))]
fn open_root_directory(_root: &Path) -> anyhow::Result<std::fs::File> {
    Err(anyhow!(SecureOpenError::UnsupportedPlatform))
}

#[cfg(target_os = "linux")]
fn open_file_beneath(root: &File, normalized: &str) -> Result<File, SecureOpenError> {
    let mut components = normalized.split('/').peekable();
    let Some(first) = components.next() else {
        return Err(SecureOpenError::FinalComponent(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty path",
        )));
    };
    let mut directory = root.try_clone().map_err(SecureOpenError::UnsafeAncestor)?;
    let mut component = first;

    loop {
        if components.peek().is_none() {
            return match openat_component(
                &directory,
                OsStr::new(component),
                O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
            ) {
                Ok(file) => Ok(file),
                Err(error) if error.raw_os_error() == Some(ELOOP) => {
                    Err(SecureOpenError::FinalSymlink)
                }
                Err(error) => Err(SecureOpenError::FinalComponent(error)),
            };
        }

        directory = openat_component(
            &directory,
            OsStr::new(component),
            O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK,
        )
        .map_err(SecureOpenError::UnsafeAncestor)?;
        component = components.next().expect("peek proved a component exists");
    }
}

#[cfg(not(target_os = "linux"))]
fn open_file_beneath(
    _root: &std::fs::File,
    _normalized: &str,
) -> Result<std::fs::File, SecureOpenError> {
    Err(SecureOpenError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn openat_component(directory: &File, component: &OsStr, flags: i32) -> std::io::Result<File> {
    let component = CString::new(component.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains a NUL byte",
        )
    })?;
    // SAFETY: `component` is a live NUL-terminated C string, `directory` owns a
    // valid descriptor for the duration of the call, and no creation flag is
    // supplied, so the zero mode argument is ignored by `openat`.
    let descriptor = unsafe { openat(directory.as_raw_fd(), component.as_ptr(), flags, 0) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a nonnegative result from `openat` is a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}
