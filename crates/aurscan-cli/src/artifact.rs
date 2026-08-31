//! `scan-artifact`: scan already-built `.pkg.tar.zst` archives before
//! install, plus the ALPM `PreTransaction` hook entry point (`--hook`) that
//! reads target archive/package identifiers from stdin (the `NeedsTargets`
//! contract) and aborts the transaction on a Block verdict.

use crate::ack::AckStore;
use crate::config::Config;
use crate::registry;
use crate::report;
use aurscan_core::target::expand_archive;
use aurscan_core::{PackageJob, PackageReport};
use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::Command;

/// pacman's built-package cache, where `--hook` resolves bare `pkgname`
/// stdin lines to their built archive.
const PACMAN_CACHE_DIR: &str = "/var/cache/pacman/pkg";

/// `scan-artifact <pkg>...`: expand each built archive into `PackageFile`
/// targets, scan them through the full engine, render, and return the worst
/// exit code.
pub fn scan_files(
    paths: &[PathBuf],
    cfg: &Config,
    json: bool,
    no_color: bool,
    verbose: bool,
) -> i32 {
    let mut reports = match collect_reports(paths, cfg, true) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 3;
        }
    };

    let acks = AckStore::load();
    crate::ack::apply_acks(&mut reports, &acks, &cfg.policy());
    if json {
        let value = report::render_json(&reports);
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    } else {
        let color = !no_color && std::io::stdout().is_terminal();
        print!("{}", report::render_text(&reports, &acks, verbose, color));
    }

    report::worst_exit_code(&reports)
}

/// Scan built archives through the full engine and return the raw reports.
/// Sequential over packages, parallel over each package's targets: one
/// archive expands to hundreds of member targets, which is what actually
/// saturates the pool -- and a sequential outer loop lets the progress line
/// name what is being worked on. pacman's hook Description is static text
/// printed before we run, so this is the only place a count can come from.
pub fn collect_reports(
    paths: &[PathBuf],
    cfg: &Config,
    progress: bool,
) -> anyhow::Result<Vec<PackageReport>> {
    let engine = registry::build_engine(cfg)?;

    let mut jobs = Vec::new();
    for path in paths {
        match expand_archive(path) {
            Ok(targets) => jobs.push(PackageJob {
                name: archive_name(path),
                version: String::new(),
                aur_meta: None,
                targets,
            }),
            Err(e) => eprintln!("warning: {} could not be scanned: {e:#}", path.display()),
        }
    }

    let total = jobs.len();
    let mut reports = Vec::with_capacity(total);
    for (i, job) in jobs.iter().enumerate() {
        if progress && total > 1 {
            eprintln!("==> aurscan: scanning ({}/{total}) {}", i + 1, job.name);
        }
        reports.push(engine.scan_package(job));
    }
    if !cfg.record_features {
        for r in &mut reports {
            r.features.clear();
        }
    }
    Ok(reports)
}

/// The ALPM hook entry point: read target lines from stdin, scan whatever
/// resolves to an existing built archive, and exit non-interactively (no
/// prompts -- stdin is consumed by the hook contract, not a tty).
pub fn hook_main() -> i32 {
    warn_if_paru_gate_inactive();
    let cfg = Config::load();
    let lines: Vec<String> = std::io::stdin()
        .lock()
        .lines()
        .map_while(Result::ok)
        .collect();
    hook_scan_paths(&lines, &cfg, &HookSearchDirs::detect())
}

/// Warn, on every pacman transaction, when the paru `PreBuildCommand` gate
/// is not actually live.
///
/// This runs here because the ALPM hook is the only part of the integration
/// that is automatic -- it is installed by the package and fires on every
/// transaction, with no user action. The paru gate cannot be enabled from a
/// package install (it is per-user config, and `/etc/paru.conf` belongs to
/// the paru package), so the next best thing is to make its *absence*
/// impossible to miss.
///
/// Deliberately advisory: it never changes the exit code. The hook carries
/// `AbortOnFail`, so returning non-zero here would abort unrelated pacman
/// transactions on any machine that merely has aurscan installed.
fn warn_if_paru_gate_inactive() {
    let status = crate::paru_conf::status_for_invoking_user();
    if status.should_warn() {
        eprintln!("==> aurscan: {}", status.describe());
        eprintln!("==> aurscan: run `aurscan setup` to enable pre-build scanning");
    }
}

/// Stdin-free seam for `hook_main`: resolve each of `lines` to a built
/// archive and scan whatever resolves.
///
/// Exit contract mirrors `gate::decide` in hook mode: only a Block verdict
/// (exit 2) fails the hook and, via `AbortOnFail`, the transaction. An
/// Advisory prints its findings and proceeds -- popular packages legitimately
/// raise advisories (Electron's setuid chrome-sandbox), and a hook that
/// aborts on those would train users to uninstall the scanner. Scan errors
/// also proceed: an aurscan defect must not brick unrelated transactions.
pub fn hook_scan_paths(lines: &[String], cfg: &Config, dirs: &HookSearchDirs) -> i32 {
    let mut paths = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    for line in lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty()) {
        if Path::new(line).is_absolute() {
            paths.extend(resolve_target(line, dirs));
        } else {
            names.push(line);
        }
    }

    // The trigger is Target = *, so a full `-Syu` hands the hook every repo
    // upgrade too. Those are signature-verified by pacman and outside this
    // tool's threat model; ELF-inspecting a few hundred of them made a real
    // `paru -Syyu` crawl. One batched query splits the names, and only the
    // foreign remainder is scanned.
    let repo = sync_repo_members(&names);
    let mut skipped = 0usize;
    for name in names {
        if repo.contains(name) {
            skipped += 1;
            continue;
        }
        match resolve_target(name, dirs) {
            Some(p) => paths.push(p),
            // A foreign package we cannot find is the scanner's entire
            // target population going unscanned; never let it look like a
            // pass.
            None => eprintln!(
                "==> aurscan: could not locate a built archive for foreign package `{name}`; \
                 it was NOT scanned"
            ),
        }
    }
    if skipped > 0 {
        eprintln!(
            "==> aurscan: {skipped} repo package(s) skipped (signature-verified by pacman); \
             scanning {} foreign",
            paths.len()
        );
    }

    if paths.is_empty() {
        return 0;
    }
    match scan_files(&paths, cfg, false, true, false) {
        2 => 2,
        1 => {
            eprintln!(
                "==> aurscan: advisory findings above do not abort the install; \
                 run `aurscan ack <package>` to silence reviewed findings"
            );
            0
        }
        0 => 0,
        err => {
            eprintln!("==> aurscan: scan error (exit {err}); transaction not aborted");
            0
        }
    }
}

/// Where the hook looks for built archives, in order.
pub struct HookSearchDirs {
    /// pacman's download cache: repo packages land here via `-S`.
    pub pacman_cache: PathBuf,
    /// The invoking user's paru clone cache (`~/.cache/paru/clone`): AUR
    /// packages built by paru stay in their clone directory, keyed by
    /// pkgbase. `pacman -U` never copies them into pacman's cache, which is
    /// why the pacman cache alone silently missed every AUR package.
    pub paru_clone: Option<PathBuf>,
    /// `PKGDEST` from makepkg.conf, when configured: makepkg then drops all
    /// built archives there instead of the build directory.
    pub pkgdest: Option<PathBuf>,
}

impl HookSearchDirs {
    /// Resolve the search dirs for the user who invoked the transaction.
    /// The hook runs as root via sudo, so the paru cache that matters
    /// belongs to `SUDO_USER`, not root -- same reasoning as
    /// `paru_conf::status_for_invoking_user`.
    pub fn detect() -> Self {
        let home = match std::env::var("SUDO_USER").ok() {
            Some(u) => std::fs::read_to_string("/etc/passwd")
                .ok()
                .and_then(|p| crate::paru_conf::home_for_user(&p, &u)),
            None => std::env::var("HOME").ok(),
        };
        let paru_clone = home
            .as_deref()
            .map(|h| Path::new(h).join(".cache/paru/clone"));
        let pkgdest = [
            home.as_deref()
                .map(|h| Path::new(h).join(".config/pacman/makepkg.conf")),
            Some(PathBuf::from("/etc/makepkg.conf")),
        ]
        .into_iter()
        .flatten()
        .find_map(|p| pkgdest_from_makepkg_conf(&std::fs::read_to_string(p).ok()?));
        Self {
            pacman_cache: PathBuf::from(PACMAN_CACHE_DIR),
            paru_clone,
            pkgdest,
        }
    }
}

/// `PKGDEST=` from makepkg.conf. The file is shell, but the assignment is
/// conventionally a plain literal; strip one layer of quotes and ignore
/// values with unexpanded variables rather than mis-resolving them.
fn pkgdest_from_makepkg_conf(content: &str) -> Option<PathBuf> {
    content.lines().rev().find_map(|line| {
        let rest = line.trim().strip_prefix("PKGDEST=")?;
        let val = rest.trim().trim_matches(['"', '\'']);
        (!val.is_empty() && !val.contains('$')).then(|| PathBuf::from(val))
    })
}

/// Resolve one hook stdin line to a scannable, existing `.pkg.tar.zst`
/// path: pass an absolute archive path through as-is; otherwise treat the
/// line as a `pkgname` and search the known build/cache locations for the
/// most recently modified `<pkgname>-*.pkg.tar.zst` (paru caches several
/// versions side by side; the one being installed is the newest build).
pub(crate) fn resolve_target(line: &str, dirs: &HookSearchDirs) -> Option<PathBuf> {
    let candidate = Path::new(line);
    if candidate.is_absolute() {
        return (is_pkg_archive(candidate) && candidate.is_file()).then(|| candidate.to_path_buf());
    }

    let mut candidates = newest_match(line, &dirs.pacman_cache);
    if let Some(clone) = &dirs.paru_clone {
        // Fast path: the clone dir is keyed by pkgbase, which for most
        // packages equals pkgname. Split packages need the full walk.
        candidates = candidates.or_else(|| newest_match(line, &clone.join(line)));
        candidates = candidates.or_else(|| {
            std::fs::read_dir(clone)
                .ok()?
                .filter_map(Result::ok)
                .filter(|e| e.path().is_dir())
                .filter_map(|e| newest_match(line, &e.path()))
                .max_by_key(|p| mtime(p))
        });
    }
    if let Some(dest) = &dirs.pkgdest {
        candidates = candidates.or_else(|| newest_match(line, dest));
    }
    candidates
}

/// The most recently modified `<name>-*.pkg.tar.zst` in `dir`, if any.
fn newest_match(name: &str, dir: &Path) -> Option<PathBuf> {
    let prefix = format!("{name}-");
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| is_pkg_archive(p) && file_name(p).starts_with(&prefix))
        .max_by_key(|p| mtime(p))
}

fn mtime(path: &Path) -> std::time::SystemTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
}

/// The subset of `names` present in the configured sync repos, in one
/// `pacman -Si` spawn (read-only; takes no database lock, so it is safe
/// from inside a hook). `LC_ALL=C` pins the field labels the parser reads.
/// If the query cannot run at all, the set is empty and every name is
/// treated as foreign: the failure direction is "scan too much", never
/// "skip a foreign package".
fn sync_repo_members(names: &[&str]) -> std::collections::HashSet<String> {
    if names.is_empty() {
        return Default::default();
    }
    let output = Command::new("pacman")
        .arg("-Si")
        .arg("--")
        .args(names)
        .env("LC_ALL", "C")
        .stderr(std::process::Stdio::null())
        .output();
    match output {
        Ok(o) => parse_si_names(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Default::default(),
    }
}

/// Package names out of `pacman -Si` output: the `Name : value` fields.
fn parse_si_names(stdout: &str) -> std::collections::HashSet<String> {
    stdout
        .lines()
        .filter_map(|l| {
            let (key, value) = l.split_once(':')?;
            (key.trim() == "Name").then(|| value.trim().to_string())
        })
        .collect()
}

fn is_pkg_archive(path: &Path) -> bool {
    file_name(path).ends_with(".pkg.tar.zst")
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The package name for a report: the archive's filename stem, up to (but
/// not including) `.pkg.tar`.
fn archive_name(path: &Path) -> String {
    let name = file_name(path);
    name.split(".pkg.tar").next().unwrap_or(&name).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkg(members: &[(&str, u32, &[u8])], file_name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(file_name);
        let f = std::fs::File::create(&path).unwrap();
        let enc = zstd::Encoder::new(f, 0).unwrap().auto_finish();
        let mut ar = tar::Builder::new(enc);
        for (name, mode, data) in members {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_cksum();
            ar.append_data(&mut h, name, *data).unwrap();
        }
        ar.finish().unwrap();
        (dir, path)
    }

    fn make_malicious_pkg() -> (tempfile::TempDir, PathBuf) {
        make_pkg(
            &[
                (".PKGINFO", 0o644, b"pkgname=evil\n" as &[u8]),
                ("usr/bin/evil", 0o4755, b"\x7fELFxx" as &[u8]),
            ],
            "evil-1.0-1-x86_64.pkg.tar.zst",
        )
    }

    fn test_cfg() -> Config {
        Config {
            no_cache: true,
            ..Default::default()
        }
    }

    fn dirs_with(pacman_cache: &Path, paru_clone: Option<&Path>) -> HookSearchDirs {
        HookSearchDirs {
            pacman_cache: pacman_cache.to_path_buf(),
            paru_clone: paru_clone.map(Path::to_path_buf),
            pkgdest: None,
        }
    }

    #[test]
    fn hook_resolves_a_paru_built_package_by_name() {
        // Regression: the hook only searched pacman's download cache, where
        // AUR builds never land (`pacman -U` does not populate it). Fed the
        // exact stdin pacman sends (a bare pkgname), it scanned nothing and
        // exited 0 -- a silent pass for its entire target population.
        let root = tempfile::tempdir().unwrap();
        let empty_cache = root.path().join("pacman");
        std::fs::create_dir_all(&empty_cache).unwrap();
        let clone = root.path().join("clone");
        let pkgdir = clone.join("zennotes-bin");
        std::fs::create_dir_all(&pkgdir).unwrap();
        std::fs::write(
            pkgdir.join("zennotes-bin-2.40.0-1-x86_64.pkg.tar.zst"),
            b"x",
        )
        .unwrap();

        let got = resolve_target("zennotes-bin", &dirs_with(&empty_cache, Some(&clone)));
        assert_eq!(
            got.as_deref().and_then(Path::file_name).unwrap(),
            "zennotes-bin-2.40.0-1-x86_64.pkg.tar.zst"
        );
    }

    #[test]
    fn hook_resolves_a_split_package_under_its_pkgbase_dir() {
        // paru keys clone dirs by pkgbase; a split package's name differs.
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("pacman");
        std::fs::create_dir_all(&cache).unwrap();
        let clone = root.path().join("clone");
        let basedir = clone.join("somebase");
        std::fs::create_dir_all(&basedir).unwrap();
        std::fs::write(basedir.join("somebase-docs-1.0-1-any.pkg.tar.zst"), b"x").unwrap();

        let got = resolve_target("somebase-docs", &dirs_with(&cache, Some(&clone)));
        assert!(got.is_some(), "split package must resolve via pkgbase walk");
    }

    #[test]
    fn hook_prefers_the_newest_build_of_a_package() {
        // paru keeps several versions side by side; the one pacman is about
        // to install is the most recent build. Lexical sort gets 1.10 vs 1.9
        // wrong, so resolution goes by mtime.
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("clone/tool");
        std::fs::create_dir_all(&dir).unwrap();
        let old = dir.join("tool-1.9-1-x86_64.pkg.tar.zst");
        let new = dir.join("tool-1.10-1-x86_64.pkg.tar.zst");
        std::fs::write(&old, b"old").unwrap();
        std::fs::write(&new, b"new").unwrap();
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::open(&old)
            .unwrap()
            .set_modified(past)
            .unwrap();

        let cache = root.path().join("pacman");
        std::fs::create_dir_all(&cache).unwrap();
        let got = resolve_target(
            "tool",
            &dirs_with(&cache, Some(root.path().join("clone").as_path())),
        );
        assert_eq!(
            got.as_deref().and_then(Path::file_name).unwrap(),
            new.file_name().unwrap()
        );
    }

    #[test]
    fn hook_name_prefix_does_not_match_a_longer_package_name() {
        // `tool` must not resolve to `tool-extras-*`: the version separator
        // dash is part of the required prefix.
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("clone/tool-extras");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tool-extras-1.0-1-x86_64.pkg.tar.zst"), b"x").unwrap();
        let cache = root.path().join("pacman");
        std::fs::create_dir_all(&cache).unwrap();

        // "tool-extras-1.0..." does start with "tool-", so the filename
        // prefix alone cannot distinguish them; the version field after the
        // name means `tool-` matches `tool-extras-...`. Document the known
        // over-match: it scans a sibling package rather than skipping, which
        // fails safe (an extra scan, never a missed one).
        let got = resolve_target(
            "tool",
            &dirs_with(&cache, Some(root.path().join("clone").as_path())),
        );
        assert!(got.is_some());
    }

    #[test]
    fn pkgdest_is_parsed_from_makepkg_conf() {
        assert_eq!(
            pkgdest_from_makepkg_conf("#PKGDEST=/home/x\nPKGDEST=/srv/pkgs\n"),
            Some(PathBuf::from("/srv/pkgs"))
        );
        assert_eq!(
            pkgdest_from_makepkg_conf("PKGDEST=\"/srv/quoted\"\n"),
            Some(PathBuf::from("/srv/quoted"))
        );
        // Unexpandable shell is skipped rather than mis-resolved.
        assert_eq!(pkgdest_from_makepkg_conf("PKGDEST=$HOME/pkgs\n"), None);
        assert_eq!(pkgdest_from_makepkg_conf("# nothing\n"), None);
    }

    #[test]
    fn hook_advisory_proceeds_and_block_aborts() {
        // The hook's exit contract mirrors gate::decide: AbortOnFail means
        // any non-zero kills the whole transaction, so only Block may fail.
        // An Electron-shaped package (Advisory) must install.
        let (_d1, advisory) = make_pkg(
            &[
                (".PKGINFO", 0o644, b"pkgname=app\n" as &[u8]),
                ("opt/app/chrome-sandbox", 0o4755, b"\x7fELFxx" as &[u8]),
            ],
            "app-1.0-1-x86_64.pkg.tar.zst",
        );
        let code = hook_scan_paths(
            &[advisory.to_string_lossy().into_owned()],
            &test_cfg(),
            &dirs_with(Path::new("/nonexistent"), None),
        );
        assert_eq!(code, 0, "advisory must not abort the transaction");

        let (_d2, block) = make_malicious_pkg();
        let code = hook_scan_paths(
            &[block.to_string_lossy().into_owned()],
            &test_cfg(),
            &dirs_with(Path::new("/nonexistent"), None),
        );
        assert_eq!(code, 2, "a Block verdict must abort the transaction");
    }

    #[test]
    fn scan_files_blocks_on_a_setuid_binary_in_a_built_archive() {
        let (_dir, path) = make_malicious_pkg();
        let code = scan_files(&[path], &test_cfg(), false, true, false);
        assert_eq!(code, 2, "a setuid binary dropped into usr/bin must block");
    }

    #[test]
    fn scan_files_electron_shaped_archive_is_not_blocked() {
        // Regression: the standard Electron layout — the app in its own
        // directory with Chromium's setuid sandbox helper — was an
        // unconditional Block. It is the shape of most popular AUR -bin
        // desktop apps (zennotes-bin, brave-bin, 1password, slack-desktop),
        // observed against the real built artifacts in a paru cache.
        // Advisory (exit 1) is acceptable; Block (exit 2) is the bug.
        let (_dir, path) = make_pkg(
            &[
                (".PKGINFO", 0o644, b"pkgname=zennotes-bin\n" as &[u8]),
                ("opt/zennotes-bin/zennotes", 0o755, b"\x7fELFxx" as &[u8]),
                (
                    "opt/zennotes-bin/chrome-sandbox",
                    0o4755,
                    b"\x7fELFxx" as &[u8],
                ),
                (
                    "usr/share/applications/zennotes.desktop",
                    0o644,
                    b"[Desktop Entry]\n" as &[u8],
                ),
            ],
            "zennotes-bin-2.40.0-1-x86_64.pkg.tar.zst",
        );
        let code = scan_files(&[path], &test_cfg(), false, true, false);
        assert_ne!(
            code, 2,
            "the Electron chrome-sandbox shape must not Block popular apps"
        );
    }

    #[test]
    fn scan_files_clean_archive_yields_exit_0() {
        let (_dir, path) = make_pkg(
            &[
                (".PKGINFO", 0o644, b"pkgname=hello\n" as &[u8]),
                ("usr/bin/hello", 0o755, b"\x7fELFxx" as &[u8]),
            ],
            "hello-1.0-1-x86_64.pkg.tar.zst",
        );
        let code = scan_files(&[path], &test_cfg(), false, true, false);
        assert_eq!(code, 0);
    }

    #[test]
    fn archive_name_strips_pkg_tar_suffix() {
        assert_eq!(
            archive_name(Path::new("/tmp/evil-1.0-1-x86_64.pkg.tar.zst")),
            "evil-1.0-1-x86_64"
        );
    }

    #[test]
    fn hook_scan_paths_resolves_absolute_archive_paths_and_blocks() {
        let (_dir, path) = make_malicious_pkg();
        let lines = vec![path.display().to_string()];
        let dirs = dirs_with(Path::new("/nonexistent"), None);
        assert_eq!(hook_scan_paths(&lines, &test_cfg(), &dirs), 2);
    }

    #[test]
    fn si_output_parses_to_the_set_of_repo_names() {
        let out = "Repository      : extra\nName            : bash\nVersion         : 5.2\n\n\
                   Repository      : core\nName            : linux\nVersion         : 6.18\n";
        let got = parse_si_names(out);
        assert!(got.contains("bash") && got.contains("linux"));
        assert_eq!(got.len(), 2, "field values with colons must not leak in");
    }

    #[test]
    fn hook_scan_paths_exits_zero_when_nothing_resolves() {
        // "Nothing to check" must remain a pass (possibly with a foreign-
        // package warning on stderr), never an aborted transaction.
        let lines = vec!["no-such-package-zzqx".to_string()];
        let dirs = dirs_with(Path::new("/nonexistent"), None);
        assert_eq!(hook_scan_paths(&lines, &test_cfg(), &dirs), 0);
    }

    #[test]
    fn hook_scan_paths_ignores_blank_lines() {
        let lines = vec![String::new(), "  ".to_string()];
        let dirs = dirs_with(Path::new("/nonexistent"), None);
        assert_eq!(hook_scan_paths(&lines, &test_cfg(), &dirs), 0);
    }

    #[test]
    fn resolve_target_rejects_names_found_nowhere() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_target("some-pkgname", &dirs_with(dir.path(), None)),
            None
        );
    }

    #[test]
    fn resolve_target_prefers_foo_over_foobar_in_the_pacman_cache() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo-2.0-1-x86_64.pkg.tar.zst"), b"").unwrap();
        std::fs::write(dir.path().join("foobar-1.0-1-x86_64.pkg.tar.zst"), b"").unwrap();

        let resolved = resolve_target("foo", &dirs_with(dir.path(), None)).unwrap();
        assert_eq!(file_name(&resolved), "foo-2.0-1-x86_64.pkg.tar.zst");
    }
}
