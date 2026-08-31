//! Acknowledgement store: lets a user silence a specific finding on a specific
//! package without suppressing the detector globally. Keyed by
//! `(package, detector, blake3(location + excerpt))` so re-running against the
//! same evidence stays quiet, while any change in the matched content resurfaces.

use aurscan_core::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

pub struct AckStore {
    acked: HashSet<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct AckFile {
    #[serde(default)]
    acknowledged: Vec<String>,
}

impl AckStore {
    /// Load `~/.config/aurscan/acknowledged.toml`; empty on missing/invalid.
    pub fn load() -> Self {
        let acked = Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str::<AckFile>(&s).ok())
            .map(|f| f.acknowledged.into_iter().collect())
            .unwrap_or_default();
        Self { acked }
    }

    /// Stable acknowledgement key for a finding.
    ///
    /// Stability is the point: an ack must survive a pkgver bump (the user
    /// judged the *finding*, not one release of it) but expire when the
    /// matched content changes. The excerpt pins the content; package and
    /// location are normalized because both embed versions -- artifact
    /// reports are named after the archive stem
    /// (`zen-browser-bin-1.21.16b-1-x86_64`) and their locations carry the
    /// full versioned archive path. Un-normalized, every upgrade un-acked
    /// everything, so the same four browser advisories re-prompted forever.
    pub fn key(f: &Finding) -> String {
        let h = blake3::hash(
            format!(
                "{}|{}",
                stable_location(&f.evidence.location),
                f.evidence.excerpt
            )
            .as_bytes(),
        );
        format!(
            "{}:{}:{}",
            stable_package(&f.package),
            f.detector.0,
            &h.to_hex()[..16]
        )
    }

    pub fn is_acked(&self, f: &Finding) -> bool {
        self.acked.contains(&Self::key(f))
    }

    /// Record and persist an acknowledgement for a finding.
    #[cfg(test)]
    pub fn add(&mut self, f: &Finding) -> anyhow::Result<()> {
        self.acked.insert(Self::key(f));
        self.persist()
    }

    fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("aurscan/acknowledged.toml"))
    }

    fn persist(&self) -> anyhow::Result<()> {
        let Some(path) = Self::path() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut acknowledged: Vec<String> = self.acked.iter().cloned().collect();
        acknowledged.sort();
        std::fs::write(&path, toml::to_string_pretty(&AckFile { acknowledged })?)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_keys<I: IntoIterator<Item = String>>(keys: I) -> Self {
        Self {
            acked: keys.into_iter().collect(),
        }
    }
}

/// The location, version-invariant. `archive!member` keeps only the member
/// path (already version-free inside the archive). `path:line` drops the
/// line number (they shift between releases while the excerpt pins the
/// content) and keeps only the file's basename (clone/cache prefixes vary
/// by invocation).
fn stable_location(location: &str) -> String {
    if let Some((_, member)) = location.rsplit_once('!') {
        return member.to_string();
    }
    let path = match location.rsplit_once(':') {
        Some((p, line)) if !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()) => p,
        _ => location,
    };
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// Strip `-pkgver-pkgrel-arch` off an archive-stem package name. Applied
/// only when the trailing three dash-fields actually look like Arch version
/// metadata, so ordinary package names pass through untouched.
fn stable_package(package: &str) -> String {
    let mut it = package.rsplitn(4, '-');
    let (Some(arch), Some(rel), Some(ver), Some(name)) =
        (it.next(), it.next(), it.next(), it.next())
    else {
        return package.to_string();
    };
    let archish = matches!(
        arch,
        "x86_64"
            | "aarch64"
            | "any"
            | "i686"
            | "pentium4"
            | "armv7h"
            | "armv6h"
            | "arm"
            | "riscv64"
    );
    let relish = !rel.is_empty() && rel.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    let verish = ver
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    if archish && relish && verish {
        name.to_string()
    } else {
        package.to_string()
    }
}

/// Recompute each report's verdict from its *unacknowledged* findings only.
///
/// Without this, an ack was cosmetic: the finding disappeared from text
/// output while the verdict (and therefore the exit code, the paru y/N
/// prompt, and the ALPM AbortOnFail gate) still counted it. Findings are
/// left in place so reports and JSON stay a full record of what was seen.
pub fn apply_acks(
    reports: &mut [aurscan_core::PackageReport],
    acks: &AckStore,
    policy: &aurscan_core::VerdictPolicy,
) {
    for r in reports.iter_mut() {
        if r.findings.iter().any(|f| acks.is_acked(f)) {
            let live: Vec<Finding> = r
                .findings
                .iter()
                .filter(|f| !acks.is_acked(f))
                .cloned()
                .collect();
            r.verdict = aurscan_core::compute_verdict(live, policy);
        }
    }
}

/// `aurscan ack <target>...`: scan the targets, show the live (unacked)
/// Medium-or-above findings, and record acknowledgements after a y/N
/// confirm (`--yes` skips it, and is required when stdin is not a tty).
///
/// A target is a build directory, a built `.pkg.tar.zst`, or a bare package
/// name -- names resolve through the same search the ALPM hook uses (paru
/// clone cache, pacman cache, PKGDEST), covering both the recipe and the
/// built artifact, so one `aurscan ack zen-browser-bin` silences what both
/// gates just showed.
pub fn run_ack(targets: &[String], yes: bool, cfg: &crate::config::Config) -> i32 {
    use std::io::IsTerminal;

    let mut dir_targets: Vec<String> = Vec::new();
    let mut archive_targets: Vec<std::path::PathBuf> = Vec::new();
    let search = crate::artifact::HookSearchDirs::detect();
    for t in targets {
        let path = std::path::Path::new(t);
        if path.is_dir() {
            dir_targets.push(t.clone());
        } else if path.is_file() {
            archive_targets.push(path.to_path_buf());
        } else {
            let mut found = false;
            if let Some(archive) = crate::artifact::resolve_target(t, &search) {
                archive_targets.push(archive);
                found = true;
            }
            if let Some(clone) = search.paru_clone.as_ref().map(|c| c.join(t)) {
                if clone.join("PKGBUILD").is_file() {
                    dir_targets.push(clone.display().to_string());
                    found = true;
                }
            }
            if !found {
                eprintln!("aurscan: nothing found to acknowledge for `{t}`");
            }
        }
    }

    let mut reports = Vec::new();
    if !dir_targets.is_empty() {
        match crate::registry::run_check(&dir_targets, cfg) {
            Ok((r, _)) => reports.extend(r),
            Err(e) => {
                eprintln!("error: {e:#}");
                return 3;
            }
        }
    }
    if !archive_targets.is_empty() {
        match crate::artifact::collect_reports(&archive_targets, cfg, false) {
            Ok(r) => reports.extend(r),
            Err(e) => {
                eprintln!("error: {e:#}");
                return 3;
            }
        }
    }

    let mut store = AckStore::load();
    let pending: Vec<&Finding> = reports
        .iter()
        .flat_map(|r| r.findings.iter())
        .filter(|f| f.severity >= aurscan_core::Severity::Medium && !store.is_acked(f))
        .collect();

    if pending.is_empty() {
        println!("aurscan: nothing to acknowledge (no unacked findings at Medium or above)");
        return 0;
    }

    for f in &pending {
        println!("{}: [{:?}] {}", f.package, f.severity, f.reason);
        println!("    \u{21b3} {}", f.evidence.location);
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            eprintln!("aurscan: not a terminal; rerun with --yes to acknowledge");
            return 1;
        }
        print!(
            "Acknowledge {} finding(s)? They stop prompting and gating until \
             their matched content changes. [y/N] ",
            pending.len()
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut line = String::new();
        let ok = std::io::stdin().read_line(&mut line).is_ok()
            && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        if !ok {
            println!("aurscan: nothing acknowledged");
            return 1;
        }
    }

    let keys: Vec<String> = pending.iter().map(|f| AckStore::key(f)).collect();
    let count = keys.len();
    for key in keys {
        store.acked.insert(key);
    }
    if let Err(e) = store.persist() {
        eprintln!("error: could not persist acknowledgements: {e:#}");
        return 3;
    }
    println!("aurscan: acknowledged {count} finding(s)");
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::{Confidence, DetectorId, Evidence, Severity};

    fn finding(pkg: &str, det: &'static str, loc: &str, excerpt: &str) -> Finding {
        Finding {
            severity: Severity::High,
            confidence: Confidence::Exact,
            detector: DetectorId(det),
            package: pkg.into(),
            reason: "r".into(),
            evidence: Evidence {
                location: loc.into(),
                excerpt: excerpt.into(),
            },
        }
    }

    #[test]
    fn artifact_ack_survives_a_version_bump() {
        // Regression: package and location both embedded the version, so
        // every upgrade un-acked everything and the same four browser
        // advisories re-prompted forever.
        let old = finding(
            "zen-browser-bin-1.21.16b-1-x86_64",
            "elf_inspect",
            "/home/u/.cache/paru/clone/zen-browser-bin/zen-browser-bin-1.21.16b-1-x86_64.pkg.tar.zst!opt/zen-browser-bin/pingsender",
            "dynamic import combo",
        );
        let new = finding(
            "zen-browser-bin-1.22.0-1-x86_64",
            "elf_inspect",
            "/home/u/.cache/paru/clone/zen-browser-bin/zen-browser-bin-1.22.0-1-x86_64.pkg.tar.zst!opt/zen-browser-bin/pingsender",
            "dynamic import combo",
        );
        assert_eq!(AckStore::key(&old), AckStore::key(&new));
        // ...but a different member is a different finding.
        let other_member = finding(
            "zen-browser-bin-1.22.0-1-x86_64",
            "elf_inspect",
            "/home/u/.cache/paru/clone/zen-browser-bin/zen-browser-bin-1.22.0-1-x86_64.pkg.tar.zst!opt/zen-browser-bin/zen",
            "dynamic import combo",
        );
        assert_ne!(AckStore::key(&new), AckStore::key(&other_member));
    }

    #[test]
    fn pkgbuild_ack_survives_line_moves_and_path_prefixes() {
        // The excerpt pins the content; the line number and the clone-dir
        // prefix vary by release and by invocation.
        let a = finding("p", "pkgbuild_static", "./PKGBUILD:39", "eval \"cat <<EOF");
        let b = finding(
            "p",
            "pkgbuild_static",
            "/home/u/.cache/paru/clone/p/PKGBUILD:42",
            "eval \"cat <<EOF",
        );
        assert_eq!(AckStore::key(&a), AckStore::key(&b));
    }

    #[test]
    fn stable_package_leaves_ordinary_names_alone() {
        assert_eq!(stable_package("zen-browser-bin"), "zen-browser-bin");
        assert_eq!(stable_package("brave-bin-1:1.92.139-1-x86_64"), "brave-bin");
        assert_eq!(stable_package("a-b-c"), "a-b-c");
    }

    #[test]
    fn apply_acks_downgrades_a_fully_acked_advisory_to_clean() {
        use aurscan_core::{compute_verdict, PackageReport, Verdict, VerdictPolicy};
        let f = finding("p", "ioc", "PKGBUILD:1", "eval thing");
        let policy = VerdictPolicy::default();
        let mut reports = vec![PackageReport {
            package: "p".into(),
            verdict: compute_verdict(vec![f.clone()], &policy),
            findings: vec![f.clone()],
            features: vec![],
        }];
        assert!(matches!(reports[0].verdict, Verdict::Block(_)));

        let acks = AckStore::from_keys([AckStore::key(&f)]);
        apply_acks(&mut reports, &acks, &policy);
        assert!(
            matches!(reports[0].verdict, Verdict::Clean),
            "acked findings must stop gating"
        );
        assert_eq!(reports[0].findings.len(), 1, "findings stay for display");
    }

    #[test]
    fn key_changes_with_evidence() {
        let a = finding("p", "ioc", "PKGBUILD:1", "one");
        let b = finding("p", "ioc", "PKGBUILD:1", "two");
        assert_ne!(AckStore::key(&a), AckStore::key(&b));
    }

    #[test]
    fn is_acked_matches_stored_key() {
        let f = finding("p", "ioc", "PKGBUILD:1", "npm install atomic-lockfile");
        let store = AckStore::from_keys([AckStore::key(&f)]);
        assert!(store.is_acked(&f));
        let other = finding("q", "ioc", "PKGBUILD:1", "npm install atomic-lockfile");
        assert!(!store.is_acked(&other));
    }

    #[test]
    fn add_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", dir.path());

        let f = finding("p", "ioc", "PKGBUILD:1", "malware");
        let mut store = AckStore::load();
        assert!(!store.is_acked(&f));
        store.add(&f).unwrap();

        let reloaded = AckStore::load();
        assert!(reloaded.is_acked(&f));
    }
}
