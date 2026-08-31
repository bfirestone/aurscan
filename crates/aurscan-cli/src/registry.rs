//! Detector registry + engine assembly, and the `check` command's local-path
//! scan flow. Wires all nine detectors, the ruleset, and the result cache into
//! a single `Engine`.

use crate::config::Config;
use crate::report;
use aurscan_core::target::expand_build_dir;
use aurscan_core::{
    Detector, Engine, NoopCache, PackageJob, PackageReport, RedbCache, ResultCache, ScanTarget,
    ScriptKind,
};
use aurscan_detectors::{
    archive_layout, aur_metadata, elf_inspect, ioc_tokens, known_bad_names, payload_hashes,
    persistence, pkgbuild_static, rules, source_provenance,
};
use std::path::Path;
use std::sync::Arc;

/// Build the fully-wired scan engine from user config.
pub fn build_engine(cfg: &Config) -> anyhow::Result<Engine> {
    let rules = rules::RuleSet::load(dirs::data_dir().as_deref())?;
    let ruleset_version = rules.version;

    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(ioc_tokens::IocTokensDetector::new(&rules)),
        Box::new(payload_hashes::PayloadHashesDetector::new(&rules)),
        Box::new(known_bad_names::KnownBadNamesDetector::new(&rules)),
        Box::new(pkgbuild_static::PkgbuildStaticDetector::new()),
        Box::new(source_provenance::SourceProvenanceDetector::new()),
        Box::new(aur_metadata::AurMetadataDetector::new(now_epoch())),
        Box::new(elf_inspect::ElfInspectDetector),
        Box::new(archive_layout::ArchiveLayoutDetector),
        Box::new(persistence::PersistenceDetector::new()),
    ];

    let cache: Arc<dyn ResultCache> = if cfg.no_cache {
        Arc::new(NoopCache)
    } else {
        match RedbCache::open(&RedbCache::default_path()) {
            Ok(c) => Arc::new(c),
            Err(_) => Arc::new(NoopCache),
        }
    };

    Ok(Engine {
        detectors,
        cache,
        policy: cfg.policy(),
        ruleset_version,
        detector_epoch: aurscan_detectors::DETECTOR_EPOCH,
    })
}

/// The scan-identity pair for the current binary + on-disk ruleset. Any
/// cached result (redb entries, the commit ledger) is only valid at a
/// matching pair.
pub fn cache_identity() -> (u32, u32) {
    let ruleset_version = rules::RuleSet::load(dirs::data_dir().as_deref())
        .map(|r| r.version)
        .unwrap_or(0);
    (ruleset_version, aurscan_detectors::DETECTOR_EPOCH)
}

/// Scan local path targets (directories or files) through the full engine.
/// Non-existent paths are skipped here; the caller reports them separately.
pub fn run_check(paths: &[String], cfg: &Config) -> anyhow::Result<(Vec<PackageReport>, i32)> {
    let engine = build_engine(cfg)?;
    let jobs: Vec<PackageJob> = paths
        .iter()
        .filter_map(|p| build_job(Path::new(p)))
        .collect();

    let mut reports = engine.scan(&jobs);
    if !cfg.record_features {
        for r in &mut reports {
            r.features.clear();
        }
    }

    crate::ack::apply_acks(&mut reports, &crate::ack::AckStore::load(), &cfg.policy());
    let code = report::worst_exit_code(&reports);
    Ok((reports, code))
}

fn build_job(path: &Path) -> Option<PackageJob> {
    if !path.exists() {
        return None;
    }
    let targets = if path.is_dir() {
        expand_build_dir(path, &[])
    } else {
        vec![wrap_file(path)]
    };
    Some(PackageJob {
        name: job_name(path),
        version: String::new(),
        aur_meta: None,
        targets,
    })
}

/// A report name a human can act on. paru's `PreBuildCommand` invokes
/// `check --hook .`, and naming that report `.` left a real 27-package
/// upgrade aborting with no way to tell *which* package raised the advisory.
/// Prefer the PKGBUILD's own `pkgname=`; fall back to the canonicalized
/// directory name so `.` still resolves to something meaningful.
fn job_name(path: &Path) -> String {
    if path.is_dir() {
        if let Some(name) = std::fs::read_to_string(path.join("PKGBUILD"))
            .ok()
            .as_deref()
            .and_then(pkgname_from_pkgbuild)
        {
            return name;
        }
    }
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    basename(&canonical)
}

/// The literal `pkgname=` value, when it is a plain name. Split-package
/// arrays and shell expansions are left to the caller's fallback rather
/// than mis-parsed.
fn pkgname_from_pkgbuild(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("pkgname=")?;
        let val = rest.trim().trim_matches(['"', '\'']);
        (!val.is_empty() && !val.contains(['$', '(', ')', ' ', '\t'])).then(|| val.to_string())
    })
}

fn basename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn wrap_file(path: &Path) -> ScanTarget {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let kind = if name == "PKGBUILD" {
        ScriptKind::Pkgbuild
    } else if name.ends_with(".install") {
        ScriptKind::InstallScript
    } else if name == ".SRCINFO" {
        ScriptKind::SrcInfo
    } else if name.ends_with(".patch") || name.ends_with(".diff") {
        ScriptKind::Patch
    } else {
        ScriptKind::Other
    };
    ScanTarget::BuildScript {
        path: path.to_path_buf(),
        kind,
    }
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::Verdict;

    #[test]
    fn job_name_comes_from_pkgbuild_not_the_path_argument() {
        // Regression: paru runs `check --hook .`, and the report was headed
        // `.: ADVISORY` -- during a 27-package upgrade there was no way to
        // tell which package fired.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), b"pkgname=onepass\n").unwrap();
        assert_eq!(job_name(dir.path()), "onepass");
    }

    #[test]
    fn job_name_falls_back_to_the_canonical_dir_for_split_packages() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), b"pkgname=('a' 'b')\n").unwrap();
        let got = job_name(dir.path());
        assert_ne!(got, ".", "must never surface the raw path argument");
        assert!(!got.is_empty());
    }

    #[test]
    fn pkgname_parsing_rejects_expansions() {
        assert_eq!(pkgname_from_pkgbuild("pkgname=foo\n"), Some("foo".into()));
        assert_eq!(
            pkgname_from_pkgbuild("pkgname=\"foo\"\n"),
            Some("foo".into())
        );
        assert_eq!(pkgname_from_pkgbuild("pkgname=$_base-bin\n"), None);
        assert_eq!(pkgname_from_pkgbuild("pkgname=('a' 'b')\n"), None);
    }

    #[test]
    fn planted_atomic_lockfile_token_yields_block_exit_2() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("PKGBUILD"),
            b"pkgname=evil\nbuild() {\n  npm install atomic-lockfile\n}\n",
        )
        .unwrap();

        let cfg = Config {
            no_cache: true,
            ..Default::default()
        };
        let (reports, code) = run_check(&[dir.path().display().to_string()], &cfg).unwrap();

        assert_eq!(code, 2, "a planted critical IOC token must block");
        assert!(
            reports
                .iter()
                .any(|r| matches!(r.verdict, Verdict::Block(_))),
            "expected a Block verdict"
        );
    }

    #[test]
    fn clean_pkgbuild_yields_exit_0() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("PKGBUILD"),
            b"pkgname=hello\npkgver=1.0\nsource=(\"https://example.com/hello-1.0.tar.gz\")\n",
        )
        .unwrap();

        let cfg = Config {
            no_cache: true,
            ..Default::default()
        };
        let (_reports, code) = run_check(&[dir.path().display().to_string()], &cfg).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn nonexistent_paths_are_skipped() {
        let cfg = Config {
            no_cache: true,
            ..Default::default()
        };
        let (reports, code) = run_check(&["/no/such/path/xyz".to_string()], &cfg).unwrap();
        assert!(reports.is_empty());
        assert_eq!(code, 0);
    }
}
