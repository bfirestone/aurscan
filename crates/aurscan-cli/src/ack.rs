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
    pub fn key(f: &Finding) -> String {
        let h = blake3::hash(format!("{}|{}", f.evidence.location, f.evidence.excerpt).as_bytes());
        format!("{}:{}:{}", f.package, f.detector.0, &h.to_hex()[..16])
    }

    pub fn is_acked(&self, f: &Finding) -> bool {
        self.acked.contains(&Self::key(f))
    }

    /// Record and persist an acknowledgement for a finding.
    // Wired by the forthcoming `ack` subcommand task; unused for now.
    #[allow(dead_code)]
    pub fn add(&mut self, f: &Finding) -> anyhow::Result<()> {
        self.acked.insert(Self::key(f));
        self.persist()
    }

    fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("aurscan/acknowledged.toml"))
    }

    #[allow(dead_code)]
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
