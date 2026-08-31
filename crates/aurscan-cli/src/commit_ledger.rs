//! Ledger of scanned AUR commits: `pkgbase -> (commit, verdict, versions)`,
//! at `~/.cache/aurscan/scanned_commits.json`.
//!
//! This is what lets a repeat `check`/`install` skip the expensive part of
//! the pipeline (git clone + `makepkg --verifysource`, the network and
//! wall-clock cost) for a package whose AUR commit has not moved: one
//! `git ls-remote` round-trip replaces the fetch when the ledger says that
//! exact commit already scanned Clean under the current ruleset and
//! detector epoch.
//!
//! The identity is deliberately the git commit, never `pkgname+pkgver`:
//! nothing forces an AUR maintainer to bump pkgver when the PKGBUILD
//! changes, `-git` packages compute pkgver at build time, and "name and
//! version stable while content changes" is exactly the orphan-adoption
//! attack this tool exists to catch. A changed PKGBUILD necessarily means a
//! changed commit.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub commit: String,
    /// "clean" | "advisory" | "block" -- only "clean" ever authorizes a skip.
    pub verdict: String,
    /// Both version fields gate the skip: a detector or rule change must
    /// reach already-scanned packages, or a fixed false negative would stay
    /// invisible forever (the staleness class DETECTOR_EPOCH exists for).
    pub ruleset_version: u32,
    pub detector_epoch: u32,
}

pub struct CommitLedger {
    entries: HashMap<String, Entry>,
}

impl CommitLedger {
    /// Load the ledger; empty on missing or unreadable. A pre-ledger file
    /// (the old `pkgbase -> commit-string` format) fails the typed parse and
    /// is treated as empty -- it recorded no verdict, so it could never
    /// authorize a skip anyway.
    pub fn load() -> Self {
        let entries = Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { entries }
    }

    /// True when `commit` is recorded as having scanned Clean for `pkgbase`
    /// under the current `ruleset_version` + `detector_epoch`.
    pub fn clean_at(
        &self,
        pkgbase: &str,
        commit: &str,
        ruleset_version: u32,
        detector_epoch: u32,
    ) -> bool {
        self.entries.get(pkgbase).is_some_and(|e| {
            e.commit == commit
                && e.verdict == "clean"
                && e.ruleset_version == ruleset_version
                && e.detector_epoch == detector_epoch
        })
    }

    /// Record `pkgbase`'s scan outcome, best-effort: an unwritable cache dir
    /// only costs the next run its skip, never the scan itself.
    pub fn record(&mut self, pkgbase: &str, entry: Entry) {
        self.entries.insert(pkgbase.to_string(), entry);
        let Some(path) = Self::path() else { return };
        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return;
            }
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.entries) {
            let _ = std::fs::write(&path, json);
        }
    }

    fn path() -> Option<PathBuf> {
        dirs::cache_dir().map(|d| d.join("aurscan/scanned_commits.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(commit: &str, verdict: &str) -> Entry {
        Entry {
            commit: commit.into(),
            verdict: verdict.into(),
            ruleset_version: 7,
            detector_epoch: 5,
        }
    }

    fn ledger_with(pkgbase: &str, e: Entry) -> CommitLedger {
        let mut entries = HashMap::new();
        entries.insert(pkgbase.to_string(), e);
        CommitLedger { entries }
    }

    #[test]
    fn clean_commit_at_matching_versions_authorizes_a_skip() {
        let l = ledger_with("paru", entry("abc123", "clean"));
        assert!(l.clean_at("paru", "abc123", 7, 5));
    }

    #[test]
    fn anything_less_than_clean_never_skips() {
        // An advisory or block verdict must be re-observed every time: the
        // skip means not looking at content at all.
        for verdict in ["advisory", "block"] {
            let l = ledger_with("p", entry("abc123", verdict));
            assert!(!l.clean_at("p", "abc123", 7, 5), "verdict {verdict}");
        }
    }

    #[test]
    fn moved_commit_or_stale_versions_never_skip() {
        let l = ledger_with("p", entry("abc123", "clean"));
        assert!(!l.clean_at("p", "def456", 7, 5), "commit moved");
        assert!(!l.clean_at("p", "abc123", 8, 5), "ruleset changed");
        assert!(
            !l.clean_at("p", "abc123", 7, 6),
            "detector epoch changed: a detector fix must reach already-scanned packages"
        );
        assert!(!l.clean_at("q", "abc123", 7, 5), "different pkgbase");
    }

    #[test]
    fn old_format_file_reads_as_empty() {
        // The pre-ledger format was pkgbase -> commit string, with no
        // verdict. It must be ignored, not misread.
        let parsed: Result<HashMap<String, Entry>, _> =
            serde_json::from_str(r#"{"paru": "abc123"}"#);
        assert!(parsed.is_err());
    }
}
