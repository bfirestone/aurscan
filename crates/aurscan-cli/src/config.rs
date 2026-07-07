//! User configuration loaded from `~/.config/aurscan/config.toml`. Every field
//! is optional and falls back to a secure default (block on High, advise on
//! Medium, no cached feature dumps).

use aurscan_core::{Severity, VerdictPolicy};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Heuristic severity at which a package is blocked.
    pub block_heuristic_at: String,
    /// Severity at which a package is flagged as advisory.
    pub advisory_at: String,
    /// Keep detector feature vectors in reports/JSON output.
    pub record_features: bool,
    /// Skip the persistent redb result cache.
    pub no_cache: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            block_heuristic_at: "high".to_string(),
            advisory_at: "medium".to_string(),
            record_features: false,
            no_cache: false,
        }
    }
}

impl Config {
    /// Read `~/.config/aurscan/config.toml`, falling back to defaults when the
    /// file is missing or unparseable.
    pub fn load() -> Self {
        dirs::config_dir()
            .map(|d| d.join("aurscan/config.toml"))
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Translate the configured severity strings into an engine policy.
    pub fn policy(&self) -> VerdictPolicy {
        VerdictPolicy {
            block_heuristic_at: parse_severity(&self.block_heuristic_at),
            advisory_at: parse_severity(&self.advisory_at),
        }
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "medium" => Severity::Medium,
        "critical" => Severity::Critical,
        _ => Severity::High,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_map_to_high_medium_policy() {
        let policy = Config::default().policy();
        assert_eq!(policy.block_heuristic_at, Severity::High);
        assert_eq!(policy.advisory_at, Severity::Medium);
    }

    #[test]
    fn severity_strings_are_case_insensitive() {
        let cfg = Config {
            block_heuristic_at: "CRITICAL".into(),
            advisory_at: "Info".into(),
            ..Default::default()
        };
        let policy = cfg.policy();
        assert_eq!(policy.block_heuristic_at, Severity::Critical);
        assert_eq!(policy.advisory_at, Severity::Info);
    }
}
