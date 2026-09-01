//! User configuration loaded from `~/.config/aurscan/config.toml`. Every field
//! is optional and falls back to a secure default (block on High, advise on
//! Medium, no cached feature dumps).

use anyhow::Context;
use aurscan_core::{Severity, VerdictPolicy};
use aurscan_llm::{LlmConfig, ValidatedLlmConfig};
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
    /// Scan worker threads. 0 (the default) picks automatically: half the
    /// available cores in hook mode, all of them otherwise.
    pub scan_threads: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            block_heuristic_at: "high".to_string(),
            advisory_at: "medium".to_string(),
            record_features: false,
            no_cache: false,
            scan_threads: 0,
        }
    }
}

#[derive(Debug)]
pub struct StrictLlmConfig {
    pub config: Config,
    pub llm: ValidatedLlmConfig,
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

    /// Strict configuration for the two explicit experimental LLM commands.
    /// Unlike `load`, this never substitutes defaults for a missing or invalid
    /// file and requires the opt-in `[experimental.llm]` table.
    pub fn load_strict_llm() -> anyhow::Result<StrictLlmConfig> {
        let path = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("configuration directory is unavailable"))?
            .join("aurscan/config.toml");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read LLM configuration from {}", path.display()))?;
        parse_strict_llm(&text)
    }

    /// Number of rayon workers to use for scanning. Hooks run behind a
    /// user's interactive pacman/paru session and were pinning every core
    /// (90C+ on a real -Syu), so hook mode defaults to half the cores;
    /// direct CLI invocations keep full parallelism. `scan_threads` in
    /// config.toml overrides both.
    pub fn effective_scan_threads(&self, hook: bool) -> usize {
        if self.scan_threads > 0 {
            return self.scan_threads;
        }
        let cores = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        if hook {
            (cores / 2).max(1)
        } else {
            cores
        }
    }

    /// Translate the configured severity strings into an engine policy.
    pub fn policy(&self) -> VerdictPolicy {
        VerdictPolicy {
            block_heuristic_at: parse_severity(&self.block_heuristic_at),
            advisory_at: parse_severity(&self.advisory_at),
        }
    }
}

fn parse_strict_llm(text: &str) -> anyhow::Result<StrictLlmConfig> {
    let document: toml::Value =
        toml::from_str(text).map_err(|_| anyhow::anyhow!("malformed configuration TOML"))?;
    let config: Config = document
        .clone()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid deterministic configuration"))?;
    let llm_value = document
        .get("experimental")
        .and_then(|experimental| experimental.get("llm"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing required [experimental.llm] configuration"))?;
    let llm: LlmConfig = llm_value
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid [experimental.llm] configuration"))?;
    let llm = aurscan_llm::validate_config(&llm).context("invalid LLM configuration")?;
    Ok(StrictLlmConfig { config, llm })
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

    #[test]
    fn strict_llm_config_requires_explicit_table_while_lenient_config_falls_back() {
        let malformed = "[not valid";
        assert!(parse_strict_llm(malformed).is_err());
        let lenient = toml::from_str::<Config>(malformed).unwrap_or_default();
        assert_eq!(
            lenient.block_heuristic_at,
            Config::default().block_heuristic_at
        );

        assert!(parse_strict_llm("block_heuristic_at = 'critical'")
            .unwrap_err()
            .to_string()
            .contains("[experimental.llm]"));
    }

    #[test]
    fn strict_parse_errors_never_echo_configuration_values() {
        let secret = "deliberately-secret-value";
        let malformed =
            format!("[experimental.llm]\nendpoint = \"http://localhost:1/v1\"\nmodel = \"{secret}");
        let error = format!("{:#}", parse_strict_llm(&malformed).unwrap_err());
        assert!(!error.contains(secret), "secret leaked in: {error}");
    }

    #[test]
    fn strict_llm_config_rejects_unknown_fields_and_invalid_values() {
        let unknown = r#"
[experimental.llm]
endpoint = "http://localhost:11434/v1"
model = "pinned"
unexpected = true
"#;
        assert!(parse_strict_llm(unknown).is_err());

        let invalid_remote = r#"
[experimental.llm]
endpoint = "https://example.com/v1"
model = "pinned"
allow_remote = false
"#;
        assert!(parse_strict_llm(invalid_remote).is_err());

        let invalid_limit = r#"
[experimental.llm]
endpoint = "http://localhost:11434/v1"
model = "pinned"
max_files = 0
"#;
        assert!(parse_strict_llm(invalid_limit).is_err());
    }

    #[test]
    fn strict_llm_config_preserves_deterministic_fields_and_validates_llm() {
        let strict = parse_strict_llm(
            r#"
block_heuristic_at = "critical"
advisory_at = "info"
scan_threads = 7

[experimental.llm]
endpoint = "http://127.0.0.1:11434/v1"
model = "pinned"
"#,
        )
        .unwrap();

        assert_eq!(strict.config.block_heuristic_at, "critical");
        assert_eq!(strict.config.advisory_at, "info");
        assert_eq!(strict.config.scan_threads, 7);
        assert_eq!(strict.llm.endpoint_origin(), "http://127.0.0.1:11434");
        assert_eq!(strict.llm.model(), "pinned");
    }
}
