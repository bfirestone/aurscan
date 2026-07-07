use aurscan_core::Severity;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

pub const TOKENS_TOML: &str = include_str!("../../../rules/tokens.toml");
pub const HASHES_TOML: &str = include_str!("../../../rules/hashes.toml");
pub const BAD_NAMES_TOML: &str = include_str!("../../../rules/bad_names.toml");
pub const REGEXES_TOML: &str = include_str!("../../../rules/regexes.toml");

/// Mirrors `aurscan_core::Severity` for deserialization, since `Severity`
/// only derives `Serialize`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SevSpec {
    Info,
    Medium,
    High,
    Critical,
}

impl From<SevSpec> for Severity {
    fn from(spec: SevSpec) -> Self {
        match spec {
            SevSpec::Info => Severity::Info,
            SevSpec::Medium => Severity::Medium,
            SevSpec::High => Severity::High,
            SevSpec::Critical => Severity::Critical,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenRule {
    pub token: String,
    pub severity: Severity,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct RegexRule {
    pub pattern: String,
    pub severity: Severity,
    pub label: String,
}

#[derive(Debug)]
pub struct RuleSet {
    pub version: u32,
    pub tokens: Vec<TokenRule>,
    pub hashes: HashMap<String, String>,
    pub bad_names: HashSet<String>,
    pub regexes: Vec<RegexRule>,
}

#[derive(Debug, Deserialize)]
struct TokensFile {
    version: u32,
    #[serde(rename = "token", default)]
    token: Vec<TokenSpec>,
}

#[derive(Debug, Deserialize)]
struct TokenSpec {
    token: String,
    severity: SevSpec,
    label: String,
}

#[derive(Debug, Deserialize)]
struct HashesFile {
    version: u32,
    #[serde(rename = "hash", default)]
    hash: Vec<HashSpec>,
}

#[derive(Debug, Deserialize)]
struct HashSpec {
    sha256: String,
    label: String,
}

#[derive(Debug, Deserialize)]
struct BadNamesFile {
    version: u32,
    names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RegexesFile {
    version: u32,
    #[serde(rename = "regex", default)]
    regex: Vec<RegexSpec>,
}

#[derive(Debug, Deserialize)]
struct RegexSpec {
    pattern: String,
    severity: SevSpec,
    label: String,
}

impl RuleSet {
    /// Parse the embedded TOML. `version` is the max of the four files'
    /// versions (drives cache invalidation).
    pub fn embedded() -> anyhow::Result<Self> {
        let tokens_file: TokensFile = toml::from_str(TOKENS_TOML)?;
        let hashes_file: HashesFile = toml::from_str(HASHES_TOML)?;
        let bad_names_file: BadNamesFile = toml::from_str(BAD_NAMES_TOML)?;
        let regexes_file: RegexesFile = toml::from_str(REGEXES_TOML)?;

        let version = tokens_file
            .version
            .max(hashes_file.version)
            .max(bad_names_file.version)
            .max(regexes_file.version);

        let tokens = tokens_file
            .token
            .into_iter()
            .map(|t| TokenRule {
                token: t.token,
                severity: t.severity.into(),
                label: t.label,
            })
            .collect();

        let hashes = hashes_file
            .hash
            .into_iter()
            .map(|h| (h.sha256, h.label))
            .collect();

        let bad_names = bad_names_file.names.into_iter().collect();

        let regexes = regexes_file
            .regex
            .into_iter()
            .map(|r| RegexRule {
                pattern: r.pattern,
                severity: r.severity.into(),
                label: r.label,
            })
            .collect();

        Ok(RuleSet {
            version,
            tokens,
            hashes,
            bad_names,
            regexes,
        })
    }

    /// `embedded()` plus any extra bad-package names merged in from
    /// `<data_dir>/lists/known_bad.txt` (one name per line, `#` comments),
    /// written by `aurscan update-lists`. When present, `version` is bumped
    /// by the override file's mtime (as a Unix timestamp truncated to
    /// `u32`) so cache entries invalidate when the list changes.
    pub fn load(data_dir: Option<&std::path::Path>) -> anyhow::Result<Self> {
        let mut rule_set = Self::embedded()?;

        let Some(data_dir) = data_dir else {
            return Ok(rule_set);
        };
        let override_path = data_dir.join("lists").join("known_bad.txt");
        if !override_path.exists() {
            return Ok(rule_set);
        }

        let contents = std::fs::read_to_string(&override_path)?;
        for line in contents.lines() {
            let name = line.split('#').next().unwrap_or("").trim();
            if !name.is_empty() {
                rule_set.bad_names.insert(name.to_string());
            }
        }

        let mtime_secs = std::fs::metadata(&override_path)?
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        rule_set.version = rule_set.version.wrapping_add(mtime_secs as u32);

        Ok(rule_set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_parse() {
        let rs = RuleSet::embedded().unwrap();
        assert!(rs.tokens.iter().any(|t| t.token == "atomic-lockfile"));
        assert_eq!(rs.hashes.len(), 3);
        assert!(rs.bad_names.contains("runescape-launcher"));
        assert!(rs.bad_names.len() > 500);
        assert!(rs
            .regexes
            .iter()
            .all(|r| regex::Regex::new(&r.pattern).is_ok()));
    }

    #[test]
    fn load_merges_runtime_bad_name_overrides() {
        let data_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(data_dir.path().join("lists")).unwrap();
        std::fs::write(
            data_dir.path().join("lists").join("known_bad.txt"),
            "# comment\nsome-new-bad-package\n",
        )
        .unwrap();

        let embedded = RuleSet::embedded().unwrap();
        let loaded = RuleSet::load(Some(data_dir.path())).unwrap();

        assert!(loaded.bad_names.contains("some-new-bad-package"));
        assert!(loaded.bad_names.contains("runescape-launcher"));
        assert_ne!(loaded.version, embedded.version);
    }

    #[test]
    fn load_without_data_dir_matches_embedded() {
        let embedded = RuleSet::embedded().unwrap();
        let loaded = RuleSet::load(None).unwrap();
        assert_eq!(loaded.version, embedded.version);
        assert_eq!(loaded.bad_names, embedded.bad_names);
    }
}
