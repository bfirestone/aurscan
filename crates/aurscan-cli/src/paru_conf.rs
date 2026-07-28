//! Detects whether paru's `PreBuildCommand` gate is actually active.
//!
//! This module exists because the gate fails *silently*. paru reads
//! `PreBuildCommand` only from the `[bin]` section, and resolves its config
//! first-match-wins rather than merging: a user config shadows
//! `/etc/paru.conf` entirely. A gate written to the wrong section, or
//! shadowed by a user config, leaves aurscan installed and paru building
//! unscanned packages with no error anywhere -- indistinguishable, from the
//! outside, from a clean scan.
//!
//! Verified against paru v2.1.0 (2026-07-27); see `docs/integration.md`.

use std::path::{Path, PathBuf};

/// The section paru actually reads `PreBuildCommand` from.
pub const GATE_SECTION: &str = "bin";
pub const GATE_KEY: &str = "PreBuildCommand";

/// What we found when looking for the gate in the effective paru config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateStatus {
    /// `PreBuildCommand` is in `[bin]` and invokes aurscan. Gate is live.
    Active,
    /// Present, but under a section paru ignores for this key -- the exact
    /// silent-failure mode. Worth a distinct message: the user believes they
    /// are protected.
    WrongSection { section: String },
    /// Present in `[bin]`, but runs something that is not aurscan. The user
    /// has their own tooling wired in; not our business to nag about.
    ForeignCommand { command: String },
    /// No `PreBuildCommand` anywhere in the effective config.
    Missing,
    /// No paru config file found at all.
    NoConfig,
}

impl GateStatus {
    /// Whether this state should produce a warning on pacman transactions.
    ///
    /// `ForeignCommand` deliberately does not warn: the user has wired a
    /// different pre-build command on purpose, and nagging them every
    /// transaction would be noise. `NoConfig` does warn -- paru with no
    /// config is ungated just the same.
    pub fn should_warn(&self) -> bool {
        !matches!(self, GateStatus::Active | GateStatus::ForeignCommand { .. })
    }

    /// A short, actionable explanation for the user.
    pub fn describe(&self) -> String {
        match self {
            GateStatus::Active => "paru PreBuildCommand gate is active".to_string(),
            GateStatus::WrongSection { section } => format!(
                "PreBuildCommand is under [{section}], but paru only reads it from [{GATE_SECTION}] -- \
                 paru is SILENTLY IGNORING it and building AUR packages unscanned"
            ),
            GateStatus::ForeignCommand { command } => {
                format!("PreBuildCommand is set to a non-aurscan command: {command}")
            }
            GateStatus::Missing => {
                "no PreBuildCommand in paru.conf -- AUR builds are not scanned before makepkg runs"
                    .to_string()
            }
            GateStatus::NoConfig => {
                "no paru config found -- AUR builds are not scanned before makepkg runs".to_string()
            }
        }
    }
}

/// One `Key = Value` occurrence, tagged with the section it appeared under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub section: String,
    pub value: String,
}

/// Resolve paru's effective config path, mirroring paru's own documented
/// order: `$PARU_CONF`, then `$XDG_CONFIG_HOME/paru/paru.conf`, then
/// `$HOME/.config/paru/paru.conf`, then `/etc/paru.conf`. First match wins;
/// paru does not merge them.
pub fn resolve_config_path(
    paru_conf: Option<&str>,
    xdg_config_home: Option<&str>,
    home: Option<&str>,
    etc: &Path,
) -> Option<PathBuf> {
    let candidates = [
        paru_conf.map(PathBuf::from),
        xdg_config_home.map(|d| Path::new(d).join("paru/paru.conf")),
        home.map(|h| Path::new(h).join(".config/paru/paru.conf")),
    ];
    for c in candidates.into_iter().flatten() {
        if c.is_file() {
            return Some(c);
        }
    }
    etc.is_file().then(|| etc.to_path_buf())
}

/// Read a config, splicing `Include = <path>` directives in place the way
/// pacman.conf-style parsing does, so section context carries across the
/// include boundary. `depth` bounds include recursion.
pub fn read_with_includes(path: &Path, depth: u8) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    if depth == 0 {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if let Some(target) = parse_key(line, "Include") {
            out.push_str(&read_with_includes(Path::new(target.trim()), depth - 1));
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Split `Key = Value` on a config line, returning the value when the key
/// matches (case-insensitively, as pacman-style parsers do).
fn parse_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let line = line.split('#').next()?.trim();
    let (k, v) = line.split_once('=')?;
    k.trim().eq_ignore_ascii_case(key).then(|| v.trim())
}

/// Every `PreBuildCommand` in the config, tagged with its enclosing section.
/// Section-aware because *which* section it lands in is the whole question.
pub fn find_gate_entries(text: &str) -> Vec<Entry> {
    let mut section = String::new();
    let mut found = Vec::new();
    for line in text.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if let Some(name) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        if let Some(value) = parse_key(line, GATE_KEY) {
            found.push(Entry {
                section: section.clone(),
                value: value.to_string(),
            });
        }
    }
    found
}

/// Classify the gate from the entries found in the effective config.
///
/// An `Active` entry (correct section, invokes aurscan) wins outright: a
/// stray copy under the wrong section is harmless once a working one exists.
/// Otherwise a misplaced entry is the most useful thing to report, because
/// it is the state the user is most likely to mistake for protection.
pub fn classify(entries: &[Entry], had_config: bool) -> GateStatus {
    if !had_config {
        return GateStatus::NoConfig;
    }
    fn in_section(e: &Entry) -> bool {
        e.section == GATE_SECTION
    }
    fn is_ours(e: &Entry) -> bool {
        e.value.contains("aurscan")
    }

    if entries.iter().any(|e| in_section(e) && is_ours(e)) {
        return GateStatus::Active;
    }
    if let Some(e) = entries.iter().find(|e| !in_section(e) && is_ours(e)) {
        return GateStatus::WrongSection {
            section: e.section.clone(),
        };
    }
    if let Some(e) = entries.iter().find(|e| in_section(e)) {
        return GateStatus::ForeignCommand {
            command: e.value.clone(),
        };
    }
    GateStatus::Missing
}

/// Home directory for `user`, read from `/etc/passwd`. Needed because the
/// ALPM hook runs as root via sudo, but the config that matters belongs to
/// the *invoking* user -- root's own paru config is irrelevant.
pub fn home_for_user(passwd: &str, user: &str) -> Option<String> {
    passwd.lines().find_map(|line| {
        let mut f = line.split(':');
        (f.next()? == user).then(|| f.nth(4).map(str::to_string))?
    })
}

/// Determine the gate status for the user who invoked the current process,
/// preferring `SUDO_USER` (set when paru escalates to run pacman).
pub fn status_for_invoking_user() -> GateStatus {
    let sudo_user = std::env::var("SUDO_USER").ok();
    let home = match &sudo_user {
        Some(u) => std::fs::read_to_string("/etc/passwd")
            .ok()
            .and_then(|p| home_for_user(&p, u)),
        None => std::env::var("HOME").ok(),
    };
    // $PARU_CONF and $XDG_CONFIG_HOME belong to the invoking user's session;
    // under sudo they are normally scrubbed, so fall back to the home path.
    let paru_conf = sudo_user
        .is_none()
        .then(|| std::env::var("PARU_CONF").ok())
        .flatten();
    let xdg = sudo_user
        .is_none()
        .then(|| std::env::var("XDG_CONFIG_HOME").ok())
        .flatten();

    let path = resolve_config_path(
        paru_conf.as_deref(),
        xdg.as_deref(),
        home.as_deref(),
        Path::new("/etc/paru.conf"),
    );
    match path {
        Some(p) => classify(&find_gate_entries(&read_with_includes(&p, 4)), true),
        None => GateStatus::NoConfig,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(text: &str) -> Vec<Entry> {
        find_gate_entries(text)
    }

    #[test]
    fn gate_in_bin_section_is_active() {
        let e = entries("[bin]\nPreBuildCommand = /usr/bin/aurscan check --hook .\n");
        assert_eq!(classify(&e, true), GateStatus::Active);
    }

    #[test]
    fn gate_in_options_section_is_flagged_as_misplaced() {
        // The exact bug shipped in v0.1.0: paru silently ignores this.
        let e = entries("[options]\nPreBuildCommand = /usr/bin/aurscan check --hook .\n");
        assert_eq!(
            classify(&e, true),
            GateStatus::WrongSection {
                section: "options".into()
            }
        );
        assert!(classify(&e, true).should_warn());
    }

    #[test]
    fn a_correct_entry_wins_over_a_stray_misplaced_one() {
        let e = entries(
            "[options]\nPreBuildCommand = /usr/bin/aurscan check --hook .\n\
             [bin]\nPreBuildCommand = /usr/bin/aurscan check --hook .\n",
        );
        assert_eq!(classify(&e, true), GateStatus::Active);
    }

    #[test]
    fn foreign_command_is_reported_but_does_not_warn() {
        let e = entries("[bin]\nPreBuildCommand = /usr/local/bin/my-own-check\n");
        let status = classify(&e, true);
        assert!(matches!(status, GateStatus::ForeignCommand { .. }));
        assert!(
            !status.should_warn(),
            "a deliberately-chosen third-party gate must not nag every transaction"
        );
    }

    #[test]
    fn absent_gate_and_absent_config_both_warn() {
        assert_eq!(classify(&[], true), GateStatus::Missing);
        assert_eq!(classify(&[], false), GateStatus::NoConfig);
        assert!(classify(&[], true).should_warn());
        assert!(classify(&[], false).should_warn());
    }

    #[test]
    fn section_headers_are_matched_case_insensitively_and_comments_ignored() {
        let e = entries("[BIN]\n# PreBuildCommand = /usr/bin/aurscan disabled\nPreBuildCommand = /usr/bin/aurscan check --hook .\n");
        assert_eq!(e.len(), 1, "commented-out entries must not count");
        assert_eq!(classify(&e, true), GateStatus::Active);
    }

    #[test]
    fn include_splices_content_and_preserves_section_context() {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path().join("system.conf");
        std::fs::write(
            &sys,
            "[bin]\nPreBuildCommand = /usr/bin/aurscan check --hook .\n",
        )
        .unwrap();
        let user = dir.path().join("paru.conf");
        std::fs::write(
            &user,
            format!("Include = {}\n[options]\nBottomUp\n", sys.display()),
        )
        .unwrap();

        let text = read_with_includes(&user, 4);
        assert_eq!(
            classify(&find_gate_entries(&text), true),
            GateStatus::Active
        );
    }

    #[test]
    fn resolve_prefers_user_config_over_etc_matching_parus_first_match_wins() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".config/paru")).unwrap();
        let user_conf = home.join(".config/paru/paru.conf");
        std::fs::write(&user_conf, "[options]\n").unwrap();
        let etc = dir.path().join("etc-paru.conf");
        std::fs::write(&etc, "[bin]\n").unwrap();

        let got = resolve_config_path(None, None, Some(home.to_str().unwrap()), &etc);
        assert_eq!(got, Some(user_conf));
    }

    #[test]
    fn resolve_falls_back_to_etc_when_no_user_config_exists() {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc-paru.conf");
        std::fs::write(&etc, "[bin]\n").unwrap();
        let got = resolve_config_path(None, None, Some(dir.path().to_str().unwrap()), &etc);
        assert_eq!(got, Some(etc));
    }

    #[test]
    fn home_for_user_parses_passwd() {
        let passwd = "root:x:0:0::/root:/bin/bash\nben:x:1000:1000::/home/ben:/bin/zsh\n";
        assert_eq!(home_for_user(passwd, "ben"), Some("/home/ben".to_string()));
        assert_eq!(home_for_user(passwd, "nobody"), None);
    }
}
