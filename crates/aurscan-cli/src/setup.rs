//! `aurscan setup`: install the two pieces a working paru + pacman
//! integration needs -- the `PreBuildCommand` snippet in `paru.conf` (so
//! `paru -S` scans PKGBUILDs/sources before building), and the ALPM
//! `PreTransaction` hook (so pacman scans built archives before installing
//! them). Idempotent: already-applied steps are reported and skipped.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const PARU_SNIPPET: &str = "PreBuildCommand = /usr/bin/aurscan check --hook .";
/// paru reads `PreBuildCommand` from `[bin]` only (`man paru.conf`, BIN
/// section). Under any other section it is silently ignored -- no warning,
/// no error, just an ungated system. Verified against paru v2.1.0.
const PARU_SECTION: &str = "[bin]";
const HOOK_TEXT: &str = include_str!("../../../data/aurscan.hook");
const HOOK_DEST: &str = "/etc/pacman.d/hooks/aurscan.hook";

/// Print/install the paru.conf snippet, then the ALPM hook. `assume_yes`
/// skips the confirm, so `aurscan setup --yes` is a one-liner suitable for
/// the message a package `post_install` prints.
pub fn run(assume_yes: bool) -> anyhow::Result<()> {
    setup_paru_conf(&paru_conf_path()?, assume_yes)?;
    install_hook(Path::new(HOOK_DEST))
}

/// `aurscan setup --check`: report whether the paru gate is actually live,
/// without changing anything. Exit non-zero when it is not, so scripts and
/// the post-install notice can branch on it.
pub fn check() -> i32 {
    let status = crate::paru_conf::status_for_invoking_user();
    if status.should_warn() {
        eprintln!("aurscan: {}", status.describe());
        eprintln!("aurscan: fix it with `aurscan setup`");
        return 1;
    }
    println!("aurscan: {}", status.describe());
    0
}

fn paru_conf_path() -> anyhow::Result<PathBuf> {
    dirs::config_dir()
        .map(|d| d.join("paru/paru.conf"))
        .ok_or_else(|| anyhow::anyhow!("could not determine the user config directory"))
}

/// Write the `PreBuildCommand` snippet under `[bin]` in `path`, after a y/N
/// confirm (skipped when `assume_yes`). Idempotent: an existing snippet in
/// the correct section is left alone.
///
/// Creating the file when it did not exist is the dangerous case. paru
/// resolves its config first-match-wins, so a brand-new user config makes
/// paru stop reading `/etc/paru.conf` entirely -- silently dropping the
/// distro defaults (`PgpFetch`, `Devel`, `Provides`, `DevelSuffixes`).
/// Losing `PgpFetch` alone is a security regression. We therefore seed a new
/// file with `Include = /etc/paru.conf`, which `man paru.conf` documents for
/// exactly this purpose.
fn setup_paru_conf(path: &Path, assume_yes: bool) -> anyhow::Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let entries = crate::paru_conf::find_gate_entries(&existing);

    if matches!(
        crate::paru_conf::classify(&entries, true),
        crate::paru_conf::GateStatus::Active
    ) {
        println!(
            "paru.conf: PreBuildCommand already active under [bin] at {}, skipping",
            path.display()
        );
        return Ok(());
    }

    // A snippet under the wrong section is worse than none: it looks
    // configured. Say so plainly rather than silently adding a second copy.
    if let Some(e) = entries.iter().find(|e| e.value.contains("aurscan")) {
        println!(
            "paru.conf: found PreBuildCommand under [{}], which paru ignores.\n  \
             Remove that line -- the correct one goes under [bin].",
            e.section
        );
    }

    let creating = !path.exists();
    println!("Add this under {PARU_SECTION} in {}:", path.display());
    println!("  {PARU_SNIPPET}");

    if !assume_yes && !confirm(&format!("Append it to {} now? [y/N] ", path.display())) {
        println!("paru.conf: not modified");
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if creating {
        writeln!(
            file,
            "# Created by `aurscan setup`. The Include keeps the distro\n\
             # defaults in /etc/paru.conf active: paru reads only the first\n\
             # config it finds, so without this line a new user config would\n\
             # silently replace them.\n\
             Include = /etc/paru.conf\n"
        )?;
    }
    writeln!(file, "{PARU_SECTION}\n{PARU_SNIPPET}")?;
    println!("paru.conf: appended PreBuildCommand under {PARU_SECTION}");
    Ok(())
}

/// Install the compiled-in ALPM hook to `dest`. Needs root; when not root,
/// print the exact `sudo install -Dm644` command instead of failing. Skips
/// (idempotently) when `dest` already holds the current hook text.
fn install_hook(dest: &Path) -> anyhow::Result<()> {
    if std::fs::read_to_string(dest)
        .map(|c| c == HOOK_TEXT)
        .unwrap_or(false)
    {
        println!("alpm hook: already installed at {}", dest.display());
        return Ok(());
    }

    if !is_root() {
        println!(
            "alpm hook: not root; install it with:\n  sudo install -Dm644 {} {}",
            hook_source_path().display(),
            dest.display()
        );
        return Ok(());
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(dest, HOOK_TEXT)?;
    println!("alpm hook: installed to {}", dest.display());
    Ok(())
}

/// The hook file's location in the installed package tree, for the printed
/// `sudo install` command (the compiled-in text is embedded from here).
fn hook_source_path() -> PathBuf {
    PathBuf::from("/usr/share/aurscan/aurscan.hook")
}

fn confirm(prompt: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok()
        && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Whether the current process is running as root, via `id -u` (no
/// additional dependency for a single euid check).
fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_paru_conf_skips_when_snippet_already_active_under_bin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("paru.conf");
        std::fs::write(&path, format!("[bin]\n{PARU_SNIPPET}\n")).unwrap();

        setup_paru_conf(&path, true).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches(PARU_SNIPPET).count(), 1);
    }

    #[test]
    fn setup_paru_conf_does_not_append_without_a_tty_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("paru.conf");
        std::fs::write(&path, "[options]\n").unwrap();

        setup_paru_conf(&path, false).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains(PARU_SNIPPET),
            "non-interactive test harness must not auto-confirm the append"
        );
    }

    #[test]
    fn setup_paru_conf_writes_the_snippet_under_bin_not_options() {
        // paru reads PreBuildCommand from [bin] only; under any other
        // section it is silently ignored and the system is left ungated.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("paru.conf");
        std::fs::write(&path, "[options]\nBottomUp\n").unwrap();

        setup_paru_conf(&path, true).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let entries = crate::paru_conf::find_gate_entries(&content);
        assert_eq!(
            crate::paru_conf::classify(&entries, true),
            crate::paru_conf::GateStatus::Active,
            "written config must leave the gate actually active, got:\n{content}"
        );
    }

    #[test]
    fn creating_a_new_config_preserves_the_system_config_via_include() {
        // paru resolves its config first-match-wins, so a brand-new user
        // config silently replaces /etc/paru.conf. Without the Include the
        // distro defaults (PgpFetch, Devel, Provides) are dropped.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("paru.conf");
        assert!(!path.exists());

        setup_paru_conf(&path, true).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("Include = /etc/paru.conf"),
            "a newly created user config must include the system config, got:\n{content}"
        );
    }

    #[test]
    fn appending_to_an_existing_config_does_not_add_an_include() {
        // The user already has a config; /etc/paru.conf was already being
        // ignored before we touched anything. Splicing it in now would
        // change their effective settings behind their back.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("paru.conf");
        std::fs::write(&path, "[options]\nBottomUp\n").unwrap();

        setup_paru_conf(&path, true).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("Include"), "got:\n{content}");
        assert!(
            content.contains("BottomUp"),
            "must preserve existing settings"
        );
    }

    #[test]
    fn install_hook_skips_when_already_installed_with_current_text() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("aurscan.hook");
        std::fs::write(&dest, HOOK_TEXT).unwrap();
        let before = std::fs::metadata(&dest).unwrap().modified().unwrap();

        install_hook(&dest).unwrap();

        let after = std::fs::metadata(&dest).unwrap().modified().unwrap();
        assert_eq!(
            before, after,
            "an up-to-date hook file must not be rewritten"
        );
    }
}
