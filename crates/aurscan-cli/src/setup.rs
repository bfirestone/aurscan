//! `aurscan setup`: install the two pieces a working paru + pacman
//! integration needs -- the `PreBuildCommand` snippet in `paru.conf` (so
//! `paru -S` scans PKGBUILDs/sources before building), and the ALPM
//! `PreTransaction` hook (so pacman scans built archives before installing
//! them). Idempotent: already-applied steps are reported and skipped.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const PARU_SNIPPET: &str = "PreBuildCommand = /usr/bin/aurscan check --hook .";
const HOOK_TEXT: &str = include_str!("../../../data/aurscan.hook");
const HOOK_DEST: &str = "/etc/pacman.d/hooks/aurscan.hook";

/// Print/install the paru.conf snippet, then the ALPM hook.
pub fn run() -> anyhow::Result<()> {
    setup_paru_conf(&paru_conf_path()?)?;
    install_hook(Path::new(HOOK_DEST))
}

fn paru_conf_path() -> anyhow::Result<PathBuf> {
    dirs::config_dir()
        .map(|d| d.join("paru/paru.conf"))
        .ok_or_else(|| anyhow::anyhow!("could not determine the user config directory"))
}

/// Print the `PreBuildCommand` snippet for the user to add under
/// `[options]`, offering to append it to `path` after a y/N confirm. Skips
/// (idempotently) when the snippet is already present.
fn setup_paru_conf(path: &Path) -> anyhow::Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    if existing.contains(PARU_SNIPPET) {
        println!(
            "paru.conf: PreBuildCommand already present at {}, skipping",
            path.display()
        );
        return Ok(());
    }

    println!("Add this line under [options] in {}:", path.display());
    println!("  {PARU_SNIPPET}");

    if !confirm(&format!("Append it to {} now? [y/N] ", path.display())) {
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
    writeln!(file, "{PARU_SNIPPET}")?;
    println!("paru.conf: appended PreBuildCommand");
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
    fn setup_paru_conf_skips_when_snippet_already_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("paru.conf");
        std::fs::write(&path, format!("[options]\n{PARU_SNIPPET}\n")).unwrap();

        setup_paru_conf(&path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches(PARU_SNIPPET).count(), 1);
    }

    #[test]
    fn setup_paru_conf_does_not_append_without_a_tty_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("paru.conf");
        std::fs::write(&path, "[options]\n").unwrap();

        setup_paru_conf(&path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains(PARU_SNIPPET),
            "non-interactive test harness must not auto-confirm the append"
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
