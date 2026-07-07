//! `update-lists`: refresh the runtime known-bad-package-name override that
//! `aurscan_detectors::rules::RuleSet::load` merges into the embedded
//! ruleset on every scan.

use std::path::PathBuf;

/// The legacy consolidated bad-package-name list (`aur-malware-check`).
const DEFAULT_LIST_URL: &str =
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/main/package_list.txt";

/// Fetch `DEFAULT_LIST_URL` and write it to
/// `~/.local/share/aurscan/lists/known_bad.txt`, printing the number of
/// names written.
pub fn update() -> anyhow::Result<()> {
    let body = ureq::get(DEFAULT_LIST_URL).call()?.into_string()?;
    let count = body.lines().filter(|l| !l.trim().is_empty()).count();

    let path = list_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, &body)?;

    println!("aurscan: updated {count} known-bad package name(s)");
    Ok(())
}

fn list_path() -> anyhow::Result<PathBuf> {
    dirs::data_dir()
        .map(|d| d.join("aurscan/lists/known_bad.txt"))
        .ok_or_else(|| anyhow::anyhow!("could not determine the user data directory"))
}
