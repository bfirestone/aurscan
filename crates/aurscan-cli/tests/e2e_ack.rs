//! The acknowledgement loop, end to end through the compiled binary: a
//! finding that prompted once must stay silent (and stop gating) after
//! `aurscan ack --yes`, within the same isolated config home.

use std::path::Path;
use std::process::Command;

fn run(args: &[&str], target: &Path, home: &Path) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_aurscan"))
        .args(args)
        .arg(target)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .expect("failed to launch aurscan binary");
    (
        output.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn acked_advisory_stops_gating_and_prompting() {
    // Regression: `aurscan ack` did not exist despite both gates directing
    // users to it, and the AckStore it would have written only hid text --
    // verdicts, exit codes, and the paru prompt still counted the finding.
    let home = tempfile::tempdir().expect("tempdir");
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("PKGBUILD"),
        "pkgname=adv\npkgver=1\npkgrel=1\narch=('x86_64')\n\
         package() {\n  eval \"$(generate-completions)\"\n}\n",
    )
    .unwrap();

    let (code, _) = run(&["--no-color", "check"], dir.path(), home.path());
    assert_eq!(code, 1, "the advisory must gate before it is acked");

    let (code, out) = run(&["--no-color", "ack", "--yes"], dir.path(), home.path());
    assert_eq!(code, 0, "ack must succeed, got:\n{out}");
    assert!(out.contains("acknowledged 1 finding"), "got:\n{out}");

    let (code, out) = run(&["--no-color", "check"], dir.path(), home.path());
    assert_eq!(code, 0, "an acked advisory must stop gating, got:\n{out}");
    assert!(out.contains("(1 acknowledged)"), "got:\n{out}");

    let (code, _) = run(&["--no-color", "check", "--hook"], dir.path(), home.path());
    assert_eq!(code, 0, "the paru gate must pass silently once acked");
}

#[test]
fn ack_refuses_silently_acking_without_a_terminal_or_yes() {
    let home = tempfile::tempdir().expect("tempdir");
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("PKGBUILD"),
        "pkgname=adv\npkgver=1\npkgrel=1\narch=('x86_64')\n\
         package() {\n  eval \"$(generate-completions)\"\n}\n",
    )
    .unwrap();

    let (code, out) = run(&["--no-color", "ack"], dir.path(), home.path());
    assert_ne!(code, 0, "no tty and no --yes must not ack, got:\n{out}");

    let (code, _) = run(&["--no-color", "check"], dir.path(), home.path());
    assert_eq!(code, 1, "nothing may have been acknowledged");
}
