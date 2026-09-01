use aurscan_llm::{BundleLimits, CoverageMode, DefaultRecipeBundleBuilder, RecipeBundleBuilder};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn write(root: &Path, path: &str, content: &[u8]) {
    let path = root.join(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn init_git(root: &Path) {
    git(root, &["init", "-q"]);
    git(root, &["config", "user.name", "Aurscan Test"]);
    git(root, &["config", "user.email", "aurscan@example.invalid"]);
    git(root, &["config", "commit.gpgsign", "false"]);
}

fn generous_limits() -> BundleLimits {
    BundleLimits {
        max_files: 64,
        max_file_bytes: 1024 * 1024,
        max_bundle_bytes: 2 * 1024 * 1024,
    }
}

#[test]
fn git_mode_uses_only_tracked_working_tree_files_and_excludes_srcinfo() {
    let dir = TempDir::new().unwrap();
    init_git(dir.path());
    write(dir.path(), "PKGBUILD", b"pkgname=old\n");
    write(dir.path(), "hooks/post.install", b"post_install() { :; }\n");
    write(dir.path(), ".SRCINFO", b"pkgbase = ignored\n");
    write(dir.path(), "nested/.SRCINFO", b"pkgbase = ignored-too\n");
    git(
        dir.path(),
        &[
            "add",
            "PKGBUILD",
            "hooks/post.install",
            ".SRCINFO",
            "nested/.SRCINFO",
        ],
    );
    git(dir.path(), &["commit", "-qm", "recipe"]);
    write(dir.path(), "PKGBUILD", b"pkgname=working-tree\n");
    write(dir.path(), "untracked.patch", b"do not transmit\n");

    let bundle = DefaultRecipeBundleBuilder
        .build(dir.path(), "demo", generous_limits())
        .unwrap();

    assert_eq!(bundle.coverage.mode, CoverageMode::GitTracked);
    assert_eq!(bundle.aur_commit.as_deref().map(str::len), Some(40));
    assert_eq!(
        bundle
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec!["PKGBUILD", "hooks/post.install"]
    );
    assert_eq!(bundle.files[0].content, "pkgname=working-tree\n");
    assert_eq!(bundle.coverage.included_files, 2);
}

#[test]
fn local_mode_is_conservative_and_supports_nested_approved_suffixes() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "PKGBUILD", b"pkgname=demo\n");
    write(dir.path(), "demo.install", b"post_install() { :; }\n");
    write(dir.path(), "patches/fix.patch", b"--- a\n+++ b\n");
    write(dir.path(), "change.diff", b"diff --git a b\n");
    write(dir.path(), ".SRCINFO", b"pkgbase = demo\n");
    write(dir.path(), "secret.txt", b"private\n");
    write(dir.path(), "downloaded/source.c", b"untrusted upstream\n");

    let bundle = DefaultRecipeBundleBuilder
        .build(dir.path(), "demo", generous_limits())
        .unwrap();

    assert_eq!(bundle.coverage.mode, CoverageMode::ConservativeLocal);
    assert_eq!(bundle.aur_commit, None);
    assert_eq!(
        bundle
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "PKGBUILD",
            "change.diff",
            "demo.install",
            "patches/fix.patch"
        ]
    );
}

#[cfg(unix)]
#[test]
fn final_component_symlinks_are_never_followed_and_are_reported() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    init_git(dir.path());
    write(dir.path(), "PKGBUILD", b"pkgname=demo\n");
    write(outside.path(), "secret", b"must not be read\n");
    symlink(
        outside.path().join("secret"),
        dir.path().join("escape.patch"),
    )
    .unwrap();
    git(dir.path(), &["add", "PKGBUILD", "escape.patch"]);

    let bundle = DefaultRecipeBundleBuilder
        .build(dir.path(), "demo", generous_limits())
        .unwrap();

    assert_eq!(bundle.files.len(), 1);
    assert_eq!(bundle.coverage.excluded_symlinks, vec!["escape.patch"]);
    assert!(!bundle.files[0].content.contains("must not be read"));
}

#[cfg(unix)]
#[test]
fn a_symlinked_ancestor_is_rejected_without_reading_outside_the_root() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    init_git(dir.path());
    write(dir.path(), "PKGBUILD", b"pkgname=demo\n");
    write(dir.path(), "tracked/inside.patch", b"tracked content\n");
    git(dir.path(), &["add", "PKGBUILD", "tracked/inside.patch"]);

    fs::remove_dir_all(dir.path().join("tracked")).unwrap();
    write(
        outside.path(),
        "inside.patch",
        b"outside secret must not be read\n",
    );
    symlink(outside.path(), dir.path().join("tracked")).unwrap();

    let error = DefaultRecipeBundleBuilder
        .build(dir.path(), "demo", generous_limits())
        .unwrap_err();

    assert!(
        error.to_string().contains("ancestor") || error.to_string().contains("symlink"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn binary_and_non_utf8_files_are_excluded_and_reported() {
    let dir = TempDir::new().unwrap();
    init_git(dir.path());
    write(dir.path(), "PKGBUILD", b"pkgname=demo\n");
    write(dir.path(), "nul.helper", b"before\0after");
    write(dir.path(), "invalid.helper", &[0xff, 0xfe]);
    git(
        dir.path(),
        &["add", "PKGBUILD", "nul.helper", "invalid.helper"],
    );

    let bundle = DefaultRecipeBundleBuilder
        .build(dir.path(), "demo", generous_limits())
        .unwrap();

    assert_eq!(bundle.files.len(), 1);
    assert_eq!(
        bundle.coverage.excluded_binary_files,
        vec!["invalid.helper", "nul.helper"]
    );
}

#[test]
fn files_are_sorted_bytewise_and_hash_is_explicitly_length_framed() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "z.patch", b"z\n");
    write(dir.path(), "PKGBUILD", b"pkgname=x\n");
    write(dir.path(), "a.install", b"a\n");

    let bundle = DefaultRecipeBundleBuilder
        .build(dir.path(), "demo", generous_limits())
        .unwrap();

    let mut hasher = blake3::Hasher::new();
    for file in &bundle.files {
        let path = file.path.as_bytes();
        let content = file.content.as_bytes();
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path);
        hasher.update(&(content.len() as u64).to_le_bytes());
        hasher.update(content);
    }
    assert_eq!(bundle.content_hash, *hasher.finalize().as_bytes());

    // These two unframed sequences are identical; framed hashes must differ.
    let first = [("PKGBUILD", "a"), ("b.patch", "c")];
    let second = [("PKGBUILD", "ab"), (".patch", "c")];
    fn framed(files: &[(&str, &str)]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for (path, content) in files {
            hasher.update(&(path.len() as u64).to_le_bytes());
            hasher.update(path.as_bytes());
            hasher.update(&(content.len() as u64).to_le_bytes());
            hasher.update(content.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }
    assert_ne!(framed(&first), framed(&second));
}

#[test]
fn missing_pkgbuild_is_rejected() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "only.patch", b"patch\n");
    let error = DefaultRecipeBundleBuilder
        .build(dir.path(), "demo", generous_limits())
        .unwrap_err();
    assert!(error.to_string().contains("PKGBUILD"));
}

#[test]
fn file_count_limit_rejects_the_whole_bundle() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "PKGBUILD", b"x\n");
    write(dir.path(), "one.patch", b"1\n");
    let error = DefaultRecipeBundleBuilder
        .build(
            dir.path(),
            "demo",
            BundleLimits {
                max_files: 1,
                ..generous_limits()
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("file count"));
}

#[test]
fn per_file_limit_rejects_the_whole_bundle() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "PKGBUILD", b"12345");
    let error = DefaultRecipeBundleBuilder
        .build(
            dir.path(),
            "demo",
            BundleLimits {
                max_file_bytes: 4,
                ..generous_limits()
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("per-file"));
}

#[test]
fn aggregate_limit_rejects_the_whole_bundle() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "PKGBUILD", b"1234");
    write(dir.path(), "one.patch", b"5678");
    let error = DefaultRecipeBundleBuilder
        .build(
            dir.path(),
            "demo",
            BundleLimits {
                max_bundle_bytes: 7,
                ..generous_limits()
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("aggregate"));
}
