//! Walks a built `.pkg.tar.zst` and flags risky filesystem layout choices:
//! setuid/setgid bits, drops into persistence/privilege directories, hidden
//! dotfiles under system paths, and whitespace-containing binary names.

use std::path::Path;

use aurscan_core::{
    Confidence, Detector, DetectorId, DetectorResult, Evidence, Finding, ScanContext, ScanTarget,
    Severity,
};

/// Directories under which a dropped file is a persistence/privilege-escalation
/// tell (systemd units, cron drops, profile scripts, sudoers fragments).
const PERSISTENCE_DIRS: &[(&str, &str)] = &[
    ("usr/lib/systemd/system/", "systemd system unit"),
    ("etc/systemd/system/", "systemd system unit"),
    ("etc/cron.d/", "cron.d drop"),
    ("etc/cron.daily/", "cron.daily drop"),
    ("etc/profile.d/", "profile.d drop"),
    ("etc/sudoers.d/", "sudoers.d drop"),
];

/// Directories where a hidden (dot-prefixed) file is unusual enough to flag.
const SYSTEM_DIRS: &[&str] = &["etc/", "usr/bin/", "usr/sbin/", "usr/lib/"];

/// `wants()` only fires on the `.PKGINFO` member, which is always present
/// exactly once in a valid archive. That lets `scan()` walk the whole tar
/// in a single pass instead of re-opening (and re-decompressing) the archive
/// once per member — per-member header mode bits aren't otherwise reachable
/// through `ScanTarget::PackageFile`.
const SENTINEL_MEMBER: &str = ".PKGINFO";

pub struct ArchiveLayoutDetector;

impl ArchiveLayoutDetector {
    pub fn new() -> Self {
        Self
    }

    fn scan_archive(&self, archive: &Path, package: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let file = match std::fs::File::open(archive) {
            Ok(f) => f,
            Err(_) => return findings,
        };
        let decoder = match zstd::Decoder::new(file) {
            Ok(d) => d,
            Err(_) => return findings,
        };
        let mut ar = tar::Archive::new(decoder);
        let entries = match ar.entries() {
            Ok(e) => e,
            Err(_) => return findings,
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let mode = match entry.header().mode() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let path = match entry.path() {
                Ok(p) => p.into_owned(),
                Err(_) => continue,
            };
            let member = path.to_string_lossy().to_string();
            let basename = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            let location = format!("{}!{}", archive.display(), member);

            if mode & 0o4000 != 0 {
                findings.push(self.finding(
                    package,
                    Severity::High,
                    format!("setuid binary in package: {member}"),
                    &location,
                    &member,
                ));
            }
            if mode & 0o2000 != 0 {
                findings.push(self.finding(
                    package,
                    Severity::Medium,
                    format!("setgid binary in package: {member}"),
                    &location,
                    &member,
                ));
            }

            for (dir, category) in PERSISTENCE_DIRS {
                if member.starts_with(dir) {
                    findings.push(self.finding(
                        package,
                        Severity::Medium,
                        format!("installs into a persistence/privilege dir ({category}): {member}"),
                        &location,
                        &member,
                    ));
                }
            }

            if basename.starts_with('.') && SYSTEM_DIRS.iter().any(|d| member.starts_with(d)) {
                findings.push(self.finding(
                    package,
                    Severity::Medium,
                    format!("hidden dotfile in system path: {member}"),
                    &location,
                    &member,
                ));
            }

            if (member.starts_with("usr/bin/") || member.starts_with("usr/sbin/"))
                && basename.contains([' ', '\n'])
            {
                findings.push(self.finding(
                    package,
                    Severity::High,
                    format!("binary name contains whitespace: {member}"),
                    &location,
                    &member,
                ));
            }
        }

        findings
    }

    fn finding(
        &self,
        package: &str,
        severity: Severity,
        reason: String,
        location: &str,
        excerpt: &str,
    ) -> Finding {
        Finding {
            severity,
            confidence: Confidence::Heuristic,
            detector: self.id(),
            package: package.to_string(),
            reason,
            evidence: Evidence {
                location: location.to_string(),
                excerpt: excerpt.to_string(),
            },
        }
    }
}

impl Default for ArchiveLayoutDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ArchiveLayoutDetector {
    fn id(&self) -> DetectorId {
        DetectorId("archive_layout")
    }

    fn wants(&self, target: &ScanTarget) -> bool {
        matches!(target, ScanTarget::PackageFile { member, .. } if member == SENTINEL_MEMBER)
    }

    fn scan(&self, target: &ScanTarget, ctx: &ScanContext) -> DetectorResult {
        let findings = match target {
            ScanTarget::PackageFile { archive, .. } => self.scan_archive(archive, &ctx.package),
            _ => Vec::new(),
        };
        DetectorResult {
            findings,
            features: None,
        }
    }
}

// --- Contract assertions ---
#[cfg(test)]
mod contract {
    use super::*;

    fn _assert_detector(_: &dyn Detector) {}

    #[test]
    fn implements_detector() {
        fn assert_impl<T: Detector>() {}
        assert_impl::<ArchiveLayoutDetector>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkg(members: &[(&str, u32, &[u8])]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.pkg.tar.zst");
        let f = std::fs::File::create(&path).unwrap();
        let enc = zstd::Encoder::new(f, 0).unwrap().auto_finish();
        let mut ar = tar::Builder::new(enc);
        for (name, mode, data) in members {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_cksum();
            ar.append_data(&mut h, name, *data).unwrap();
        }
        ar.finish().unwrap();
        (dir, path)
    }

    fn scan_pkginfo(archive: &Path) -> DetectorResult {
        let det = ArchiveLayoutDetector::new();
        let target = ScanTarget::PackageFile {
            archive: archive.to_path_buf(),
            member: ".PKGINFO".to_string(),
        };
        let ctx = ScanContext {
            package: "x".to_string(),
            version: "1".to_string(),
            aur_meta: None,
        };
        assert!(det.wants(&target));
        det.scan(&target, &ctx)
    }

    #[test]
    fn setuid_binary_is_high() {
        let (_d, p) = make_pkg(&[
            (".PKGINFO", 0o644, b"pkgname=x\n"),
            ("usr/bin/tool", 0o4755, b"\x7fELFxx"),
        ]);
        let r = scan_pkginfo(&p);
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("setuid")));
    }

    #[test]
    fn drop_into_systemd_system_is_medium() {
        let (_d, p) = make_pkg(&[
            (".PKGINFO", 0o644, b"pkgname=x\n"),
            ("usr/lib/systemd/system/x.service", 0o644, b"[Service]\n"),
        ]);
        let r = scan_pkginfo(&p);
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::Medium && f.reason.contains("systemd")));
    }

    #[test]
    fn hidden_file_in_etc_is_medium() {
        let (_d, p) = make_pkg(&[
            (".PKGINFO", 0o644, b"pkgname=x\n"),
            ("etc/.hidden_cfg", 0o644, b"x"),
        ]);
        let r = scan_pkginfo(&p);
        assert!(r.findings.iter().any(|f| f.severity >= Severity::Medium));
    }

    #[test]
    fn ordinary_bin_package_is_clean() {
        let (_d, p) = make_pkg(&[
            (".PKGINFO", 0o644, b"pkgname=x\n"),
            ("usr/bin/tool", 0o755, b"\x7fELFxx"),
            ("usr/share/doc/x/README", 0o644, b"hi"),
        ]);
        assert!(scan_pkginfo(&p).findings.is_empty());
    }
}
