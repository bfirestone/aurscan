//! Host-side persistence and post-exploitation artifact checks (audit mode).
//!
//! Ports the legacy Python `scan_systemd_persistence` and `scan_host_artifacts`
//! heuristics (see `legacy/aurscan.py` lines ~318-456) to a `Detector` that
//! operates on `ScanTarget::HostArtifact`.

use aurscan_core::{
    Confidence, Detector, DetectorId, DetectorResult, Evidence, Finding, ScanContext, ScanTarget,
    Severity,
};

/// Binary locations a systemd unit's `ExecStart` is expected to live under.
/// An `ExecStart` pointing outside these is the suspicious tell the legacy
/// malware signature exhibits.
const TRUSTED_PREFIXES: &[&str] = &["/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/"];

/// Filename prefix of the eBPF rootkit pin artifact the payload leaves under
/// `/sys/fs/bpf` (ported from legacy `HOST_ARTIFACT_GLOBS`: `("/sys/fs/bpf",
/// "hidden_*")`).
const EBPF_PIN_PREFIX: &str = "hidden_";

pub struct PersistenceDetector;

impl PersistenceDetector {
    pub fn new() -> Self {
        Self
    }

    fn finding(
        &self,
        package: &str,
        severity: Severity,
        reason: String,
        location: &str,
    ) -> Finding {
        Finding {
            severity,
            confidence: Confidence::Heuristic,
            detector: self.id(),
            package: package.to_string(),
            reason,
            evidence: Evidence {
                location: location.to_string(),
                excerpt: location.to_string(),
            },
        }
    }

    /// Strip systemd's leading special-execution prefix characters (`-@+!:`)
    /// from an `ExecStart=` value, then return the first whitespace-delimited
    /// token (the binary path), as legacy does.
    fn exec_start_binary(exec_start: &str) -> Option<&str> {
        let stripped = exec_start
            .trim_start_matches(['-', '@', '+', '!', ':'])
            .trim_start();
        stripped.split_whitespace().next()
    }

    fn scan_systemd_unit(&self, path: &std::path::Path, package: &str) -> Vec<Finding> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut restart = String::new();
        let mut restart_sec = String::new();
        let mut exec_start = String::new();
        for line in content.lines() {
            let s = line.trim();
            if let Some(v) = s.strip_prefix("Restart=") {
                restart = v.trim().to_string();
            } else if let Some(v) = s.strip_prefix("RestartSec=") {
                restart_sec = v.trim().to_string();
            } else if exec_start.is_empty() {
                if let Some(v) = s.strip_prefix("ExecStart=") {
                    exec_start = v.trim().to_string();
                }
            }
        }

        let tells = restart == "always" && (restart_sec == "30" || restart_sec == "30s");
        if !tells {
            return Vec::new();
        }

        let binary = Self::exec_start_binary(&exec_start).unwrap_or("");
        let suspicious_path =
            !binary.is_empty() && !TRUSTED_PREFIXES.iter().any(|p| binary.starts_with(p));

        let location = format!(
            "{}  ExecStart={}",
            path.display(),
            if binary.is_empty() { "?" } else { binary }
        );

        if suspicious_path {
            vec![self.finding(
                package,
                Severity::High,
                "systemd unit matches malware persistence pattern (Restart=always, \
                 RestartSec=30, ExecStart outside trusted system dirs)"
                    .to_string(),
                &location,
            )]
        } else {
            vec![self.finding(
                package,
                Severity::Info,
                "systemd unit has Restart=always + RestartSec=30 (common in legit units; \
                 verify ExecStart)"
                    .to_string(),
                &location,
            )]
        }
    }

    fn scan_host_artifact(&self, path: &std::path::Path, package: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let basename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if basename.starts_with(EBPF_PIN_PREFIX) {
            findings.push(self.finding(
                package,
                Severity::Critical,
                "eBPF rootkit pin artifact present".to_string(),
                &path.display().to_string(),
            ));
        }

        if path.extension().and_then(|e| e.to_str()) == Some("service") {
            findings.extend(self.scan_systemd_unit(path, package));
        }

        findings
    }
}

impl Default for PersistenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PersistenceDetector {
    fn id(&self) -> DetectorId {
        DetectorId("persistence")
    }

    fn wants(&self, target: &ScanTarget) -> bool {
        matches!(target, ScanTarget::HostArtifact { .. })
    }

    fn scan(&self, target: &ScanTarget, ctx: &ScanContext) -> DetectorResult {
        let findings = match target {
            ScanTarget::HostArtifact { path } => self.scan_host_artifact(path, &ctx.package),
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
        assert_impl::<PersistenceDetector>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebpf_pin_named_hidden_is_critical() {
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("hidden_rk");
        std::fs::write(&pin, b"").unwrap();
        let det = PersistenceDetector::new();
        let r = det.scan(
            &ScanTarget::HostArtifact { path: pin.clone() },
            &ScanContext {
                package: "<host>".into(),
                version: "".into(),
                aur_meta: None,
            },
        );
        assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn malware_signature_unit_is_high() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("x.service");
        std::fs::write(
            &unit,
            "[Service]\nRestart=always\nRestartSec=30\nExecStart=/var/lib/.h\n",
        )
        .unwrap();
        let det = PersistenceDetector::new();
        let r = det.scan(
            &ScanTarget::HostArtifact { path: unit.clone() },
            &ScanContext {
                package: "<host>".into(),
                version: "".into(),
                aur_meta: None,
            },
        );
        assert!(r.findings.iter().any(|f| f.severity >= Severity::High));
    }

    #[test]
    fn normal_unit_is_info_or_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("ok.service");
        std::fs::write(
            &unit,
            "[Service]\nRestart=always\nRestartSec=30\nExecStart=/usr/bin/foo\n",
        )
        .unwrap();
        let det = PersistenceDetector::new();
        let r = det.scan(
            &ScanTarget::HostArtifact { path: unit },
            &ScanContext {
                package: "<host>".into(),
                version: "".into(),
                aur_meta: None,
            },
        );
        assert!(r.findings.iter().all(|f| f.severity <= Severity::Info));
    }
}
