//! SHA-256 matching of file contents (and archive members) against a
//! curated list of known-malicious payload hashes. Files larger than the
//! size cap are skipped without hashing — legacy payloads are ~3MB.

use aurscan_core::target::read_archive_member;
use aurscan_core::{
    Confidence, Detector, DetectorId, DetectorResult, Evidence, Finding, ScanContext, ScanTarget,
    Severity,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Payloads are hashed up to this size; larger files are skipped entirely.
const MAX_HASH_BYTES: u64 = 16 * 1024 * 1024;

pub struct PayloadHashesDetector {
    hashes: HashMap<String, String>,
}

impl PayloadHashesDetector {
    pub fn new(rules: &crate::rules::RuleSet) -> Self {
        Self {
            hashes: rules.hashes.clone(),
        }
    }

    /// Bytes to hash and their evidence location, or `None` when the
    /// target is out of scope or over the size cap.
    fn bytes_for(target: &ScanTarget) -> Option<(Vec<u8>, String)> {
        match target {
            ScanTarget::SourceFile { path, .. } | ScanTarget::HostArtifact { path } => {
                let meta = std::fs::metadata(path).ok()?;
                if meta.len() > MAX_HASH_BYTES {
                    return None;
                }
                let bytes = std::fs::read(path).ok()?;
                Some((bytes, path.display().to_string()))
            }
            ScanTarget::PackageFile { archive, member } => {
                let bytes = read_archive_member(archive, member, MAX_HASH_BYTES).ok()?;
                Some((bytes, format!("{}!{member}", archive.display())))
            }
            ScanTarget::BuildScript { .. } => None,
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Detector for PayloadHashesDetector {
    fn id(&self) -> DetectorId {
        DetectorId("payload_hashes")
    }

    fn wants(&self, target: &ScanTarget) -> bool {
        matches!(
            target,
            ScanTarget::SourceFile { .. } | ScanTarget::PackageFile { .. } | ScanTarget::HostArtifact { .. }
        )
    }

    fn scan(&self, target: &ScanTarget, ctx: &ScanContext) -> DetectorResult {
        let Some((bytes, location)) = Self::bytes_for(target) else {
            return DetectorResult::default();
        };

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hex_digest(&hasher.finalize());

        let findings = match self.hashes.get(&digest) {
            Some(label) => vec![Finding {
                severity: Severity::Critical,
                confidence: Confidence::Exact,
                detector: self.id(),
                package: ctx.package.clone(),
                reason: format!("Malware payload: {label}"),
                evidence: Evidence {
                    location,
                    excerpt: digest,
                },
            }],
            None => Vec::new(),
        };

        DetectorResult {
            findings,
            features: None,
        }
    }
}

// --- Contract assertions ---
const _: fn() = || {
    fn is_detector<T: aurscan_core::Detector>() {}
    is_detector::<PayloadHashesDetector>();
};

#[cfg(test)]
mod tests {
    use aurscan_core::{Confidence, Detector, ScanContext, ScanTarget, Severity, SourceOrigin};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    use super::PayloadHashesDetector;

    fn ctx() -> ScanContext {
        ScanContext {
            package: "x".into(),
            version: "1".into(),
            aur_meta: None,
        }
    }

    fn rules_with_hashes(hashes: HashMap<String, String>) -> crate::rules::RuleSet {
        crate::rules::RuleSet {
            version: 1,
            tokens: Vec::new(),
            hashes,
            bad_names: Default::default(),
            regexes: Vec::new(),
        }
    }

    #[test]
    fn matches_known_hash() {
        let content = b"totally-legit-payload-bytes";
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        let mut hashes = HashMap::new();
        hashes.insert(digest, "test malware payload".to_string());
        let rules = rules_with_hashes(hashes);
        let det = PayloadHashesDetector::new(&rules);

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("payload.bin");
        std::fs::write(&p, content).unwrap();
        let t = ScanTarget::SourceFile {
            path: p.clone(),
            origin: SourceOrigin::LocalFile,
        };

        let res = det.scan(&t, &ctx());
        assert_eq!(res.findings.len(), 1);
        assert_eq!(res.findings[0].severity, Severity::Critical);
        assert_eq!(res.findings[0].confidence, Confidence::Exact);
    }

    #[test]
    fn oversize_file_skipped_by_size_cap() {
        let rules = rules_with_hashes(HashMap::new());
        let det = PayloadHashesDetector::new(&rules);

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.bin");
        let f = std::fs::File::create(&p).unwrap();
        f.set_len(17 * 1024 * 1024).unwrap();
        let t = ScanTarget::SourceFile {
            path: p.clone(),
            origin: SourceOrigin::LocalFile,
        };

        let res = det.scan(&t, &ctx());
        assert!(res.findings.is_empty());
    }

    #[test]
    fn no_match_no_findings() {
        let rules = rules_with_hashes(HashMap::new());
        let det = PayloadHashesDetector::new(&rules);

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("payload.bin");
        std::fs::write(&p, b"nothing interesting here").unwrap();
        let t = ScanTarget::SourceFile {
            path: p.clone(),
            origin: SourceOrigin::LocalFile,
        };

        let res = det.scan(&t, &ctx());
        assert!(res.findings.is_empty());
    }
}
