//! `source_provenance` — judges `source=()` URLs in `.SRCINFO`/PKGBUILD:
//! raw IPs, URL shorteners, non-HTTPS transports, typosquats of popular
//! source hosts, and domain mismatch against the package's `url=` field.

use aurscan_core::{
    Confidence, Detector, DetectorId, DetectorResult, Evidence, Finding, ScanContext, ScanTarget,
    ScriptKind, Severity,
};
use std::path::Path;

const KNOWN_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "codeberg.org",
    "sourceforge.net",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "registry.npmjs.org",
    "bitbucket.org",
    "sr.ht",
    "kernel.org",
    "gnu.org",
    "savannah.gnu.org",
];

const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
];

/// One `key = value` (or `key=(...)`) line extracted from a `.SRCINFO` /
/// PKGBUILD, with its 1-indexed source line number.
struct KeyValue {
    line_no: usize,
    key: String,
    value: String,
}

/// Extract `key = value` lines from a `.SRCINFO`. Lines are `\t?key = value`.
fn parse_srcinfo_lines(content: &str) -> Vec<KeyValue> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        out.push(KeyValue {
            line_no: idx + 1,
            key: key.trim().to_string(),
            value: value.trim().to_string(),
        });
    }
    out
}

/// Cheap line-regex extraction of `url=` and `source=(...)` arrays from a
/// PKGBUILD, since PKGBUILD is bash and we don't want to run a shell parser
/// just to pull out source URLs.
fn parse_pkgbuild_lines(content: &str) -> Vec<KeyValue> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("url").map(str::trim_start) {
            if let Some(value) = rest.strip_prefix('=') {
                out.push(KeyValue {
                    line_no: idx + 1,
                    key: "url".to_string(),
                    value: value
                        .trim()
                        .trim_matches(|c| c == '"' || c == '\'')
                        .to_string(),
                });
            }
            continue;
        }
        if !trimmed.starts_with("source") {
            continue;
        }
        let Some(eq_idx) = trimmed.find('=') else {
            continue;
        };
        let key = trimmed[..eq_idx].trim();
        if key != "source" && !key.starts_with("source_") {
            continue;
        }
        let rhs = trimmed[eq_idx + 1..].trim();
        let inner = rhs.trim_start_matches('(').trim_end_matches(')');
        for entry in inner.split_whitespace() {
            let entry = entry.trim_matches(|c| c == '"' || c == '\'');
            if entry.is_empty() {
                continue;
            }
            out.push(KeyValue {
                line_no: idx + 1,
                key: "source".to_string(),
                value: entry.to_string(),
            });
        }
    }
    out
}

/// Parse `scheme://host[:port]/...` by hand — no need for a URL crate.
fn parse_url(url: &str) -> Option<(String, String)> {
    let url = url.strip_prefix("git+").unwrap_or(url);
    let scheme_end = url.find("://")?;
    let scheme = url[..scheme_end].to_lowercase();
    let rest = &url[scheme_end + 3..];
    let host_end = rest.find(['/', ':', '?', '#']).unwrap_or(rest.len());
    let host = rest[..host_end].to_lowercase();
    if host.is_empty() {
        return None;
    }
    Some((scheme, host))
}

/// A `name::url` source value uses `::` to separate the local filename from
/// the fetch URL — split on the first occurrence.
fn source_url(value: &str) -> &str {
    match value.split_once("::") {
        Some((_, url)) => url,
        None => value,
    }
}

fn is_raw_ip(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return inner.contains(':');
    }
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

/// Classic two-row Levenshtein edit distance — not worth a dependency for a
/// handful of typosquat checks against a fixed host list.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

#[derive(Debug, Default)]
pub struct SourceProvenanceDetector;

impl SourceProvenanceDetector {
    pub fn new() -> Self {
        Self
    }

    fn finding(
        &self,
        package: &str,
        path: &Path,
        line_no: usize,
        url: &str,
        severity: Severity,
        reason: impl Into<String>,
    ) -> Finding {
        Finding {
            severity,
            confidence: Confidence::Heuristic,
            detector: self.id(),
            package: package.to_string(),
            reason: reason.into(),
            evidence: Evidence {
                location: format!("{}:{}", path.display(), line_no),
                excerpt: url.to_string(),
            },
        }
    }

    fn check_source(
        &self,
        package: &str,
        path: &Path,
        line_no: usize,
        raw_value: &str,
        url_host: Option<&str>,
        findings: &mut Vec<Finding>,
    ) {
        let url = source_url(raw_value);
        let Some((scheme, host)) = parse_url(url) else {
            return;
        };

        if is_raw_ip(&host) {
            findings.push(self.finding(
                package,
                path,
                line_no,
                url,
                Severity::High,
                "raw IP source URL",
            ));
        }

        if SHORTENERS.contains(&host.as_str()) {
            findings.push(self.finding(
                package,
                path,
                line_no,
                url,
                Severity::High,
                "URL shortener in source",
            ));
        }

        if scheme == "http" || scheme == "git" {
            findings.push(self.finding(
                package,
                path,
                line_no,
                url,
                Severity::Medium,
                "non-HTTPS source transport",
            ));
        }

        let is_known_or_subdomain = KNOWN_HOSTS
            .iter()
            .any(|known| host == *known || host.ends_with(&format!(".{known}")));
        if !is_known_or_subdomain {
            for known in KNOWN_HOSTS {
                if levenshtein(&host, known) <= 2 {
                    findings.push(self.finding(
                        package,
                        path,
                        line_no,
                        url,
                        Severity::High,
                        format!("possible typosquat of {known}"),
                    ));
                }
            }
        }

        if let Some(url_host) = url_host {
            if host != url_host && !KNOWN_HOSTS.contains(&host.as_str()) {
                findings.push(self.finding(
                    package,
                    path,
                    line_no,
                    url,
                    Severity::Info,
                    "source domain mismatch with package url=",
                ));
            }
        }
    }
}

impl Detector for SourceProvenanceDetector {
    fn id(&self) -> DetectorId {
        DetectorId("source_provenance")
    }

    fn wants(&self, target: &ScanTarget) -> bool {
        matches!(
            target,
            ScanTarget::BuildScript {
                kind: ScriptKind::SrcInfo | ScriptKind::Pkgbuild,
                ..
            }
        )
    }

    fn scan(&self, target: &ScanTarget, ctx: &ScanContext) -> DetectorResult {
        let ScanTarget::BuildScript { path, kind } = target else {
            return DetectorResult::default();
        };
        let Ok(content) = std::fs::read_to_string(path) else {
            return DetectorResult::default();
        };

        let entries = match kind {
            ScriptKind::SrcInfo => parse_srcinfo_lines(&content),
            ScriptKind::Pkgbuild => parse_pkgbuild_lines(&content),
            _ => return DetectorResult::default(),
        };

        let url_host = entries
            .iter()
            .find(|kv| kv.key == "url")
            .and_then(|kv| parse_url(&kv.value))
            .map(|(_, host)| host);

        let mut findings = Vec::new();
        for kv in entries
            .iter()
            .filter(|kv| kv.key == "source" || kv.key.starts_with("source_"))
        {
            self.check_source(
                &ctx.package,
                path,
                kv.line_no,
                &kv.value,
                url_host.as_deref(),
                &mut findings,
            );
        }

        DetectorResult {
            findings,
            features: None,
        }
    }
}

// --- Contract assertion ---
// SourceProvenanceDetector must satisfy the frozen T0 `Detector` trait.
const _: fn() = || {
    fn is_detector<T: Detector>() {}
    is_detector::<SourceProvenanceDetector>();
};

#[cfg(test)]
mod tests {
    use aurscan_core::{Detector, DetectorResult, ScanContext, ScanTarget, ScriptKind, Severity};
    use std::io::Write;

    fn scan_srcinfo(content: &str) -> DetectorResult {
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(content.as_bytes()).expect("write");
        let target = ScanTarget::BuildScript {
            path: file.path().to_path_buf(),
            kind: ScriptKind::SrcInfo,
        };
        let ctx = ScanContext {
            package: "x".to_string(),
            version: "1.0".to_string(),
            aur_meta: None,
        };
        let detector = super::SourceProvenanceDetector::new();
        detector.scan(&target, &ctx)
    }

    #[test]
    fn raw_ip_source_is_high() {
        let r = scan_srcinfo("pkgbase = x\n\tsource = http://203.0.113.7/payload.tar.gz\n");
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("raw IP")));
    }

    #[test]
    fn shortener_is_high() {
        let r = scan_srcinfo("pkgbase = x\n\tsource = https://bit.ly/3xyz\n");
        assert!(r.findings.iter().any(|f| f.severity >= Severity::High));
    }

    #[test]
    fn plain_http_is_medium() {
        let r = scan_srcinfo("pkgbase = x\n\tsource = http://example.com/x.tar.gz\n");
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity == Severity::Medium && f.reason.contains("non-HTTPS")));
    }

    #[test]
    fn typosquat_of_github_is_high() {
        let r = scan_srcinfo(
            "pkgbase = x\n\tsource = https://github.co/owner/repo/archive/v1.tar.gz\n",
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("typosquat")));
    }

    #[test]
    fn url_source_domain_mismatch_is_info() {
        let r = scan_srcinfo(
            "pkgbase = x\n\turl = https://github.com/owner/repo\n\tsource = https://cdn.example.net/x.tar.gz\n",
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity == Severity::Info && f.reason.contains("mismatch")));
    }

    #[test]
    fn clean_github_https_no_findings() {
        let r = scan_srcinfo(
            "pkgbase = x\n\turl = https://github.com/owner/repo\n\tsource = https://github.com/owner/repo/archive/v1.tar.gz\n",
        );
        assert!(r.findings.is_empty());
    }

    fn scan_pkgbuild(content: &str) -> DetectorResult {
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(content.as_bytes()).expect("write");
        let target = ScanTarget::BuildScript {
            path: file.path().to_path_buf(),
            kind: ScriptKind::Pkgbuild,
        };
        let ctx = ScanContext {
            package: "x".to_string(),
            version: "1.0".to_string(),
            aur_meta: None,
        };
        let detector = super::SourceProvenanceDetector::new();
        detector.scan(&target, &ctx)
    }

    #[test]
    fn pkgbuild_fallback_flags_raw_ip() {
        let r = scan_pkgbuild(
            "pkgname=x\nurl=\"https://example.com\"\nsource=('http://203.0.113.7/payload.tar.gz')\n",
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("raw IP")));
    }

    #[test]
    fn named_source_splits_on_double_colon() {
        let r = scan_srcinfo(
            "pkgbase = x\n\tsource = payload.tar.gz::http://203.0.113.7/payload.tar.gz\n",
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("raw IP")));
    }
}
