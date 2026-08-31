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

/// Strip a trailing `# comment` from a PKGBUILD line fragment, being careful
/// not to treat a `#` inside quotes as a comment marker. Since URLs never
/// legitimately contain a literal `#` fragment marker in these arrays and
/// entries are always quoted, a simple quote-aware scan is sufficient.
fn strip_inline_comment(fragment: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (byte_idx, ch) in fragment.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &fragment[..byte_idx],
            _ => {}
        }
    }
    fragment
}

/// Split a source-array fragment into individual quoted/unquoted entries,
/// stripping surrounding quotes and whitespace.
fn split_array_entries(fragment: &str) -> impl Iterator<Item = &str> {
    fragment.split_whitespace().filter_map(|entry| {
        let entry = entry.trim_matches(|c| c == '"' || c == '\'');
        if entry.is_empty() {
            None
        } else {
            Some(entry)
        }
    })
}

/// Cheap line-regex extraction of `url=` and `source=(...)` arrays from a
/// PKGBUILD, since PKGBUILD is bash and we don't want to run a shell parser
/// just to pull out source URLs. `source`/`source_<arch>` arrays commonly
/// span multiple lines, so this tracks a small "inside source array" state
/// from the opening `(` to its matching closing `)`, accumulating entries
/// (and skipping `# comment` lines/fragments) along the way.
fn parse_pkgbuild_lines(content: &str) -> Vec<KeyValue> {
    let mut out = Vec::new();
    let mut in_source_array = false;

    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();

        if in_source_array {
            let fragment = strip_inline_comment(trimmed).trim();
            let (fragment, closed) = match fragment.strip_suffix(')') {
                Some(rest) => (rest, true),
                None => (fragment, false),
            };
            for entry in split_array_entries(fragment) {
                out.push(KeyValue {
                    line_no,
                    key: "source".to_string(),
                    value: entry.to_string(),
                });
            }
            if closed {
                in_source_array = false;
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("url").map(str::trim_start) {
            if let Some(value) = rest.strip_prefix('=') {
                out.push(KeyValue {
                    line_no,
                    key: "url".to_string(),
                    value: strip_inline_comment(value.trim())
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
        let rhs = strip_inline_comment(trimmed[eq_idx + 1..].trim()).trim();
        let Some(inner) = rhs.strip_prefix('(') else {
            // Scalar assignment without an array, e.g. `source=http://...`.
            for entry in split_array_entries(rhs) {
                out.push(KeyValue {
                    line_no,
                    key: "source".to_string(),
                    value: entry.to_string(),
                });
            }
            continue;
        };
        let (inner, closed) = match inner.strip_suffix(')') {
            Some(rest) => (rest, true),
            None => (inner, false),
        };
        for entry in split_array_entries(inner) {
            out.push(KeyValue {
                line_no,
                key: "source".to_string(),
                value: entry.to_string(),
            });
        }
        if !closed {
            in_source_array = true;
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

    #[allow(clippy::too_many_arguments)]
    fn check_source(
        &self,
        package: &str,
        path: &Path,
        line_no: usize,
        raw_value: &str,
        url_host: Option<&str>,
        seen_mismatch_domains: &mut std::collections::HashSet<String>,
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
            // Compare registrable domains, not hosts: www.spotify.com vs
            // repository.spotify.com is the same organization, and the
            // host-exact version of this rule was 97.8% of all findings
            // across the real top-50 corpus (174 of 178) -- almost entirely
            // homepage-vs-download-host splits within one domain or plainly
            // legitimate CDNs. Cross-domain sources stay Info: real signal
            // for verbose/JSON/ML consumers, and Info never gates.
            // One finding per distinct source domain, not per URL: electron37
            // fetches ~147 sources from chromium.googlesource.com and each
            // one repeating the same fact drowned every other signal in the
            // report and the ML corpus.
            let source_domain = registrable_domain(&host);
            if source_domain != registrable_domain(url_host)
                && !KNOWN_HOSTS.contains(&host.as_str())
                && seen_mismatch_domains.insert(source_domain)
            {
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

/// Country-code second-level suffixes under which the registrable domain is
/// three labels, not two. A short common-cases table rather than the full
/// public-suffix list: this feeds an Info-severity comparison, and the
/// failure mode of a miss is one extra Info finding, not a wrong verdict.
const TWO_LEVEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "or.jp", "ne.jp",
    "com.br", "com.cn", "com.tw", "co.nz", "co.in", "co.kr", "com.mx", "com.ar",
];

/// The registrable domain of `host`: its last two labels, or three when the
/// two-label tail is a known country-code second-level suffix.
fn registrable_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let take = if labels.len() >= 3
        && TWO_LEVEL_SUFFIXES.contains(&labels[labels.len() - 2..].join(".").as_str())
    {
        3
    } else {
        2
    };
    if labels.len() <= take {
        host.to_string()
    } else {
        labels[labels.len() - take..].join(".")
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
        let mut seen_mismatch_domains = std::collections::HashSet::new();
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
                &mut seen_mismatch_domains,
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
    use super::registrable_domain;
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
    fn same_registrable_domain_is_not_a_mismatch() {
        // Regression: www.spotify.com vs repository.spotify.com is one
        // organization; the host-exact comparison flagged it (and every
        // homepage-vs-download-host split like it) on nearly every real
        // package.
        let r = scan_srcinfo(
            "pkgbase = x\n\turl = https://www.spotify.com\n\tsource = https://repository.spotify.com/pool/s/spotify.deb\n",
        );
        assert!(
            !r.findings.iter().any(|f| f.reason.contains("mismatch")),
            "got {:?}",
            r.findings
        );
    }

    #[test]
    fn registrable_domain_handles_cc_second_level_suffixes() {
        assert_eq!(registrable_domain("www.spotify.com"), "spotify.com");
        assert_eq!(registrable_domain("repository.spotify.com"), "spotify.com");
        assert_eq!(
            registrable_domain("downloads.example.co.uk"),
            "example.co.uk"
        );
        // Two unrelated .co.uk sites must NOT collapse into "co.uk".
        assert_ne!(
            registrable_domain("foo.co.uk"),
            registrable_domain("bar.co.uk")
        );
        assert_eq!(registrable_domain("github.com"), "github.com");
    }

    #[test]
    fn mismatch_fires_once_per_source_domain_not_per_url() {
        // Regression: electron37 fetches ~147 sources from
        // chromium.googlesource.com and each URL repeated the same fact.
        let r = scan_srcinfo(
            "pkgbase = x\n\turl = https://example.org\n\
             \tsource = https://cdn.example.net/a.tar.gz\n\
             \tsource = https://cdn.example.net/b.tar.gz\n\
             \tsource = https://other.example.io/c.tar.gz\n",
        );
        let mismatches = r
            .findings
            .iter()
            .filter(|f| f.reason.contains("mismatch"))
            .count();
        assert_eq!(
            mismatches, 2,
            "one per distinct domain, got {:?}",
            r.findings
        );
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

    #[test]
    fn pkgbuild_multiline_source_array_flags_raw_ip_on_continuation_line() {
        let r = scan_pkgbuild(
            "pkgname=x\nurl=\"https://example.com\"\nsource=(\n  \"https://github.com/o/r/archive/v1.tar.gz\"\n  \"http://203.0.113.7/evil.tar.gz\"\n)\n",
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("raw IP")));
    }

    #[test]
    fn pkgbuild_multiline_source_array_clean_github_no_findings() {
        let r = scan_pkgbuild(
            "pkgname=x\nurl=\"https://github.com/o/r\"\nsource=(\n  \"https://github.com/o/r/archive/v1.tar.gz\"\n  \"https://github.com/o/r/archive/v2.tar.gz\"\n)\n",
        );
        assert!(r.findings.is_empty());
    }

    #[test]
    fn pkgbuild_single_line_source_array_still_works() {
        let r = scan_pkgbuild(
            "pkgname=x\nurl=\"https://example.com\"\nsource=('http://203.0.113.7/payload.tar.gz')\n",
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("raw IP")));
    }

    #[test]
    fn pkgbuild_multiline_source_array_with_comment_line_still_parses_entries() {
        let r = scan_pkgbuild(
            "pkgname=x\nurl=\"https://example.com\"\nsource=(\n  # payload\n  \"http://203.0.113.7/evil.tar.gz\"\n  # trailer comment\n)\n",
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("raw IP")));
    }

    #[test]
    fn pkgbuild_multiline_source_array_closing_paren_with_trailing_comment_still_closes() {
        let r = scan_pkgbuild(
            "pkgname=x\nurl=\"https://github.com/o/r\"\nsource=(\n  \"https://github.com/o/r/archive/v1.tar.gz\"\n) # end of sources\nsource_x86_64=('http://203.0.113.7/evil.tar.gz')\n",
        );
        let finding = r
            .findings
            .iter()
            .find(|f| f.severity >= Severity::High && f.reason.contains("raw IP"))
            .expect("expected a raw IP finding");
        assert_eq!(finding.evidence.excerpt, "http://203.0.113.7/evil.tar.gz");
    }

    #[test]
    fn pkgbuild_scalar_source_without_parens_still_flags_raw_ip() {
        let r = scan_pkgbuild(
            "pkgname=x\nurl=\"https://example.com\"\nsource=http://203.0.113.7/payload.tar.gz\n",
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("raw IP")));
    }
}
