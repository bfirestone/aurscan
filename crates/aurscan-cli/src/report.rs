//! Rendering: tiered, severity-sorted text output (mirroring the legacy
//! `render_report`) plus a structured JSON view, and the verdict->exit-code
//! mapping that gates hooks/CI.

use crate::ack::AckStore;
use aurscan_core::{Finding, PackageReport, Severity, Verdict};
use std::fmt::Write;

/// Escape terminal controls and Unicode format controls as visible codepoint
/// notation. JSON rendering intentionally keeps the underlying structured
/// strings unchanged and relies on normal JSON escaping.
pub(crate) fn terminal_safe(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if is_non_printing(character) {
            let _ = write!(escaped, "\\u{{{:x}}}", character as u32);
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Unicode 17.0.0 `General_Category=Format` (`Cf`) scalar ranges.
///
/// Keep this table explicit so terminal escaping stays auditable when Unicode
/// adds format characters in a later release.
const UNICODE_FORMAT_RANGES: &[(char, char)] = &[
    ('\u{00ad}', '\u{00ad}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061c}', '\u{061c}'),
    ('\u{06dd}', '\u{06dd}'),
    ('\u{070f}', '\u{070f}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08e2}', '\u{08e2}'),
    ('\u{180e}', '\u{180e}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{110bd}', '\u{110bd}'),
    ('\u{110cd}', '\u{110cd}'),
    ('\u{13430}', '\u{1343f}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0001}', '\u{e0001}'),
    ('\u{e0020}', '\u{e007f}'),
];

fn is_non_printing(character: char) -> bool {
    character.is_control()
        || matches!(character, '\u{2028}' | '\u{2029}')
        || UNICODE_FORMAT_RANGES
            .iter()
            .any(|&(start, end)| (start..=end).contains(&character))
}

/// Human-readable, severity-sorted report. `Info` findings ride along only when
/// `verbose`; acknowledged findings are suppressed and summarized instead.
pub fn render_text(
    reports: &[PackageReport],
    acks: &AckStore,
    verbose: bool,
    color: bool,
) -> String {
    let mut out = String::new();
    for report in reports {
        let _ = writeln!(
            out,
            "{}: {}",
            terminal_safe(&report.package),
            verdict_name(&report.verdict)
        );

        let mut findings: Vec<&Finding> = report.findings.iter().collect();
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

        let mut acknowledged = 0usize;
        for f in findings {
            if acks.is_acked(f) {
                acknowledged += 1;
                continue;
            }
            if f.severity == Severity::Info && !verbose {
                continue;
            }
            let marker = severity_marker(f.severity, color);
            let provenance = if matches!(&f.confidence, aurscan_core::Confidence::Llm) {
                " [LLM; ADVISORY CEILING]"
            } else {
                ""
            };
            let _ = writeln!(out, "  {marker}{provenance} {}", terminal_safe(&f.reason));
            let _ = writeln!(out, "    \u{21b3} {}", terminal_safe(&f.evidence.location));
            for line in excerpt_lines(f) {
                let _ = writeln!(out, "      \u{2502} {}", terminal_safe(&line));
            }
        }
        if acknowledged > 0 {
            let _ = writeln!(out, "  ({acknowledged} acknowledged)");
        }
    }
    out
}

/// How many excerpt lines a finding may print before elision.
const MAX_EXCERPT_LINES: usize = 4;

/// The evidence excerpt as displayable lines, or nothing when it would not
/// add information. A user deciding at the paru y/N prompt needs to *see*
/// the flagged code, not open PKGBUILD:39 mid-transaction — but detectors
/// like `archive_layout` put the member path in both the reason and the
/// excerpt, and repeating it is noise.
fn excerpt_lines(f: &Finding) -> Vec<String> {
    let excerpt = &f.evidence.excerpt;
    if excerpt.is_empty() || f.reason.contains(excerpt) {
        return Vec::new();
    }
    let mut lines: Vec<String> = excerpt
        .split_inclusive('\n')
        .map(|chunk| {
            let (content, had_newline) = chunk
                .strip_suffix('\n')
                .map_or((chunk, false), |content| (content, true));
            let mut display = content.trim_end_matches([' ', '\t']).to_string();
            if had_newline {
                display.push('\n');
            }
            display
        })
        .take(MAX_EXCERPT_LINES + 1)
        .collect();
    if lines.len() > MAX_EXCERPT_LINES {
        lines.truncate(MAX_EXCERPT_LINES);
        lines.push("\u{2026}".to_string());
    }
    lines
}

/// Structured view: per-package verdicts + findings plus a rollup summary.
pub fn render_json(reports: &[PackageReport]) -> serde_json::Value {
    let (mut clean, mut advisory, mut block) = (0u32, 0u32, 0u32);
    let entries: Vec<serde_json::Value> = reports
        .iter()
        .map(|r| {
            let verdict = match r.verdict {
                Verdict::Clean => {
                    clean += 1;
                    "clean"
                }
                Verdict::Advisory(_) => {
                    advisory += 1;
                    "advisory"
                }
                Verdict::Block(_) => {
                    block += 1;
                    "block"
                }
            };
            serde_json::json!({
                "package": r.package,
                "verdict": verdict,
                "findings": r.findings,
            })
        })
        .collect();
    serde_json::json!({
        "reports": entries,
        "summary": { "clean": clean, "advisory": advisory, "block": block },
    })
}

/// Structured deep-scan view. Existing command JSON continues to use
/// `render_json`; this schema is exclusive to the explicit LLM command.
pub(crate) fn render_deep_json(
    run: &crate::deep_scan::DeepRun,
    preflight: &crate::deep_scan::DeepPreflight,
) -> serde_json::Value {
    use aurscan_llm::{AnalysisSource, AnalysisStatus};

    let (mut clean, mut advisory, mut block) = (0u32, 0u32, 0u32);
    let (mut completed, mut cache_hit, mut unavailable, mut incomplete) = (0u32, 0u32, 0u32, 0u32);
    let packages: Vec<serde_json::Value> = run
        .packages
        .iter()
        .map(|package| {
            let verdict = match package.combined.verdict {
                Verdict::Clean => {
                    clean += 1;
                    "clean"
                }
                Verdict::Advisory(_) => {
                    advisory += 1;
                    "advisory"
                }
                Verdict::Block(_) => {
                    block += 1;
                    "block"
                }
            };
            match package.analysis.status {
                AnalysisStatus::Completed => completed += 1,
                AnalysisStatus::Unavailable => unavailable += 1,
                AnalysisStatus::Incomplete => incomplete += 1,
            }
            if package.analysis.source == Some(AnalysisSource::Cache) {
                cache_hit += 1;
            }

            let identity = package.analysis.identity.as_ref();
            let mut analysis = serde_json::Map::new();
            analysis.insert(
                "status".into(),
                serde_json::to_value(package.analysis.status).unwrap(),
            );
            if let Some(source) = package.analysis.source {
                analysis.insert("source".into(), serde_json::to_value(source).unwrap());
            }
            analysis.insert(
                "model".into(),
                serde_json::Value::String(
                    identity
                        .map(|identity| identity.model_id.clone())
                        .unwrap_or_else(|| preflight.model.clone()),
                ),
            );
            analysis.insert(
                "review_strategy_id".into(),
                serde_json::Value::String(
                    identity
                        .map(|identity| identity.review_strategy_id.clone())
                        .unwrap_or_else(|| aurscan_llm::REVIEW_STRATEGY_ID.to_string()),
                ),
            );
            analysis.insert(
                "prompt_version".into(),
                serde_json::json!(identity
                    .map(|identity| identity.prompt_version)
                    .unwrap_or(aurscan_llm::PROMPT_VERSION)),
            );
            analysis.insert(
                "bundle_hash".into(),
                package.bundle_hash.map_or(serde_json::Value::Null, |hash| {
                    serde_json::Value::String(hex_bytes(&hash))
                }),
            );
            analysis.insert(
                "coverage".into(),
                serde_json::to_value(&package.coverage).unwrap(),
            );
            if let Some(usage) = package.analysis.usage {
                analysis.insert("usage".into(), serde_json::to_value(usage).unwrap());
            }
            analysis.insert(
                "reason".into(),
                package
                    .analysis
                    .reason
                    .as_ref()
                    .map_or(serde_json::Value::Null, |reason| {
                        serde_json::Value::String(reason.clone())
                    }),
            );

            serde_json::json!({
                "pkgbase": package.pkgbase,
                "requested_packages": package.requested_packages,
                "verdict": verdict,
                "findings": package.combined.findings,
                "analysis": analysis,
            })
        })
        .collect();

    serde_json::json!({
        "packages": packages,
        "preflight": {
            "endpoint_host": preflight.endpoint_host,
            "model": preflight.model,
            "review_strategy_id": aurscan_llm::REVIEW_STRATEGY_ID,
            "package_count": preflight.package_count,
            "original_bytes": preflight.original_bytes,
            "encoded_request_bytes": preflight.encoded_request_bytes,
            "large_request_mode": preflight.large_request_mode,
        },
        "summary": {
            "clean": clean,
            "advisory": advisory,
            "block": block,
            "completed": completed,
            "cache_hit": cache_hit,
            "unavailable": unavailable,
            "incomplete": incomplete,
        },
        "exit_code": run.exit_code,
    })
}

pub(crate) fn render_deep_text(
    run: &crate::deep_scan::DeepRun,
    preflight: &crate::deep_scan::DeepPreflight,
    acks: &AckStore,
    verbose: bool,
    color: bool,
) -> String {
    use aurscan_llm::{AnalysisSource, AnalysisStatus, CoverageMode};

    let mut out = String::new();
    let _ = writeln!(
        out,
        "LLM preflight: host={}, model={}, strategy={}, prompt version={}, packages={}, original bytes={}, encoded bytes={}, large mode={}",
        terminal_safe(&preflight.endpoint_host),
        terminal_safe(&preflight.model),
        aurscan_llm::REVIEW_STRATEGY_ID,
        aurscan_llm::PROMPT_VERSION,
        preflight.package_count,
        preflight_byte_count(preflight.original_bytes),
        preflight_byte_count(preflight.encoded_request_bytes),
        preflight.large_request_mode,
    );
    for package in &run.packages {
        out.push_str(&render_text(
            std::slice::from_ref(&package.combined),
            acks,
            verbose,
            color,
        ));
        let requested = package
            .requested_packages
            .iter()
            .map(|name| terminal_safe(name))
            .collect::<Vec<_>>()
            .join(", ");
        let status = match package.analysis.status {
            AnalysisStatus::Completed => "completed",
            AnalysisStatus::Unavailable => "unavailable",
            AnalysisStatus::Incomplete => "incomplete",
        };
        let source = match package.analysis.source {
            Some(AnalysisSource::Provider) => "provider",
            Some(AnalysisSource::Cache) => "cache",
            None => "no source",
        };
        let _ = writeln!(
            out,
            "  LLM provenance: {status} via {source}; experimental, Advisory ceiling; no model-issued clearance"
        );
        let _ = writeln!(out, "  requested/resolved packages: {requested}");
        if package.analysis.findings.is_empty() {
            let _ = writeln!(out, "  no accepted LLM findings");
        } else {
            let _ = writeln!(
                out,
                "  accepted LLM findings: {}",
                package.analysis.findings.len()
            );
        }
        let coverage_mode = match package.coverage.mode {
            CoverageMode::GitTracked => "git_tracked",
            CoverageMode::ConservativeLocal => "conservative_local",
        };
        let _ = writeln!(
            out,
            "  coverage: mode={coverage_mode}, included files={}, excluded binaries={}, excluded symlinks={}",
            package.coverage.included_files,
            package.coverage.excluded_binary_files.len(),
            package.coverage.excluded_symlinks.len(),
        );
        for path in &package.coverage.excluded_binary_files {
            let _ = writeln!(out, "    excluded binary: {}", terminal_safe(path));
        }
        for path in &package.coverage.excluded_symlinks {
            let _ = writeln!(out, "    excluded symlink: {}", terminal_safe(path));
        }
        if let Some(reason) = &package.analysis.reason {
            let _ = writeln!(out, "  analysis reason: {}", terminal_safe(reason));
        }
    }
    let completed = run
        .packages
        .iter()
        .filter(|package| package.analysis.status == AnalysisStatus::Completed)
        .count();
    let cache_hits = run
        .packages
        .iter()
        .filter(|package| package.analysis.source == Some(AnalysisSource::Cache))
        .count();
    let unavailable = run
        .packages
        .iter()
        .filter(|package| package.analysis.status == AnalysisStatus::Unavailable)
        .count();
    let incomplete = run
        .packages
        .iter()
        .filter(|package| package.analysis.status == AnalysisStatus::Incomplete)
        .count();
    let _ = writeln!(
        out,
        "LLM summary: completed={completed}, cache-hit={cache_hits}, unavailable={unavailable}, incomplete={incomplete}"
    );
    out
}

fn preflight_byte_count(bytes: Option<usize>) -> String {
    bytes
        .map(|bytes| bytes.to_string())
        .unwrap_or_else(|| "unmeasured".to_string())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Worst exit code across all reports: `2` Block, `1` Advisory, `0` Clean.
pub fn worst_exit_code(reports: &[PackageReport]) -> i32 {
    reports
        .iter()
        .map(|r| match r.verdict {
            Verdict::Clean => 0,
            Verdict::Advisory(_) => 1,
            Verdict::Block(_) => 2,
        })
        .max()
        .unwrap_or(0)
}

fn verdict_name(v: &Verdict) -> &'static str {
    match v {
        Verdict::Clean => "CLEAN",
        Verdict::Advisory(_) => "ADVISORY",
        Verdict::Block(_) => "BLOCK",
    }
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "INFO",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn severity_marker(s: Severity, color: bool) -> String {
    let name = severity_name(s);
    if !color {
        return format!("[{name}]");
    }
    let code = match s {
        Severity::Critical => "1;31",
        Severity::High => "31",
        Severity::Medium => "33",
        Severity::Info => "36",
    };
    format!("\u{1b}[{code}m[{name}]\u{1b}[0m")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::{Confidence, DetectorId, Evidence};

    fn finding(sev: Severity, reason: &str, excerpt: &str) -> Finding {
        Finding {
            severity: sev,
            confidence: Confidence::Exact,
            detector: DetectorId("ioc_tokens"),
            package: "pkg".into(),
            reason: reason.into(),
            evidence: Evidence {
                location: "PKGBUILD:3".into(),
                excerpt: excerpt.into(),
            },
        }
    }

    fn report(package: &str, verdict: Verdict, findings: Vec<Finding>) -> PackageReport {
        PackageReport {
            package: package.into(),
            verdict,
            findings,
            features: vec![],
        }
    }

    #[test]
    fn text_report_shows_the_flagged_code_under_the_location() {
        // Regression: the paru y/N prompt showed only "PKGBUILD:39" and
        // asked the user to judge safety of code they could not see.
        let f = finding(
            Severity::Medium,
            "eval of dynamic command substitution in package()",
            "eval \"cat <<EOF\n$(envsubst < env.conf)\nEOF\"",
        );
        let out = render_text(
            &[report("1password", Verdict::Advisory(vec![]), vec![f])],
            &AckStore::from_keys([]),
            false,
            false,
        );
        assert!(out.contains("\u{2502} eval \"cat <<EOF"), "got:\n{out}");
        assert!(
            out.contains("\u{2502} $(envsubst < env.conf)"),
            "got:\n{out}"
        );
    }

    #[test]
    fn excerpt_is_skipped_when_the_reason_already_contains_it() {
        // archive_layout puts the member path in both fields.
        let f = finding(
            Severity::High,
            "setuid binary in package: usr/bin/evil",
            "usr/bin/evil",
        );
        let out = render_text(
            &[report("p", Verdict::Block(vec![]), vec![f])],
            &AckStore::from_keys([]),
            false,
            false,
        );
        assert!(!out.contains('\u{2502}'), "got:\n{out}");
    }

    #[test]
    fn long_excerpts_are_line_capped_with_an_ellipsis() {
        let body = (1..=8)
            .map(|i| format!("line{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let f = finding(Severity::Medium, "large opaque blob", &body);
        let lines = excerpt_lines(&f);
        assert_eq!(lines.len(), MAX_EXCERPT_LINES + 1);
        assert_eq!(lines.last().unwrap(), "\u{2026}");
    }

    #[test]
    fn exit_code_reflects_worst_verdict() {
        assert_eq!(worst_exit_code(&[report("a", Verdict::Clean, vec![])]), 0);
        assert_eq!(
            worst_exit_code(&[report("a", Verdict::Advisory(vec![]), vec![])]),
            1
        );
        assert_eq!(
            worst_exit_code(&[report("a", Verdict::Block(vec![]), vec![])]),
            2
        );
        // Worst across a mix wins.
        assert_eq!(
            worst_exit_code(&[
                report("a", Verdict::Clean, vec![]),
                report("b", Verdict::Advisory(vec![]), vec![]),
                report("c", Verdict::Block(vec![]), vec![]),
            ]),
            2
        );
        // No reports -> clean.
        assert_eq!(worst_exit_code(&[]), 0);
    }

    #[test]
    fn acked_finding_is_filtered_from_text() {
        let f = finding(
            Severity::High,
            "malicious token",
            "npm install atomic-lockfile",
        );
        let rep = report("pkg", Verdict::Block(vec![f.clone()]), vec![f.clone()]);
        let acks = AckStore::from_keys([AckStore::key(&f)]);

        let out = render_text(&[rep], &acks, false, false);
        assert!(!out.contains("malicious token"));
        assert!(out.contains("(1 acknowledged)"));
    }

    #[test]
    fn info_findings_hidden_unless_verbose() {
        let f = finding(Severity::Info, "informational note", "note");
        let rep = report("pkg", Verdict::Clean, vec![f]);
        let acks = AckStore::from_keys(std::iter::empty());

        assert!(
            !render_text(std::slice::from_ref(&rep), &acks, false, false)
                .contains("informational note")
        );
        assert!(render_text(&[rep], &acks, true, false).contains("informational note"));
    }

    #[test]
    fn findings_sorted_by_severity_descending() {
        let low = finding(Severity::Medium, "medium finding", "m");
        let high = finding(Severity::Critical, "critical finding", "c");
        let rep = report("pkg", Verdict::Block(vec![]), vec![low, high]);
        let acks = AckStore::from_keys(std::iter::empty());

        let out = render_text(&[rep], &acks, false, false);
        let ci = out.find("critical finding").unwrap();
        let mi = out.find("medium finding").unwrap();
        assert!(ci < mi, "critical should render before medium");
    }

    #[test]
    fn json_has_reports_and_summary() {
        let f = finding(Severity::Critical, "bad", "x");
        let rep = report("pkg", Verdict::Block(vec![f.clone()]), vec![f]);
        let v = render_json(&[rep]);
        assert_eq!(v["summary"]["block"], 1);
        assert_eq!(v["reports"][0]["verdict"], "block");
        assert_eq!(v["reports"][0]["package"], "pkg");
    }

    #[test]
    fn evidence_newlines_and_controls_are_visible_not_interpreted_as_terminal_content() {
        let mut f = finding(
            Severity::Medium,
            "suspicious multiline evidence",
            "first\u{1b}\nsecond\rthird",
        );
        f.evidence.location = "PKGBUILD:3".into();
        let rep = report("pkg", Verdict::Advisory(vec![]), vec![f]);
        let text = render_text(&[rep], &AckStore::from_keys([]), false, false);
        assert!(text.contains("first\\u{1b}\\u{a}"), "got:\n{text}");
        assert!(text.contains("second\\u{d}third"), "got:\n{text}");
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\r'));

        let newline_only = finding(Severity::Medium, "newline evidence", "\n");
        let rep = report("pkg", Verdict::Advisory(vec![]), vec![newline_only]);
        let text = render_text(&[rep], &AckStore::from_keys([]), false, false);
        assert!(text.contains("\\u{a}"), "got:\n{text}");
    }

    #[test]
    fn terminal_safety_visibly_escapes_controls_and_unicode_format_characters_without_mutating_json(
    ) {
        let escape_cases = [
            ("C0 control", '\u{001f}', "\\u{1f}"),
            ("C1 control", '\u{009f}', "\\u{9f}"),
            ("soft hyphen", '\u{00ad}', "\\u{ad}"),
            ("Arabic number signs", '\u{0600}', "\\u{600}"),
            ("Arabic letter mark", '\u{061c}', "\\u{61c}"),
            ("Arabic end of ayah", '\u{06dd}', "\\u{6dd}"),
            ("Syriac abbreviation mark", '\u{070f}', "\\u{70f}"),
            ("Arabic currency marks", '\u{0890}', "\\u{890}"),
            ("Arabic disputed end of ayah", '\u{08e2}', "\\u{8e2}"),
            ("Mongolian vowel separator", '\u{180e}', "\\u{180e}"),
            ("zero-width and directional marks", '\u{200e}', "\\u{200e}"),
            ("line separator", '\u{2028}', "\\u{2028}"),
            ("paragraph separator", '\u{2029}', "\\u{2029}"),
            ("bidi embeddings and overrides", '\u{202e}', "\\u{202e}"),
            (
                "word joiner and invisible operators",
                '\u{2060}',
                "\\u{2060}",
            ),
            (
                "bidi isolates and related format characters",
                '\u{2066}',
                "\\u{2066}",
            ),
            ("byte order mark", '\u{feff}', "\\u{feff}"),
            (
                "interlinear annotation format characters",
                '\u{fff9}',
                "\\u{fff9}",
            ),
            ("Kaithi number sign", '\u{110bd}', "\\u{110bd}"),
            ("Kaithi number sign alternate", '\u{110cd}', "\\u{110cd}"),
            (
                "Egyptian hieroglyph format controls",
                '\u{13430}',
                "\\u{13430}",
            ),
            ("shorthand format controls", '\u{1bca0}', "\\u{1bca0}"),
            ("musical symbol format controls", '\u{1d173}', "\\u{1d173}"),
            ("language tag", '\u{e0001}', "\\u{e0001}"),
            ("tag characters", '\u{e0020}', "\\u{e0020}"),
        ];
        for (name, character, expected) in escape_cases {
            assert_eq!(terminal_safe(&character.to_string()), expected, "{name}");
        }

        for (name, printable) in [
            ("C0-adjacent space", "\u{0020}"),
            ("C1-adjacent non-breaking space", "\u{00a0}"),
            ("before bidi embedding controls", "\u{2027}"),
            ("after bidi embedding controls", "\u{2030}"),
            ("ordinary printable Unicode", "é中😀"),
        ] {
            assert_eq!(terminal_safe(printable), printable, "{name}");
        }

        let unsafe_text = "pkg\u{1b}\r\u{85}\u{180e}\u{2028}\u{2029}\u{202e}\u{200b}";
        let escaped = terminal_safe(unsafe_text);
        assert!(!escaped.contains('\u{1b}'));
        assert!(!escaped.contains('\r'));
        assert!(!escaped.contains('\u{85}'));
        assert!(!escaped.contains('\u{180e}'));
        assert!(!escaped.contains('\u{2028}'));
        assert!(!escaped.contains('\u{2029}'));
        assert!(!escaped.contains('\u{202e}'));
        assert!(!escaped.contains('\u{200b}'));

        let mut f = finding(Severity::Medium, unsafe_text, unsafe_text);
        f.evidence.location = unsafe_text.into();
        let rep = report(unsafe_text, Verdict::Advisory(vec![]), vec![f]);
        let text = render_text(
            std::slice::from_ref(&rep),
            &AckStore::from_keys([]),
            false,
            false,
        );
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{180e}'));
        assert!(!text.contains('\u{2028}'));
        assert!(!text.contains('\u{2029}'));
        assert!(!text.contains('\u{202e}'));
        assert!(text.contains("\\u{1b}"));
        assert!(text.contains("\\u{180e}"));

        let json = render_json(&[rep]);
        assert_eq!(json["reports"][0]["package"], unsafe_text);
        assert_eq!(json["reports"][0]["findings"][0]["reason"], unsafe_text);
    }

    #[test]
    fn deep_json_has_analysis_identity_coverage_and_completion_summary() {
        use crate::deep_scan::{DeepPackageReport, DeepPreflight, DeepRun};
        use aurscan_llm::{
            AnalysisIdentity, AnalysisOutcome, AnalysisSource, AnalysisStatus, BundleCoverage,
            CoverageMode, TokenUsage,
        };

        fn package(status: AnalysisStatus, source: Option<AnalysisSource>) -> DeepPackageReport {
            let identity = AnalysisIdentity {
                bundle_hash: [0xab; 32],
                provider_protocol_version: 1,
                endpoint_origin_fingerprint: [1; 32],
                model_id: "pinned-model".into(),
                review_strategy_id: "findings_first_v1".into(),
                request_profile_fingerprint: [2; 32],
                prompt_version: 1,
                prompt_hash: [3; 32],
                response_schema_version: 1,
                response_schema_hash: [4; 32],
                analysis_epoch: 1,
            };
            DeepPackageReport {
                pkgbase: format!("base-{status:?}"),
                requested_packages: vec!["split".into()],
                combined: report("base", Verdict::Clean, vec![]),
                analysis: AnalysisOutcome {
                    status,
                    source,
                    findings: vec![],
                    identity: Some(identity),
                    usage: (status == AnalysisStatus::Completed).then_some(TokenUsage {
                        input_tokens: 12,
                        output_tokens: 3,
                    }),
                    reason: (status != AnalysisStatus::Completed).then(|| "offline".into()),
                },
                bundle_hash: Some([0xab; 32]),
                coverage: BundleCoverage {
                    mode: CoverageMode::GitTracked,
                    included_files: 2,
                    excluded_binary_files: vec!["binary.bin".into()],
                    excluded_symlinks: vec!["link".into()],
                },
            }
        }

        let run = DeepRun {
            packages: vec![
                package(AnalysisStatus::Completed, Some(AnalysisSource::Cache)),
                package(AnalysisStatus::Completed, Some(AnalysisSource::Provider)),
                package(AnalysisStatus::Unavailable, None),
                package(AnalysisStatus::Incomplete, Some(AnalysisSource::Provider)),
            ],
            exit_code: 3,
        };
        let preflight = DeepPreflight {
            endpoint_host: "localhost".into(),
            model: "pinned-model".into(),
            package_count: 4,
            original_bytes: Some(100),
            encoded_request_bytes: Some(400),
            large_request_mode: false,
        };
        let json = render_deep_json(&run, &preflight);

        assert_eq!(json["packages"][0]["pkgbase"], "base-Completed");
        assert_eq!(json["packages"][0]["requested_packages"][0], "split");
        assert_eq!(json["packages"][0]["analysis"]["status"], "completed");
        assert_eq!(json["packages"][0]["analysis"]["source"], "cache");
        assert_eq!(json["packages"][0]["analysis"]["model"], "pinned-model");
        assert_eq!(
            json["packages"][0]["analysis"]["review_strategy_id"],
            "findings_first_v1"
        );
        assert_eq!(json["packages"][0]["analysis"]["prompt_version"], 1);
        assert_eq!(
            json["packages"][0]["analysis"].get("bundle_hash"),
            Some(&serde_json::Value::String("ab".repeat(32)))
        );
        assert_eq!(
            json["packages"][0]["analysis"]["coverage"]["included_files"],
            2
        );
        assert_eq!(json["summary"]["completed"], 2);
        assert_eq!(json["summary"]["cache_hit"], 1);
        assert_eq!(json["summary"]["unavailable"], 1);
        assert_eq!(json["summary"]["incomplete"], 1);
        assert!(json["packages"][2]["analysis"].get("source").is_none());
        assert!(json["packages"][2]["analysis"].get("usage").is_none());
        assert_eq!(json["preflight"]["endpoint_host"], "localhost");
        assert_eq!(json["preflight"]["encoded_request_bytes"], 400);
    }

    #[test]
    fn deep_json_emits_null_bundle_hash_without_analysis_identity() {
        use crate::deep_scan::{DeepPackageReport, DeepPreflight, DeepRun};
        use aurscan_llm::{AnalysisOutcome, AnalysisStatus, BundleCoverage, CoverageMode};

        let run = DeepRun {
            packages: vec![DeepPackageReport {
                pkgbase: "base".into(),
                requested_packages: vec!["split".into()],
                combined: report("base", Verdict::Clean, vec![]),
                analysis: AnalysisOutcome {
                    status: AnalysisStatus::Unavailable,
                    source: None,
                    findings: vec![],
                    identity: None,
                    usage: None,
                    reason: Some("offline".into()),
                },
                bundle_hash: None,
                coverage: BundleCoverage {
                    mode: CoverageMode::ConservativeLocal,
                    included_files: 0,
                    excluded_binary_files: vec![],
                    excluded_symlinks: vec![],
                },
            }],
            exit_code: 0,
        };
        let preflight = DeepPreflight {
            endpoint_host: "localhost".into(),
            model: "model".into(),
            package_count: 1,
            original_bytes: Some(0),
            encoded_request_bytes: Some(0),
            large_request_mode: false,
        };

        let analysis = &render_deep_json(&run, &preflight)["packages"][0]["analysis"];
        assert_eq!(analysis.get("bundle_hash"), Some(&serde_json::Value::Null));
        assert!(analysis.get("source").is_none());
        assert!(analysis.get("usage").is_none());
    }

    #[test]
    fn deep_json_preserves_valid_bundle_hash_when_analyzer_is_unavailable_and_marks_bytes_unmeasured(
    ) {
        use crate::deep_scan::{DeepPackageReport, DeepPreflight, DeepRun};
        use aurscan_llm::{AnalysisOutcome, AnalysisStatus, BundleCoverage, CoverageMode};

        let unavailable = DeepPackageReport {
            pkgbase: "valid-bundle".into(),
            requested_packages: vec!["valid-bundle".into()],
            combined: report("valid-bundle", Verdict::Clean, vec![]),
            analysis: AnalysisOutcome {
                status: AnalysisStatus::Unavailable,
                source: None,
                findings: vec![],
                identity: None,
                usage: None,
                reason: Some("offline".into()),
            },
            bundle_hash: Some([0xcd; 32]),
            coverage: BundleCoverage {
                mode: CoverageMode::GitTracked,
                included_files: 1,
                excluded_binary_files: vec![],
                excluded_symlinks: vec![],
            },
        };
        let bundle_failure = DeepPackageReport {
            pkgbase: "bundle-failure".into(),
            requested_packages: vec!["bundle-failure".into()],
            combined: report("bundle-failure", Verdict::Clean, vec![]),
            analysis: AnalysisOutcome {
                status: AnalysisStatus::Incomplete,
                source: None,
                findings: vec![],
                identity: None,
                usage: None,
                reason: Some("bundle failed".into()),
            },
            bundle_hash: None,
            coverage: BundleCoverage {
                mode: CoverageMode::ConservativeLocal,
                included_files: 0,
                excluded_binary_files: vec![],
                excluded_symlinks: vec![],
            },
        };
        let run = DeepRun {
            packages: vec![unavailable, bundle_failure],
            exit_code: 3,
        };
        let preflight = DeepPreflight {
            endpoint_host: "localhost".into(),
            model: "model".into(),
            package_count: 1,
            original_bytes: None,
            encoded_request_bytes: None,
            large_request_mode: false,
        };

        let json = render_deep_json(&run, &preflight);
        assert_eq!(
            json["packages"][0]["analysis"]["bundle_hash"],
            "cd".repeat(32)
        );
        assert_eq!(
            json["packages"][1]["analysis"]["bundle_hash"],
            serde_json::Value::Null
        );
        assert_eq!(json["preflight"]["original_bytes"], serde_json::Value::Null);
        assert_eq!(
            json["preflight"]["encoded_request_bytes"],
            serde_json::Value::Null
        );
        let text = render_deep_text(&run, &preflight, &AckStore::from_keys([]), false, false);
        assert!(text.contains("original bytes=unmeasured"));
        assert!(text.contains("encoded bytes=unmeasured"));
    }

    #[test]
    fn deep_text_names_llm_provenance_ceiling_and_zero_findings_without_clearance() {
        use crate::deep_scan::{DeepPackageReport, DeepPreflight, DeepRun};
        use aurscan_llm::{
            AnalysisOutcome, AnalysisSource, AnalysisStatus, BundleCoverage, CoverageMode,
        };
        let run = DeepRun {
            packages: vec![DeepPackageReport {
                pkgbase: "base".into(),
                requested_packages: vec!["split".into()],
                combined: report("base", Verdict::Clean, vec![]),
                analysis: AnalysisOutcome {
                    status: AnalysisStatus::Completed,
                    source: Some(AnalysisSource::Cache),
                    findings: vec![],
                    identity: None,
                    usage: None,
                    reason: None,
                },
                bundle_hash: None,
                coverage: BundleCoverage {
                    mode: CoverageMode::ConservativeLocal,
                    included_files: 1,
                    excluded_binary_files: vec![],
                    excluded_symlinks: vec![],
                },
            }],
            exit_code: 0,
        };
        let preflight = DeepPreflight {
            endpoint_host: "localhost".into(),
            model: "model".into(),
            package_count: 1,
            original_bytes: Some(10),
            encoded_request_bytes: Some(100),
            large_request_mode: false,
        };
        let text = render_deep_text(&run, &preflight, &AckStore::from_keys([]), false, false);
        assert!(text.contains("LLM provenance"));
        assert!(text.contains("Advisory ceiling"));
        assert!(text.contains("prompt version=1"));
        assert!(text.contains("cache"));
        assert!(text.contains("conservative_local"));
        assert!(text.contains("no accepted LLM findings"));
        assert!(!text.to_ascii_lowercase().contains("model clean"));
    }
}
