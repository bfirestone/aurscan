//! Rendering: tiered, severity-sorted text output (mirroring the legacy
//! `render_report`) plus a structured JSON view, and the verdict->exit-code
//! mapping that gates hooks/CI.

use crate::ack::AckStore;
use aurscan_core::{Finding, PackageReport, Severity, Verdict};
use std::fmt::Write;

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
        let _ = writeln!(out, "{}: {}", report.package, verdict_name(&report.verdict));

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
            let _ = writeln!(out, "  {marker} {}", f.reason);
            let _ = writeln!(out, "    \u{21b3} {}", f.evidence.location);
        }
        if acknowledged > 0 {
            let _ = writeln!(out, "  ({acknowledged} acknowledged)");
        }
    }
    out
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
}
