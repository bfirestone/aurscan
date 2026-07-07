//! Tiered interactive verdict gate: decides whether `install` may proceed to
//! `paru -S` given the scan reports for the packages about to be built.
//!
//! - `Block` on a package not in `allow` aborts unless the operator is at an
//!   interactive tty and types the package name back to override.
//! - `Advisory` prompts for confirmation at an interactive tty; anywhere else
//!   it's a non-blocking signal (the exit code already carries `1`).
//! - `--hook` mode never prompts (stdin may be detached under
//!   `PreTransaction`/`PreBuildCommand`): `Block` still aborts, `Advisory`
//!   proceeds with a printed pointer to `check`/`ack`.
//! - `allow` entries downgrade that package's `Block` to a logged override.

use aurscan_core::{PackageReport, Verdict};
use std::io::{IsTerminal, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    Proceed,
    Abort,
}

/// Decide whether the install may proceed given the scanned `reports`.
pub fn decide(
    reports: &[PackageReport],
    allow: &[String],
    interactive: bool,
    hook: bool,
) -> GateOutcome {
    let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let prompt_ok = interactive && !hook && tty;

    for report in reports {
        match &report.verdict {
            Verdict::Block(_) if allow.iter().any(|a| a == &report.package) => {
                eprintln!(
                    "note: {} is Block but allow-listed; overriding",
                    report.package
                );
            }
            Verdict::Block(findings) => {
                if prompt_ok && confirm_override(&report.package, findings) {
                    continue;
                }
                return GateOutcome::Abort;
            }
            Verdict::Advisory(findings) => {
                if prompt_ok {
                    if !confirm_proceed(&report.package, findings) {
                        return GateOutcome::Abort;
                    }
                } else if hook {
                    eprintln!(
                        "note: {} has advisory findings; run `aurscan check {}` to review or `aurscan ack` to acknowledge",
                        report.package, report.package
                    );
                }
            }
            Verdict::Clean => {}
        }
    }
    GateOutcome::Proceed
}

fn confirm_override(package: &str, findings: &[aurscan_core::Finding]) -> bool {
    print_findings(package, findings);
    print!("Type '{package}' to override and proceed anyway: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok() && line.trim() == package
}

fn confirm_proceed(package: &str, findings: &[aurscan_core::Finding]) -> bool {
    print_findings(package, findings);
    print!("Proceed with {package}? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok()
        && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn print_findings(package: &str, findings: &[aurscan_core::Finding]) {
    eprintln!("{package}:");
    for f in findings {
        eprintln!(
            "  [{:?}] {} ({})",
            f.severity, f.reason, f.evidence.location
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::{Confidence, DetectorId, Evidence, Finding, Severity};

    fn finding(severity: Severity) -> Finding {
        Finding {
            severity,
            confidence: Confidence::Exact,
            detector: DetectorId("ioc_tokens"),
            package: "pkg".into(),
            reason: "malicious token".into(),
            evidence: Evidence {
                location: "PKGBUILD:3".into(),
                excerpt: "npm install atomic-lockfile".into(),
            },
        }
    }

    fn report(package: &str, verdict: Verdict) -> PackageReport {
        PackageReport {
            package: package.into(),
            verdict,
            findings: vec![],
            features: vec![],
        }
    }

    #[test]
    fn block_non_interactive_aborts() {
        let reports = [report(
            "pkg",
            Verdict::Block(vec![finding(Severity::Critical)]),
        )];
        let outcome = decide(&reports, &[], false, false);
        assert_eq!(outcome, GateOutcome::Abort);
    }

    #[test]
    fn allow_list_downgrades_block_to_proceed() {
        let reports = [report(
            "pkg",
            Verdict::Block(vec![finding(Severity::Critical)]),
        )];
        let outcome = decide(&reports, &["pkg".to_string()], false, false);
        assert_eq!(outcome, GateOutcome::Proceed);
    }

    #[test]
    fn clean_proceeds() {
        let reports = [report("pkg", Verdict::Clean)];
        let outcome = decide(&reports, &[], false, false);
        assert_eq!(outcome, GateOutcome::Proceed);
    }

    #[test]
    fn hook_mode_advisory_proceeds_without_prompt() {
        // Non-interactive test harness stdin isn't a tty anyway, but hook=true
        // must short-circuit prompting even if it were attached to one.
        let reports = [report(
            "pkg",
            Verdict::Advisory(vec![finding(Severity::Medium)]),
        )];
        let outcome = decide(&reports, &[], true, true);
        assert_eq!(outcome, GateOutcome::Proceed);
    }
}
