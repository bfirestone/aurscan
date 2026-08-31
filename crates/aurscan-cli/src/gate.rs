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

/// Map a `check` exit code to the paru `PreBuildCommand` contract. paru
/// aborts the build on any non-zero exit, so a raw Advisory (1) means one
/// Medium finding on one legitimate package kills a whole `-Syyu` (observed
/// with tilt-bin).
///
/// On an interactive terminal an Advisory asks whether to proceed.
/// Declining (or plain Enter) aborts that build. Without a terminal there
/// is nobody to ask, so print the note and proceed -- aborting there would
/// just re-create the tilt-bin failure for every scripted update.
///
/// The tty test is stdin-only and the prompt goes to *stderr*: paru
/// captures the hook's stdout but passes stdin through as the terminal
/// (verified against paru v2.1.0; see docs/integration.md), so a
/// stdout-gated prompt would never fire under the one caller this exists
/// for.
///
/// Block stays 2. Scan errors stay non-zero, unlike the ALPM hook: that
/// hook fires on every pacman transaction and must never brick unrelated
/// installs, while `PreBuildCommand` only fires on the AUR build being
/// gated, so the primary gate fails closed.
pub fn hook_exit_code(code: i32) -> i32 {
    if code != 1 {
        return code;
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "==> aurscan: advisory findings above do not abort the build; \
             run `aurscan ack <package>` to silence reviewed findings"
        );
        return 0;
    }
    eprint!("==> aurscan: advisory findings above. Proceed with this build? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let proceed = std::io::stdin().read_line(&mut line).is_ok()
        && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    if proceed {
        0
    } else {
        eprintln!("==> aurscan: build aborted at advisory findings");
        1
    }
}

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
                        "note: {0} has advisory findings; run `aurscan check {0}` to review or `aurscan ack {0}` to acknowledge",
                        report.package
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
    fn hook_exit_code_maps_advisory_to_success_without_a_tty() {
        // Regression: `paru -Syyu` died at tilt-bin because one Medium
        // advisory exited 1 and paru aborts PreBuildCommand on any non-zero.
        // The test harness has no tty, which is exactly the unattended case:
        // note and proceed.
        assert_eq!(hook_exit_code(1), 0);
    }

    #[test]
    fn hook_exit_code_passes_everything_else_through() {
        assert_eq!(hook_exit_code(0), 0);
        assert_eq!(hook_exit_code(2), 2, "Block must still abort the build");
        assert_eq!(hook_exit_code(3), 3, "scan errors fail closed in this gate");
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
