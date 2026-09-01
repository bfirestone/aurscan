//! clap command surface. `check` is fully wired for local paths; the other
//! subcommands are stubs owned by later tasks.

#[derive(clap::Parser)]
#[command(name = "aurscan", version)]
pub struct Cli {
    /// Emit JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,
    /// Disable ANSI color in text output.
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Include Info findings and extra detail.
    #[arg(short, long, global = true)]
    pub verbose: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(clap::Subcommand)]
pub enum Cmd {
    /// Scan PKGBUILDs/sources without installing. Paths or package names.
    Check {
        targets: Vec<String>,
        #[arg(long)]
        hook: bool,
    },
    /// EXPERIMENTAL: deep semantic review; may contact a remote, cost-bearing LLM service.
    DeepScan {
        /// AUR package names or local build directories.
        targets: Vec<String>,
        /// Bypass only the LLM analysis cache.
        #[arg(long)]
        refresh: bool,
    },
    /// Fetch, scan, and (if clean) install AUR packages.
    Install {
        packages: Vec<String>,
        #[arg(long)]
        allow: Vec<String>,
    },
    /// Scan already-built package archives.
    ScanArtifact {
        packages: Vec<String>,
        /// ALPM `PreTransaction` hook mode: read target archives/pkgnames
        /// from stdin instead of `packages`.
        #[arg(long)]
        hook: bool,
    },
    /// Acknowledge current findings for packages so they stop prompting and
    /// gating until their matched content changes. LLM acknowledgement is
    /// experimental and may contact a remote, cost-bearing service.
    Ack {
        /// Package names, build directories, or built .pkg.tar.zst archives.
        targets: Vec<String>,
        /// EXPERIMENTAL: analyze and acknowledge only LLM findings; may be remote/cost-bearing.
        #[arg(long)]
        llm: bool,
        /// Acknowledge without prompting (required when not at a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Audit an installed system for compromise artifacts.
    Audit {
        #[arg(long, default_value = "/")]
        root: String,
    },
    /// Refresh the bundled compromised-package lists.
    UpdateLists,
    /// Install the pacman hook and initial configuration.
    Setup {
        /// Apply changes without prompting.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Report whether the paru gate is active and exit; change nothing.
        #[arg(long, conflicts_with = "yes")]
        check: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn parses_explicit_deep_scan_and_llm_ack_surfaces() {
        let deep = Cli::try_parse_from(["aurscan", "deep-scan", "split", "--refresh"]).unwrap();
        assert!(matches!(
            deep.cmd,
            Cmd::DeepScan { targets, refresh } if targets == ["split"] && refresh
        ));

        let ack = Cli::try_parse_from(["aurscan", "ack", "--llm", "split", "--yes"]).unwrap();
        assert!(matches!(
            ack.cmd,
            Cmd::Ack { targets, yes: true, llm: true } if targets == ["split"]
        ));
    }

    #[test]
    fn llm_help_warns_that_analysis_is_experimental_and_may_be_remote_or_cost_bearing() {
        let mut command = Cli::command();
        let deep = command
            .find_subcommand_mut("deep-scan")
            .expect("deep-scan subcommand");
        let help = deep.render_long_help().to_string().to_ascii_lowercase();
        assert!(help.contains("experimental"));
        assert!(help.contains("remote"));
        assert!(help.contains("cost"));

        let mut command = Cli::command();
        let ack = command.find_subcommand_mut("ack").expect("ack subcommand");
        let help = ack.render_long_help().to_string().to_ascii_lowercase();
        assert!(help.contains("experimental"));
        assert!(help.contains("remote"));
        assert!(help.contains("cost"));
    }
}
