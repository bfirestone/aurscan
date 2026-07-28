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
