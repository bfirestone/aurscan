mod ack;
mod aur_rpc;
mod cli;
mod config;
mod registry;
mod report;

use clap::Parser;
use cli::{Cli, Cmd};
use config::Config;
use std::io::IsTerminal;

fn main() {
    let cli = Cli::parse();
    let cfg = Config::load();

    let code = match cli.cmd {
        Cmd::Check { targets, hook } => {
            let _ = hook;
            run_check(&targets, &cfg, cli.json, cli.no_color, cli.verbose)
        }
        Cmd::Install { packages, allow } => {
            let _ = (packages, allow);
            not_implemented("install")
        }
        Cmd::ScanArtifact { packages } => {
            let _ = packages;
            not_implemented("scan-artifact")
        }
        Cmd::Audit { root } => {
            let _ = root;
            not_implemented("audit")
        }
        Cmd::UpdateLists => not_implemented("update-lists"),
        Cmd::Setup => not_implemented("setup"),
    };

    std::process::exit(code);
}

fn run_check(targets: &[String], cfg: &Config, json: bool, no_color: bool, verbose: bool) -> i32 {
    let mut paths = Vec::new();
    for t in targets {
        if std::path::Path::new(t).exists() {
            paths.push(t.clone());
        } else {
            eprintln!(
                "note: '{t}' is not a local path; name-based check requires the RPC/fetch flow (not yet wired)"
            );
        }
    }

    let (reports, code) = match registry::run_check(&paths, cfg) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 3;
        }
    };

    let acks = ack::AckStore::load();
    if json {
        let value = report::render_json(&reports);
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    } else {
        let color = !no_color && std::io::stdout().is_terminal();
        print!("{}", report::render_text(&reports, &acks, verbose, color));
    }

    code
}

fn not_implemented(name: &str) -> ! {
    eprintln!("aurscan {name}: not yet implemented");
    std::process::exit(3);
}
