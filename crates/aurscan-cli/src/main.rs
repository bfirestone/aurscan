mod ack;
mod artifact;
mod aur_rpc;
mod audit;
mod cli;
mod config;
mod corpus;
mod fetch;
mod flow;
mod gate;
mod lists;
mod registry;
mod report;
mod setup;

use clap::Parser;
use cli::{Cli, Cmd};
use config::Config;
use std::io::IsTerminal;

fn main() {
    let cli = Cli::parse();
    let cfg = Config::load();

    let code = match cli.cmd {
        Cmd::Check { targets, hook } => {
            let (paths, names): (Vec<String>, Vec<String>) = targets
                .into_iter()
                .partition(|t| std::path::Path::new(t).exists());

            let path_code = if paths.is_empty() {
                0
            } else {
                run_check(&paths, &cfg, cli.json, cli.no_color, cli.verbose)
            };
            let name_code = if names.is_empty() {
                0
            } else {
                let refs: Vec<&str> = names.iter().map(String::as_str).collect();
                flow::run_check_names(&refs, &cfg, hook, cli.json, cli.no_color, cli.verbose)
            };
            path_code.max(name_code)
        }
        Cmd::Install { packages, allow } => {
            let refs: Vec<&str> = packages.iter().map(String::as_str).collect();
            flow::run_install(&refs, &allow, &cfg, cli.json, cli.no_color, cli.verbose)
        }
        Cmd::ScanArtifact { packages, hook } => {
            if hook {
                artifact::hook_main()
            } else {
                let paths: Vec<std::path::PathBuf> = packages.into_iter().map(Into::into).collect();
                artifact::scan_files(&paths, &cfg, cli.json, cli.no_color, cli.verbose)
            }
        }
        Cmd::Audit { root } => audit::run_audit(std::path::Path::new(&root), &cfg),
        Cmd::UpdateLists => match lists::update() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("warning: {e:#}");
                3
            }
        },
        Cmd::Setup => match setup::run() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e:#}");
                3
            }
        },
    };

    std::process::exit(code);
}

fn run_check(paths: &[String], cfg: &Config, json: bool, no_color: bool, verbose: bool) -> i32 {
    let (reports, code) = match registry::run_check(paths, cfg) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 3;
        }
    };

    if cfg.record_features {
        if let Some(data_dir) = dirs::data_dir() {
            corpus::record(&reports, &data_dir);
        }
    }

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
