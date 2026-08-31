mod ack;
mod artifact;
mod audit;
mod aur_rpc;
mod cli;
mod config;
mod corpus;
mod fetch;
mod flow;
mod gate;
mod lists;
mod paru_conf;
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

    // Size the rayon pool before anything scans (build_global is
    // first-caller-wins). Hooks run behind an interactive pacman/paru
    // session, so they get half the cores by default; see
    // Config::effective_scan_threads.
    let hook_mode = matches!(
        cli.cmd,
        Cmd::Check { hook: true, .. } | Cmd::ScanArtifact { hook: true, .. }
    );
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.effective_scan_threads(hook_mode))
        .build_global();

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
                flow::run_check_names(&refs, &cfg, cli.json, cli.no_color, cli.verbose)
            };
            // The hook mapping wraps *both* branches: paru's PreBuildCommand
            // passes a path (`check --hook .`), which previously bypassed
            // the hook flag entirely.
            let code = path_code.max(name_code);
            if hook {
                gate::hook_exit_code(code)
            } else {
                code
            }
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
        Cmd::Ack { targets, yes } => {
            if targets.is_empty() {
                eprintln!(
                    "aurscan: name at least one package, build dir, or archive to acknowledge"
                );
                3
            } else {
                ack::run_ack(&targets, yes, &cfg)
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
        Cmd::Setup { yes, check } => {
            if check {
                setup::check()
            } else {
                match setup::run(yes) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("error: {e:#}");
                        3
                    }
                }
            }
        }
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
