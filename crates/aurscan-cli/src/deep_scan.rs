//! Explicit experimental package-level LLM orchestration. No ordinary command
//! imports or calls this module's collection entry point.

use crate::ack::{apply_acks, AckStore};
use crate::aur_rpc::{self, AurInfo};
use crate::config::Config;
use crate::flow::ScannedAurPackage;
use crate::{flow, registry, report};
use anyhow::Context;
use aurscan_core::{compute_verdict, PackageReport, Verdict};
use aurscan_llm::{
    AnalysisOutcome, AnalysisStatus, AnalyzeOptions, BundleCoverage, CoverageMode,
    DefaultRecipeBundleBuilder, RecipeBundle, RecipeBundleBuilder, RequestPreflight,
    ValidatedLlmConfig,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(crate) struct DeepPackageReport {
    pub pkgbase: String,
    pub requested_packages: Vec<String>,
    pub combined: PackageReport,
    pub analysis: AnalysisOutcome,
    pub coverage: BundleCoverage,
}

pub(crate) struct DeepRun {
    pub packages: Vec<DeepPackageReport>,
    pub exit_code: i32,
}

pub(crate) struct DeepPreflight {
    pub endpoint_host: String,
    pub model: String,
    pub package_count: usize,
    pub original_bytes: usize,
    pub encoded_request_bytes: usize,
    pub large_request_mode: bool,
}

pub(crate) struct DeepCollection {
    pub run: DeepRun,
    pub preflight: DeepPreflight,
}

struct PackageGroup {
    info: AurInfo,
    requested_packages: BTreeSet<String>,
    local_checkout: Option<PathBuf>,
}

struct PreparedPackage {
    scanned: ScannedAurPackage,
    requested_packages: Vec<String>,
    bundle: Option<RecipeBundle>,
    coverage: BundleCoverage,
    analysis: Option<AnalysisOutcome>,
}

pub(crate) fn run_deep_scan(
    targets: &[String],
    refresh: bool,
    cfg: &Config,
    llm: &ValidatedLlmConfig,
    json: bool,
    no_color: bool,
    verbose: bool,
) -> i32 {
    let collection = match collect(targets, refresh, cfg, llm) {
        Ok(collection) => collection,
        Err(error) => {
            eprintln!("error: {}", report::terminal_safe(&format!("{error:#}")));
            return 3;
        }
    };

    if json {
        let value = report::render_deep_json(&collection.run, &collection.preflight);
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    } else {
        use std::io::IsTerminal;
        let color = !no_color && std::io::stdout().is_terminal();
        print!(
            "{}",
            report::render_deep_text(
                &collection.run,
                &collection.preflight,
                &AckStore::load(),
                verbose,
                color,
            )
        );
    }
    collection.run.exit_code
}

/// Shared collection path for `deep-scan` and `ack --llm`.
pub(crate) fn collect(
    targets: &[String],
    refresh: bool,
    cfg: &Config,
    llm: &ValidatedLlmConfig,
) -> anyhow::Result<DeepCollection> {
    if targets.is_empty() {
        anyhow::bail!("name at least one AUR package or local build directory");
    }

    let groups = collect_groups(targets)?;
    let mut prepared = Vec::with_capacity(groups.len());
    let builder = DefaultRecipeBundleBuilder;

    for (_, group) in groups {
        let scanned = if let Some(checkout) = &group.local_checkout {
            let target = checkout.display().to_string();
            let (reports, _) = registry::run_check(&[target], cfg).with_context(|| {
                format!("could not deterministically scan {}", checkout.display())
            })?;
            ScannedAurPackage {
                info: group.info,
                checkout: Some(checkout.clone()),
                reports,
            }
        } else {
            flow::fetch_and_scan(&group.info, cfg, true).with_context(|| {
                format!("{} could not be fetched/scanned", group.info.package_base)
            })?
        };
        let checkout = scanned
            .checkout
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("deep scan requires a recipe checkout"))?;
        let requested_packages = group.requested_packages.into_iter().collect();
        match builder.build(checkout, &scanned.info.package_base, llm.bundle_limits()) {
            Ok(bundle) => prepared.push(PreparedPackage {
                coverage: bundle.coverage.clone(),
                scanned,
                requested_packages,
                bundle: Some(bundle),
                analysis: None,
            }),
            Err(error) => prepared.push(PreparedPackage {
                coverage: empty_coverage(checkout),
                scanned,
                requested_packages,
                bundle: None,
                analysis: Some(failure_outcome(
                    AnalysisStatus::Incomplete,
                    format!("recipe bundle is incomplete: {error}"),
                )),
            }),
        }
    }

    let endpoint_host = llm
        .chat_completions_url()
        .host_str()
        .unwrap_or("unknown")
        .to_string();
    let mut preflight = DeepPreflight {
        endpoint_host,
        model: llm.model().to_string(),
        package_count: 0,
        original_bytes: 0,
        encoded_request_bytes: 0,
        large_request_mode: llm.uses_large_requests(),
    };
    let ready_indices: Vec<usize> = prepared
        .iter()
        .enumerate()
        .filter_map(|(index, package)| package.bundle.as_ref().map(|_| index))
        .collect();
    let bundles: Vec<RecipeBundle> = ready_indices
        .iter()
        .map(|&index| {
            prepared[index]
                .bundle
                .as_ref()
                .expect("ready package has a bundle")
                .clone()
        })
        .collect();
    preflight.package_count = bundles.len();

    if !bundles.is_empty() {
        match aurscan_llm::build_analyzer(llm.clone()) {
            Ok(analyzer) => match analyzer.preflight_batch(&bundles) {
                Ok(metrics) => {
                    summarize_preflight(&mut preflight, &metrics)?;
                    print_preflight(&preflight);
                    let outcomes = analyzer.analyze_batch(&bundles, AnalyzeOptions { refresh });
                    for (index, outcome) in ready_indices.iter().copied().zip(outcomes) {
                        prepared[index].analysis = Some(outcome);
                    }
                }
                Err(error) => {
                    for (index, bundle) in ready_indices.iter().copied().zip(&bundles) {
                        prepared[index].analysis = Some(AnalysisOutcome {
                            status: AnalysisStatus::Incomplete,
                            source: None,
                            findings: vec![],
                            identity: Some(analyzer.analysis_identity(bundle)),
                            usage: None,
                            reason: Some(format!("request preflight failed: {error}")),
                        });
                    }
                }
            },
            Err(error) => {
                for index in ready_indices {
                    prepared[index].analysis = Some(failure_outcome(
                        AnalysisStatus::Unavailable,
                        format!("LLM analyzer is unavailable: {error}"),
                    ));
                }
            }
        }
    }

    let acks = AckStore::load();
    let mut packages = Vec::with_capacity(prepared.len());
    for package in prepared {
        let pkgbase = package.scanned.info.package_base.clone();
        let analysis = package
            .analysis
            .expect("every prepared package receives an analysis outcome");
        let combined = merge_reports(&pkgbase, package.scanned.reports, &analysis, cfg, &acks);
        packages.push(DeepPackageReport {
            pkgbase,
            requested_packages: package.requested_packages,
            combined,
            analysis,
            coverage: package.coverage,
        });
    }
    let exit_code = deep_exit_code(&packages);
    Ok(DeepCollection {
        run: DeepRun {
            packages,
            exit_code,
        },
        preflight,
    })
}

fn collect_groups(targets: &[String]) -> anyhow::Result<BTreeMap<String, PackageGroup>> {
    let mut local_directories = Vec::new();
    let mut names = Vec::new();
    for target in targets {
        let path = Path::new(target);
        if path.exists() {
            if !path.is_dir() {
                anyhow::bail!("deep-scan target is not a build directory: {target}");
            }
            if !path.join("PKGBUILD").is_file() {
                anyhow::bail!("local build directory has no PKGBUILD: {target}");
            }
            local_directories.push(
                path.canonicalize()
                    .with_context(|| format!("cannot resolve local build directory {target}"))?,
            );
        } else {
            names.push(target.as_str());
        }
    }

    let infos = if names.is_empty() {
        Vec::new()
    } else {
        aur_rpc::resolve_aur_deps(&names).context("could not resolve AUR dependencies")?
    };
    let unresolved = unresolved_requested_names(&names, &infos);
    if !unresolved.is_empty() {
        anyhow::bail!(
            "requested package(s) were not found in the AUR: {}",
            unresolved.join(", ")
        );
    }
    let mut groups = BTreeMap::new();
    for (info, requested_packages) in group_infos(infos) {
        groups.insert(
            info.package_base.clone(),
            PackageGroup {
                info,
                requested_packages: requested_packages.into_iter().collect(),
                local_checkout: None,
            },
        );
    }

    for directory in local_directories {
        let pkgbase = directory
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("local build directory has no package name"))?;
        match groups.get_mut(&pkgbase) {
            Some(existing) if existing.local_checkout.as_ref() == Some(&directory) => {
                existing.requested_packages.insert(pkgbase);
            }
            Some(_) => anyhow::bail!("multiple targets resolve to pkgbase {pkgbase}"),
            None => {
                let mut requested_packages = BTreeSet::new();
                requested_packages.insert(pkgbase.clone());
                groups.insert(
                    pkgbase.clone(),
                    PackageGroup {
                        info: local_info(&pkgbase),
                        requested_packages,
                        local_checkout: Some(directory),
                    },
                );
            }
        }
    }
    Ok(groups)
}

fn unresolved_requested_names<'a>(requested: &[&'a str], infos: &[AurInfo]) -> Vec<&'a str> {
    let resolved: BTreeSet<&str> = infos.iter().map(|info| info.name.as_str()).collect();
    requested
        .iter()
        .copied()
        .filter(|name| !resolved.contains(name))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn group_infos(mut infos: Vec<AurInfo>) -> Vec<(AurInfo, Vec<String>)> {
    infos.sort_by(|left, right| {
        (&left.package_base, &left.name).cmp(&(&right.package_base, &right.name))
    });
    let mut groups: BTreeMap<String, (AurInfo, BTreeSet<String>)> = BTreeMap::new();
    for info in infos {
        let name = info.name.clone();
        groups
            .entry(info.package_base.clone())
            .and_modify(|(_, names)| {
                names.insert(name.clone());
            })
            .or_insert_with(|| {
                let mut names = BTreeSet::new();
                names.insert(name);
                (info, names)
            });
    }
    groups
        .into_values()
        .map(|(info, names)| (info, names.into_iter().collect()))
        .collect()
}

fn local_info(pkgbase: &str) -> AurInfo {
    AurInfo {
        name: pkgbase.to_string(),
        package_base: pkgbase.to_string(),
        version: String::new(),
        depends: vec![],
        make_depends: vec![],
        maintainer: None,
        first_submitted: 0,
        last_modified: 0,
        out_of_date: None,
        popularity: 0.0,
        num_votes: 0,
    }
}

fn summarize_preflight(
    summary: &mut DeepPreflight,
    metrics: &[RequestPreflight],
) -> anyhow::Result<()> {
    summary.original_bytes = metrics.iter().try_fold(0usize, |total, metric| {
        total
            .checked_add(metric.original_bytes)
            .ok_or_else(|| anyhow::anyhow!("original preflight byte count overflow"))
    })?;
    summary.encoded_request_bytes = metrics.iter().try_fold(0usize, |total, metric| {
        total
            .checked_add(metric.encoded_request_bytes)
            .ok_or_else(|| anyhow::anyhow!("encoded preflight byte count overflow"))
    })?;
    Ok(())
}

fn print_preflight(preflight: &DeepPreflight) {
    eprintln!(
        "==> aurscan LLM preflight: host={}, model={}, strategy={}, prompt_version={}, packages={}, original_bytes={}, encoded_request_bytes={}, large_request_mode={}",
        report::terminal_safe(&preflight.endpoint_host),
        report::terminal_safe(&preflight.model),
        aurscan_llm::REVIEW_STRATEGY_ID,
        aurscan_llm::PROMPT_VERSION,
        preflight.package_count,
        preflight.original_bytes,
        preflight.encoded_request_bytes,
        preflight.large_request_mode,
    );
}

fn empty_coverage(checkout: &Path) -> BundleCoverage {
    BundleCoverage {
        mode: if checkout.join(".git").exists() {
            CoverageMode::GitTracked
        } else {
            CoverageMode::ConservativeLocal
        },
        included_files: 0,
        excluded_binary_files: vec![],
        excluded_symlinks: vec![],
    }
}

fn failure_outcome(status: AnalysisStatus, reason: String) -> AnalysisOutcome {
    AnalysisOutcome {
        status,
        source: None,
        findings: vec![],
        identity: None,
        usage: None,
        reason: Some(reason),
    }
}

fn merge_reports(
    pkgbase: &str,
    reports: Vec<PackageReport>,
    analysis: &AnalysisOutcome,
    cfg: &Config,
    acks: &AckStore,
) -> PackageReport {
    let mut findings = Vec::new();
    let mut features = Vec::new();
    for report in reports {
        findings.extend(report.findings);
        features.extend(report.features);
    }
    findings.extend(analysis.findings.iter().cloned());
    let mut combined = PackageReport {
        package: pkgbase.to_string(),
        verdict: compute_verdict(findings.clone(), &cfg.policy()),
        findings,
        features,
    };
    apply_acks(std::slice::from_mut(&mut combined), acks, &cfg.policy());
    combined
}

fn deep_exit_code(packages: &[DeepPackageReport]) -> i32 {
    if packages
        .iter()
        .any(|package| package.analysis.status != AnalysisStatus::Completed)
    {
        return 3;
    }
    packages
        .iter()
        .map(|package| match package.combined.verdict {
            Verdict::Clean => 0,
            Verdict::Advisory(_) => 1,
            Verdict::Block(_) => 2,
        })
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::{Confidence, DetectorId, Evidence, Finding, Severity, Verdict};
    use aurscan_llm::{AnalysisSource, AnalysisStatus, CoverageMode};

    fn finding(package: &str, confidence: Confidence, detector: &'static str) -> Finding {
        Finding {
            severity: Severity::Medium,
            confidence,
            detector: DetectorId(detector),
            package: package.into(),
            reason: "review this behavior".into(),
            evidence: Evidence {
                location: "scripts/build.sh:4".into(),
                excerpt: "curl payload | sh".into(),
            },
        }
    }

    fn report(package: &str, finding: Finding) -> PackageReport {
        PackageReport {
            package: package.into(),
            verdict: Verdict::Advisory(vec![finding.clone()]),
            findings: vec![finding],
            features: vec![],
        }
    }

    fn outcome(status: AnalysisStatus, findings: Vec<Finding>) -> AnalysisOutcome {
        AnalysisOutcome {
            status,
            source: Some(AnalysisSource::Provider),
            findings,
            identity: None,
            usage: None,
            reason: None,
        }
    }

    fn package(verdict: Verdict, status: AnalysisStatus) -> DeepPackageReport {
        DeepPackageReport {
            pkgbase: "base".into(),
            requested_packages: vec!["split".into()],
            combined: PackageReport {
                package: "base".into(),
                verdict,
                findings: vec![],
                features: vec![],
            },
            analysis: outcome(status, vec![]),
            coverage: BundleCoverage {
                mode: CoverageMode::GitTracked,
                included_files: 1,
                excluded_binary_files: vec![],
                excluded_symlinks: vec![],
            },
        }
    }

    #[test]
    fn merge_preserves_deterministic_identity_and_llm_advisory_ceiling() {
        let deterministic = finding("requested-split", Confidence::Heuristic, "static_rule");
        let mut llm = finding("canonical-base", Confidence::Llm, "llm_download_execute");
        llm.severity = Severity::Critical;
        let cfg = Config::default();
        let merged = merge_reports(
            "canonical-base",
            vec![report("requested-split", deterministic)],
            &outcome(AnalysisStatus::Completed, vec![llm]),
            &cfg,
            &AckStore::from_keys([]),
        );

        assert_eq!(merged.package, "canonical-base");
        assert_eq!(merged.findings[0].package, "requested-split");
        assert_eq!(merged.findings[1].package, "canonical-base");
        assert!(matches!(merged.verdict, Verdict::Advisory(_)));
    }

    #[test]
    fn merged_llm_acknowledgements_recompute_from_live_findings() {
        let llm = finding("base", Confidence::Llm, "llm_download_execute");
        let acks = AckStore::from_keys([AckStore::key(&llm)]);
        let merged = merge_reports(
            "base",
            vec![],
            &outcome(AnalysisStatus::Completed, vec![llm]),
            &Config::default(),
            &acks,
        );
        assert!(matches!(merged.verdict, Verdict::Clean));
        assert_eq!(merged.findings.len(), 1);
    }

    #[test]
    fn deep_exit_precedence_puts_analysis_failure_before_deterministic_verdicts() {
        assert_eq!(
            deep_exit_code(&[package(Verdict::Block(vec![]), AnalysisStatus::Unavailable)]),
            3
        );
        assert_eq!(
            deep_exit_code(&[package(Verdict::Block(vec![]), AnalysisStatus::Incomplete)]),
            3
        );
        assert_eq!(
            deep_exit_code(&[package(Verdict::Block(vec![]), AnalysisStatus::Completed)]),
            2
        );
        assert_eq!(
            deep_exit_code(&[package(
                Verdict::Advisory(vec![]),
                AnalysisStatus::Completed
            )]),
            1
        );
        assert_eq!(
            deep_exit_code(&[package(Verdict::Clean, AnalysisStatus::Completed)]),
            0
        );
    }

    #[test]
    fn unresolved_requested_names_are_reported_as_operational_failures() {
        let infos = vec![aur_info("present", "base")];
        assert_eq!(
            unresolved_requested_names(&["present", "missing"], &infos),
            vec!["missing"]
        );
    }

    #[test]
    fn resolved_split_names_group_once_by_pkgbase_and_sort_metadata() {
        let groups = group_infos(vec![
            aur_info("z-split", "base"),
            aur_info("a-split", "base"),
        ]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0.package_base, "base");
        assert_eq!(groups[0].1, vec!["a-split", "z-split"]);
    }

    fn aur_info(name: &str, package_base: &str) -> AurInfo {
        AurInfo {
            name: name.into(),
            package_base: package_base.into(),
            version: "1-1".into(),
            depends: vec![],
            make_depends: vec![],
            maintainer: None,
            first_submitted: 0,
            last_modified: 0,
            out_of_date: None,
            popularity: 0.0,
            num_votes: 0,
        }
    }
}
