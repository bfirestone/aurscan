//! Explicit experimental package-level LLM orchestration. No ordinary command
//! imports or calls this module's collection entry point.

use crate::ack::{apply_acks, AckStore};
use crate::aur_rpc::{self, AurInfo};
use crate::config::Config;
use crate::flow::ScannedAurPackage;
use crate::{fetch, flow, registry, report};
use anyhow::Context;
use aurscan_core::{compute_verdict, PackageReport, Verdict};
use aurscan_llm::{
    AnalysisOutcome, AnalysisStatus, AnalyzeOptions, BundleCoverage, CoverageMode,
    DefaultRecipeBundleBuilder, RecipeBundle, RecipeBundleBuilder, RequestPreflight,
    ValidatedLlmConfig,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

pub(crate) struct DeepPackageReport {
    pub pkgbase: String,
    pub requested_packages: Vec<String>,
    pub combined: PackageReport,
    pub analysis: AnalysisOutcome,
    pub bundle_hash: Option<[u8; 32]>,
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
    pub original_bytes: Option<usize>,
    pub encoded_request_bytes: Option<usize>,
    pub large_request_mode: bool,
}

pub(crate) struct DeepCollection {
    pub run: DeepRun,
    pub preflight: DeepPreflight,
}

struct PackageGroup {
    info: AurInfo,
    requested_packages: BTreeSet<String>,
    local_checkout: Option<LocalCheckout>,
}

struct LocalCheckout {
    root: fetch::SecureRoot,
    target: PathBuf,
}

impl LocalCheckout {
    fn proc_path(&self) -> PathBuf {
        self.root.proc_path()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LocalRecipeMetadata {
    pkgbase: String,
    package_names: Vec<String>,
}

struct PreparedPackage {
    scanned: ScannedAurPackage,
    requested_packages: Vec<String>,
    bundle: Option<RecipeBundle>,
    bundle_hash: Option<[u8; 32]>,
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
            let checkout_path = checkout.proc_path();
            let target = checkout_path.display().to_string();
            let (reports, _) = registry::run_check(&[target], cfg).with_context(|| {
                format!(
                    "could not deterministically scan {}",
                    checkout.target.display()
                )
            })?;
            ScannedAurPackage {
                info: group.info,
                checkout: Some(checkout_path),
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
                bundle_hash: Some(bundle.content_hash),
                bundle: Some(bundle),
                analysis: None,
            }),
            Err(error) => prepared.push(PreparedPackage {
                coverage: empty_coverage(checkout),
                scanned,
                requested_packages,
                bundle_hash: None,
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
        original_bytes: None,
        encoded_request_bytes: None,
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
            bundle_hash: package.bundle_hash,
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
    if targets.iter().any(String::is_empty) {
        anyhow::bail!("target must not be empty");
    }

    let mut local_directories = Vec::new();
    let mut names = Vec::new();
    for target in targets {
        let path = Path::new(target);
        match fetch::SecureRoot::open_local_directory(path) {
            Ok(root) => {
                let metadata = parse_local_recipe_metadata_at(&root, path).with_context(|| {
                    format!("could not establish local recipe identity for {target}")
                })?;
                local_directories.push((
                    LocalCheckout {
                        root,
                        target: path.to_path_buf(),
                    },
                    metadata,
                ));
            }
            Err(fetch::SecureOpenError::Absent) => names.push(target.as_str()),
            Err(error) => {
                return Err(anyhow::Error::new(error)).with_context(|| {
                    format!("cannot securely open local build directory {target}")
                });
            }
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

    for (directory, metadata) in local_directories {
        insert_local_group(&mut groups, directory, metadata)?;
    }
    Ok(groups)
}

fn insert_local_group(
    groups: &mut BTreeMap<String, PackageGroup>,
    checkout: LocalCheckout,
    metadata: LocalRecipeMetadata,
) -> anyhow::Result<()> {
    let LocalRecipeMetadata {
        pkgbase,
        package_names,
    } = metadata;
    match groups.get_mut(&pkgbase) {
        Some(existing)
            if existing
                .local_checkout
                .as_ref()
                .is_some_and(|local| local.target == checkout.target) =>
        {
            existing.requested_packages.extend(package_names);
        }
        Some(_) => anyhow::bail!("multiple targets resolve to pkgbase {pkgbase}"),
        None => {
            groups.insert(
                pkgbase.clone(),
                PackageGroup {
                    info: local_info(&pkgbase),
                    requested_packages: package_names.into_iter().collect(),
                    local_checkout: Some(checkout),
                },
            );
        }
    }
    Ok(())
}

const MAX_LOCAL_METADATA_BYTES: u64 = 1024 * 1024;

#[cfg(test)]
fn parse_local_recipe_metadata(directory: &Path) -> anyhow::Result<LocalRecipeMetadata> {
    let root = fetch::SecureRoot::open_local_directory(directory)
        .map_err(anyhow::Error::new)
        .with_context(|| {
            format!(
                "cannot securely open local recipe root {}",
                directory.display()
            )
        })?;
    parse_local_recipe_metadata_at(&root, directory)
}

/// Establish a local recipe's canonical package identity without evaluating
/// any PKGBUILD code. A checked-in `.SRCINFO` is authoritative; otherwise a
/// deliberately narrow literal PKGBUILD subset is the only accepted fallback.
fn parse_local_recipe_metadata_at(
    root: &fetch::SecureRoot,
    directory: &Path,
) -> anyhow::Result<LocalRecipeMetadata> {
    let descriptor_path = root.proc_path();
    let pkgbuild = root
        .open_regular_file(Path::new("PKGBUILD"))
        .map_err(anyhow::Error::new)
        .with_context(|| {
            format!(
                "cannot securely open PKGBUILD beneath {}",
                directory.display()
            )
        })?;

    match root.open_regular_file(Path::new(".SRCINFO")) {
        Ok(srcinfo) => parse_srcinfo_metadata(&read_metadata_descriptor(
            srcinfo,
            ".SRCINFO",
            &descriptor_path.join(".SRCINFO"),
        )?),
        Err(fetch::SecureOpenError::Absent) => parse_literal_pkgbuild_metadata(
            &read_metadata_descriptor(pkgbuild, "PKGBUILD", &descriptor_path.join("PKGBUILD"))?,
        ),
        Err(error) => Err(anyhow::Error::new(error)).with_context(|| {
            format!(
                "cannot securely open .SRCINFO beneath {}",
                directory.display()
            )
        }),
    }
}

fn read_metadata_descriptor(
    mut file: std::fs::File,
    label: &str,
    path: &Path,
) -> anyhow::Result<String> {
    let metadata = file.metadata().with_context(|| {
        format!(
            "cannot inspect opened {label} descriptor at {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        anyhow::bail!("{label} must be a regular file: {}", path.display());
    }
    if metadata.len() > MAX_LOCAL_METADATA_BYTES {
        anyhow::bail!(
            "{label} exceeds the local metadata size limit: {}",
            path.display()
        );
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_LOCAL_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| {
            format!(
                "cannot read opened {label} descriptor at {}",
                path.display()
            )
        })?;
    if bytes.len() as u64 > MAX_LOCAL_METADATA_BYTES {
        anyhow::bail!(
            "{label} exceeds the local metadata size limit: {}",
            path.display()
        );
    }
    String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("{label} must be valid UTF-8: {}", path.display()))
}

fn parse_srcinfo_metadata(content: &str) -> anyhow::Result<LocalRecipeMetadata> {
    let mut pkgbase = None;
    let mut package_names = BTreeSet::new();
    for (line_number, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("malformed .SRCINFO metadata at line {}", line_number + 1)
        })?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty()
            || value.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            anyhow::bail!("malformed .SRCINFO metadata at line {}", line_number + 1);
        }
        match key {
            "pkgbase" => {
                if pkgbase.is_some() || !is_valid_package_name(value) {
                    anyhow::bail!("ambiguous or invalid pkgbase in .SRCINFO");
                }
                pkgbase = Some(value.to_string());
            }
            "pkgname"
                if !is_valid_package_name(value) || !package_names.insert(value.to_string()) =>
            {
                anyhow::bail!("ambiguous or invalid pkgname in .SRCINFO");
            }
            "pkgname" => {}
            _ => {}
        }
    }
    local_metadata_from_parts(pkgbase, package_names, ".SRCINFO")
}

fn parse_literal_pkgbuild_metadata(content: &str) -> anyhow::Result<LocalRecipeMetadata> {
    let mut pkgbase = None;
    let mut package_names = BTreeSet::new();
    let mut saw_pkgname = false;
    for (line_number, line) in content.lines().enumerate() {
        let candidate = line.trim_start();
        if (candidate.starts_with("pkgbase") || candidate.starts_with("pkgname"))
            && candidate != line
        {
            anyhow::bail!(
                "non-literal local package metadata in PKGBUILD at line {}",
                line_number + 1
            );
        }
        if let Some(value) = candidate.strip_prefix("pkgbase=") {
            if pkgbase.is_some() {
                anyhow::bail!("ambiguous pkgbase in PKGBUILD at line {}", line_number + 1);
            }
            let values = parse_literal_package_values(value).with_context(|| {
                format!(
                    "invalid literal pkgbase in PKGBUILD at line {}",
                    line_number + 1
                )
            })?;
            if values.len() != 1 {
                anyhow::bail!(
                    "invalid literal pkgbase in PKGBUILD at line {}",
                    line_number + 1
                );
            }
            pkgbase = values.into_iter().next();
        } else if let Some(value) = candidate.strip_prefix("pkgname=") {
            if saw_pkgname {
                anyhow::bail!("ambiguous pkgname in PKGBUILD at line {}", line_number + 1);
            }
            saw_pkgname = true;
            let values = parse_literal_package_values(value).with_context(|| {
                format!(
                    "invalid literal pkgname in PKGBUILD at line {}",
                    line_number + 1
                )
            })?;
            for value in values {
                if !package_names.insert(value) {
                    anyhow::bail!("ambiguous pkgname in PKGBUILD at line {}", line_number + 1);
                }
            }
        } else if candidate.starts_with("pkgbase") || candidate.starts_with("pkgname") {
            anyhow::bail!(
                "non-literal local package metadata in PKGBUILD at line {}",
                line_number + 1
            );
        }
    }

    if pkgbase.is_none() && package_names.len() == 1 {
        pkgbase = package_names.iter().next().cloned();
    }
    local_metadata_from_parts(pkgbase, package_names, "PKGBUILD")
}

fn parse_literal_package_values(value: &str) -> anyhow::Result<Vec<String>> {
    let value = value.trim();
    let body = if let Some(body) = value.strip_prefix('(') {
        body.strip_suffix(')')
            .ok_or_else(|| anyhow::anyhow!("unterminated literal array"))?
    } else {
        value
    };
    let mut values = Vec::new();
    let mut remaining = body.trim();
    while !remaining.is_empty() {
        let (value, rest) =
            if let Some(quote) = remaining.chars().next().filter(|c| matches!(c, '\'' | '"')) {
                let after_quote = &remaining[quote.len_utf8()..];
                let end = after_quote
                    .find(quote)
                    .ok_or_else(|| anyhow::anyhow!("unterminated quoted literal"))?;
                let value = &after_quote[..end];
                let rest = &after_quote[end + quote.len_utf8()..];
                if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
                    anyhow::bail!("non-literal package value");
                }
                (value, rest)
            } else {
                let end = remaining
                    .find(char::is_whitespace)
                    .unwrap_or(remaining.len());
                (&remaining[..end], &remaining[end..])
            };
        if !is_valid_package_name(value) {
            anyhow::bail!("invalid literal package name");
        }
        values.push(value.to_string());
        remaining = rest.trim_start();
    }
    if values.is_empty() {
        anyhow::bail!("missing literal package name");
    }
    Ok(values)
}

fn local_metadata_from_parts(
    pkgbase: Option<String>,
    package_names: BTreeSet<String>,
    source: &str,
) -> anyhow::Result<LocalRecipeMetadata> {
    let pkgbase =
        pkgbase.ok_or_else(|| anyhow::anyhow!("missing canonical pkgbase in {source}"))?;
    if package_names.is_empty() {
        anyhow::bail!("missing canonical pkgname entries in {source}");
    }
    Ok(LocalRecipeMetadata {
        pkgbase,
        package_names: package_names.into_iter().collect(),
    })
}

fn is_valid_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-')
        })
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
    summary.original_bytes = Some(metrics.iter().try_fold(0usize, |total, metric| {
        total
            .checked_add(metric.original_bytes)
            .ok_or_else(|| anyhow::anyhow!("original preflight byte count overflow"))
    })?);
    summary.encoded_request_bytes = Some(metrics.iter().try_fold(0usize, |total, metric| {
        total
            .checked_add(metric.encoded_request_bytes)
            .ok_or_else(|| anyhow::anyhow!("encoded preflight byte count overflow"))
    })?);
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
        preflight_byte_count(preflight.original_bytes),
        preflight_byte_count(preflight.encoded_request_bytes),
        preflight.large_request_mode,
    );
}

fn preflight_byte_count(bytes: Option<usize>) -> String {
    bytes
        .map(|bytes| bytes.to_string())
        .unwrap_or_else(|| "unmeasured".to_string())
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
            bundle_hash: None,
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

    fn local_recipe(srcinfo: Option<&str>, pkgbuild: &str) -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix("renamed-directory-")
            .tempdir()
            .unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), pkgbuild).unwrap();
        if let Some(srcinfo) = srcinfo {
            std::fs::write(dir.path().join(".SRCINFO"), srcinfo).unwrap();
        }
        dir
    }

    fn local_checkout(path: &Path) -> LocalCheckout {
        LocalCheckout {
            root: fetch::SecureRoot::open_local_directory(path).unwrap(),
            target: path.to_path_buf(),
        }
    }

    #[test]
    fn collect_groups_rejects_empty_targets_before_local_or_aur_resolution() {
        let error = match collect_groups(&[String::new()]) {
            Ok(_) => panic!("an empty target must be rejected"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("target must not be empty"));
    }

    #[test]
    fn local_srcinfo_identity_ignores_renamed_directory_and_preserves_split_names() {
        let dir = local_recipe(
            Some("pkgbase = canonical-base\n\tpkgname = z-split\n\tpkgname = a-split\n"),
            "pkgname=wrong-directory-name\n",
        );

        let groups = collect_groups(&[dir.path().display().to_string()]).unwrap();
        let group = groups.get("canonical-base").unwrap();
        assert_eq!(
            group.requested_packages.iter().cloned().collect::<Vec<_>>(),
            vec!["a-split", "z-split"]
        );
        assert_eq!(
            std::fs::read_to_string(
                group
                    .local_checkout
                    .as_ref()
                    .unwrap()
                    .proc_path()
                    .join("PKGBUILD")
            )
            .unwrap(),
            "pkgname=wrong-directory-name\n"
        );
    }

    #[test]
    fn literal_pkgbuild_metadata_establishes_split_canonical_identity_without_execution() {
        let dir = local_recipe(
            None,
            "pkgbase=canonical-base\npkgname=('z-split' 'a-split')\npkgver=1\n",
        );

        let metadata = parse_local_recipe_metadata(dir.path()).unwrap();
        assert_eq!(metadata.pkgbase, "canonical-base");
        assert_eq!(metadata.package_names, vec!["a-split", "z-split"]);
    }

    #[test]
    fn local_metadata_rejects_ambiguous_or_dynamic_recipe_identity() {
        let ambiguous = local_recipe(
            Some("pkgbase = first\npkgbase = second\npkgname = first\n"),
            "pkgname=first\n",
        );
        assert!(parse_local_recipe_metadata(ambiguous.path()).is_err());

        let dynamic = local_recipe(None, "pkgbase=$(printf base)\npkgname=base\n");
        assert!(parse_local_recipe_metadata(dynamic.path()).is_err());

        let nested_dynamic = local_recipe(
            None,
            "pkgbase=canonical\npkgname=canonical\nprepare() {\n  pkgbase=$(printf other)\n}\n",
        );
        assert!(parse_local_recipe_metadata(nested_dynamic.path()).is_err());
    }

    #[test]
    fn local_metadata_rejects_malformed_or_incomplete_srcinfo() {
        let malformed = local_recipe(
            Some("pkgbase canonical\npkgname = canonical\n"),
            "pkgname=x\n",
        );
        assert!(parse_local_recipe_metadata(malformed.path()).is_err());

        let incomplete = local_recipe(Some("pkgbase = canonical\n"), "pkgname=x\n");
        assert!(parse_local_recipe_metadata(incomplete.path()).is_err());

        let missing_pkgbuild = tempfile::tempdir().unwrap();
        std::fs::write(
            missing_pkgbuild.path().join(".SRCINFO"),
            "pkgbase = canonical\npkgname = canonical\n",
        )
        .unwrap();
        assert!(parse_local_recipe_metadata(missing_pkgbuild.path()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_target_symlink_is_rejected_before_collection_can_start_later_work() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let recipe = parent.path().join("recipe");
        std::fs::create_dir(&recipe).unwrap();
        std::fs::write(recipe.join("PKGBUILD"), "pkgname=canonical\n").unwrap();
        let target = parent.path().join("linked-recipe");
        symlink("recipe", &target).unwrap();

        match collect_groups(&[target.display().to_string()]) {
            Ok(_) => panic!("a symlinked local target must be rejected"),
            Err(error) => assert!(
                format!("{error:#}").contains("final path component is a symlink"),
                "unexpected error: {error:#}"
            ),
        };
    }

    #[cfg(unix)]
    #[test]
    fn local_metadata_rejects_a_symlinked_recipe_root_ancestor() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let recipe = parent.path().join("recipe");
        std::fs::create_dir(&recipe).unwrap();
        std::fs::write(recipe.join("PKGBUILD"), "pkgname=canonical\n").unwrap();
        let linked = parent.path().join("linked-recipe");
        symlink("recipe", &linked).unwrap();

        assert!(parse_local_recipe_metadata(&linked).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_metadata_rejects_symlinked_metadata_files() {
        use std::os::unix::fs::symlink;

        let srcinfo_target = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            srcinfo_target.path(),
            "pkgbase = canonical\npkgname = canonical\n",
        )
        .unwrap();
        let srcinfo_recipe = local_recipe(None, "pkgname=canonical\n");
        symlink(
            srcinfo_target.path(),
            srcinfo_recipe.path().join(".SRCINFO"),
        )
        .unwrap();
        assert!(parse_local_recipe_metadata(srcinfo_recipe.path()).is_err());

        let pkgbuild_target = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(pkgbuild_target.path(), "pkgname=canonical\n").unwrap();
        let pkgbuild_recipe = tempfile::tempdir().unwrap();
        symlink(
            pkgbuild_target.path(),
            pkgbuild_recipe.path().join("PKGBUILD"),
        )
        .unwrap();
        assert!(parse_local_recipe_metadata(pkgbuild_recipe.path()).is_err());
    }

    #[test]
    fn local_metadata_rejects_oversized_files_before_scanning() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=canonical\n").unwrap();
        std::fs::write(
            dir.path().join(".SRCINFO"),
            vec![b'x'; MAX_LOCAL_METADATA_BYTES as usize + 1],
        )
        .unwrap();

        assert!(parse_local_recipe_metadata(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_metadata_rejects_special_metadata_files() {
        use std::os::unix::net::UnixListener;

        let srcinfo_recipe = local_recipe(None, "pkgname=canonical\n");
        let _srcinfo_socket = UnixListener::bind(srcinfo_recipe.path().join(".SRCINFO")).unwrap();
        assert!(parse_local_recipe_metadata(srcinfo_recipe.path()).is_err());

        let pkgbuild_recipe = tempfile::tempdir().unwrap();
        let _pkgbuild_socket = UnixListener::bind(pkgbuild_recipe.path().join("PKGBUILD")).unwrap();
        assert!(parse_local_recipe_metadata(pkgbuild_recipe.path()).is_err());
    }

    #[test]
    fn local_metadata_reads_use_the_descriptor_anchored_secure_open_api() {
        let implementation = include_str!("deep_scan.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        let metadata_reader = implementation
            .split("fn parse_local_recipe_metadata_at")
            .nth(1)
            .unwrap()
            .split("fn parse_srcinfo_metadata")
            .next()
            .unwrap();

        assert!(implementation.contains("root: &fetch::SecureRoot"));
        assert!(metadata_reader.contains("root.open_regular_file"));
        assert!(metadata_reader.contains("root.proc_path"));
        assert!(!metadata_reader.contains("symlink_metadata"));
        assert!(!metadata_reader.contains("File::open"));
    }

    #[test]
    fn local_and_named_targets_cannot_collide_at_a_canonical_pkgbase() {
        let dir = local_recipe(
            Some("pkgbase = canonical-base\npkgname = local-split\n"),
            "pkgname=local-split\n",
        );
        let metadata = parse_local_recipe_metadata(dir.path()).unwrap();
        let mut groups = BTreeMap::new();
        groups.insert(
            "canonical-base".into(),
            PackageGroup {
                info: aur_info("named-split", "canonical-base"),
                requested_packages: BTreeSet::from(["named-split".into()]),
                local_checkout: None,
            },
        );

        assert!(insert_local_group(&mut groups, local_checkout(dir.path()), metadata).is_err());
    }
}
