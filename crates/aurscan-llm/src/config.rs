use crate::types::{BundleLimits, LlmConfig, ResponseFormat};
use anyhow::{bail, Context};
use std::net::IpAddr;
use std::time::Duration;
use url::{Host, Url};

const NORMAL_MAX_FILES: usize = 64;
const PROCESS_MAX_FILES: usize = 256;
const NORMAL_MAX_FILE_BYTES: usize = 256 * 1024;
const PROCESS_MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
const NORMAL_MAX_BUNDLE_BYTES: usize = 512 * 1024;
const PROCESS_MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
const NORMAL_MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const PROCESS_MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const NORMAL_MAX_FINDINGS: usize = 64;
const PROCESS_MAX_FINDINGS: usize = 256;
const NORMAL_MAX_EVIDENCE_LINES: usize = 16;
const PROCESS_MAX_EVIDENCE_LINES: usize = 64;
const NORMAL_MAX_EXCERPT_BYTES: usize = 400;
const PROCESS_MAX_EXCERPT_BYTES: usize = 2048;
const NORMAL_MAX_OUTPUT_TOKENS: u32 = 8192;
const PROCESS_MAX_OUTPUT_TOKENS: u32 = 65_536;
const NORMAL_MAX_REQUESTS: usize = 50;
const PROCESS_MAX_REQUESTS: usize = 500;
const NORMAL_MAX_TIMEOUT_SECONDS: u64 = 300;
const PROCESS_MAX_TIMEOUT_SECONDS: u64 = 3600;

#[derive(Debug, Clone)]
pub struct ValidatedLlmConfig {
    pub(crate) endpoint_origin: String,
    pub(crate) chat_completions_url: Url,
    pub(crate) model: String,
    pub(crate) response_format: ResponseFormat,
    pub(crate) api_key_env: Option<String>,
    pub(crate) timeout: Duration,
    pub(crate) max_output_tokens: u32,
    pub(crate) max_requests_per_run: usize,
    pub(crate) max_files: usize,
    pub(crate) max_file_bytes: usize,
    pub(crate) max_bundle_bytes: usize,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_findings: usize,
    pub(crate) max_evidence_lines: usize,
    pub(crate) max_excerpt_bytes: usize,
    uses_large_requests: bool,
}

impl ValidatedLlmConfig {
    pub fn endpoint_origin(&self) -> &str {
        &self.endpoint_origin
    }

    pub fn chat_completions_url(&self) -> &Url {
        &self.chat_completions_url
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn response_format(&self) -> ResponseFormat {
        self.response_format
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    pub fn max_requests_per_run(&self) -> usize {
        self.max_requests_per_run
    }

    pub fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    pub fn max_findings(&self) -> usize {
        self.max_findings
    }

    pub fn max_evidence_lines(&self) -> usize {
        self.max_evidence_lines
    }

    pub fn max_excerpt_bytes(&self) -> usize {
        self.max_excerpt_bytes
    }

    pub fn bundle_limits(&self) -> BundleLimits {
        BundleLimits {
            max_files: self.max_files,
            max_file_bytes: self.max_file_bytes,
            max_bundle_bytes: self.max_bundle_bytes,
        }
    }

    pub fn uses_large_requests(&self) -> bool {
        self.uses_large_requests
    }
}

pub fn validate_config(config: &LlmConfig) -> anyhow::Result<ValidatedLlmConfig> {
    if config.endpoint.trim().is_empty() {
        bail!("LLM endpoint must not be empty");
    }
    if config.model.trim().is_empty() {
        bail!("LLM model must not be empty");
    }

    let mut endpoint = Url::parse(&config.endpoint).context("invalid LLM endpoint URL")?;
    if !matches!(endpoint.scheme(), "http" | "https") {
        bail!("LLM endpoint must use HTTP or HTTPS");
    }
    if endpoint.host().is_none() {
        bail!("LLM endpoint must include a host");
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        bail!("LLM endpoint must not contain credentials");
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        bail!("LLM endpoint must not contain a query or fragment");
    }

    let loopback = is_literal_loopback(endpoint.host().expect("host checked above"));
    if endpoint.scheme() == "http" {
        if !has_permitted_http_authority(&config.endpoint) {
            bail!(
                "HTTP LLM endpoint requires localhost, dotted-decimal 127.0.0.0/8, or bracketed ::1; all other endpoints require HTTPS"
            );
        }
    } else if !loopback && !config.allow_remote {
        bail!("non-loopback LLM endpoint requires allow_remote=true");
    }

    let uses_large_requests = validate_limit(
        "max_files",
        config.max_files,
        NORMAL_MAX_FILES,
        PROCESS_MAX_FILES,
        config.allow_large_requests,
    )? | validate_limit(
        "max_file_bytes",
        config.max_file_bytes,
        NORMAL_MAX_FILE_BYTES,
        PROCESS_MAX_FILE_BYTES,
        config.allow_large_requests,
    )? | validate_limit(
        "max_bundle_bytes",
        config.max_bundle_bytes,
        NORMAL_MAX_BUNDLE_BYTES,
        PROCESS_MAX_BUNDLE_BYTES,
        config.allow_large_requests,
    )? | validate_limit(
        "max_request_bytes",
        config.max_request_bytes,
        NORMAL_MAX_REQUEST_BYTES,
        PROCESS_MAX_REQUEST_BYTES,
        config.allow_large_requests,
    )? | validate_limit(
        "max_findings",
        config.max_findings,
        NORMAL_MAX_FINDINGS,
        PROCESS_MAX_FINDINGS,
        config.allow_large_requests,
    )? | validate_limit(
        "max_evidence_lines",
        config.max_evidence_lines,
        NORMAL_MAX_EVIDENCE_LINES,
        PROCESS_MAX_EVIDENCE_LINES,
        config.allow_large_requests,
    )? | validate_limit(
        "max_excerpt_bytes",
        config.max_excerpt_bytes,
        NORMAL_MAX_EXCERPT_BYTES,
        PROCESS_MAX_EXCERPT_BYTES,
        config.allow_large_requests,
    )? | validate_limit(
        "max_output_tokens",
        config.max_output_tokens,
        NORMAL_MAX_OUTPUT_TOKENS,
        PROCESS_MAX_OUTPUT_TOKENS,
        config.allow_large_requests,
    )? | validate_limit(
        "max_requests_per_run",
        config.max_requests_per_run,
        NORMAL_MAX_REQUESTS,
        PROCESS_MAX_REQUESTS,
        config.allow_large_requests,
    )? | validate_limit(
        "timeout_seconds",
        config.timeout_seconds,
        NORMAL_MAX_TIMEOUT_SECONDS,
        PROCESS_MAX_TIMEOUT_SECONDS,
        config.allow_large_requests,
    )?;

    let endpoint_origin = endpoint.origin().ascii_serialization();
    let mut path = endpoint.path().trim_end_matches('/').to_owned();
    path.push_str("/chat/completions");
    endpoint.set_path(&path);

    Ok(ValidatedLlmConfig {
        endpoint_origin,
        chat_completions_url: endpoint,
        model: config.model.clone(),
        response_format: config.response_format,
        api_key_env: config.api_key_env.clone(),
        timeout: Duration::from_secs(config.timeout_seconds),
        max_output_tokens: config.max_output_tokens,
        max_requests_per_run: config.max_requests_per_run,
        max_files: config.max_files,
        max_file_bytes: config.max_file_bytes,
        max_bundle_bytes: config.max_bundle_bytes,
        max_request_bytes: config.max_request_bytes,
        max_findings: config.max_findings,
        max_evidence_lines: config.max_evidence_lines,
        max_excerpt_bytes: config.max_excerpt_bytes,
        uses_large_requests,
    })
}

fn is_literal_loopback(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.octets()[0] == 127,
        Host::Ipv6(address) => IpAddr::V6(address).is_loopback(),
    }
}

fn has_permitted_http_authority(configured_endpoint: &str) -> bool {
    if configured_endpoint.contains('\\') {
        return false;
    }
    let Some((scheme, remainder)) = configured_endpoint.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return false;
    }

    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(close) = bracketed.find(']') else {
            return false;
        };
        return &bracketed[..close] == "::1" && valid_port_suffix(&bracketed[close + 1..]);
    }

    let (host, port) = match authority.split_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        Some(_) => return false,
        None => (authority, None),
    };
    if port.is_some_and(|port| !valid_port(port)) {
        return false;
    }
    host.eq_ignore_ascii_case("localhost") || is_dotted_decimal_loopback(host)
}

fn valid_port_suffix(suffix: &str) -> bool {
    suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn is_dotted_decimal_loopback(host: &str) -> bool {
    let octets = host.split('.').collect::<Vec<_>>();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && !(octet.len() > 1 && octet.starts_with('0'))
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u8>().is_ok()
        })
        && octets[0] == "127"
}

fn validate_limit<T>(
    field: &str,
    value: T,
    normal_maximum: T,
    process_maximum: T,
    allow_large_requests: bool,
) -> anyhow::Result<bool>
where
    T: Copy + Ord + Default + std::fmt::Display,
{
    if value == T::default() {
        bail!("{field} must be greater than zero");
    }
    if value > process_maximum {
        bail!("{field} exceeds process-safety maximum {process_maximum}");
    }
    if value > normal_maximum && !allow_large_requests {
        bail!("{field} above {normal_maximum} requires allow_large_requests=true");
    }
    Ok(value > normal_maximum)
}
