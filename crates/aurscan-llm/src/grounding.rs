use crate::types::{
    AnalysisFailure, AnalysisFailureCode, LlmFindingKind, RecipeBundle, ValidatedFindingSpan,
    MAX_REASON_BYTES,
};
use aurscan_core::{Confidence, Evidence, Finding, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CandidateSeverity {
    Info,
    Medium,
    High,
    Critical,
}

impl CandidateSeverity {
    fn materialize(self) -> Severity {
        match self {
            Self::Info => Severity::Info,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
            Self::Critical => Severity::Critical,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateResponse {
    findings: Vec<CandidateFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateFinding {
    kind: LlmFindingKind,
    severity: CandidateSeverity,
    file: String,
    start_line: usize,
    end_line: usize,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GroundedClaim {
    pub(crate) kind: LlmFindingKind,
    pub(crate) severity: CandidateSeverity,
    pub(crate) relative_path: String,
    pub(crate) start_line: usize,
    pub(crate) end_line: usize,
    pub(crate) reason: String,
    pub(crate) excerpt: String,
}

#[derive(Debug)]
pub(crate) struct GroundingResult {
    pub(crate) claims: Vec<GroundedClaim>,
    pub(crate) rejected_reasons: Vec<String>,
    pub(crate) failures: Vec<AnalysisFailure>,
    pub(crate) candidate_count: usize,
}

#[derive(Debug)]
pub(crate) struct GroundingError {
    pub(crate) code: AnalysisFailureCode,
    reason: String,
}

impl GroundingError {
    fn new(code: AnalysisFailureCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for GroundingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

pub(crate) fn ground_response(
    content: &str,
    bundle: &RecipeBundle,
    max_findings: usize,
    max_evidence_lines: usize,
    max_excerpt_bytes: usize,
) -> Result<GroundingResult, GroundingError> {
    let candidate: CandidateResponse = serde_json::from_str(content).map_err(|_| {
        GroundingError::new(
            AnalysisFailureCode::CandidateSchema,
            "candidate response was structurally invalid",
        )
    })?;
    if candidate.findings.len() > max_findings {
        return Err(GroundingError::new(
            AnalysisFailureCode::FindingCountLimit,
            format!(
                "candidate finding count {} exceeds limit {max_findings}",
                candidate.findings.len()
            ),
        ));
    }

    let candidate_count = candidate.findings.len();
    let mut claims = Vec::with_capacity(candidate_count);
    let mut failures = Vec::new();
    let mut rejected_reasons = Vec::new();
    for (index, finding) in candidate.findings.into_iter().enumerate() {
        match ground_finding(finding, bundle, max_evidence_lines, max_excerpt_bytes) {
            Ok(claim) => claims.push(claim),
            Err(error) => {
                failures.push(AnalysisFailure {
                    code: error.code,
                    finding_index: Some(index),
                });
                rejected_reasons.push(format!("finding {}: {error}", index + 1));
            }
        }
    }
    Ok(GroundingResult {
        claims,
        rejected_reasons,
        failures,
        candidate_count,
    })
}

fn ground_finding(
    finding: CandidateFinding,
    bundle: &RecipeBundle,
    max_evidence_lines: usize,
    max_excerpt_bytes: usize,
) -> Result<GroundedClaim, GroundingError> {
    let file = bundle
        .files
        .iter()
        .find(|file| file.path == finding.file)
        .ok_or_else(|| {
            GroundingError::new(AnalysisFailureCode::UnknownFile, "unknown file citation")
        })?;
    if finding.start_line == 0 || finding.end_line == 0 {
        return Err(GroundingError::new(
            AnalysisFailureCode::InvalidCitationRange,
            "line numbers must be positive",
        ));
    }
    if finding.start_line > finding.end_line {
        return Err(GroundingError::new(
            AnalysisFailureCode::InvalidCitationRange,
            "line range must be ordered",
        ));
    }
    let lines = line_byte_ranges(&file.content);
    if finding.end_line > lines.len() {
        return Err(GroundingError::new(
            AnalysisFailureCode::CitationOutOfBounds,
            format!(
                "line range ends at {}, but file has {} lines",
                finding.end_line,
                lines.len()
            ),
        ));
    }
    let range_length = finding.end_line - finding.start_line + 1;
    if range_length > max_evidence_lines {
        return Err(GroundingError::new(
            AnalysisFailureCode::EvidenceLineLimit,
            format!(
                "evidence range has {range_length} lines, exceeding limit {max_evidence_lines}"
            ),
        ));
    }
    validate_reason(&finding.reason)?;

    let start_byte = lines[finding.start_line - 1].0;
    let end_byte = lines[finding.end_line - 1].1;
    let excerpt = cap_utf8(&file.content[start_byte..end_byte], max_excerpt_bytes).to_owned();
    Ok(GroundedClaim {
        kind: finding.kind,
        severity: finding.severity,
        relative_path: file.path.clone(),
        start_line: finding.start_line,
        end_line: finding.end_line,
        reason: finding.reason,
        excerpt,
    })
}

fn validate_reason(reason: &str) -> Result<(), GroundingError> {
    if reason.len() > MAX_REASON_BYTES {
        return Err(GroundingError::new(
            AnalysisFailureCode::ReasonSizeLimit,
            format!("reason exceeds {MAX_REASON_BYTES}-byte limit"),
        ));
    }
    if let Some(character) = reason
        .chars()
        .find(|character| is_forbidden_reason_char(*character))
    {
        return Err(GroundingError::new(
            AnalysisFailureCode::ForbiddenReasonCharacter,
            format!(
                "reason contains forbidden control character U+{:04X}",
                character as u32
            ),
        ));
    }
    Ok(())
}

fn is_forbidden_reason_char(character: char) -> bool {
    let code = character as u32;
    character == '\r'
        || code <= 0x1f
        || (0x7f..=0x9f).contains(&code)
        || matches!(
            code,
            0x061c
                | 0x200e
                | 0x200f
                | 0x2028
                | 0x2029
                | 0x202a..=0x202e
                | 0x2066..=0x206f
        )
}

fn line_byte_ranges(content: &str) -> Vec<(usize, usize)> {
    if content.is_empty() {
        return Vec::new();
    }
    let bytes = content.as_bytes();
    let mut ranges = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            ranges.push((start, index));
            start = index + 1;
        }
    }
    if start < bytes.len() {
        ranges.push((start, bytes.len()));
    }
    ranges
}

fn cap_utf8(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Materialize each claim and its original span together. Both vectors have
/// identical length and order, including repeated file/start coordinates.
pub(crate) fn materialize_claims(
    claims: &[GroundedClaim],
    package: &str,
) -> (Vec<Finding>, Vec<ValidatedFindingSpan>) {
    claims
        .iter()
        .enumerate()
        .map(|(finding_index, claim)| {
            (
                Finding {
                    severity: claim.severity.materialize(),
                    confidence: Confidence::Llm,
                    detector: claim.kind.detector_id(),
                    package: package.to_owned(),
                    reason: claim.reason.clone(),
                    evidence: Evidence {
                        location: format!("{}:{}", claim.relative_path, claim.start_line),
                        excerpt: claim.excerpt.clone(),
                    },
                },
                ValidatedFindingSpan {
                    finding_index,
                    kind: claim.kind,
                    severity: claim.severity.materialize(),
                    relative_file: claim.relative_path.clone(),
                    start_line: claim.start_line,
                    end_line: claim.end_line,
                },
            )
        })
        .unzip()
}
