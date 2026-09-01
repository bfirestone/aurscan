use aurscan_llm::{
    validate_config, AnalysisSource, AnalysisStatus, AnalyzeOptions, Analyzer, BundleCoverage,
    CoverageMode, LlmConfig, RecipeBundle, RecipeFile, ResponseFormat, LLM_ANALYSIS_EPOCH,
    PROMPT_VERSION, PROVIDER_PROTOCOL_VERSION, RESPONSE_SCHEMA_VERSION, REVIEW_STRATEGY_ID,
};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn local_config() -> LlmConfig {
    LlmConfig {
        endpoint: "http://127.0.0.1:11434/v1".into(),
        model: "pinned-model".into(),
        ..LlmConfig::default()
    }
}

#[test]
fn validation_normalizes_local_origin_without_reading_the_key() {
    let mut config = local_config();
    config.endpoint = "http://LOCALHOST:11434/v1/".into();
    config.api_key_env = Some("AURSCAN_TEST_KEY_THAT_MUST_NOT_EXIST".into());

    let validated = validate_config(&config).unwrap();

    assert_eq!(validated.endpoint_origin(), "http://localhost:11434");
    assert_eq!(
        validated.chat_completions_url().as_str(),
        "http://localhost:11434/v1/chat/completions"
    );
    assert_eq!(validated.model(), "pinned-model");
    assert!(!validated.uses_large_requests());
}

#[test]
fn validation_rejects_empty_or_malformed_endpoint_and_model() {
    let mut config = local_config();
    config.endpoint.clear();
    assert!(validate_config(&config)
        .unwrap_err()
        .to_string()
        .contains("endpoint"));

    let mut config = local_config();
    config.endpoint = "not a url".into();
    assert!(validate_config(&config)
        .unwrap_err()
        .to_string()
        .contains("endpoint"));

    let mut config = local_config();
    config.model = "  ".into();
    assert!(validate_config(&config)
        .unwrap_err()
        .to_string()
        .contains("model"));
}

#[test]
fn only_literal_loopback_may_use_http_and_remote_https_requires_consent() {
    for endpoint in [
        "http://127.0.0.2/v1",
        "http://127.255.255.254/v1",
        "http://[::1]/v1",
        "http://localhost/v1",
    ] {
        let mut config = local_config();
        config.endpoint = endpoint.into();
        assert!(validate_config(&config).is_ok(), "rejected {endpoint}");
    }

    for endpoint in [
        "http://example.com/v1",
        "http://192.168.1.2/v1",
        "http://localhost.example/v1",
        "https://example.com/v1",
    ] {
        let mut config = local_config();
        config.endpoint = endpoint.into();
        let error = validate_config(&config).unwrap_err().to_string();
        assert!(
            error.contains("HTTPS") || error.contains("allow_remote"),
            "unexpected error for {endpoint}: {error}"
        );
    }

    let mut config = local_config();
    config.endpoint = "https://example.com/v1".into();
    config.allow_remote = true;
    assert!(validate_config(&config).is_ok());

    let mut config = local_config();
    config.endpoint = "http://example.com/v1".into();
    config.allow_remote = true;
    assert!(validate_config(&config).is_err());
}

#[test]
fn endpoints_with_ambient_credentials_query_or_fragment_are_rejected() {
    for endpoint in [
        "http://user:pass@localhost/v1",
        "http://localhost/v1?key=secret",
        "http://localhost/v1#fragment",
    ] {
        let mut config = local_config();
        config.endpoint = endpoint.into();
        assert!(validate_config(&config).is_err(), "accepted {endpoint}");
    }
}

macro_rules! limit_cases {
    ($(($name:ident, $field:ident, $normal:expr, $maximum:expr)),+ $(,)?) => {$ (
        #[test]
        fn $name() {
            let mut zero = local_config();
            zero.$field = 0;
            assert!(validate_config(&zero).is_err(), "zero must fail");

            let mut normal = local_config();
            normal.$field = $normal;
            assert!(validate_config(&normal).is_ok(), "normal guardrail must pass");

            let mut needs_opt_in = local_config();
            needs_opt_in.$field = $normal + 1;
            let error = validate_config(&needs_opt_in).unwrap_err().to_string();
            assert!(error.contains("allow_large_requests"), "{error}");

            needs_opt_in.allow_large_requests = true;
            assert!(validate_config(&needs_opt_in).is_ok(), "opted-in value must pass");

            let mut maximum = local_config();
            maximum.allow_large_requests = true;
            maximum.$field = $maximum;
            assert!(validate_config(&maximum).is_ok(), "process maximum must pass");

            maximum.$field = $maximum + 1;
            assert!(validate_config(&maximum).is_err(), "above process maximum must fail");
        }
    )+};
}

limit_cases!(
    (validates_file_count_limits, max_files, 64, 256),
    (
        validates_per_file_byte_limits,
        max_file_bytes,
        256 * 1024,
        2 * 1024 * 1024
    ),
    (
        validates_bundle_byte_limits,
        max_bundle_bytes,
        512 * 1024,
        8 * 1024 * 1024
    ),
    (
        validates_request_byte_limits,
        max_request_bytes,
        2 * 1024 * 1024,
        32 * 1024 * 1024
    ),
    (validates_finding_limits, max_findings, 64, 256),
    (validates_evidence_line_limits, max_evidence_lines, 16, 64),
    (validates_excerpt_byte_limits, max_excerpt_bytes, 400, 2048),
    (
        validates_output_token_limits,
        max_output_tokens,
        8192,
        65_536
    ),
    (
        validates_request_count_limits,
        max_requests_per_run,
        50,
        500
    ),
    (validates_timeout_limits, timeout_seconds, 300, 3600),
);

struct ScriptedServer {
    origin: String,
    request_count: Arc<Mutex<usize>>,
    overlap: Arc<Mutex<bool>>,
    join: Option<thread::JoinHandle<()>>,
}

impl ScriptedServer {
    fn completed_responses(count: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let request_count = Arc::new(Mutex::new(0));
        let overlap = Arc::new(Mutex::new(false));
        let thread_count = request_count.clone();
        let thread_overlap = overlap.clone();
        let join = thread::spawn(move || {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                consume_request(&mut stream);
                *thread_count.lock().unwrap() += 1;

                listener.set_nonblocking(true).unwrap();
                match listener.accept() {
                    Ok((mut concurrent, _)) => {
                        *thread_overlap.lock().unwrap() = true;
                        let body = provider_body(r#"{"findings":[]}"#, "stop");
                        write_response(&mut concurrent, "200 OK", &body);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("concurrency probe failed: {error}"),
                }
                listener.set_nonblocking(false).unwrap();

                let body = provider_body(r#"{"findings":[]}"#, "stop");
                write_response(&mut stream, "200 OK", &body);
            }
        });
        Self {
            origin,
            request_count,
            overlap,
            join: Some(join),
        }
    }

    fn count(&self) -> usize {
        *self.request_count.lock().unwrap()
    }

    fn wait_for_count(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.count() != expected {
            assert!(
                Instant::now() < deadline,
                "request count did not reach {expected}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn overlapped(&self) -> bool {
        *self.overlap.lock().unwrap()
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}

fn provider_body(content: &str, finish_reason: &str) -> String {
    json!({
        "choices": [{
            "message": {"content": content},
            "finish_reason": finish_reason
        }]
    })
    .to_string()
}

fn write_response(stream: &mut TcpStream, status: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
}

fn consume_request(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0);
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            if bytes.len() >= header_end + content_length {
                return;
            }
        }
    }
}

fn recipe_bundle(hash_byte: u8, pkgbase: &str) -> RecipeBundle {
    RecipeBundle {
        pkgbase: pkgbase.into(),
        aur_commit: None,
        content_hash: [hash_byte; 32],
        files: vec![RecipeFile {
            path: "PKGBUILD".into(),
            content: format!("pkgname={pkgbase}\n"),
        }],
        coverage: BundleCoverage {
            mode: CoverageMode::GitTracked,
            included_files: 1,
            excluded_binary_files: vec![],
            excluded_symlinks: vec![],
        },
    }
}

fn analyzer_config(origin: &str) -> LlmConfig {
    LlmConfig {
        endpoint: format!("{origin}/v1"),
        model: "batch-model".into(),
        ..LlmConfig::default()
    }
}

fn analyzer_at(config: LlmConfig, dir: &TempDir) -> Analyzer {
    Analyzer::with_cache_path(
        validate_config(&config).unwrap(),
        dir.path().join("llm.redb"),
    )
    .unwrap()
}

#[test]
fn all_cache_hit_run_does_not_read_a_now_absent_key() {
    let _guard = ENV_LOCK.lock().unwrap();
    let variable = "AURSCAN_ANALYZER_ALL_HIT_KEY";
    std::env::set_var(variable, "temporary-key");
    let server = ScriptedServer::completed_responses(1);
    let dir = TempDir::new().unwrap();
    let mut config = analyzer_config(&server.origin);
    config.api_key_env = Some(variable.into());
    let analyzer = analyzer_at(config, &dir);
    let bundle = recipe_bundle(1, "hit");

    let initial = analyzer.analyze_batch(
        std::slice::from_ref(&bundle),
        AnalyzeOptions { refresh: false },
    );
    std::env::remove_var(variable);
    let cached = analyzer.analyze_batch(
        std::slice::from_ref(&bundle),
        AnalyzeOptions { refresh: false },
    );

    server.wait_for_count(1);
    assert_eq!(initial[0].source, Some(AnalysisSource::Provider));
    assert_eq!(cached[0].status, AnalysisStatus::Completed);
    assert_eq!(cached[0].source, Some(AnalysisSource::Cache));
}

#[test]
fn missing_key_with_any_miss_sends_zero_new_requests() {
    let _guard = ENV_LOCK.lock().unwrap();
    let variable = "AURSCAN_ANALYZER_MISSING_KEY";
    std::env::set_var(variable, "temporary-key");
    let server = ScriptedServer::completed_responses(1);
    let dir = TempDir::new().unwrap();
    let mut config = analyzer_config(&server.origin);
    config.api_key_env = Some(variable.into());
    let analyzer = analyzer_at(config, &dir);
    let hit = recipe_bundle(2, "hit");
    let miss = recipe_bundle(3, "miss");
    let _ = analyzer.analyze_batch(
        std::slice::from_ref(&hit),
        AnalyzeOptions { refresh: false },
    );
    server.wait_for_count(1);
    std::env::remove_var(variable);

    let outcomes = analyzer.analyze_batch(&[hit, miss], AnalyzeOptions { refresh: false });

    assert_eq!(server.count(), 1);
    assert_eq!(outcomes[0].status, AnalysisStatus::Completed);
    assert_eq!(outcomes[0].source, Some(AnalysisSource::Cache));
    assert_eq!(outcomes[1].status, AnalysisStatus::Unavailable);
    assert!(outcomes[1].reason.as_deref().unwrap().contains(variable));
}

#[test]
fn too_many_batch_misses_performs_zero_provider_calls() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let dir = TempDir::new().unwrap();
    let mut config = analyzer_config(&origin);
    config.max_requests_per_run = 1;
    let analyzer = analyzer_at(config, &dir);

    let outcomes = analyzer.analyze_batch(
        &[recipe_bundle(4, "one"), recipe_bundle(5, "two")],
        AnalyzeOptions { refresh: false },
    );

    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes
        .iter()
        .all(|outcome| outcome.status == AnalysisStatus::Incomplete));
    assert!(outcomes.iter().all(|outcome| outcome
        .reason
        .as_deref()
        .unwrap()
        .contains("request cap")));
}

#[test]
fn encoded_request_over_limit_is_incomplete_without_a_call() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let dir = TempDir::new().unwrap();
    let mut config = analyzer_config(&origin);
    config.max_request_bytes = 64;
    let analyzer = analyzer_at(config, &dir);

    let outcomes = analyzer.analyze_batch(
        &[recipe_bundle(6, "oversized")],
        AnalyzeOptions { refresh: false },
    );

    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert_eq!(outcomes[0].status, AnalysisStatus::Incomplete);
    assert!(outcomes[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("encoded request size"));
}

#[test]
fn provider_requests_are_strictly_sequential_and_output_order_is_preserved() {
    let server = ScriptedServer::completed_responses(3);
    let dir = TempDir::new().unwrap();
    let analyzer = analyzer_at(analyzer_config(&server.origin), &dir);
    let bundles = [
        recipe_bundle(7, "first"),
        recipe_bundle(8, "second"),
        recipe_bundle(9, "third"),
    ];

    let outcomes = analyzer.analyze_batch(&bundles, AnalyzeOptions { refresh: false });

    server.wait_for_count(3);
    assert!(!server.overlapped());
    assert_eq!(outcomes.len(), 3);
    for (outcome, bundle) in outcomes.iter().zip(bundles) {
        assert_eq!(outcome.status, AnalysisStatus::Completed);
        assert_eq!(
            outcome.identity.as_ref().unwrap().bundle_hash,
            bundle.content_hash
        );
    }
}

#[test]
fn identity_covers_all_fixed_versions_bytes_origin_model_and_request_profile() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let bundle = recipe_bundle(10, "identity");
    let dir = TempDir::new().unwrap();
    let base = analyzer_at(analyzer_config(&origin), &dir);
    let identity = base.analysis_identity(&bundle);

    assert_eq!(identity.bundle_hash, bundle.content_hash);
    assert_eq!(
        identity.provider_protocol_version,
        PROVIDER_PROTOCOL_VERSION
    );
    assert_eq!(
        identity.endpoint_origin_fingerprint,
        *blake3::hash(origin.as_bytes()).as_bytes()
    );
    assert_eq!(identity.model_id, "batch-model");
    assert_eq!(identity.review_strategy_id, REVIEW_STRATEGY_ID);
    assert_eq!(identity.prompt_version, PROMPT_VERSION);
    assert_ne!(
        identity.prompt_hash,
        *blake3::hash(include_bytes!("../prompts/v1/system.txt")).as_bytes(),
        "prompt identity must cover the fixed envelope, not only system.txt"
    );
    assert_eq!(identity.response_schema_version, RESPONSE_SCHEMA_VERSION);
    assert_eq!(
        identity.response_schema_hash,
        *blake3::hash(include_bytes!("../prompts/v1/response-schema.json")).as_bytes()
    );
    assert_eq!(identity.analysis_epoch, LLM_ANALYSIS_EPOCH);

    let cases = [
        {
            let mut config = analyzer_config(&origin);
            config.response_format = ResponseFormat::JsonObject;
            config
        },
        {
            let mut config = analyzer_config(&origin);
            config.max_output_tokens += 1;
            config
        },
        {
            let mut config = analyzer_config(&origin);
            config.max_excerpt_bytes += 1;
            config
        },
        {
            let mut config = analyzer_config(&origin);
            config.max_findings += 1;
            config
        },
        {
            let mut config = analyzer_config(&origin);
            config.max_evidence_lines += 1;
            config
        },
    ];
    for (index, config) in cases.into_iter().enumerate() {
        let case_dir = TempDir::new().unwrap();
        let changed = analyzer_at(config, &case_dir).analysis_identity(&bundle);
        assert_ne!(
            changed.request_profile_fingerprint, identity.request_profile_fingerprint,
            "request profile case {index} did not change identity"
        );
    }
}
