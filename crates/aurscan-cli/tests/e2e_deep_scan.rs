//! Serial, hermetic end-to-end coverage for the two explicit experimental LLM
//! command surfaces. Every provider is a loopback fake and every user-owned
//! path is redirected into the test's temporary directory.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const API_KEY_ENV: &str = "AURSCAN_E2E_DEEP_SCAN_KEY";
const DEFAULT_PKGBUILD: &str = "pkgbase=canonical-base\npkgname=canonical-package\npkgver=1\npkgrel=1\narch=('any')\npackage() {\n  :\n}\n";

#[derive(Clone)]
struct QueuedResponse {
    status: u16,
    body: String,
}

struct FakeServer {
    origin: String,
    address: std::net::SocketAddr,
    requests: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    captured_headers: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    captured_bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    captured_request_lines: Arc<Mutex<Vec<String>>>,
    queued_responses: Arc<Mutex<VecDeque<QueuedResponse>>>,
    errors: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl FakeServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fake server");
        let address = listener.local_addr().expect("fake server address");
        let requests = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let captured_headers = Arc::new(Mutex::new(Vec::new()));
        let captured_bodies = Arc::new(Mutex::new(Vec::new()));
        let captured_request_lines = Arc::new(Mutex::new(Vec::new()));
        let queued_responses = Arc::new(Mutex::new(VecDeque::<QueuedResponse>::new()));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));

        let worker_requests = Arc::clone(&requests);
        let worker_connections = Arc::clone(&connections);
        let worker_headers = Arc::clone(&captured_headers);
        let worker_bodies = Arc::clone(&captured_bodies);
        let worker_request_lines = Arc::clone(&captured_request_lines);
        let worker_responses = Arc::clone(&queued_responses);
        let worker_errors = Arc::clone(&errors);
        let worker_stopping = Arc::clone(&stopping);
        let worker = thread::spawn(move || loop {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) => {
                    worker_errors
                        .lock()
                        .expect("fake server error lock")
                        .push(format!("accept failed: {error}"));
                    break;
                }
            };
            if worker_stopping.load(Ordering::Acquire) {
                break;
            }
            worker_connections.fetch_add(1, Ordering::SeqCst);

            match read_http_request(&mut stream) {
                Ok((request_line, headers, body)) => {
                    worker_requests.fetch_add(1, Ordering::SeqCst);
                    worker_request_lines
                        .lock()
                        .expect("fake server request-line lock")
                        .push(request_line);
                    worker_headers
                        .lock()
                        .expect("fake server header lock")
                        .push(headers);
                    worker_bodies
                        .lock()
                        .expect("fake server body lock")
                        .push(body);

                    let response = worker_responses
                        .lock()
                        .expect("fake server response lock")
                        .pop_front()
                        .unwrap_or_else(|| {
                            worker_errors
                                .lock()
                                .expect("fake server error lock")
                                .push("received a request without a queued response".into());
                            QueuedResponse {
                                status: 500,
                                body: "{\"error\":\"no queued response\"}".into(),
                            }
                        });
                    if let Err(error) = write_http_response(&mut stream, &response) {
                        worker_errors
                            .lock()
                            .expect("fake server error lock")
                            .push(format!("response write failed: {error}"));
                    }
                }
                Err(error) => {
                    worker_errors
                        .lock()
                        .expect("fake server error lock")
                        .push(format!("request read failed: {error}"));
                    let _ = write_http_response(
                        &mut stream,
                        &QueuedResponse {
                            status: 400,
                            body: "{\"error\":\"bad request\"}".into(),
                        },
                    );
                }
            }
        });

        Self {
            origin: format!("http://{address}"),
            address,
            requests,
            connections,
            captured_headers,
            captured_bodies,
            captured_request_lines,
            queued_responses,
            errors,
            stopping,
            worker: Some(worker),
        }
    }

    fn endpoint(&self) -> String {
        format!("{}/v1", self.origin)
    }

    fn queue_raw(&self, status: u16, body: impl Into<String>) {
        self.queued_responses
            .lock()
            .expect("fake server response lock")
            .push_back(QueuedResponse {
                status,
                body: body.into(),
            });
    }

    fn queue_completion(&self, content: &str, finish_reason: &str) {
        self.queue_raw(200, completion_envelope(content, finish_reason));
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn captured_headers(&self) -> Vec<BTreeMap<String, String>> {
        self.captured_headers
            .lock()
            .expect("fake server header lock")
            .clone()
    }

    fn captured_bodies(&self) -> Vec<Vec<u8>> {
        self.captured_bodies
            .lock()
            .expect("fake server body lock")
            .clone()
    }

    fn captured_request_lines(&self) -> Vec<String> {
        self.captured_request_lines
            .lock()
            .expect("fake server request-line lock")
            .clone()
    }

    fn assert_healthy(&self) {
        let errors = self.errors.lock().expect("fake server error lock");
        assert!(errors.is_empty(), "fake server errors: {errors:?}");
    }

    fn stop(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address).and_then(|stream| stream.shutdown(Shutdown::Both));
        if worker.join().is_err() {
            self.errors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("fake server worker panicked".into());
        }
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_http_request(
    stream: &mut TcpStream,
) -> std::io::Result<(String, BTreeMap<String, String>, Vec<u8>)> {
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    let mut received = Vec::new();
    let header_end = loop {
        if let Some(index) = find_bytes(&received, b"\r\n\r\n") {
            break index + 4;
        }
        if received.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request headers exceeded test-server limit",
            ));
        }
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before request headers",
            ));
        }
        received.extend_from_slice(&chunk[..count]);
    };

    let header_text = std::str::from_utf8(&received[..header_end - 4]).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("non-UTF-8 request headers: {error}"),
        )
    })?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed request header")
        })?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing Content-Length")
        })?
        .parse::<usize>()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid Content-Length: {error}"),
            )
        })?;
    if content_length > 40 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body exceeded test-server limit",
        ));
    }

    while received.len() - header_end < content_length {
        let mut chunk = [0_u8; 8192];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before request body",
            ));
        }
        received.extend_from_slice(&chunk[..count]);
    }
    Ok((
        request_line,
        headers,
        received[header_end..header_end + content_length].to_vec(),
    ))
}

fn write_http_response(stream: &mut TcpStream, response: &QueuedResponse) -> std::io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.status,
        reason,
        response.body.len(),
        response.body
    )?;
    stream.flush()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct TestEnv {
    server: FakeServer,
    _root: tempfile::TempDir,
    home: PathBuf,
    config_home: PathBuf,
    cache_home: PathBuf,
    data_home: PathBuf,
    build_dir: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary E2E root");
        let home = root.path().join("home");
        let config_home = root.path().join("config");
        let cache_home = root.path().join("cache");
        let data_home = root.path().join("data");
        for directory in [&home, &config_home, &cache_home, &data_home] {
            std::fs::create_dir_all(directory).expect("create isolated user directory");
        }
        let build_dir = root.path().join("recipes/default");
        create_git_recipe(&build_dir, &[("PKGBUILD", DEFAULT_PKGBUILD)]);
        Self {
            server: FakeServer::start(),
            _root: root,
            home,
            config_home,
            cache_home,
            data_home,
            build_dir,
        }
    }

    fn recipe(&self, relative: &str, files: &[(&str, &str)]) -> PathBuf {
        let directory = self
            .home
            .parent()
            .expect("home has temporary parent")
            .join("recipes")
            .join(relative);
        create_git_recipe(&directory, files);
        directory
    }

    fn write_config(&self, endpoint: &str, model: &str, key_env: Option<&str>, extra: &str) {
        let directory = self.config_home.join("aurscan");
        std::fs::create_dir_all(&directory).expect("create aurscan config directory");
        let key_line = key_env
            .map(|variable| format!("api_key_env = {variable:?}\n"))
            .unwrap_or_default();
        std::fs::write(
            directory.join("config.toml"),
            format!(
                "[experimental.llm]\nendpoint = {endpoint:?}\nmodel = {model:?}\n{key_line}{extra}\n"
            ),
        )
        .expect("write strict LLM config");
    }

    fn write_local_config(&self, model: &str, key_env: Option<&str>, extra: &str) {
        self.write_config(&self.server.endpoint(), model, key_env, extra);
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aurscan"));
        command
            .env_clear()
            .env("PATH", inherited_path())
            .env("LC_ALL", "C")
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_CACHE_HOME", &self.cache_home)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(args);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_key(args, None)
    }

    fn run_with_key(&self, args: &[&str], key: Option<(&str, &str)>) -> Output {
        let mut command = self.command(args);
        if let Some((name, value)) = key {
            command.env(name, value);
        }
        command.output().expect("launch compiled aurscan binary")
    }

    fn run_with_path(&self, args: &[&str], path: &Path) -> Output {
        self.command(args)
            .env("PATH", path)
            .output()
            .expect("launch compiled aurscan binary with isolated PATH")
    }

    fn run_with_stdin_and_path(&self, args: &[&str], input: &str, path: &Path) -> Output {
        let mut child = self
            .command(args)
            .env("PATH", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch compiled aurscan binary with controlled stdin");
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(input.as_bytes())
            .expect("write child stdin");
        child.wait_with_output().expect("wait for aurscan binary")
    }

    fn cache_file(&self) -> PathBuf {
        self.cache_home.join("aurscan/llm.redb")
    }

    fn ack_file(&self) -> PathBuf {
        self.config_home.join("aurscan/acknowledged.toml")
    }
}

fn inherited_path() -> std::ffi::OsString {
    std::env::var_os("PATH").unwrap_or_else(|| std::ffi::OsString::from("/usr/bin:/bin"))
}

fn create_git_recipe(directory: &Path, files: &[(&str, &str)]) {
    std::fs::create_dir_all(directory).expect("create local recipe directory");
    for (relative, content) in files {
        let path = directory.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create recipe file parent");
        }
        std::fs::write(path, content).expect("write local recipe file");
    }
    git(directory, &["init", "--quiet"]);
    git(directory, &["add", "--all"]);
    git(directory, &["commit", "--quiet", "-m", "test recipe"]);
}

fn commit_recipe(directory: &Path, message: &str) {
    git(directory, &["add", "--all"]);
    git(directory, &["commit", "--quiet", "-m", message]);
}

fn git(directory: &Path, args: &[&str]) {
    let output = Command::new("git")
        .env_clear()
        .env("PATH", inherited_path())
        .env("LC_ALL", "C")
        .env("HOME", directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "user.name=aurscan e2e",
            "-c",
            "user.email=aurscan-e2e@localhost",
            "-C",
        ])
        .arg(directory.as_os_str())
        .args(args.iter().map(OsStr::new))
        .output()
        .expect("run local git command");
    assert!(
        output.status.success(),
        "git {args:?} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn completion_envelope(content: &str, finish_reason: &str) -> String {
    json!({
        "choices": [{
            "message": {"content": content},
            "finish_reason": finish_reason
        }],
        "usage": {"prompt_tokens": 101, "completion_tokens": 17}
    })
    .to_string()
}

fn findings_content(findings: Vec<Value>) -> String {
    json!({"findings": findings}).to_string()
}

fn candidate(
    kind: &str,
    severity: &str,
    file: &str,
    start_line: usize,
    end_line: usize,
    reason: &str,
) -> Value {
    json!({
        "kind": kind,
        "severity": severity,
        "file": file,
        "start_line": start_line,
        "end_line": end_line,
        "reason": reason
    })
}

fn output_code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn all_output(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

fn parse_stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            stdout(output),
            stderr(output)
        )
    })
}

fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        output_code(output),
        expected,
        "unexpected exit code\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

fn acknowledged_keys(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).expect("read acknowledgement file");
    let document: toml::Value = toml::from_str(&text).expect("parse acknowledgement TOML");
    document["acknowledged"]
        .as_array()
        .expect("acknowledged array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("acknowledgement key string")
                .to_owned()
        })
        .collect()
}

fn assert_llm_unused(env: &TestEnv, command: &str) {
    assert_eq!(
        env.server.request_count(),
        0,
        "plain command {command} contacted the LLM provider"
    );
    assert_eq!(
        env.server.connection_count(),
        0,
        "plain command {command} connected to the LLM provider"
    );
    assert!(
        !env.cache_file().exists(),
        "plain command {command} created LLM cache state"
    );
}

#[test]
fn deep_scan_requires_explicit_config_before_target_work() {
    let env = TestEnv::new();
    let target = env.build_dir.to_string_lossy().into_owned();

    let output = env.run(&["--no-color", "deep-scan", &target]);

    assert_exit(&output, 3);
    let error = stderr(&output).to_ascii_lowercase();
    assert!(
        error.contains("cannot read llm configuration"),
        "missing explicit not-configured error:\n{}",
        stderr(&output)
    );
    assert_eq!(env.server.request_count(), 0);
    assert!(
        !env.cache_file().exists(),
        "strict failure must precede cache work"
    );
    env.server.assert_healthy();
}

#[test]
fn deep_scan_sends_raw_file_message_and_returns_grounded_advisory() {
    const RECIPE: &str = "pkgbase=canonical-base\npkgname=('split-z' 'split-a')\npkgver=1\npkgrel=1\narch=('any')\ninstaller='downloaded-upstream-bootstrap.sh'\npackage() {\n  :\n}\n";
    const REASON: &str =
        "A downloaded bootstrap is selected for execution, allowing upstream compromise to run during packaging.";
    let env = TestEnv::new();
    let recipe = env.recipe("raw-message", &[("PKGBUILD", RECIPE)]);
    env.write_local_config("pinned-e2e-model", Some(API_KEY_ENV), "");
    env.server.queue_completion(
        &findings_content(vec![candidate(
            "download_execute",
            "critical",
            "PKGBUILD",
            6,
            6,
            REASON,
        )]),
        "stop",
    );
    let target = recipe.to_string_lossy().into_owned();

    let output = env.run_with_key(
        &["--json", "--no-color", "deep-scan", &target],
        Some((API_KEY_ENV, "test-secret")),
    );

    assert_exit(&output, 1);
    let report = parse_stdout_json(&output);
    let package = &report["packages"][0];
    let finding = &package["findings"][0];
    assert_eq!(package["pkgbase"], "canonical-base");
    assert_eq!(package["requested_packages"], json!(["split-a", "split-z"]));
    assert_eq!(package["verdict"], "advisory");
    assert_eq!(package["analysis"]["status"], "completed");
    assert_eq!(package["analysis"]["source"], "provider");
    assert_eq!(
        package["analysis"]["review_strategy_id"],
        "findings_first_v1"
    );
    assert_eq!(
        report["preflight"]["review_strategy_id"],
        "findings_first_v1"
    );
    assert_eq!(finding["severity"], "critical");
    assert_eq!(finding["confidence"], "llm");
    assert_eq!(finding["detector"], "llm_download_execute");
    assert_eq!(finding["package"], "canonical-base");
    assert_eq!(finding["evidence"]["location"], "PKGBUILD:6");
    assert_eq!(
        finding["evidence"]["excerpt"],
        "installer='downloaded-upstream-bootstrap.sh'"
    );

    assert_eq!(env.server.request_count(), 1);
    let lines = env.server.captured_request_lines();
    assert_eq!(lines, ["POST /v1/chat/completions HTTP/1.1"]);
    let headers = env.server.captured_headers();
    assert_eq!(
        headers[0].get("authorization").map(String::as_str),
        Some("Bearer test-secret")
    );
    let bodies = env.server.captured_bodies();
    let body: Value = serde_json::from_slice(&bodies[0]).expect("captured request JSON");
    let messages = body["messages"].as_array().expect("request messages");
    assert_eq!(
        messages.len(),
        3,
        "one file must have one distinct raw message"
    );
    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[1]["role"], "user");
    assert!(messages[1]["content"]
        .as_str()
        .expect("manifest content")
        .contains("\n- \"PKGBUILD\""));
    assert_eq!(messages[2]["role"], "user");
    assert_eq!(
        messages[2]["content"],
        format!("File: PKGBUILD\nLine 1 begins after this header.\n{RECIPE}")
    );
    assert_eq!(
        messages
            .iter()
            .filter(|message| message["content"]
                .as_str()
                .is_some_and(|content| content.starts_with("File: ")))
            .count(),
        1
    );
    let top_level: BTreeSet<&str> = body
        .as_object()
        .expect("request object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        top_level,
        BTreeSet::from([
            "max_tokens",
            "messages",
            "model",
            "n",
            "response_format",
            "temperature"
        ])
    );
    assert!(body.get("tools").is_none());
    assert!(body.get("tool_choice").is_none());
    assert!(body.get("host_findings").is_none());
    assert!(body.get("verdict").is_none());
    let schema = &body["response_format"]["json_schema"]["schema"];
    assert_eq!(
        schema["properties"]
            .as_object()
            .expect("response schema properties")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["findings"]
    );
    env.server.assert_healthy();
}

#[test]
fn deep_scan_cache_hit_needs_no_key_or_provider() {
    let mut env = TestEnv::new();
    env.write_local_config("cache-model", Some(API_KEY_ENV), "");
    env.server
        .queue_completion(&findings_content(vec![]), "stop");
    let target = env.build_dir.to_string_lossy().into_owned();

    let first = env.run_with_key(
        &["--json", "deep-scan", &target],
        Some((API_KEY_ENV, "first-run-only")),
    );
    assert_exit(&first, 0);
    assert_eq!(
        parse_stdout_json(&first)["packages"][0]["analysis"]["source"],
        "provider"
    );
    assert_eq!(env.server.request_count(), 1);

    let observed_hit = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&observed_hit, 0);
    let observed_json = parse_stdout_json(&observed_hit);
    assert_eq!(
        observed_json["packages"][0]["analysis"]["status"],
        "completed"
    );
    assert_eq!(observed_json["packages"][0]["analysis"]["source"], "cache");
    assert_eq!(env.server.request_count(), 1);
    assert_eq!(env.server.connection_count(), 1);

    env.server.stop();
    env.server.assert_healthy();

    let text_hit = env.run(&["--no-color", "deep-scan", &target]);
    assert_exit(&text_hit, 0);
    let text = all_output(&text_hit);
    assert!(text.contains("completed via cache"), "got:\n{text}");
    assert!(text.contains("no accepted LLM findings"), "got:\n{text}");
    assert!(!text.to_ascii_lowercase().contains("model clean"));
    assert!(!text.to_ascii_lowercase().contains("model safe"));

    let json_hit = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&json_hit, 0);
    let json = parse_stdout_json(&json_hit);
    assert_eq!(json["packages"][0]["analysis"]["status"], "completed");
    assert_eq!(json["packages"][0]["analysis"]["source"], "cache");
    assert_eq!(json["packages"][0]["findings"], json!([]));
    let rendered = stdout(&json_hit).to_ascii_lowercase();
    assert!(!rendered.contains("model clean"));
    assert!(!rendered.contains("model safe"));
    assert_eq!(env.server.request_count(), 1);
    assert_eq!(env.server.connection_count(), 1);
}

#[test]
fn content_prompt_model_schema_and_strategy_identity_miss() {
    let env = TestEnv::new();
    env.write_local_config("identity-model-a", None, "");
    for _ in 0..5 {
        env.server
            .queue_completion(&findings_content(vec![]), "stop");
    }
    let target = env.build_dir.to_string_lossy().into_owned();

    let initial = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&initial, 0);
    assert_eq!(env.server.request_count(), 1);
    assert_eq!(
        parse_stdout_json(&initial)["packages"][0]["analysis"]["source"],
        "provider"
    );
    let unchanged = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&unchanged, 0);
    assert_eq!(env.server.request_count(), 1);
    assert_eq!(
        parse_stdout_json(&unchanged)["packages"][0]["analysis"]["source"],
        "cache"
    );

    std::fs::write(
        env.build_dir.join("PKGBUILD"),
        format!("{DEFAULT_PKGBUILD}# changed bundle bytes\n"),
    )
    .expect("change tracked PKGBUILD");
    commit_recipe(&env.build_dir, "change content identity");
    let content_miss = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&content_miss, 0);
    assert_eq!(env.server.request_count(), 2);
    assert_eq!(
        parse_stdout_json(&content_miss)["packages"][0]["analysis"]["source"],
        "provider"
    );
    let content_hit = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&content_hit, 0);
    assert_eq!(env.server.request_count(), 2);

    env.write_local_config("identity-model-b", None, "");
    let model_miss = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&model_miss, 0);
    let model_json = parse_stdout_json(&model_miss);
    assert_eq!(env.server.request_count(), 3);
    assert_eq!(
        model_json["packages"][0]["analysis"]["model"],
        "identity-model-b"
    );
    assert_eq!(
        model_json["packages"][0]["analysis"]["review_strategy_id"],
        "findings_first_v1"
    );
    let model_hit = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&model_hit, 0);
    assert_eq!(env.server.request_count(), 3);

    env.write_local_config(
        "identity-model-b",
        None,
        "response_format = \"json_object\"",
    );
    let profile_miss = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&profile_miss, 0);
    assert_eq!(env.server.request_count(), 4);
    let profile_hit = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&profile_hit, 0);
    assert_eq!(env.server.request_count(), 4);

    let refresh = env.run(&["--json", "deep-scan", "--refresh", &target]);
    assert_exit(&refresh, 0);
    assert_eq!(env.server.request_count(), 5);
    let refreshed_hit = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&refreshed_hit, 0);
    assert_eq!(env.server.request_count(), 5);
    assert_eq!(
        parse_stdout_json(&refreshed_hit)["packages"][0]["analysis"]["source"],
        "cache"
    );

    let bodies = env.server.captured_bodies();
    assert_eq!(bodies.len(), 5);
    let initial_request: Value = serde_json::from_slice(&bodies[0]).unwrap();
    let model_request: Value = serde_json::from_slice(&bodies[2]).unwrap();
    let profile_request: Value = serde_json::from_slice(&bodies[3]).unwrap();
    assert_eq!(initial_request["model"], "identity-model-a");
    assert_eq!(model_request["model"], "identity-model-b");
    assert_eq!(initial_request["response_format"]["type"], "json_schema");
    assert_eq!(profile_request["response_format"]["type"], "json_object");
    assert!(initial_request["messages"][0]["content"]
        .as_str()
        .expect("system prompt")
        .contains("findings-first security"));
    assert!(
        initial_request["response_format"]["json_schema"]["schema"]["properties"]
            .get("findings")
            .is_some()
    );
    env.server.assert_healthy();
}

#[test]
fn invalid_mixed_and_truncated_responses_exit_three_and_do_not_cache() {
    let env = TestEnv::new();
    env.write_local_config("invalid-response-model", None, "");
    let target = env.build_dir.to_string_lossy().into_owned();
    let mixed = findings_content(vec![
        candidate(
            "other_semantic",
            "medium",
            "PKGBUILD",
            3,
            3,
            "The version assignment participates in a suspicious semantic path with package-time impact.",
        ),
        candidate(
            "download_execute",
            "high",
            "outside-the-bundle.sh",
            1,
            1,
            "This invented file would execute a download.",
        ),
    ]);
    let cases = [
        ("malformed", "{not-json".to_owned(), "stop", 0_usize),
        (
            "unknown-field",
            json!({"findings": [], "unexpected": true}).to_string(),
            "stop",
            0,
        ),
        ("mixed", mixed, "stop", 1),
        ("truncated", findings_content(vec![]), "length", 0),
    ];

    for (name, content, finish_reason, expected_findings) in cases {
        let before = env.server.request_count();
        env.server.queue_completion(&content, finish_reason);
        env.server.queue_completion(&content, finish_reason);
        for repeat in 0..2 {
            let output = env.run(&["--json", "deep-scan", &target]);
            assert_exit(&output, 3);
            let report = parse_stdout_json(&output);
            assert_eq!(
                report["packages"][0]["analysis"]["status"], "incomplete",
                "case {name}, repeat {repeat}"
            );
            assert_eq!(
                report["packages"][0]["analysis"]["source"], "provider",
                "case {name}, repeat {repeat}"
            );
            assert_eq!(
                report["packages"][0]["findings"]
                    .as_array()
                    .expect("findings array")
                    .len(),
                expected_findings,
                "case {name}, repeat {repeat}"
            );
            assert_eq!(
                env.server.request_count(),
                before + repeat + 1,
                "case {name} must not cache incomplete analysis"
            );
            if name == "mixed" {
                assert_eq!(
                    report["packages"][0]["findings"][0]["evidence"]["excerpt"],
                    "pkgver=1"
                );
                assert!(stdout(&output).contains("llm_other_semantic"));
                assert!(report["packages"][0]["analysis"]["reason"]
                    .as_str()
                    .expect("mixed rejection reason")
                    .contains("unknown file citation"));
            }
        }
    }
    assert_eq!(env.server.request_count(), 8);
    env.server.assert_healthy();
}

#[test]
fn provider_http_errors_are_unavailable_and_never_cached() {
    let env = TestEnv::new();
    env.write_local_config("provider-error-model", None, "");
    let target = env.build_dir.to_string_lossy().into_owned();

    for (repeat, status) in [500_u16, 503].into_iter().enumerate() {
        env.server
            .queue_raw(status, json!({"error": "provider unavailable"}).to_string());
        let output = env.run(&["--json", "deep-scan", &target]);

        assert_exit(&output, 3);
        let report = parse_stdout_json(&output);
        assert_eq!(
            report["packages"][0]["analysis"]["status"], "unavailable",
            "HTTP {status}, repeat {repeat}"
        );
        assert_eq!(
            report["packages"][0]["analysis"]["source"], "provider",
            "HTTP {status}, repeat {repeat} must not be a cache hit"
        );
        assert_eq!(
            env.server.request_count(),
            repeat + 1,
            "HTTP {status} must issue exactly one new provider request"
        );
    }
    env.server.assert_healthy();
}

#[test]
fn request_cap_preflight_sends_nothing() {
    let env = TestEnv::new();
    env.write_local_config("cap-model", None, "max_requests_per_run = 1");
    let second = env.recipe(
        "second-cap-package",
        &[(
            "PKGBUILD",
            "pkgbase=second-base\npkgname=second-package\npkgver=1\npkgrel=1\narch=('any')\npackage() { :; }\n",
        )],
    );
    let first_target = env.build_dir.to_string_lossy().into_owned();
    let second_target = second.to_string_lossy().into_owned();

    let output = env.run(&["--json", "deep-scan", &first_target, &second_target]);

    assert_exit(&output, 3);
    assert_eq!(env.server.request_count(), 0);
    let report = parse_stdout_json(&output);
    assert_eq!(report["packages"].as_array().unwrap().len(), 2);
    for package in report["packages"].as_array().unwrap() {
        assert_eq!(package["analysis"]["status"], "incomplete");
        assert!(package["analysis"]["reason"]
            .as_str()
            .expect("request-cap reason")
            .contains("cache miss count 2 exceeds request cap 1"));
    }
    env.server.assert_healthy();
}

#[test]
fn plain_commands_never_contact_llm() {
    const ABSENT_API_KEY_ENV: &str = "AURSCAN_E2E_DELIBERATELY_ABSENT_KEY";
    let env = TestEnv::new();
    env.write_local_config("must-remain-unused", Some(ABSENT_API_KEY_ENV), "");
    let target = env.build_dir.to_string_lossy().into_owned();
    let fake_path = env
        .home
        .parent()
        .expect("home has temporary parent")
        .join("fake-path");
    std::fs::create_dir(&fake_path).expect("create empty isolated PATH");

    let check = env.run_with_path(&["--no-color", "check", &target], &fake_path);
    assert_exit(&check, 0);
    assert_llm_unused(&env, "check");

    let check_hook = env.run_with_path(&["--no-color", "check", "--hook", &target], &fake_path);
    assert_exit(&check_hook, 0);
    assert_llm_unused(&env, "check --hook");

    let ack = env.run_with_path(&["--no-color", "ack", "--yes", &target], &fake_path);
    assert_exit(&ack, 0);
    assert!(all_output(&ack).contains("nothing to acknowledge"));
    assert_llm_unused(&env, "ack --yes");

    let bad_archive = env.home.join("expected-local-error.pkg.tar.zst");
    std::fs::write(&bad_archive, b"not a package archive").unwrap();
    let archive = bad_archive.to_string_lossy().into_owned();
    let artifact = env.run_with_path(&["--no-color", "scan-artifact", &archive], &fake_path);
    assert_exit(&artifact, 0);
    assert!(
        all_output(&artifact).contains("could not be scanned"),
        "expected the deterministic local archive error path:\n{}",
        all_output(&artifact)
    );
    assert_llm_unused(&env, "scan-artifact");

    let artifact_hook = env.run_with_stdin_and_path(
        &["--no-color", "scan-artifact", "--hook"],
        &format!("{archive}\n"),
        &fake_path,
    );
    assert_exit(&artifact_hook, 0);
    assert!(
        all_output(&artifact_hook).contains("could not be scanned"),
        "expected the deterministic local artifact-hook error path:\n{}",
        all_output(&artifact_hook)
    );
    assert_llm_unused(&env, "scan-artifact --hook");

    let install = env.run_with_path(&["--no-color", "install"], &fake_path);
    assert_exit(&install, 3);
    assert!(
        stderr(&install).contains("failed to launch paru"),
        "expected fake-PATH install error:\n{}",
        all_output(&install)
    );
    assert_llm_unused(&env, "install");

    let setup = env.run_with_path(&["--no-color", "setup", "--check"], &fake_path);
    assert!(
        matches!(output_code(&setup), 0 | 1),
        "setup --check returned unexpected code {}:\n{}",
        output_code(&setup),
        all_output(&setup)
    );
    assert_llm_unused(&env, "setup --check");
    env.server.assert_healthy();
}

#[test]
fn ack_llm_persists_only_complete_live_findings() {
    const INSTALLER: &str = "payload='review-me'\n";
    const REASON: &str =
        "The reviewed payload marker reaches an install-time execution path if upstream recipe logic is compromised.";
    let env = TestEnv::new();
    let recipe = env.recipe(
        "relative-ack-paths",
        &[
            ("PKGBUILD", DEFAULT_PKGBUILD),
            ("helpers/one/install.sh", INSTALLER),
            ("helpers/two/install.sh", INSTALLER),
        ],
    );
    env.write_local_config("ack-model", None, "");
    env.server.queue_completion(
        &findings_content(vec![candidate(
            "build_install_boundary",
            "medium",
            "helpers/one/install.sh",
            1,
            1,
            REASON,
        )]),
        "stop",
    );
    let target = recipe.to_string_lossy().into_owned();

    let first_ack = env.run(&["--no-color", "ack", "--llm", "--yes", &target]);
    assert_exit(&first_ack, 0);
    assert!(all_output(&first_ack).contains("acknowledged 1 LLM finding"));
    let first_keys = acknowledged_keys(&env.ack_file());
    assert_eq!(first_keys.len(), 1);
    assert_eq!(env.server.request_count(), 1);

    let suppressed = env.run(&["--no-color", "deep-scan", &target]);
    assert_exit(&suppressed, 0);
    let suppressed_text = all_output(&suppressed);
    assert!(suppressed_text.contains("canonical-base: CLEAN"));
    assert!(suppressed_text.contains("(1 acknowledged)"));
    assert!(!suppressed_text.contains(REASON));
    assert_eq!(
        env.server.request_count(),
        1,
        "suppression should use the cache"
    );

    env.server.queue_completion(
        &findings_content(vec![candidate(
            "build_install_boundary",
            "medium",
            "helpers/two/install.sh",
            1,
            1,
            REASON,
        )]),
        "stop",
    );
    let refreshed = env.run(&["--json", "deep-scan", "--refresh", &target]);
    assert_exit(&refreshed, 1);
    let refreshed_report = parse_stdout_json(&refreshed);
    assert_eq!(
        refreshed_report["packages"][0]["analysis"]["source"],
        "provider"
    );
    assert_eq!(
        refreshed_report["packages"][0]["findings"][0]["evidence"]["location"],
        "helpers/two/install.sh:1"
    );
    assert_eq!(env.server.request_count(), 2);

    let second_ack = env.run(&["--no-color", "ack", "--llm", "--yes", &target]);
    assert_exit(&second_ack, 0);
    assert!(all_output(&second_ack).contains("acknowledged 1 LLM finding"));
    let second_keys = acknowledged_keys(&env.ack_file());
    assert_eq!(second_keys.len(), 2);
    assert_ne!(second_keys[0], second_keys[1]);
    assert_eq!(
        env.server.request_count(),
        2,
        "ack must use the refreshed cache"
    );
    let request_bodies = env.server.captured_bodies();
    assert_eq!(
        request_bodies[0], request_bodies[1],
        "path identity must change without changing content, model, or bundle identity"
    );
    env.server.assert_healthy();
}

#[test]
fn ack_llm_refuses_incomplete_analysis() {
    let env = TestEnv::new();
    env.write_local_config("incomplete-ack-model", None, "");
    let mixed = findings_content(vec![
        candidate(
            "other_semantic",
            "medium",
            "PKGBUILD",
            3,
            3,
            "A valid live claim is present but the overall provider analysis is incomplete.",
        ),
        candidate(
            "download_execute",
            "high",
            "not-submitted.sh",
            1,
            1,
            "An invalid outside-bundle claim must make acknowledgement fail closed.",
        ),
    ]);
    env.server.queue_completion(&mixed, "stop");
    let target = env.build_dir.to_string_lossy().into_owned();

    let llm_ack = env.run(&["--no-color", "ack", "--llm", "--yes", &target]);
    assert_exit(&llm_ack, 3);
    let text = all_output(&llm_ack);
    assert!(text.contains("one or more requested LLM analyses did not complete"));
    assert!(text.contains("no LLM acknowledgements were persisted"));
    assert!(!env.ack_file().exists());
    assert_eq!(env.server.request_count(), 1);

    let plain_ack = env.run(&["--no-color", "ack", "--yes", &target]);
    assert_exit(&plain_ack, 0);
    assert_eq!(env.server.request_count(), 1);
    assert!(!env.ack_file().exists());
    env.server.assert_healthy();
}

#[test]
fn terminal_output_escapes_untrusted_controls() {
    let env = TestEnv::new();
    let raw_evidence = format!(
        "payload='prefix{}escape{}overwrite{}bidi{}soft'\n",
        '\u{1b}', '\r', '\u{202e}', '\u{00ad}'
    );
    let recipe = env.recipe(
        "terminal-controls",
        &[
            ("PKGBUILD", DEFAULT_PKGBUILD),
            ("evidence.install", &raw_evidence),
        ],
    );
    env.write_local_config("terminal-model", None, "");
    env.server.queue_completion(
        &findings_content(vec![candidate(
            "other_semantic",
            "medium",
            "evidence.install",
            1,
            1,
            "The payload marker crosses a package boundary under attacker-controlled recipe changes.",
        )]),
        "stop",
    );
    let target = recipe.to_string_lossy().into_owned();

    let text_output = env.run(&["--no-color", "deep-scan", &target]);
    assert_exit(&text_output, 1);
    let text_stdout = stdout(&text_output);
    let text_stderr = stderr(&text_output);
    assert!(text_stdout.contains("\\u{1b}"), "got:\n{text_stdout}");
    assert!(text_stdout.contains("\\u{d}"), "got:\n{text_stdout}");
    assert!(text_stdout.contains("\\u{202e}"), "got:\n{text_stdout}");
    assert!(text_stdout.contains("\\u{ad}"), "got:\n{text_stdout}");
    for rendered in [&text_stdout, &text_stderr] {
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\r'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\u{00ad}'));
    }

    let json_output = env.run(&["--json", "--no-color", "deep-scan", &target]);
    assert_exit(&json_output, 1);
    assert!(!json_output.stdout.contains(&0x1b));
    assert!(!json_output.stderr.contains(&0x1b));
    let report = parse_stdout_json(&json_output);
    assert_eq!(report["packages"][0]["analysis"]["source"], "cache");
    assert_eq!(
        report["packages"][0]["findings"][0]["evidence"]["excerpt"],
        raw_evidence.trim_end_matches('\n')
    );
    assert_eq!(env.server.request_count(), 1);
    env.server.assert_healthy();
}

#[test]
fn remote_consent_fails_before_request() {
    let env = TestEnv::new();
    let target = env.build_dir.to_string_lossy().into_owned();
    let observer_port = env.server.address.port();
    // IPv4-mapped loopback routes only to this local observer, while the
    // endpoint policy intentionally does not classify it as literal loopback.
    let mapped_http = format!("http://[::ffff:127.0.0.1]:{observer_port}/v1");
    let mapped_https = format!("https://[::ffff:127.0.0.1]:{observer_port}/v1");

    env.write_config(
        &mapped_http,
        "remote-model",
        None,
        "allow_remote = false\ntimeout_seconds = 1",
    );
    let insecure_remote = env.run(&["deep-scan", &target]);
    assert_exit(&insecure_remote, 3);
    assert!(stderr(&insecure_remote).contains("HTTP LLM endpoint requires localhost"));
    assert_eq!(env.server.request_count(), 0);
    assert_eq!(env.server.connection_count(), 0);

    env.write_config(
        &mapped_https,
        "remote-model",
        None,
        "allow_remote = false\ntimeout_seconds = 1",
    );
    let no_consent = env.run(&["deep-scan", &target]);
    assert_exit(&no_consent, 3);
    assert!(stderr(&no_consent).contains("requires allow_remote=true"));
    assert_eq!(env.server.request_count(), 0);
    assert_eq!(env.server.connection_count(), 0);

    env.write_local_config(
        "loopback-model",
        None,
        "allow_remote = false\ntimeout_seconds = 1",
    );
    env.server
        .queue_completion(&findings_content(vec![]), "stop");
    let loopback = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&loopback, 0);
    assert_eq!(env.server.request_count(), 1);
    assert_eq!(env.server.connection_count(), 1);
    assert_eq!(
        parse_stdout_json(&loopback)["packages"][0]["analysis"]["source"],
        "provider"
    );
    env.server.assert_healthy();
}

#[test]
fn large_limits_require_explicit_override() {
    let env = TestEnv::new();
    let target = env.build_dir.to_string_lossy().into_owned();

    env.write_local_config(
        "large-limit-model",
        None,
        "max_files = 65\nallow_large_requests = false",
    );
    let guarded = env.run(&["deep-scan", &target]);
    assert_exit(&guarded, 3);
    assert!(stderr(&guarded).contains("max_files above 64 requires allow_large_requests=true"));
    assert_eq!(env.server.request_count(), 0);

    env.write_local_config(
        "large-limit-model",
        None,
        "max_files = 65\nallow_large_requests = true",
    );
    env.server
        .queue_completion(&findings_content(vec![]), "stop");
    let explicitly_allowed = env.run(&["--json", "deep-scan", &target]);
    assert_exit(&explicitly_allowed, 0);
    let report = parse_stdout_json(&explicitly_allowed);
    assert_eq!(report["preflight"]["large_request_mode"], true);
    assert_eq!(report["packages"][0]["analysis"]["source"], "provider");
    assert_eq!(env.server.request_count(), 1);

    env.write_local_config(
        "large-limit-model",
        None,
        "max_files = 257\nallow_large_requests = true",
    );
    let process_maximum = env.run(&["deep-scan", &target]);
    assert_exit(&process_maximum, 3);
    assert!(stderr(&process_maximum).contains("max_files exceeds process-safety maximum 256"));
    assert_eq!(env.server.request_count(), 1);
    env.server.assert_healthy();
}
