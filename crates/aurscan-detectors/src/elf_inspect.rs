//! goblin-based static ELF analysis for fetched sources and built-package
//! members: high-entropy/packed sections, W^X segments, suspicious dynamic
//! imports, and bare executables masquerading as sources. It is also the
//! primary ELF `FeatureVector` producer (schema v2) for the phase-2 ONNX
//! classifier.

use std::collections::HashSet;

use aurscan_core::{
    Confidence, Detector, DetectorId, DetectorResult, Evidence, FeatureId, FeatureVector, Finding,
    ScanContext, ScanTarget, Severity, SourceOrigin,
};
use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
use goblin::elf::section_header::SHT_INIT_ARRAY;

/// Bigger ELFs get magic+size features only, no section analysis.
const READ_CAP: u64 = 32 * 1024 * 1024;

/// Sections smaller than this are too small for a meaningful entropy signal
/// (compressed debug sections and small metadata blobs land noisy here).
const MIN_SECTION_SIZE_FOR_ENTROPY: usize = 4096;

/// UPX-packed and encrypted payloads sit ~7.8-8.0; compressed debug sections
/// land lower; 7.2 balances the two.
const HIGH_ENTROPY_THRESHOLD: f32 = 7.2;

/// Higher bar for the combined static+stripped+hidden-binary rule (R5).
const PACKAGE_HIGH_ENTROPY_THRESHOLD: f32 = 7.6;

/// Known archive suffixes; an ELF fetched as a source under any other name
/// is unusual enough to flag (R4).
const KNOWN_ARCHIVE_SUFFIXES: &[&str] = &[
    ".tar",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tar.lz",
    ".tgz",
    ".txz",
    ".zip",
    ".appimage",
];

/// Suspicious import set (R3 / feature 109).
const SUSPICIOUS_IMPORT_NAMES: &[&str] = &[
    "ptrace",
    "bpf",
    "memfd_create",
    "mmap",
    "mprotect",
    "dlopen",
    "fork",
    "connect",
];

pub struct ElfInspectDetector;

impl ElfInspectDetector {
    fn finding(
        &self,
        package: &str,
        severity: Severity,
        reason: String,
        location: &str,
        excerpt: &str,
    ) -> Finding {
        Finding {
            severity,
            confidence: Confidence::Heuristic,
            detector: self.id(),
            package: package.to_string(),
            reason,
            evidence: Evidence {
                location: location.to_string(),
                excerpt: excerpt.chars().take(200).collect(),
            },
        }
    }
}

impl Detector for ElfInspectDetector {
    fn id(&self) -> DetectorId {
        DetectorId("elf_inspect")
    }

    fn wants(&self, target: &ScanTarget) -> bool {
        matches!(
            target,
            ScanTarget::SourceFile { .. } | ScanTarget::PackageFile { .. }
        )
    }

    fn scan(&self, target: &ScanTarget, ctx: &ScanContext) -> DetectorResult {
        let bytes = match target {
            ScanTarget::SourceFile { path, .. } => std::fs::read(path).unwrap_or_default(),
            ScanTarget::PackageFile { archive, member } => {
                aurscan_core::target::read_archive_member(archive, member, READ_CAP)
                    .unwrap_or_default()
            }
            _ => return DetectorResult::default(),
        };
        if !bytes.starts_with(b"\x7fELF") {
            return DetectorResult::default();
        }

        let location = location_of(target);
        let mut findings = Vec::new();

        // R4: an ELF arriving as a SourceFile fetched from a raw URL (not a
        // release archive) is itself a signal.
        if let ScanTarget::SourceFile {
            origin: SourceOrigin::Url(url),
            ..
        } = target
        {
            if !has_known_archive_suffix(url) {
                findings.push(self.finding(
                    &ctx.package,
                    Severity::Medium,
                    "bare executable fetched as source".to_string(),
                    &location,
                    url,
                ));
            }
        }

        let file_len = bytes.len() as f32;
        let too_big = bytes.len() as u64 > READ_CAP;
        let elf = if too_big {
            None
        } else {
            match goblin::Object::parse(&bytes) {
                Ok(goblin::Object::Elf(elf)) => Some(elf),
                _ => None,
            }
        };

        let mut n_sections = 0.0f32;
        let mut mean_section_entropy = 0.0f32;
        let mut max_section_entropy = 0.0f32;
        let mut exec_writable_segment = 0.0f32;
        let mut n_dynlibs = 0.0f32;
        let mut has_init_array = 0.0f32;
        let mut n_init_array_entries = 0.0f32;
        let mut stripped = 0.0f32;
        let mut n_suspicious_imports = 0.0f32;
        let mut text_entropy = 0.0f32;

        if let Some(elf) = &elf {
            n_sections = elf.section_headers.len() as f32;
            n_dynlibs = elf.libraries.len() as f32;
            stripped = if elf.syms.is_empty() { 1.0 } else { 0.0 };

            // R1: exec+writable PT_LOAD segment.
            let has_wx_segment = elf
                .program_headers
                .iter()
                .any(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0 && ph.p_flags & PF_W != 0);
            if has_wx_segment {
                exec_writable_segment = 1.0;
                findings.push(self.finding(
                    &ctx.package,
                    Severity::High,
                    "W^X violating segment (self-modifying/packed code)".to_string(),
                    &location,
                    "PT_LOAD segment with PF_X|PF_W",
                ));
            }

            // Section entropy: mean/max over sections >= 4KB, plus .text.
            let pointer_size = if elf.is_64 { 8u64 } else { 4u64 };
            let mut qualifying_entropies = Vec::new();
            for sh in elf.section_headers.iter() {
                if sh.sh_type == SHT_INIT_ARRAY {
                    has_init_array = 1.0;
                    let entsize = if sh.sh_entsize > 0 {
                        sh.sh_entsize
                    } else {
                        pointer_size
                    };
                    n_init_array_entries += (sh.sh_size / entsize) as f32;
                }

                let start = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                let Some(data) = bytes.get(start..start.saturating_add(size)) else {
                    continue;
                };
                if data.is_empty() {
                    continue;
                }
                let e = entropy(data);
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if name == ".text" {
                    text_entropy = e;
                }
                if size >= MIN_SECTION_SIZE_FOR_ENTROPY {
                    qualifying_entropies.push(e);
                }
            }
            if !qualifying_entropies.is_empty() {
                mean_section_entropy =
                    qualifying_entropies.iter().sum::<f32>() / qualifying_entropies.len() as f32;
                max_section_entropy = qualifying_entropies.iter().cloned().fold(0.0f32, f32::max);

                // R2: packed/encrypted payload.
                if max_section_entropy > HIGH_ENTROPY_THRESHOLD {
                    findings.push(self.finding(
                        &ctx.package,
                        Severity::Medium,
                        "high-entropy section (packed or encrypted payload)".to_string(),
                        &location,
                        &format!("max section entropy {max_section_entropy:.2}"),
                    ));
                }
            }

            // R3: suspicious dynamic imports.
            let imports: HashSet<&str> = elf
                .dynsyms
                .iter()
                .filter(|sym| sym.is_import())
                .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
                .filter(|name| !name.is_empty())
                .collect();
            n_suspicious_imports = SUSPICIOUS_IMPORT_NAMES
                .iter()
                .filter(|name| imports.contains(*name))
                .count() as f32;
            let solo_hit = imports.contains("ptrace")
                || imports.contains("bpf")
                || imports.contains("memfd_create");
            let combo_hit = (imports.contains("fork") && imports.contains("connect"))
                || (imports.contains("mmap")
                    && imports.contains("mprotect")
                    && imports.contains("dlopen"));
            if solo_hit {
                findings.push(self.finding(
                    &ctx.package,
                    Severity::Medium,
                    "suspicious dynamic import (ptrace/bpf/memfd_create)".to_string(),
                    &location,
                    "dynamic import",
                ));
            }
            if combo_hit {
                // Info, not Medium: fork+connect is every networked program
                // and mmap+mprotect+dlopen is every JIT, so on real artifacts
                // this was the single noisiest advisory wall (four Mediums on
                // one browser install). All hits come from this one detector,
                // so they never fed the 3-distinct-detector escalation
                // either; the combo still rides in reports, JSON, and the ML
                // feature vector (n_suspicious_imports).
                findings.push(
                    self.finding(
                        &ctx.package,
                        Severity::Info,
                        "suspicious import combination (fork+connect or mmap+mprotect+dlopen)"
                            .to_string(),
                        &location,
                        "dynamic import combo",
                    ),
                );
            }

            // R5: static, stripped, high-entropy binary hidden under usr/bin
            // or usr/lib.
            if let ScanTarget::PackageFile { member, .. } = target {
                let under_bin_or_lib =
                    member.starts_with("usr/bin/") || member.starts_with("usr/lib/");
                if under_bin_or_lib
                    && stripped == 1.0
                    && n_dynlibs == 0.0
                    && max_section_entropy > PACKAGE_HIGH_ENTROPY_THRESHOLD
                {
                    findings.push(self.finding(
                        &ctx.package,
                        Severity::High,
                        "static, stripped, high-entropy binary under usr/bin or usr/lib (packed and hidden)"
                            .to_string(),
                        &location,
                        member,
                    ));
                }
            }
        }

        let features = FeatureVector {
            schema_version: 2,
            values: vec![
                (FeatureId(100), file_len),
                (FeatureId(101), n_sections),
                (FeatureId(102), mean_section_entropy),
                (FeatureId(103), max_section_entropy),
                (FeatureId(104), exec_writable_segment),
                (FeatureId(105), n_dynlibs),
                (FeatureId(106), has_init_array),
                (FeatureId(107), n_init_array_entries),
                (FeatureId(108), stripped),
                (FeatureId(109), n_suspicious_imports),
                (FeatureId(110), text_entropy),
            ],
        };

        DetectorResult {
            findings,
            features: Some(features),
        }
    }
}

fn location_of(target: &ScanTarget) -> String {
    match target {
        ScanTarget::SourceFile { path, .. } | ScanTarget::HostArtifact { path } => {
            path.display().to_string()
        }
        ScanTarget::PackageFile { archive, member } => {
            format!("{}!{}", archive.display(), member)
        }
        ScanTarget::BuildScript { path, .. } => path.display().to_string(),
    }
}

fn has_known_archive_suffix(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    KNOWN_ARCHIVE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Shannon entropy of a byte slice, in bits per byte.
fn entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for &b in bytes {
        hist[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut h = 0.0f32;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f32 / len;
            h -= p * p.log2();
        }
    }
    h
}

// --- Contract assertions ---
#[cfg(test)]
mod contract {
    use super::*;

    fn _assert_detector(_: &dyn Detector) {}

    #[test]
    fn implements_detector() {
        fn assert_impl<T: Detector>() {}
        assert_impl::<ElfInspectDetector>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn minimal_elf() -> Vec<u8> {
        // 64-byte ELF64 header: magic, class=2 (64-bit), data=1 (LE), version=1,
        // type=ET_DYN, machine=EM_X86_64, no sections/programs.
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16] = 3; // ET_DYN
        b[18] = 62; // EM_X86_64
        b[52] = 64; // ehsize
        b
    }

    /// A minimal ELF with a single PT_LOAD program header carrying both
    /// PF_X and PF_W, for exercising the W^X rule (R1).
    fn minimal_elf_with_wx_segment() -> Vec<u8> {
        let mut b = minimal_elf();
        b.resize(64 + 56, 0);
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

        let ph = 64;
        b[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes()); // p_type
        b[ph + 4..ph + 8].copy_from_slice(&(PF_X | PF_W).to_le_bytes()); // p_flags
        b
    }

    fn ctx() -> ScanContext {
        ScanContext {
            package: "x".to_string(),
            version: "1".to_string(),
            aur_meta: None,
        }
    }

    fn scan_source(path: &Path) -> DetectorResult {
        scan_source_with_origin(path, SourceOrigin::LocalFile)
    }

    fn scan_source_with_origin(path: &Path, origin: SourceOrigin) -> DetectorResult {
        let det = ElfInspectDetector;
        let target = ScanTarget::SourceFile {
            path: path.to_path_buf(),
            origin,
        };
        assert!(det.wants(&target));
        det.scan(&target, &ctx())
    }

    #[test]
    fn non_elf_bytes_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("data.bin");
        std::fs::write(&p, b"not an elf").unwrap();
        let r = scan_source(&p);
        assert!(r.findings.is_empty() && r.features.is_none());
    }

    #[test]
    fn minimal_elf_emits_features_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("lib.so");
        std::fs::write(&p, minimal_elf()).unwrap();
        let r = scan_source(&p);
        assert!(r.findings.is_empty());
        assert_eq!(r.features.expect("features").schema_version, 2);
    }

    #[test]
    fn elf_in_source_tarball_of_script_package_is_medium() {
        // An ELF arriving as a *source file* (not built) is itself a signal
        // when the origin is a raw URL rather than a release tarball name.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("downloaded");
        std::fs::write(&p, minimal_elf()).unwrap();
        let r = scan_source_with_origin(
            &p,
            SourceOrigin::Url("https://example.com/payload".to_string()),
        );
        assert!(r.findings.iter().any(|f| f.severity >= Severity::Medium
            && f.reason.contains("bare executable fetched as source")));
    }

    #[test]
    fn elf_from_release_tarball_url_is_not_flagged_by_r4() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("downloaded");
        std::fs::write(&p, minimal_elf()).unwrap();
        let r = scan_source_with_origin(
            &p,
            SourceOrigin::Url("https://example.com/proj-1.0.tar.gz".to_string()),
        );
        assert!(!r
            .findings
            .iter()
            .any(|f| f.reason.contains("bare executable fetched as source")));
    }

    #[test]
    fn wx_segment_is_high() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packed.so");
        std::fs::write(&p, minimal_elf_with_wx_segment()).unwrap();
        let r = scan_source(&p);
        assert!(r
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High && f.reason.contains("W^X")));
    }

    #[test]
    fn entropy_scorer_low_for_zeros_high_for_spread() {
        // Hand-crafting a section-entropy fixture (valid ELF section headers
        // + a real high-entropy section blob) is impractical byte-by-byte;
        // the scorer is unit-tested directly here per the design spec.
        assert!(entropy(&[0u8; 1024]) < 0.1);
        let spread: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(entropy(&spread) > 7.9);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn usr_bin_true_is_clean() {
        let bytes = std::fs::read("/usr/bin/true").expect("/usr/bin/true not present");
        assert!(bytes.starts_with(b"\x7fELF"));
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("true");
        std::fs::write(&p, &bytes).unwrap();
        let r = scan_source(&p);
        assert!(r.findings.is_empty());
        assert_eq!(r.features.expect("features").schema_version, 2);
    }
}
