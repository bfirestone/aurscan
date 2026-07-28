/// Version of the detectors' *logic*, independent of the ruleset data.
///
/// **Bump this whenever a detector change can alter a verdict for content
/// that has not changed.** It is part of the scan cache key: without a bump,
/// already-scanned packages keep their old verdicts forever, so a new
/// detection never reaches them and a fixed false positive keeps blocking.
///
/// History:
/// - 1: initial release (v0.1.0)
/// - 2: `pkgbuild_static` write-destination fix -- source operands are no
///   longer mistaken for write targets, clearing a false-positive Block on
///   packages using `install -Dm644 /dev/stdin "$pkgdir/..."`.
/// - 3: `pkgbuild_static` no longer treats discard/stream device nodes
///   (`/dev/null`, `/dev/stderr`, ...) as system-path writes, clearing a
///   false-positive Block on `paru`, `shelly-bin` and `xrizer`. Destructive
///   nodes (`/dev/sda`, `/dev/mem`) still Block.
pub const DETECTOR_EPOCH: u32 = 3;

pub mod archive_layout;
pub mod aur_metadata;
pub mod elf_inspect;
pub mod ioc_tokens;
pub mod known_bad_names;
pub mod payload_hashes;
pub mod persistence;
pub mod pkgbuild_static;
pub mod rules;
pub mod source_provenance;
