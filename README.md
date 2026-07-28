# aurscan

A proactive, high-performance AUR package scanner in Rust that gates the install path before any PKGBUILD executes. Detects both known malware IOCs (legacy incident response) and novel attack patterns (heuristic analysis).

> **Bootstrap Trust:** The scanner itself arrives via the AUR — the channel it scans. Verify the first install manually by inspecting this repository and the PKGBUILD source before trusting it.

## What it is

`aurscan` is a four-stage security gate for AUR packages:

1. **Build scripts** — scan PKGBUILD/install-scripts before `makepkg` runs any shell code
2. **Fetched sources** — inspect archives after download, before build
3. **Built artifacts** — verify `.pkg.tar.zst` binaries before pacman installs
4. **System audit** — detect installed compromised packages and host malware traces

Unlike the legacy incident-specific Python tool (`legacy/aurscan.py`, retained for the June 2026 incident), this Rust engine generalizes detection to catch novel attacks, gates proactively (stages 1–2 pre-execution), and integrates natively with paru and pacman.

## Install

### From AUR

> **Not yet published.** `paru -S aurscan` does not work yet — the AUR submission is pending. Use one of the methods below until then.

Once published:

```bash
paru -S aurscan
aurscan setup  # Enable paru PreBuildCommand integration and pacman hook
```

If paru updates its paru.conf and overwrites the custom `PreBuildCommand`, run `aurscan setup` again to restore it.

### From the PKGBUILD (recommended today)

Builds the released tarball with checksum verification, and installs the pacman hook and license the same way the AUR package will:

```bash
git clone https://github.com/bfirestone/aurscan
cd aurscan
makepkg -si
aurscan setup
```

### From source (cargo install)

```bash
git clone https://github.com/bfirestone/aurscan
cd aurscan
cargo install --path crates/aurscan-cli
aurscan setup  # Install the paru.conf snippet and pacman hook
```

## Usage

### `check` — Scan without installing

Scan PKGBUILDs and sources locally (stage 1–2). Paths are scanned directly; package names are resolved via AUR RPC and cloned into a temporary directory.

```bash
aurscan check .                    # Scan PKGBUILD in current directory
aurscan check firefox aspell-en    # Scan two AUR packages by name
aurscan check --verbose            # Show informational findings
```

In **paru-native mode**, paru runs `aurscan check --hook .` automatically before each build, scanning the PKGBUILD paru will actually execute (stage 1) and verified sources (stage 2). If findings block, paru aborts before `makepkg` runs. If findings advise, an interactive prompt offers override (`--allow`).

### `install` — Fetch, scan, gate, then install

Wrapper that resolves the AUR dependency tree, clones packages to paru's cache, scans stages 1–2, then delegates to paru for installation. Records the scanned git commit per package; the ALPM hook (stage 3) re-checks that HEAD matches before allowing install.

```bash
aurscan install firefox aspell-en  # Fetch, scan, then `paru -S`
```

Secondary UX compared to paru-native mode; primarily useful for scripted/CI workflows. The wrapper gates on findings; once clean, `paru -S` reuses the cached clone and sources (PreBuildCommand re-scan is a warm-cache no-op).

### `scan-artifact` — Scan built packages

Inspect `.pkg.tar.zst` archive members (stage 3): binaries for entropy/packing, setuid bits, daemon installation. Primary entry point is the ALPM pacman hook (automatic); also available for standalone use on cached or downloaded archives.

```bash
aurscan scan-artifact /var/cache/pacman/pkg/firefox-*.pkg.tar.zst
aurscan scan-artifact chrome chromium  # By package name from pacman DB
```

The `--hook` flag reads from stdin (ALPM's PreTransaction format); it is the pacman hook entry point and need not be invoked directly.

### `audit` — Audit the installed system

Scan stage 4: installed foreign packages + host artifacts (eBPF pins, suspicious processes, etc.). Scans all AUR-installed packages and looks for malware traces. Useful as a cron job, post-incident assessment, or before/after security updates.

```bash
aurscan audit                    # Scan this system's foreign packages
aurscan audit --root /mnt        # Scan an offline filesystem image
aurscan audit --verbose          # Show informational findings
```

Replaces the incident-specific role of `legacy/aurscan.py`; generalizes to all installed foreign packages, not just June 2026 IOCs.

### `update-lists` — Refresh known-bad overrides

Fetch the latest remote list of known-compromised package names and payload hashes. Bundled lists are embedded at compile time; this command fetches upstream additions.

```bash
aurscan update-lists
```

### `setup` — Configure paru integration and install the hook

Add the `PreBuildCommand` line to paru.conf (stage 1–2 gates) and install the pacman hook (stage 3 gates). Idempotent; safe to re-run.

Use `--yes` to skip the prompt, or `--check` to report whether the gate is actually active without changing anything (exit 1 if it is not). The paru gate lives in per-user config and cannot be enabled by the package installer, so the pacman hook warns on every transaction while it is missing.

```bash
aurscan setup
sudo aurscan setup  # Required for hook installation
```

## How it protects

```text
User runs: paru -S firefox
                 ↓
[paru-native PreBuildCommand] → aurscan check --hook . (stage 1,2)
          ↓ if findings → Block
     abort before makepkg
          ↓ if clean/advisory+allowed
[makepkg + build] → makes firefox-*.pkg.tar.zst
                 ↓
[pacman hook PreTransaction] → aurscan scan-artifact --hook (stage 3)
          ↓ if findings → Block
     abort before install
          ↓ if clean/advisory+allowed
[pacman -U] → install
```

Stages 1 and 2 prevent PKGBUILD code execution. Stage 3 is last-line defense for already-compiled artifacts (protects yay users, catches late-stage modifications). Stage 4 audits the running system.

## Detectors

Each detector targets one or more stages and emits findings (or feature vectors for ML in phase 2).

| Detector | Stage | Catches | Confidence |
|---|---|---|---|
| `ioc_tokens` | 1, 2, 4 | Known-bad literal strings in text; ports the Python IOC list | Exact |
| `payload_hashes` | 2, 3, 4 | Known malware hashes (BLAKE3/SHA256) match | Exact |
| `known_bad_names` | 1, 4 | Confirmed-compromised package names (June 2026 incident list) | Exact |
| `pkgbuild_static` | 1 | Bash AST analysis via tree-sitter: curl-pipe-sh, eval-of-decoded, base64/hex blobs, writes outside $pkgdir/$srcdir, network in prepare()/build(), suspicious .install scripts | Heuristic |
| `source_provenance` | 1 | URL anomalies: raw IPs, shorteners, typosquat distance, non-HTTPS, domain mismatch | Heuristic |
| `aur_metadata` | 1 | Cross-signals from AUR RPC: recent orphan adoption + maintainer change + modified sources | Heuristic |
| `elf_inspect` | 2, 3 | Binary analysis via goblin: packed sections, high entropy, unexpected syscalls, setuid, .init_array oddities | Heuristic |
| `archive_layout` | 3 | Tar walk analysis: systemd/cron/profile drops, setuid bits, hidden dotfiles in system paths | Heuristic |
| `persistence` | 4 | Systemd unit heuristics, eBPF pin detection (ports Python `legacy/aurscan.py` checks) | Heuristic |

**Exact** findings are verified matches against curated IOC data; they auto-escalate to CRITICAL severity. **Heuristic** findings apply rule-based inference; severity is configurable per rule. Findings are scored and co-occurring weak signals escalate via a weighted function.

## Verdicts & exit codes

Each package receives a verdict after all detectors have scanned:

- **Clean** (exit 0): no findings
- **Advisory** (exit 1): Medium/High heuristic findings; interactive mode prompts y/N
- **Block** (exit 2): Critical findings or configured block rules; interactive mode aborts

In non-interactive mode (non-TTY, `--json`, cron), exit code reflects the worst verdict across all packages:

```bash
$ aurscan check pkg1 pkg2 pkg3
pkg1: CLEAN
pkg2: ADVISORY
pkg3: CLEAN
$ echo $?
1
```

Non-interactive mode never prompts; Block verdicts fail the command.

Findings can be acknowledged via `~/.config/aurscan/acknowledged.toml` to suppress re-alerts for the same content (anti-alert-fatigue). Acknowledged findings are still reported but do not block.

### Global flags

```text
--json              # Machine-readable JSON output (see docs/json-schema.md)
--no-color          # Disable ANSI color codes in text output
-v, --verbose       # Include Info findings (normally hidden) and extra detail
--allow <pkg>       # Override Block verdicts for specific packages (interactive only)
-h, --help          # Print help
```

## Exit codes

- `0` — Clean (no findings)
- `1` — Advisory (Medium/High findings; prompts in interactive mode)
- `2` — Block (Critical findings or configured block rules)
- `>2` — Error (I/O failure, network error, invalid input; see stderr for detail)

## Legacy tool

`legacy/aurscan.py` is the incident-specific Python scanner from June 2026, retained for reference and as prior art for the audit mode. Its role is now covered by `aurscan audit`, which generalizes the persistence and IOC checks to all installed foreign packages.

The June 2026 IOC data (known-bad package names, tokens, hashes) are embedded in this Rust tool and regularly updated. The Python tool is no longer maintained.

## JSON output

All subcommands support `--json` for machine-readable output. The schema documents the report structure, verdict, findings, and evidence. See `docs/json-schema.md` for the full specification and examples.

## Configuration

Configuration and state files:

- `~/.config/paru/paru.conf` — `setup` adds the `[bin] PreBuildCommand` line here (paru's own config, not an aurscan file)
- `~/.config/aurscan/acknowledged.toml` — acknowledged findings (auto-created)
- `~/.cache/aurscan/results.redb` — content-hash cache (auto-created, safe to delete)

## Integration with paru and pacman

`aurscan setup` configures two integration points:

1. **paru PreBuildCommand** (stage 1–2 gate): paru runs `aurscan check --hook .` before build, scanning the PKGBUILD and verified sources. Non-zero exit aborts paru's build of that package.
2. **pacman hook** (stage 3 gate): `/usr/share/libalpm/hooks/aurscan.hook` runs `aurscan scan-artifact --hook` on PreTransaction, scanning all packages being installed before pacman touches the filesystem.

See `docs/integration.md` for implementation details, TOCTOU mitigation, and caveat notes.

## For developers & maintainers

### Repository structure

```text
aurscan/
├── Cargo.toml              # Workspace root (Rust 2021, workspace members)
├── crates/
│   ├── aurscan-core/       # Shared types, detector trait, scan engine
│   ├── aurscan-detectors/  # Detection logic (9 detectors)
│   └── aurscan-cli/        # Binary: CLI, report rendering, hook modes
├── data/
│   └── aurscan.hook        # pacman hook definition (installs to /usr/share/libalpm/hooks/)
├── rules/                  # Rule data: TOML with IOCs, hashes, regex rules
├── docs/
│   ├── plans/              # Design documents
│   ├── json-schema.md      # JSON output specification
│   └── integration.md      # paru/pacman integration guide
├── legacy/                 # Prior-art Python scanner (June 2026 incident)
└── README.md               # This file
```

### Building

```bash
cargo build --release --locked --bin aurscan
./target/release/aurscan --version
```

### Tests

The workspace includes 190 unit tests covering detectors, rules, verdict logic, and the scan engine.

```bash
cargo test --locked
```

## Security considerations

- **Rule data:** All IOC data (tokens, hashes, package names, regex rules) live in `rules/*.toml` and are embedded at compile time. New IOCs are a data PR, not code changes.
- **Cache:** The scan cache at `~/.cache/aurscan/scan-cache.redb` is content-addressed and self-validating; it's safe to delete, and cache hits skip re-scanning.
- **Privileges:** Stages 1–3 run unprivileged; stage 4 (system audit) requires read access to foreign package metadata (normal user can read pacman DB) and optionally `sudo` for host artifact checks.

## Contributing

Contributions welcome: detector improvements, new IOC rules, false-positive reduction, and test fixtures. Please file issues and pull requests.

## License

MIT. See the repository root for the license text.
