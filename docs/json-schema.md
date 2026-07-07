# JSON Output Schema

All `aurscan` subcommands support `--json` for machine-readable output. This document specifies the JSON structure, intended for downstream CI, automation, and JSON schema validators.

## Top-level structure

```json
{
  "reports": [
    {
      "package": "string",
      "verdict": "clean|advisory|block",
      "findings": [ /* Finding objects */ ]
    }
  ],
  "summary": {
    "clean": "number",
    "advisory": "number",
    "block": "number"
  }
}
```

- **`reports`** — array of per-package scan results
- **`summary`** — counts of verdicts across all packages (used for analytics, CI gating)

## Per-package report

Each report contains:

| Field | Type | Description |
|---|---|---|
| `package` | string | Package name (e.g., `"firefox"`, `"chromium"`) |
| `verdict` | enum | One of: `"clean"` (no findings), `"advisory"` (Medium/High heuristic findings), `"block"` (Critical or configured block rules) |
| `findings` | array | Array of Finding objects (empty if Clean) |

## Finding object

Each finding describes a specific detection result:

```json
{
  "severity": "critical|high|medium|info",
  "confidence": "exact|heuristic",
  "detector": "detector_id",
  "package": "package_name",
  "reason": "Human-readable description of the finding",
  "evidence": {
    "location": "Location string (path:line or archive!member@offset)",
    "excerpt": "Matched content, capped at 200 characters"
  }
}
```

### Severity levels (totally ordered)

- **`critical`** — definite malware or security-critical misconfiguration; auto-escalates to Block
- **`high`** — strong suspicious indicator; typically Advisory or Block per config
- **`medium`** — moderate risk; typically Advisory
- **`info`** — informational finding (e.g., installed during attack window); requires `-v/--verbose` flag to display

### Confidence levels

- **`exact`** — verified match against curated IOC data (hash, known-bad name, literal token)
- **`heuristic`** — rule-based inference (AST pattern, URL anomaly, binary analysis); can be tuned or acknowledged to reduce noise

### Detector IDs

See README.md § Detectors for the full catalog. Examples:

- `ioc_tokens` — literal IOC string match
- `payload_hashes` — malware hash match
- `known_bad_names` — confirmed-compromised package name
- `pkgbuild_static` — suspicious bash patterns
- `source_provenance` — URL anomalies
- `aur_metadata` — AUR RPC cross-signals
- `elf_inspect` — ELF binary analysis
- `archive_layout` — tar archive structure analysis
- `persistence` — system persistence indicators

### Evidence

Precisely locates the finding:

- For text files (PKGBUILD, sources): `"PKGBUILD:42"` (filename:line)
- For archives: `"pkg.tar.zst!usr/bin/curl@0x1000"` (archive!member@offset)
- For system audit: `"eBPF hidden_infostealer"` or `"/sys/fs/bpf/hidden_*"`

The `excerpt` field contains the matched substring or context, capped at 200 characters to keep JSON size manageable.

## Exit codes

The exit code reflects the worst verdict across all packages:

| Exit Code | Meaning |
|---|---|
| `0` | All packages Clean |
| `1` | At least one Advisory, none Block |
| `2` | At least one Block |
| `>2` | Error (I/O, network, invalid input) |

## Example: mixed verdicts

Input: `aurscan check firefox chromium aspell-en --json`

```json
{
  "reports": [
    {
      "package": "firefox",
      "verdict": "clean",
      "findings": []
    },
    {
      "package": "chromium",
      "verdict": "block",
      "findings": [
        {
          "severity": "critical",
          "confidence": "exact",
          "detector": "payload_hashes",
          "package": "chromium",
          "reason": "Built binary matches known infostealer SHA256",
          "evidence": {
            "location": "chromium-*.pkg.tar.zst!usr/bin/chromium@0x3a40",
            "excerpt": "MZ\\x90\\x00...ELF header matches elf_infostealer_v2"
          }
        }
      ]
    },
    {
      "package": "aspell-en",
      "verdict": "advisory",
      "findings": [
        {
          "severity": "high",
          "confidence": "heuristic",
          "detector": "source_provenance",
          "package": "aspell-en",
          "reason": "Source URL uses shortener; cannot verify upstream authenticity",
          "evidence": {
            "location": "PKGBUILD:8",
            "excerpt": "https://bit.ly/2kL9sP"
          }
        }
      ]
    }
  ],
  "summary": {
    "clean": 1,
    "advisory": 1,
    "block": 1
  }
}
```

In this example:
- firefox → exit would be 2 (Block wins)
- chromium blocks due to exact hash match
- aspell-en advises due to a heuristic finding (shortener URL)

## Integration with CI/automation

Typical CI pipeline:

```bash
aurscan check $PACKAGES --json > scan-results.json
EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
  # Block: fail the build
  echo "Security block: install denied"
  exit 1
elif [ $EXIT_CODE -eq 1 ]; then
  # Advisory: log warning but allow (or fail based on policy)
  echo "Advisory findings detected; review scan-results.json"
fi

# Parse JSON for fine-grained policy checks
jq '.reports[] | select(.verdict == "block")' scan-results.json
```

## Acknowledged findings

When findings are acknowledged via `~/.config/aurscan/acknowledged.toml`, they are still included in the JSON output but with a note that they've been acknowledged in the text output. The JSON structure is unchanged; filtering is the caller's responsibility.

To filter out acknowledged findings in downstream processing, either:
1. Track the acknowledgement file separately and cross-reference by `(package, detector, evidence-hash)`
2. Use the text output (which filters acknowledged findings automatically)

## Version notes

This schema is versioned implicitly by the aurscan release version. Future versions may add optional fields (backward-compatible) but will not remove or change existing field meanings without a major version bump.

Detectors with ML phase-2 support may emit `"confidence": "model(0.87)"` (a model score), which the schema allows via the `confidence` enum.
