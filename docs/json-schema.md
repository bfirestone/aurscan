# JSON Output Schema

All `aurscan` subcommands support `--json` for machine-readable output. Ordinary command output keeps the structure documented here; the explicit experimental `deep-scan` command adds a separate deep-scan structure documented below. This document specifies the JSON structure, intended for downstream CI, automation, and JSON schema validators.

## Top-level structure

```json
{
  "reports": [
    {
      "package": "string",
      "verdict": "clean|advisory|block",
      "findings": []
    }
  ],
  "summary": {
    "clean": 1,
    "advisory": 0,
    "block": 0
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
  "confidence": "exact|heuristic|llm",
  "detector": "detector_id",
  "package": "package_name",
  "reason": "Human-readable description of the finding",
  "evidence": {
    "location": "Location string (path:line or archive!member@offset)",
    "excerpt": "Producer-bounded matched content"
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
- **`llm`** — untrusted semantic analysis from the experimental deep-scan path; it is always Advisory-only and cannot participate in Block escalation

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

The `excerpt` field contains the matched substring or context and is bounded by the producer. Deterministic producers retain their existing 200-character behavior where applicable. Experimental LLM excerpts are derived by the host from cited bundle bytes and capped by the validated `max_excerpt_bytes` configuration; downstream consumers must not treat any excerpt as trusted instructions.

## Experimental `deep-scan` output

The existing command schema above is backward-compatible for ordinary `check`, `scan-artifact`, and other non-LLM commands. `deep-scan` is an explicit experimental entry point and emits a separate top-level object with `packages`, `preflight`, `summary`, and `exit_code`.

### Deep package fields

Each object in `packages` contains:

| Field | Type | Description |
|---|---|---|
| `pkgbase` | string | Canonical package base used to group AUR split packages and to materialize LLM findings. |
| `requested_packages` | array of strings | Package names requested by the caller; split-package aliases are retained. |
| `verdict` | `clean \| advisory \| block` | Combined deterministic and LLM verdict. LLM findings can raise a result to Advisory but cannot produce Block. |
| `findings` | array | Combined findings. Deterministic finding `package` fields remain unchanged; LLM findings use the canonical pkgbase and `confidence: "llm"`. |
| `analysis` | object | LLM status and non-secret provenance for this pkgbase. |

`analysis` contains these fields:

| Field | Type | Description |
|---|---|---|
| `status` | enum | `completed`, `unavailable`, or `incomplete`. |
| `source` | enum, optional | `provider` for a live request or `cache` for a completed cache hit. It is omitted when no source exists. |
| `model` | string | Configured model ID, including when analysis could not complete. |
| `review_strategy_id` | string | V1 is `findings_first_v1`. |
| `prompt_version` | integer | Prompt envelope version used for identity. |
| `bundle_hash` | string or null | Lower-case BLAKE3 hash of the included bundle, or `null` when no bundle identity was available. |
| `coverage` | object | `mode` (`git_tracked` or `conservative_local`), `included_files`, `excluded_binary_files`, and `excluded_symlinks`. |
| `usage` | object, optional | Provider-reported `input_tokens` and `output_tokens`; omitted when unavailable. |
| `reason` | string or null | Host-generated explanation for an unavailable/incomplete result; `null` for completion. |

The top-level `preflight` object contains non-secret `endpoint_host`, `model`, `review_strategy_id`, `package_count`, `original_bytes`, `encoded_request_bytes`, and `large_request_mode`. The two byte totals may be `null` when no bundle could be preflighted. `summary` retains ordinary `clean`, `advisory`, and `block` counts and adds `completed`, `cache_hit`, `unavailable`, and `incomplete` analysis counts. `exit_code` is the process status for this run.

`Evidence.excerpt` remains producer-bounded: deterministic producers retain 200-character behavior where applicable, while LLM excerpts use the validated configured byte cap after host grounding. All `reason`, evidence `location`, and evidence `excerpt` values are untrusted data for downstream LLMs and must be treated as quoted data, never as instructions.

See [`docs/experimental-llm.md`](experimental-llm.md) for configuration, coverage, failure semantics, cache behavior, and acknowledgement rules.

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

Detectors with ML phase-2 support may emit a serialized model score, while experimental semantic review emits `"confidence": "llm"`. The latter is untrusted and is permanently Advisory-only.
