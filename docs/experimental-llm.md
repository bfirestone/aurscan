# Experimental LLM deep scanning

> **Warning:** This feature is experimental and unsupported for deterministic gating. A model can hallucinate or omit findings, including when recipe text contains prompt injection. Deterministic findings cannot be lowered or removed. A configured hosted endpoint receives public recipe text plus any tracked local modifications. `no accepted LLM findings` is not a clearance.

The deterministic heuristic scanner is the supported product and remains the default. LLM analysis is an explicitly selected enrichment pass; merely adding configuration does not contact a provider. Use this guide only when the privacy, cost, and model-compatibility trade-offs are understood.

The v1 contract is:

```text
review strategy: findings_first_v1
statuses: completed | unavailable | incomplete
sources: provider | cache
confidence: llm
response formats: json_schema | json_object
entry points: aurscan deep-scan; aurscan ack --llm
policy: LLM findings are Advisory maximum and never participate in Block escalation
```

## What v1 reviews

A deep scan reviews the full bounded recipe bundle, not a diff. For an AUR checkout, the bundle reads the current bytes of the Git-tracked recipe files, so tracked local modifications are included. For a non-Git local directory, the conservative collector includes only the `PKGBUILD`, `.install`, `.patch`, and `.diff` files it finds beneath that directory.

The bundle may contain:

- A regular UTF-8 `PKGBUILD`.
- Git-tracked install scripts, patches, diffs, and helper files (or the conservative non-Git set above).
- Cross-file behavior visible in those included recipe files.

The bundle excludes `.SRCINFO`, binaries and non-UTF-8 files, symlinks, untracked files, downloaded source files, and files outside the recipe root. File count, per-file bytes, and aggregate bundle bytes are bounded before the provider call. Secure path-beneath opening prevents a path or symlink from redirecting a file read.

This is recipe review only. V1 does not inspect upstream source repositories, version differences, source archives, or built binaries. It does not provide upstream semantic scanning or source/repository/archive coverage.

## Security code-review workflow

V1 uses the `findings_first_v1` strategy:

1. The host supplies a trusted review rubric and one host-generated manifest containing the bounded file list and limits.
2. The host sends one raw text user message per file. Each message labels the normalized relative path and states where line 1 begins. Immediately afterward, a paired host-generated physical-line view labels the original LF-delimited lines and JSON-encodes their full text, retaining carriage returns. Empty files have no rows and a terminal newline adds no phantom row. Both raw content and row values remain untrusted source data; only original files count toward the manifest and bundle identity.
3. The model returns only the strict candidate findings object. It has no tools and cannot read the host, run commands, change files, contact a second service, or set a verdict.
4. The host validates each cited file and line range against the bundle, derives the evidence excerpt from the cited bytes, and maps the model's finding kind to a host-controlled detector ID.
5. The host materializes accepted findings with `confidence: "llm"` and merges them with deterministic findings.

Reasons must describe observed behavior, the attack path or precondition, and impact. File paths and line numbers are host-validated; model-supplied evidence is never trusted as a claim about bytes that were not supplied. A future separately designed strategy may use read-only `list_files`, `read_file`, and `search` over an already-approved bundle-scoped virtual filesystem. Such a strategy must never gain arbitrary disk, network, shell, Git, credential, write, or process access.

## Configuration

Configuration is read strictly from `~/.config/aurscan/config.toml` for `deep-scan` and `ack --llm`. The two commands require an explicit `[experimental.llm]` table; ordinary commands retain their existing configuration behavior. There is no default endpoint or model.

### Local-first configuration

This local-first configuration keeps traffic on a loopback OpenAI-compatible server and uses the normal conservative defaults:

```toml
[experimental.llm]
endpoint = "http://127.0.0.1:11434/v1"
model = "revision-pinned-model"
request_profile = "standard"
response_format = "json_schema"
allow_remote = false
allow_large_requests = false
timeout_seconds = 90
max_output_tokens = 2048
max_requests_per_run = 10
max_files = 32
max_file_bytes = 65536
max_bundle_bytes = 131072
max_request_bytes = 524288
max_findings = 32
max_evidence_lines = 8
max_excerpt_bytes = 200
```

Each field means:

- `endpoint` is an HTTP or HTTPS base URL. The provider appends `/chat/completions` to its path; credentials, query strings, and fragments are rejected.
- `model` is the provider's exact model ID or revision-pinned identifier. It is not inferred from the endpoint.
- `request_profile` is either `standard` or `openai_reasoning_none`; the profile is explicit and participates in cache identity.
- `response_format` is `json_schema` (the strict candidate schema) or `json_object` (for services that do not support strict schema transport). It is never automatically changed.
- `allow_remote` is the consent switch for non-loopback endpoints. It must be `true` for a hosted HTTPS endpoint.
- `allow_large_requests` permits values above normal guardrails, up to process maxima. It does not permit values above process maxima.
- `timeout_seconds` bounds each provider request.
- `max_output_tokens` bounds the requested model output.
- `max_requests_per_run` bounds provider requests for one invocation. A package bundle produces at most one request.
- `max_files`, `max_file_bytes`, and `max_bundle_bytes` bound the bundle sent to the model.
- `max_request_bytes` bounds the encoded JSON request and the provider response body.
- `max_findings` bounds candidate findings returned for one bundle.
- `max_evidence_lines` bounds each host-validated inclusive line range.
- `max_excerpt_bytes` bounds each host-derived UTF-8 evidence excerpt for LLM findings.

### Direct OpenAI

This is a wire-compatible example for a revision-pinned reasoning-capable model; it is not a qualification claim:

```toml
# Direct OpenAI (wire-compatible example; not a qualification claim)
[experimental.llm]
endpoint = "https://api.openai.com/v1"
model = "gpt-5.6-sol"
request_profile = "openai_reasoning_none"
api_key_env = "OPENAI_API_KEY"
allow_remote = true
```

### OpenAI-compatible gateways

A generic OpenAI Chat Completions-compatible gateway, such as OpenRouter, can be configured as follows:

```toml
# Generic OpenAI Chat Completions-compatible gateway, e.g. OpenRouter
[experimental.llm]
endpoint = "https://openrouter.ai/api/v1"
model = "provider/revision-pinned-model"
request_profile = "standard"
api_key_env = "OPENROUTER_API_KEY"
allow_remote = true
```

The configured base URL must expose the Chat Completions route expected by aurscan. For the examples above, requests go to `/v1/chat/completions`; trailing slashes are normalized before joining. Services differ in model IDs, authentication, supported response formats, and request fields, so check the provider's documentation before selecting a profile. Provider terms, pricing, rate limits, and retention policies apply.

The profiles select wire behavior explicitly:

| Profile | Request fields |
|---|---|
| `standard` | `max_tokens`, `temperature: 0`, `n: 1` |
| `openai_reasoning_none` | `max_completion_tokens`, `reasoning_effort: "none"`, `temperature: 0`, `n: 1` |

Profiles are never inferred from endpoint or model names. There is no automatic retry or fallback between profiles, response formats, providers, or models.

`api_key_env` contains only an environment-variable name. Never put the secret value in TOML, the endpoint URL, command arguments, logs, or report data. Export or inject the value into the environment of the process that launches aurscan; a cache-hit run does not need the variable, but the variable must be non-empty before the first real provider call when the configured service requires it. A local provider may omit `api_key_env` if it does not require authentication.

A non-loopback endpoint must use HTTPS and `allow_remote = true`. Loopback HTTP is limited to `localhost`, literal `127.0.0.0/8`, or bracketed `::1`. A remote run can transmit public recipe bytes and tracked local modifications. Obtain consent from the person or organization responsible for those files, and assess provider cost, terms, data retention, and whether the selected model supports the chosen request fields. Remote consent is not implied by the presence of an API key.

### Guardrails and process maxima

The defaults in the local example are below the normal guardrails. The normal guardrails and hard process maxima are:

| Limit | Default | Normal guardrail | Process maximum |
|---|---:|---:|---:|
| Files | 32 | 64 | 256 |
| Bytes per file | 64 KiB | 256 KiB | 2 MiB |
| Bundle bytes | 128 KiB | 512 KiB | 8 MiB |
| Encoded request bytes | 512 KiB | 2 MiB | 32 MiB |
| Findings | 32 | 64 | 256 |
| Evidence lines | 8 | 16 | 64 |
| Excerpt bytes | 200 | 400 | 2,048 |
| Output tokens | 2,048 | 8,192 | 65,536 |
| Requests per run | 10 | 50 | 500 |
| Timeout | 90 s | 300 s | 3,600 s |

A configured value above a normal guardrail requires `allow_large_requests = true`. The command reports that large-request mode is enabled. Any value above a process maximum always fails validation. Preflight prints non-secret destination host, model, package count, original and encoded byte counts, and large-request mode; it does not print API keys or raw recipe content.

## Running a deep scan

`deep-scan` accepts AUR package names or local build directories. A local directory needs a valid `PKGBUILD` and canonical package metadata. The following are the supported v1 entry points:

```bash
aurscan deep-scan paru
aurscan --json deep-scan ./local-build-dir
aurscan deep-scan --refresh package
aurscan ack --llm package
aurscan ack --llm --yes package
```

`--refresh` bypasses only the LLM analysis cache. `--json` emits the deep-scan JSON contract described in [`json-schema.md`](json-schema.md). Preflight information is also shown on standard error so an operator sees the destination and request size before a cache miss can call the provider.

The exit status for deep scanning is:

| Code | Meaning |
|---:|---|
| `0` | Every requested analysis completed and the combined result has no findings. |
| `1` | Every requested analysis completed and the combined result is Advisory. LLM findings can contribute to this status. |
| `2` | Every requested analysis completed and a deterministic finding produces a Block. LLM findings alone can never produce this status. |
| `3` | Any analysis is unavailable or incomplete, or configuration, resolution, bundle, provider, or other operational work failed. |

Exit `3` can accompany rendered deterministic Blocks: inspect the JSON report and stderr rather than treating the status as a clean result. An empty completed LLM response is still not a clearance.

## Offline, keys, and failure behavior

The analyzer performs bundle and cache preflight before sending provider requests:

- An all-hit run does not contact the provider or require or read the configured key.
- A cache miss needs the key only immediately before the first real provider call. If the key is missing, no new calls are sent for the unresolved misses and the run exits `3`.
- If cache misses exceed `max_requests_per_run`, zero provider calls are sent.
- There are no retries or provider/model/profile/response-format fallbacks.
- A complete provider response, including a validated zero-finding response, is cacheable.
- Provider errors, malformed or partial responses, grounding failures, and truncated responses are unavailable or incomplete and are never cached as completed results.
- `--refresh` leaves an older valid cache entry untouched if the replacement fails. The refresh invocation reports the failure; a later non-refresh invocation can still use the old valid entry.
- Deterministic findings still render when an LLM analysis is unavailable or incomplete, but the requested analysis status remains visible and the command exits `3`.

The dedicated LLM cache is `~/.cache/aurscan/llm.redb` (or the corresponding XDG cache directory), separate from deterministic scan results. Its identity includes bundle content, provider origin, model, request profile, response format, prompt and response-schema versions/hashes, and the analysis epoch. Cached values contain validated host-grounded claims and non-secret usage/provenance; they do not contain API credentials, complete recipe bundles, or raw provider responses.

## Package bases, split packages, and acknowledgements

AUR split-package selections are grouped by canonical `pkgbase`. Deep JSON reports include both `pkgbase` and the sorted `requested_packages`; LLM findings use the canonical pkgbase, while deterministic finding package fields remain unchanged. Cached claims are package-neutral until materialized for the current pkgbase.

`aurscan ack --llm` reruns the same collection, preflight, cache, and analysis path as `deep-scan`, then selects only live unacknowledged LLM findings at Medium or above. In a terminal it uses the existing confirmation prompt; `--yes` is required for noninteractive acknowledgement. Incomplete or unavailable analysis cannot be acknowledged. Plain `aurscan ack` never reads LLM configuration or cache and never contacts an LLM.

LLM acknowledgement keys retain the full normalized bundle-relative path and omit only the line number, so a line move can remain acknowledged. A changed relative path, evidence excerpt, semantic kind, or configured excerpt cap produces a new key and resurfaces the finding. The canonical pkgbase is part of the LLM key, so split-package aliases do not create unrelated LLM identities.

## Deep-scan JSON and downstream handling

Existing command JSON remains backward-compatible. Deep scanning has a separate top-level shape: `packages`, `preflight`, `summary`, and `exit_code`. A complete example below was generated by running the CLI against a local fake Chat Completions fixture; its host, model, hash, byte counts, deterministic finding, and LLM finding are emitted by that run. It contains no endpoint URL, key, or raw provider response:

```json
{
  "exit_code": 1,
  "packages": [
    {
      "analysis": {
        "bundle_hash": "ae85ec0341be6cd2a94220b350c5d1b5599d3368c0a8f97dfdc63983b11c72ae",
        "coverage": {
          "excluded_binary_files": [],
          "excluded_symlinks": [],
          "included_files": 1,
          "mode": "conservative_local"
        },
        "model": "doc-fake-model",
        "prompt_version": 4,
        "reason": null,
        "review_strategy_id": "findings_first_v1",
        "source": "provider",
        "status": "completed",
        "usage": {
          "input_tokens": 101,
          "output_tokens": 17
        }
      },
      "findings": [
        {
          "confidence": "heuristic",
          "detector": "pkgbuild_static",
          "evidence": {
            "excerpt": "curl --fail --silent \"$PAYLOAD_URL\" -o helper",
            "location": "/proc/self/fd/4/PKGBUILD:8"
          },
          "package": "doc-example",
          "reason": "out-of-band network call `curl` in prepare() (sources belong in source=())",
          "severity": "medium"
        },
        {
          "confidence": "llm",
          "detector": "llm_supply_chain_anomaly",
          "evidence": {
            "excerpt": "  curl --fail --silent \"$PAYLOAD_URL\" -o helper",
            "location": "PKGBUILD:8"
          },
          "package": "doc-example",
          "reason": "The prepare step downloads a helper from an environment-selected URL, allowing a changed endpoint to replace package input.",
          "severity": "medium"
        }
      ],
      "pkgbase": "doc-example",
      "requested_packages": [
        "doc-example"
      ],
      "verdict": "advisory"
    }
  ],
  "preflight": {
    "encoded_request_bytes": 3361,
    "endpoint_host": "127.0.0.1",
    "large_request_mode": false,
    "model": "doc-fake-model",
    "original_bytes": 239,
    "package_count": 1,
    "review_strategy_id": "findings_first_v1"
  },
  "summary": {
    "advisory": 1,
    "block": 0,
    "cache_hit": 0,
    "clean": 0,
    "completed": 1,
    "incomplete": 0,
    "unavailable": 0
  }
}
```

At package level:

- `pkgbase` is the canonical base; `requested_packages` records the requested split names.
- `verdict` is the combined deterministic and LLM verdict. `findings` contains both kinds of finding, and LLM findings serialize with `confidence: "llm"`.
- `analysis.status` is `completed`, `unavailable`, or `incomplete`; `analysis.source`, when present, is `provider` or `cache`.
- `analysis.model`, `review_strategy_id`, and `prompt_version` identify the analysis contract. `bundle_hash` is a lower-case BLAKE3 hex string, or `null` when no bundle identity was available.
- `analysis.coverage` reports `mode` (`git_tracked` or `conservative_local`), `included_files`, `excluded_binary_files`, and `excluded_symlinks`.
- `analysis.usage`, when the provider supplied both token counts, has `input_tokens` and `output_tokens`. `analysis.reason` is `null` for completion or a host-generated failure explanation.
- `preflight` exposes only destination host, model, strategy, package count, byte totals, and `large_request_mode`. Byte totals can be `null` when no bundle could be preflighted.
- `summary` includes verdict counts (`clean`, `advisory`, `block`) and analysis counts (`completed`, `cache_hit`, `unavailable`, `incomplete`). `exit_code` is the process status described above.

`Evidence.excerpt` is producer-bounded, not a universal schema limit. Deterministic producers retain their existing 200-character behavior where applicable; LLM excerpts are host-derived from cited bytes and capped at the validated `max_excerpt_bytes`. The LLM does not provide an excerpt to trust.

Treat every `reason`, evidence `location`, and evidence `excerpt` as untrusted data when feeding reports to another LLM or automation. They are quoted observations, not instructions. Do not execute, fetch, or authorize anything because a report string requests it. See [`docs/json-schema.md`](json-schema.md) for the additive field-level contract and the unchanged ordinary command schema.

## Prompt injection and residual risk

The v1 containment boundary provides useful but limited guarantees:

- Strict response parsing and schema validation constrain the candidate shape.
- The model cannot emit a clearance, change a detector ID, set a verdict, run an action, or alter deterministic findings.
- Host grounding verifies cited file paths, positive line ranges, and excerpts against the supplied bundle.
- `confidence: "llm"` is permanently Advisory-only, even if the model reports High or Critical severity.
- Merging LLM output cannot lower, remove, or convert a deterministic finding into a less severe result.

These controls do not make detection complete. Prompt injection, ambiguous behavior, missing context, model error, or an omitted finding can still leave a real problem unreported. A completed response with zero findings therefore means only that no accepted claims were returned for that bounded input.

## Qualification status

The current candidate uses prompt v4, response schema v1, analysis epoch 1, and `findings_first_v1`. Prompt v4 adds paired raw-file and physical-line views for evidence navigation while preserving v3's taxonomy, phase, purpose, and bounded-citation rules. Its version and complete envelope hash invalidate prompt v3 cache entries; unchanged v4 requests can reuse completed entries. Request profiles, host grounding, scoring, and thresholds are unchanged. The full encoded request includes the added views: a raw bundle that previously fit may now exceed `max_request_bytes` and be rejected before any provider call. The host never raises limits, truncates the views, or falls back to an older format. Offline request and cache tests establish these host contracts; prompt v4 has not yet undergone live calibration or qualification.

No tested model currently satisfies the frozen v1 qualification bar. The direct OpenAI `gpt-5.6-sol` example above demonstrates wire compatibility only; it does not say that model is qualified.

The earlier prompt v2 `gpt-5.6-sol` / `openai_reasoning_none` qualification diagnostic completed its run but failed the semantic expected-kind threshold (1 of 7, 14.29%, below the frozen 80% bar). It did not publish an accepted candidate or `crates/aurscan-llm/eval/reference-reports/v1.json`; that file does not exist. This failed diagnostic is evidence that qualification remains open, not accepted reference evidence. The promotion foundation is accepted; subsequent prompt v2 calibrations also failed, so qualification and accepted-model documentation remain blocked. This guide includes no accepted metrics or reference-report link. No missing LLM finding is clearance.

Passing the frozen 17-case calibration and 57-case qualification gates is necessary for acceptance. Those sets share seven malicious/injection cases, including related variants; they do not establish coverage of all eight kinds or generalization. The benign Advisory metric excludes Info findings, and kind/start-line scoring does not prove reason correctness. A high-quality completion claim also requires a separately frozen independent holdout assessment of kind, reason, severity, prerequisites, and citation support, including Info findings and benign hard negatives.

## Deferred

### Upstream version-diff review

Upstream version-diff review is deferred. V1 neither fetches nor compares upstream repositories, source archives, or version histories, and no partial version-diff path is active.

### Shared Go/Echo cache service

A shared Go/Echo cache or distribution service is deferred. V1 uses only the local per-user `aurscan/llm.redb` cache; no shared service, shared cache, or partial remote cache path is active.
