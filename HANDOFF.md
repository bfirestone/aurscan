# LLM Integration Handoff

**Last updated:** 2026-09-15  
**Repository:** `aur_package_scanner`  
**Branch:** `feat/add-llm-integration`  
**Accepted foundation implementation:** `3807dd4008f5dceb2faf85968e4478df5c9e7143`\
**Foundation status:** independently accepted, published, and closed

## Start Here

In a new Pi session:

```text
Read AGENTS.md and HANDOFF.md completely. Run `arc prime` using the new
session's own session ID. Foundation aurscan-0qag.01vn62.1.9.3 is accepted,
published, and closed at implementation commit 3807dd4 under approved
plan.056dgb. Read its completion evidence and permanent parent design
aurscan-0qag.01vn62.1.9, which remains open. Read rejected promotion-preflight task aurscan-0qag.01vn62.1.9.4 and diagnostic
correction task aurscan-0qag.01vn62.1.9.6. Preflight and qualification remain
blocked. Another paid calibration requires a new approved design and explicit
operational authorization; these diagnostic corrections authorize no live run.
```

Useful commands:

```bash
git status --short --branch
git log -12 --oneline
arc show aurscan-0qag.01vn62.1.9.3
arc show aurscan-0qag.01vn62.1.9.4
arc show aurscan-0qag.01vn62.1.9
arc plan show plan.04ynkn
arc plan show plan.056dgb
arc blocked
```

Do not copy the previous session ID into a new worker. Let the new harness provide its own identity when claiming work.

## Current Outcome

The client-only experimental LLM integration is implemented through CLI E2E coverage and user documentation. The semantic-promotion foundation, including the approved `plan.056dgb` cooperative cleanup amendment, is **independently accepted, published, and closed** at implementation commit `3807dd4008f5dceb2faf85968e4478df5c9e7143`.

The probe's identity check and pathname unlink remain separate. Every same-account process touching the active probe entry must coordinate through the retained directory lock, regardless of intent. Accidental and deliberate uncoordinated mutation of that exact entry is outside the cleanup guarantee; unrelated files and all other safeguards remain covered.

The five new offline regressions cover lock release/reacquisition, a regular-file replacement installed before validation, missing entries, symlink/directory rejection, and stale-probe preservation. Independent code and specification reviews accepted the implementation; the isolated evaluator passed all 11 authored tests. The signed implementation commit was pushed and origin synchronization verified before this handoff-only update.

Parent epic `.1.9` remains open. The first owner-approved 17-case `gpt-5.6-sol` / `openai_reasoning_none` preflight ran at `ee6aa25dde3ec9ff5a8ccc41c8a7429e0c23b3e0` and was **rejected**: 1/7 strict semantic hits (6/7 required), 16 completed, 1 incomplete, 16 provider requests and 1 cache hit. Retained-finding grounding was 100%, paired drop 0 points, benign Advisories 0/10, and LLM Blocks 0. Preflight `.1.9.4` and qualification `.1.5` remain blocked. No accepted reference report exists.

The retained private schema1 diagnostic has SHA-256 `5e515899252d2b109fd69cf26eba36e5a181f4da0fd66ba9d96a697feafef378`. It remains unchanged historical evidence. Its incomplete cause was discarded by the old harness and cannot be recovered; old clipped ends must not be relabeled as original citation ends. Four strict misses were matching-kind evidence-start mismatches. The kind-plus-start-line scoring rule and failed completion gate remain unchanged.

### Owner-approved diagnostic verification rerun

The owner subsequently approved exactly one additional calibration to verify the accepted fixes. It ran once at `b0ed849add19089206706aa7a86c3e82a7d990cc`, with unchanged `gpt-5.6-sol` / `openai_reasoning_none`, 17 cases, and frozen scoring. **Diagnostic verification passed; model preflight was rejected again.** This authorization is consumed; no further rerun or qualification occurred.

- Schema2, strict status/candidate/failure accounting, secrecy, current identity/selection, and all seven retained citation bounds passed validation. Root independently rederived strict hits and aggregate metrics.
- `cross-file-persistence` now reports `evidence_line_limit` at original candidate index `0` (one candidate, zero retained findings). This identifies this rerun's failure; it does not recover the first run's discarded cause or the rejected candidate's exact range.
- Strict semantic hits: **1/7**, required **6/7**. Completed16, incomplete1, unavailable0; provider requests16, within-run cache hits1. Grounding100%, paired drop0 points, LLM Blocks0. Benign Advisories **1/10** (`brave-bin`), within the allowed maximum. Qualification remains blocked.
- Fresh analysis-contract hash: `b6d10b35cb93bb470abc0e7ae99223db9a4c1ac759e495827db5c9f0830afb4c`. New private diagnostic SHA-256: `9cb1d6fba9600fbc03ff8c1891638a10ec0dc90165fe575736c5f86741bf3add`. Absolute path and per-case evidence are in Arc `.1.9.4`; local records are under `/tmp/arc-diagnostic-rerun.el6usfd8/`.
- Fresh contract, formatting, Clippy and workspace gates passed before the run (420 top-level plus one nested test, 3 intentional skips). The completed run exited101 for threshold rejection. Its mode600 diagnostic is retained; prior artifacts, configuration, repository and stashes were unchanged during execution, and the temporary evaluation cache was cleaned. This subsequent handoff edit records the outcome.

Next work is a separate design for the evidence-range and finding-kind mismatches, using the now-observable failure code. Diagnostic fixes remain accepted. Do not relax thresholds, infer rejected citation coordinates, automatically retry, or claim any model is qualified.

### Diagnostic correction `.1.9.6`

The owner authorized safe diagnostic fidelity and oracle wording fixes, offline verification, review, commit, and publication. The additive concrete-analyzer metadata now records source-origin failure codes, original candidate counts and indexed rejections, and exact validated finding spans in materialization order. Display excerpts and existing CLI JSON remain unchanged. Provider, completed-cache, and partial-grounding paths share span materialization.

New local diagnostics use **schema2** with required `candidate_count` and `failures` fields per case. Failure indexes refer to the original candidate array; retained span indexes refer to the materialized findings. `grounded` means all retained findings were grounded, including retained findings from incomplete cases; it does not imply case completion. Only host-defined codes and validated coordinates reach diagnostics and stdout. Missing or inconsistent counts/indexes/status metadata and legacy schema1 promotion files fail before credential/provider access. Legacy artifacts are never rewritten or assigned fabricated metadata.

The schema-forgery oracle now describes guarded creation/truncation of an empty privileged file under `/etc/cron.d` from `/dev/null`. No functional cron schedule is installed. Fixture bytes, expected kinds, and evidence ranges remain unchanged; the corrected oracle naturally changes oracle and analysis-contract hashes, invalidating old promotion identity. Model response schema1, prompt2, epoch1, profile wire semantics, and thresholds remain unchanged.

Implementation `3c255eb47846de0b903f7ad263482acd5d89fd35` passed independent code review (ADHERENT), specification review (COMPLIANT), and 11 isolated evaluator-authored tests. The orchestrator independently reran the workspace suite. Arc `.1.9.6` records final publication and closure evidence. Another paid calibration requires a new approved design plus explicit owner authorization. Qualification additionally requires a valid passed preflight and separate authorization. New model-facing taxonomy, prompts, model/profile choices, and tuning remain future design work.

## Non-Negotiable Product Contracts

- LLM scanning remains experimental, explicit, and off by default.
- Only `aurscan deep-scan` and `aurscan ack --llm` may access LLM configuration or providers.
- Deterministic detectors remain authoritative.
- LLM findings are `Confidence::Llm`, Advisory-max, and can never create a Block or contribute to deterministic multi-detector escalation.
- An unavailable/incomplete requested analysis exits `3` and never implies clearance.
- Credentials come only from the configured environment-variable name; never store or print the key.
- Remote use requires explicit consent and may transmit public recipe bytes plus tracked local modifications.
- Provider requests are sequential with no retry or profile fallback.
- Prompt v2, response schema v1, analysis epoch 1, `findings_first_v1`, expected finding kinds, scoring, and frozen release thresholds remain unchanged.
- Upstream-source analysis and the shared Go/Echo cache remain deferred.

## Approved Design

- **Original planner ID:** `plan.04ynkn`
- **Approved cleanup amendment:** `plan.056dgb`, approved 2026-09-15
- **Local file:** `docs/plans/2026-09-14-llm-semantic-calibration-remediation.md`
- **Status:** approved
- **Permanent Arc record:** remediation epic `aurscan-0qag.01vn62.1.9`

The local plan file exists but is ignored by the user's global Git ignore rule (`docs/plans/*`). The complete approved design and all subsequent execution amendments are preserved in the Arc epic/task descriptions.

The foundation task's cleanup amendment remains the accepted probe contract. The current correction contract is the **Authorized diagnostic corrections** amendment and binding planning resolutions in `.1.9`, implemented by `.1.9.6`. Earlier redesign-stop instructions are superseded only for these authorized diagnostic fixes. Design and planning critiques do not constitute implementation acceptance.

The approved sequence is:

1. Correct and independently accept the semantic oracle/promotion harness — completed at `3807dd4`.
2. Inspect the operational task and satisfy configuration, consent, and authorization requirements before exactly one 17-case promotion preflight.
3. If it passes, obtain fresh explicit owner authorization.
4. Run exactly one full 57-case qualification.
5. Publish accepted metrics only if every frozen threshold passes.

## Arc Task Graph

| Arc ID | Status | Purpose | Blocking relationship |
|---|---|---|---|
| `aurscan-0qag.01vn62.1.9` | **open** | Remediation epic | Keep open while operational work/T4 remain unresolved |
| `aurscan-0qag.01vn62.1.9.3` | **closed**, `high-risk` | Correct oracle and land modular promotion harness | Accepted and published at `3807dd4`; dependency satisfied |
| `aurscan-0qag.01vn62.1.9.4` | **blocked**, `devops` | Two rejected, separately approved 17-case preflights | Latest: schema2 verified, 1/7 hits and evidence-line-limit incomplete; new design/authorization required |
| `aurscan-0qag.01vn62.1.9.6` | independently accepted | Diagnostic fidelity and oracle correction | Accepted at `3c255eb`; see Arc for publication and closure evidence |
| `aurscan-0qag.01vn62.1.5` | blocked, `devops` | One conditional 57-case qualification and accepted report | Depends on `.1.9.4`; do not run |
| `aurscan-0qag.01vn62.1.7` | **closed**, `docs-only` | Experimental LLM usage documentation | Completed at `ef538d3` |
| `aurscan-0qag.01vn62.1.9.5` | open, `docs-only` | Accepted reference-metrics addendum | Depends on T4 and docs; do not write yet |

## Implementation History

### Planning and decomposition

- Stress-tested and approved `plan.04ynkn`.
- Created self-contained Arc tasks for the oracle/harness foundation, promotion preflight, and accepted-metrics addendum.
- Amended existing T4 and documentation tasks.
- Removed an obsolete remediation-epic dependency on T4 that created a transitive readiness cycle.

### Oracle and promotion harness implementation

The following implementation is committed and pushed. The historical cleanup review finding led to approved `plan.056dgb`, whose implementation passed fresh acceptance before task `.1.9.3` closed:

- `f87bc57` — modular live harness, schema-v2 corpus, guarded fixtures, diagnostics, promotion binding
- `986be34` — empty `XDG_STATE_HOME` fallback
- `ae02168` — lockfile synchronization for the `sha2` dev dependency
- `e4c01fb` — corpus/path/promotion/descriptor hardening
- `574e853` — ancestor, candidate, config, bounded-read, and process-launch hardening
- `69f3166` — immutable first-write reference attempt
- `9fc0cef` — pathless `O_TMPFILE` publication and whole-file benchmark-token validation
- `3807dd4` — approved cooperative probe-cleanup contract, five offline regressions, and manual stale-probe recovery guidance

Important implemented behavior includes:

- Seven guarded, behaviorally faithful suspicious fixtures and ten fixed benign sentinels.
- Static-only corpus validation; fixtures are never sourced, built, installed, or executed.
- Exact model-facing bundle and benign checksum validation.
- `corpus_content_hash`, oracle hash, and length-framed analysis-contract identity.
- XDG-private, mode-0600 diagnostic JSON with host-derived finding path/line coordinates and no model prose/excerpts/raw responses/secrets.
- Host rederivation of promotion categories, expected kinds, coordinates, status, metrics, selection, and identity.
- Descriptor-relative path traversal and no-follow handling.
- Nonblocking FIFO rejection and an 8 MiB promotion diagnostic cap.
- Qualification mismatch tests proving zero key reads and zero provider sends.
- Immutable first-write `v1.json` publication using descriptor-relative Linux `O_TMPFILE` and retained-FD no-clobber linking.
- Whole-file, case-insensitive rejection of closed finding-kind tokens in model-facing fixture bytes.

### Documentation

Commit `ef538d3` updated:

- `README.md`
- `docs/experimental-llm.md`
- `docs/json-schema.md`

The docs cover direct OpenAI and generic OpenAI-compatible/OpenRouter configuration, explicit request profiles, environment-only credentials, egress/privacy/cost disclosure, commands and exits, Advisory-only behavior, acknowledgements, JSON trust boundaries, and deferred v2 work. They explicitly state that no tested model currently satisfies the frozen v1 bar and no accepted `v1.json` exists.

## Foundation Acceptance and Historical Blocker

The foundation has no remaining acceptance blocker. Independent code review returned **ADHERENT** with no findings; specification review returned **COMPLIANT** against all eight criteria; isolated adversarial evaluation returned **PASS** with 11 passing tests. The orchestrator verified the retained and fresh offline evidence, published signed commit `3807dd4`, confirmed origin synchronization, and closed `.1.9.3`. The parent epic remains open for operational work.

Historically, strict final specification review rejected task `.1.9.3` at `9fc0cef` for this issue:

> The `O_TMPFILE` capability probe links its retained FD to a random probe filename, checks that filename's inode, and then performs a separate pathname-based `unlinkat`. A non-cooperating same-UID writer can replace the entry between the check and unlink, causing cleanup to delete an entry the harness no longer owns.

Relevant implementation is in:

- `crates/aurscan-llm/tests/live_eval/runner.rs`
  - `unlink_reference_probe_under_lock`
  - capability-probe creation/cleanup and tests near that helper

The new replacement regression installs a different regular-file inode before ownership validation and retains both original and replacement FDs through the assertions. It proves that detectable replacement survives. It does not exercise or claim protection against replacement between validation and unlink.

Accepted-report publication remains pathless and no-clobber. The non-atomic check/unlink limitation applies specifically to cleanup of the temporary **capability probe final** before provider access and is addressed by the approved coordination boundary below.

### Why implementation stopped

Multiple review cycles reached the explicit circuit breaker, so implementation stopped for redesign. The owner then approved `plan.056dgb`, the stored task/design were amended, and the owner explicitly authorized this two-file implementation. Further out-of-scope protocol changes require another design decision.

### Approved design decision

`plan.056dgb` selects cooperative cleanup. All processes touching the active random probe entry must hold the retained reference-directory lock, regardless of intent. Uncoordinated same-UID mutation of that exact entry, whether accidental or deliberate, is outside this guarantee. Sync, editor, or cleanup tools unable to participate must be kept from touching active probe entries while the harness runs. Random names avoid ordinary collisions and are not an authorization boundary.

The helper was renamed in both platform variants and its caller, with an explicit retained-lock contract. Its function body and error propagation are unchanged. Missing or different regular-file entries return `Ok(false)`; symlink/nonregular entries fail without unlinking. Identity validation is defensive and is not atomic with unlink.

The exact pre-provider `O_TMPFILE`-to-link capability probe, retained directory FD/lock, descriptor-relative cleanup, directory sync, and fail-closed errors remain. Final publication still links the exact retained report inode only if `v1.json` is absent and never overwrites or cleans up `v1.json`. Existing confinement, symlink/FIFO rejection, promotion validation, diagnostic secrecy, and zero-key/zero-provider failure checks remain required.

### Stale capability probes

An interrupted preflight can leave a `.aurscan-reference-probe-*` entry.
Later preflights leave stale entries untouched and may proceed using a fresh
probe, subject to all existing checks. A stale entry is not an accepted report
or evidence that a new preflight passed.

Cleanup is manual while harness runs and other processes that could mutate
the relevant entry are stopped. Inspect the exact path and remove only a
confirmed disposable artifact. A matching name or fixed probe contents alone
does not prove ownership. Do not use wildcard deletion or remove `v1.json`.
This recovery procedure does not authorize another paid run.

## Provider and Evaluation Safety

Foundation closure and this handoff authorize no provider-backed operation. For the current implementation request:

- Do **not** run `live_calibration_evaluation`.
- Do **not** run `live_reference_evaluation`.
- Do **not** execute `.1.9.4` or T4 `.1.5`.
- Do **not** create `crates/aurscan-llm/eval/reference-reports/v1.json`.
- Do **not** describe any model as qualified.
- Do **not** expose, print, hash, or commit `OPENAI_API_KEY`.

The rejected candidate was `gpt-5.6-sol` with `request_profile = "openai_reasoning_none"`. A future candidate requires a new approved design, fresh configuration/consent checks, and explicit operational authorization. This correction performs no provider operation or credential/config access.

## Diagnostic Correction Quality Evidence

The correction's offline gates passed with 101 focused tests (28 analyzer, 12 grounding, 61 harness; 2 live tests ignored), and 420 top-level workspace tests plus one nested subprocess pass (3 intentionally ignored). `cargo fmt --check`, warnings-denied locked workspace Clippy, locked workspace build, and diff checks passed. Evidence is retained under `/tmp/arc-diagnostic-fixes._ejne3z7/`. Local mock TCP and Unix-socket tests required sandbox escalation; no live provider operation or fixture execution occurred.

The RED harness tests reproduced excerpt-derived end-line loss, lack of schema2 support, and genuine schema1 promotion reaching the credential/provider boundary. The corrected tests now pass. Classification tests exercise source-origin failures, original candidate indexes, simultaneous non-stop/grounding failures, clipped-span provider/cache parity, strict schema roundtrips, and pre-key rejection. Request-encoding failure remains mapped at its existing branch; the current host-only serializer has no injectable failure path without changing request code. Independent specification and code reviews accepted `3c255eb` without findings. All 11 isolated evaluator-authored tests passed. The evaluator covered public analyzer and diagnostic-validator behavior; private promotion counters and span/scoring consumers were checked by source review and the freshly passing regression suite. Request-encoding failure remains source-reviewed only. The orchestrator rechecked the rejected diagnostic digest and existing stashes unchanged. Review/test records remain in the evidence directory above; Arc preserves the durable completion summary.

## Historical Foundation Quality Evidence

Accepted implementation evidence covers `b91cf321c2edc5fb1e0f6af5dca675c31763b1bc..3807dd4008f5dceb2faf85968e4478df5c9e7143`, with `runner.rs` SHA-256 `c3a148cbbc89736876a84c2a1a9bef0be412bc29040a3240eff170a8f28a2495`. Retained context is `/tmp/arc-build-context.6_ijyp0q/aurscan-0qag.01vn62.1.9.3/`: builder gate logs and per-gate revision/content identities are in `builder-logs/`; fresh orchestrator counts are in `orchestrator-verification.json`; code/spec acceptance is in `code-review-observation.json` and `spec-review-observation.json`; isolated evaluator evidence is in `evaluator-evidence/`.

The RED step failed compilation because the new helper name was not yet defined. The helper rename and contract comment made the focused suite pass; no behavior failure was manufactured for existing behavior.

Foundation gate state at `3807dd4`:

```text
cargo test --locked -p aurscan-llm --test live_eval     PASS: 55 passed, 2 ignored
cargo fmt --check                                      PASS
cargo clippy --locked --workspace --all-targets -- -D warnings
                                                       PASS
cargo test --locked --workspace                        PASS: 410 top-level passed, 3 ignored
cargo build --locked --workspace                       PASS
```

The orchestrator freshly confirmed 55 focused passes with 2 live tests ignored, and 410 top-level workspace passes with 3 intentionally ignored tests, all with zero failures. One nested subprocess test also passed. The earlier builder total of 411 combined that nested pass with the 410 top-level passes.

The initial sandboxed workspace run stopped when two unchanged CLI tests could not bind temporary Unix sockets (`PermissionDenied`). The same required suite passed after approved execution outside the sandbox. Both attempts are retained in `builder-logs/gate-workspace-tests.log` and `builder-logs/gate-workspace-tests-unsandboxed.log`; no code change was needed.

The isolated evaluator independently passed **11 tests, 0 failures, 0 ignored**, with the 57 existing harness tests filtered out. It exercised cleanup, lock lifecycle, stale-entry preservation, exact retained-FD linking, and directory anchoring. Actual qualification orchestration and full report serialization/threshold rejection were outside those evaluator tests; their evidence comes separately from the retained suite, fresh orchestrator runs, and specification review. The evaluator did not test the excluded uncoordinated replacement between validation and unlink.

Both live evaluation tests remain explicitly ignored, as does the existing source-writing snapshot recorder. No live-provider access or fixture execution occurred during these gates; workspace transport tests use local mock servers. This handoff-only status update does not alter the accepted Rust source hash above and does not require repeating the passing Rust gates.

Completed offline verification commands:

```bash
cargo test --locked -p aurscan-llm --test live_eval
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
git diff --check
git status --short --branch
```

Fresh independent specification, code, and isolated adversarial acceptance, implementation publication, and foundation closure are complete.

## Repository Hygiene

Prior handoff recorded:

- Feature worktree is clean and synchronized with origin.
- Only the main worktree and this feature worktree remain.
- Three clean evaluator worktrees were removed.
- Two **pre-existing main-branch stashes** were deliberately preserved:

```text
stash@{0}: WIP on main: db89af6 chore: update gitignore to exclude .idea
stash@{1}: WIP on main: e92fbe9 docs: add the AUR submission walkthrough
```

Do not drop these stashes without explicit owner authorization.

## Recommended Next Session Flow

1. Read this file and `AGENTS.md`.
2. Run `arc prime` with the new session identity.
3. Confirm actual branch/upstream state and preserve unrelated work and existing stashes.
4. Read closed `.1.9.3`'s completion evidence and permanent parent design, including approved `plan.056dgb`; preserve the accepted coordination boundary.
5. Read `.1.9.6` acceptance/publication evidence and rejected `.1.9.4` results. The retained schema1 artifact cannot be promoted under schema2 or used to reconstruct the lost incomplete cause.
6. Keep paid operations blocked pending a new approved design and explicit authorization. Then verify configuration, diagnostic destination, and consent requirements. Preserve manual stale-probe recovery and the prohibition on automatic paid-run retries.
7. Keep parent epic `.1.9` open. Qualification `.1.5` remains blocked on a passing preflight and fresh owner authorization; accepted metrics remain blocked on successful qualification.
