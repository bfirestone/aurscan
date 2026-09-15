# LLM Integration Handoff

**Last updated:** 2026-09-15  
**Repository:** `aur_package_scanner`  
**Branch:** `feat/add-llm-integration`  
**Implementation base:** `b91cf321c2edc5fb1e0f6af5dca675c31763b1bc`\
**Review/publication:** cooperative cleanup amendment awaits fresh independent acceptance and publication

## Start Here

In a new Pi session:

```text
Read AGENTS.md and HANDOFF.md completely. Run `arc prime` using the new
session's own session ID. Do not run any provider-backed calibration or
qualification. Read the Current Execution Amendment in Arc task
aurscan-0qag.01vn62.1.9.3 and approved plan.056dgb in permanent parent design
aurscan-0qag.01vn62.1.9. The two-file implementation is ready for fresh
independent specification, code, and adversarial review under the approved
cooperative cleanup boundary. Check actual review and publication evidence
before closing the foundation task.
```

Useful commands:

```bash
git status --short --branch
git log -12 --oneline
arc show aurscan-0qag.01vn62.1.9.3
arc show aurscan-0qag.01vn62.1.9
arc plan show plan.04ynkn
arc plan show plan.056dgb
arc blocked
```

Do not copy the previous session ID into a new worker. Let the new harness provide its own identity when claiming work.

## Current Outcome

The client-only experimental LLM integration is implemented through CLI E2E coverage and user documentation. The approved `plan.056dgb` cooperative cleanup amendment is implemented in `runner.rs` and this handoff, but the semantic-promotion foundation is **awaiting independent implementation acceptance**.

The probe's identity check and pathname unlink remain separate. Every same-account process touching the active probe entry must coordinate through the retained directory lock, regardless of intent. Accidental and deliberate uncoordinated mutation of that exact entry is outside the cleanup guarantee; unrelated files and all other safeguards remain covered.

The five new offline regressions cover lock release/reacquisition, a regular-file replacement installed before validation, missing entries, symlink/directory rejection, and stale-probe preservation. Fresh implementation review and publication remain pending. No provider-backed calibration or qualification was run in this session, and no accepted reference report exists.

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

The foundation task's **Current Execution Amendment** is the current two-file implementation contract. Earlier broad file lists and redesign-stop instructions remain history; the owner authorized this implementation after the cleanup design was approved. Design and planning critiques do not constitute implementation acceptance.

The approved sequence is:

1. Correct and independently accept the semantic oracle/promotion harness.
2. Run exactly one 17-case promotion preflight.
3. If it passes, obtain fresh explicit owner authorization.
4. Run exactly one full 57-case qualification.
5. Publish accepted metrics only if every frozen threshold passes.

## Arc Task Graph

| Arc ID | Status | Purpose | Blocking relationship |
|---|---|---|---|
| `aurscan-0qag.01vn62.1.9` | open | Remediation epic | Keep open while foundation/T4 remain unresolved |
| `aurscan-0qag.01vn62.1.9.3` | **in progress; independent acceptance pending**, `high-risk` | Correct oracle and land modular promotion harness | Blocks `.1.9.4` |
| `aurscan-0qag.01vn62.1.9.4` | open, `devops` | One paid 17-case promotion preflight | Depends on `.1.9.3`; do not run |
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

The following prior implementation is committed and pushed. Its final cleanup review finding led to approved `plan.056dgb`; task `.1.9.3` still requires fresh acceptance of the current amendment:

- `f87bc57` — modular live harness, schema-v2 corpus, guarded fixtures, diagnostics, promotion binding
- `986be34` — empty `XDG_STATE_HOME` fallback
- `ae02168` — lockfile synchronization for the `sha2` dev dependency
- `e4c01fb` — corpus/path/promotion/descriptor hardening
- `574e853` — ancestor, candidate, config, bounded-read, and process-launch hardening
- `69f3166` — immutable first-write reference attempt
- `9fc0cef` — pathless `O_TMPFILE` publication and whole-file benchmark-token validation

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

## Exact Remaining Blocker

Fresh independent specification, code, and isolated adversarial acceptance of the current two-file amendment, followed by publication, remain required before `.1.9.3` can close.

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

Until `.1.9.3` is accepted and closed:

- Do **not** run `live_calibration_evaluation`.
- Do **not** run `live_reference_evaluation`.
- Do **not** execute `.1.9.4` or T4 `.1.5`.
- Do **not** create `crates/aurscan-llm/eval/reference-reports/v1.json`.
- Do **not** describe any model as qualified.
- Do **not** expose, print, hash, or commit `OPENAI_API_KEY`.

The intended candidate remains revision-pinned `gpt-5.6-sol` with `request_profile = "openai_reasoning_none"`, but a future run still requires fresh configuration/key/consent checks and explicit authorization.

## Last Fresh Quality Evidence

Current implementation evidence is based on `b91cf321c2edc5fb1e0f6af5dca675c31763b1bc`, with `runner.rs` SHA-256 `c3a148cbbc89736876a84c2a1a9bef0be412bc29040a3240eff170a8f28a2495`. Full gate logs and per-gate revision/content identities are retained in `/tmp/arc-build-context.6_ijyp0q/aurscan-0qag.01vn62.1.9.3/builder-logs/`.

The RED step failed compilation because the new helper name was not yet defined. The helper rename and contract comment made the focused suite pass; no behavior failure was manufactured for existing behavior.

Current gate state:

```text
cargo test --locked -p aurscan-llm --test live_eval     PASS: 55 passed, 2 ignored
cargo fmt --check                                      PASS
cargo clippy --locked --workspace --all-targets -- -D warnings
                                                       PASS
cargo test --locked --workspace                        PASS: 411 passed, 3 ignored
cargo build --locked --workspace                       PASS
```

The initial sandboxed workspace run stopped when two unchanged CLI tests could not bind temporary Unix sockets (`PermissionDenied`). The same required suite passed after approved execution outside the sandbox. Both attempts are retained in `gate-workspace-tests.log` and `gate-workspace-tests-unsandboxed.log`; no code change was needed.

Both live evaluation tests remain explicitly ignored, as does the existing source-writing snapshot recorder. No live-provider access or fixture execution occurred during these gates; workspace transport tests use local mock servers. Independent implementation reviews remain pending. Subsequent handoff-only evidence updates do not alter the tested Rust source hash above.

Required offline verification commands:

```bash
cargo test --locked -p aurscan-llm --test live_eval
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
git diff --check
git status --short --branch
```

Then run fresh Arc spec review, code review, and isolated adversarial evaluation before closing `.1.9.3`.

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
4. Read `.1.9.3`'s Current Execution Amendment and permanent parent design, including approved `plan.056dgb`.
5. Review the two-file implementation and its revision-bound offline evidence; obtain fresh independent specification, code, and isolated adversarial acceptance under the stated cooperative boundary.
6. If acceptance passes, publish and verify the reviewed commit, record actual evidence, and close only the foundation task. Keep it unaccepted if any required review fails; do not widen the exclusion to waive findings.
7. Do not progress to `.1.9.4` until `.1.9.3` has fresh independent acceptance and is formally closed. Operational work retains its separate configuration, consent, and authorization gates.
