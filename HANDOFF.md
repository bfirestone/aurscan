# LLM Integration Handoff

**Last updated:** 2026-09-15  
**Repository:** `aur_package_scanner`  
**Branch:** `feat/add-llm-integration`  
**Functional/docs HEAD before this handoff file:** `ef538d33bbb47bca4c156c64222c5237026f823c`  
**Remote:** `origin/feat/add-llm-integration` is synchronized

## Start Here

In a new Pi session:

```text
Read AGENTS.md and HANDOFF.md completely. Run `arc prime` using the new
session's own session ID. Do not run any provider-backed calibration or
qualification. Inspect Arc task aurscan-0qag.01vn62.1.9.3 and approved plan
plan.04ynkn, then use /arc-brainstorm to resolve the capability-probe cleanup
threat model before changing the promotion harness.
```

Useful commands:

```bash
git status --short --branch
git log -12 --oneline
arc show aurscan-0qag.01vn62.1.9.3
arc show aurscan-0qag.01vn62.1.9
arc plan show plan.04ynkn
arc blocked
```

Do not copy the previous session ID into a new worker. Let the new harness provide its own identity when claiming work.

## Current Outcome

The client-only experimental LLM integration is implemented through CLI E2E coverage and user documentation, but the new semantic-promotion foundation is **not acceptance-complete**. One filesystem race remains in a pre-provider capability probe.

The branch is clean, committed, pushed, and synchronized. No provider-backed calibration or qualification was run in this session, and no accepted reference report exists.

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

- **Planner ID:** `plan.04ynkn`
- **Local file:** `docs/plans/2026-09-14-llm-semantic-calibration-remediation.md`
- **Status:** approved
- **Permanent Arc record:** remediation epic `aurscan-0qag.01vn62.1.9`

The local plan file exists but is ignored by the user's global Git ignore rule (`docs/plans/*`). The complete approved design and all subsequent execution amendments are preserved in the Arc epic/task descriptions.

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
| `aurscan-0qag.01vn62.1.9.3` | **blocked**, `high-risk` | Correct oracle and land modular promotion harness | Blocks `.1.9.4` |
| `aurscan-0qag.01vn62.1.9.4` | open, `devops` | One paid 17-case promotion preflight | Depends on `.1.9.3`; do not run |
| `aurscan-0qag.01vn62.1.5` | blocked, `devops` | One conditional 57-case qualification and accepted report | Depends on `.1.9.4`; do not run |
| `aurscan-0qag.01vn62.1.7` | **closed**, `docs-only` | Experimental LLM usage documentation | Completed at `ef538d3` |
| `aurscan-0qag.01vn62.1.9.5` | open, `docs-only` | Accepted reference-metrics addendum | Depends on T4 and docs; do not write yet |

## Completed in the Latest Session

### Planning and decomposition

- Stress-tested and approved `plan.04ynkn`.
- Created self-contained Arc tasks for the oracle/harness foundation, promotion preflight, and accepted-metrics addendum.
- Amended existing T4 and documentation tasks.
- Removed an obsolete remediation-epic dependency on T4 that created a transitive readiness cycle.

### Oracle and promotion harness implementation

The following implementation is committed and pushed, but task `.1.9.3` remains blocked by the final review finding below:

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

Strict final specification review rejected task `.1.9.3` at `9fc0cef` for one remaining issue:

> The `O_TMPFILE` capability probe links its retained FD to a random probe filename, checks that filename's inode, and then performs a separate pathname-based `unlinkat`. A non-cooperating same-UID writer can replace the entry between the check and unlink, causing cleanup to delete an entry the harness no longer owns.

Relevant implementation is in:

- `crates/aurscan-llm/tests/live_eval/runner.rs`
  - `unlink_reference_probe_if_owned`
  - capability-probe creation/cleanup and tests near that helper

The current regression proves unrelated files survive, but it does not replace the exact probe path between ownership validation and unlink.

The accepted-report publication itself is pathless and no-clobber. The unresolved race is specifically cleanup of the temporary **capability probe final** before any provider access.

### Why implementation stopped

Multiple review cycles reached the explicit circuit breaker. The owner authorized one final simplification and directed that any further fix-required result stop for redesign. The task was therefore marked blocked and no additional code change was attempted.

### Design decision required

Use `/arc-brainstorm`; do not silently choose. The core question is whether a non-cooperating process running as the same Unix UID is inside the capability-probe cleanup threat model.

Possible directions to evaluate:

1. **Cooperative same-UID boundary:** treat the retained directory lock plus random probe name as sufficient for local test harness operations, explicitly excluding malicious same-UID mutation.
2. **Weaker preflight:** prove descriptor-relative `O_TMPFILE` creation before provider access but allow the final retained-FD link operation itself to fail closed after a paid run.
3. **Persistent capability marker:** avoid cleanup races by retaining an explicitly managed marker, while addressing repository cleanliness and provenance.
4. **Different kernel isolation:** find a practical unprivileged Linux mechanism that exercises the exact target filesystem/link operation without requiring pathname cleanup.

Do not resume implementation until one option is approved and the Arc task/design is amended.

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

At current code/docs state:

```text
cargo fmt --check                                      PASS
cargo clippy --locked --workspace --all-targets -- -D warnings
                                                       PASS
cargo test --locked --workspace                        PASS
cargo build --locked --workspace                       PASS
```

Latest workspace test total after the pathless simplification:

```text
405 passed, 3 intentionally ignored
```

Latest focused live harness result:

```text
50 passed, 2 explicitly ignored live tests
```

No provider/network access or fixture execution occurred during those gates.

Recommended verification after any approved redesign:

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

At handoff creation:

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
3. Confirm branch/upstream cleanliness.
4. Inspect `.1.9.3`, its final blocker, and `plan.04ynkn`.
5. Invoke `/arc-brainstorm` for the capability-probe cleanup threat-model decision.
6. Register and approve any design amendment before implementation.
7. If implementation is authorized, keep it limited to the approved harness files and run only offline tests.
8. Do not progress to `.1.9.4` until `.1.9.3` has fresh independent acceptance and is formally closed.
