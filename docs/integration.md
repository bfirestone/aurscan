# paru & pacman Integration

This document describes how `aurscan` integrates with paru (AUR helper) and pacman (package manager) to gate package installation at multiple stages.

## Overview

`aurscan setup` configures two integration points:

1. **paru PreBuildCommand** — stage 1 packaging gate before the build
2. **pacman hook** (ALPM PreTransaction) — stage 3 gate (before package installation)

Together, they check packaging inputs before the build and built artifacts before installation. These checks do not sandbox the package manager or guarantee that no earlier helper operation has sourced a PKGBUILD.

## paru PreBuildCommand integration

### What it does

paru v2.1.0 (and later) supports a `PreBuildCommand` configuration in `paru.conf`. When set, paru runs this command in the PKGBUILD directory before `makepkg` executes each package, and also if the build is skipped as already-built.

`aurscan setup` adds this to your paru.conf:

```ini
[bin]
PreBuildCommand = /usr/bin/aurscan check --hook .
```

> **The `[bin]` section is mandatory.** paru reads `PreBuildCommand` only from
> `[bin]` (`man paru.conf`, BIN section). Placed under `[options]` — or any
> other section — paru **silently ignores it**: no warning, no error, and
> every AUR package builds unscanned while appearing configured. aurscan
> v0.1.0 shipped this bug; if you configured it by hand back then, check with
> `aurscan setup --check`.

The command scans packaging inputs in the current directory (stage 1). The `--hook` flag changes gating and prompt behavior; it does not fetch sources, invoke `makepkg --verifysource`, or run the source-analysis stage.

If findings Block, `aurscan` exits non-zero and paru aborts the build. If findings are Advisory and stdin is a terminal, the hook asks **Proceed with this build? [y/N]** on stderr — `y` continues, anything else aborts that build. Without a terminal (scripted updates, CI) it prints the findings and continues. See "Advisory findings in hook mode" below.

### paru.conf setup

```bash
aurscan setup          # prompts before changing anything
aurscan setup --yes    # non-interactive
aurscan setup --check  # report status only; exit 1 if the gate is inactive
```

Idempotent: re-running is safe.

`setup` also seeds a **newly created** user config with `Include = /etc/paru.conf`. paru resolves its config first-match-wins rather than merging (`$PARU_CONF` → `$XDG_CONFIG_HOME/paru/paru.conf` → `$HOME/.config/paru/paru.conf` → `/etc/paru.conf`), so creating a user config where none existed would otherwise silently disable your distro defaults — including `PgpFetch`, itself a security regression.

**Manual setup:** add the `[bin]` block above to `~/.config/paru/paru.conf`, then confirm with `aurscan setup --check`.

### Verifying the gate is live

The gate cannot be enabled by the package installer: it is per-user configuration, and `/etc/paru.conf` is owned by the paru package. Because a missing gate is otherwise invisible, the ALPM hook — which *is* installed automatically and runs on every pacman transaction — checks it and warns:

```
==> aurscan: no PreBuildCommand in paru.conf -- AUR builds are not scanned before makepkg runs
==> aurscan: run `aurscan setup` to enable pre-build scanning
```

The warning is advisory and never changes the transaction's exit status. A `PreBuildCommand` pointing at some *other* tool is reported but not warned about — that is a deliberate choice, not a misconfiguration.

### The scanned-commit ledger

Every name-based `check`/`install` scan records its outcome in
`~/.cache/aurscan/scanned_commits.json`: the pkgbase's git commit, the
verdict, and the ruleset version + detector epoch it was scanned under.

On the next scan of the same package, one `git ls-remote` round-trip fetches
the AUR's current HEAD. If that exact commit is recorded **Clean** at the
current ruleset + epoch, the clone and `makepkg --verifysource` are skipped —
that fetch is where a repeat scan's network and wall-clock cost live, and the
redb result cache cannot help there because content must be fetched before it
can be hashed. Any other recorded verdict, a moved commit, or a detector/
ruleset change falls through to the full fetch and scan. `--no-cache`
disables the skip.

The identity is deliberately the git commit, never `pkgname+pkgver`: nothing
forces a maintainer to bump pkgver when the PKGBUILD changes, `-git` packages
compute pkgver at build time, and "version stable while content changes" is
the orphan-adoption attack this tool exists to catch. Trusting `ls-remote` is
the same assumption as cloning from the same host. paru's own PreBuildCommand
still re-scans the actual cloned directory before every build, so a skip in
the name-based flow never bypasses the pre-build gate.

### Implementation notes

**Measured behavior (paru v2.1.0, verified 2026-07-27 in a clean container):**

| Behavior | Result |
| --- | --- |
| Non-zero exit aborts that package's build | **Yes.** paru exits 1 with `error: failed to run: sh -c <cmd>`; nothing is built or installed. |
| Runs in the PKGBUILD directory | **Yes.** cwd is the clone dir, with `PKGBUILD` present. |
| Runs even when the build is skipped as already-built | **Yes.** |
| Also covers local `paru -U` builds | **Yes.** |
| TTY is inherited | **Partly, and not usefully.** Under a real PTY the hook sees stdin as a TTY but **stdout is not** — paru captures it. |

**Advisory findings in hook mode:**
An Advisory prompts **[y/N]** when stdin is a terminal. The prompt is written to stderr and the tty test is stdin-only, because of the TTY situation above: paru captures the hook's stdout but hands it the terminal on stdin, so a stdout-gated prompt would never fire. Declining aborts that build with exit 1. Without a terminal the findings print and the build proceeds — aborting unattended runs is exactly the `-Syyu`-killed-by-one-advisory failure this replaced. Only Block aborts unconditionally.

An earlier gate exited 1 on every Advisory, which paru treats as failure: one Medium finding on one package (observed: `1password`, `eval` of a heredoc in `package()`) aborted a whole 27-package upgrade with the report unhelpfully headed `.:` (fixed: reports are named from the PKGBUILD's `pkgname`).

To silence a reviewed Advisory permanently, run `aurscan ack <package>` (it resolves the recipe and the built artifact by bare name and records both after a y/N confirm; `--yes` for scripts), or scan directly with `aurscan check <package>` outside the hook.

**Multi-package builds:**
`paru -S pkg1 pkg2 pkg3` runs PreBuildCommand per package, but the **first** failure aborts the whole transaction — remaining packages are neither scanned nor built. Verified with `paru -S worktrunk-bin 1password-cli` failing on the first: paru exited 1 and the second package was never touched. This is fail-closed, which is the safe direction, but it is not independent per-package gating.

**`makepkg --verifysource` with VCS sources** (e.g. `-git` packages) fetches without executing the full build. This one is inherited from the original design and has **not** been re-verified empirically; treat it as a design assumption rather than a measured result.

## Scan-input and source-analysis boundary

`aurscan_core::target::scan_input_inventory` is shared by local directory checks,
the paru hook, and the fetch/scan pipeline. It separates packaging targets,
explicit materialized source targets, and generated content. It never sources a
PKGBUILD to discover inputs.

- Root-level `src/` and `pkg/` are excluded from packaging analysis, except for
  explicitly Git-tracked files. Untracked helpers elsewhere remain eligible.
- Discovery reads the scan-root Git index, supports `.git` files and linked
  worktrees, removes ambient Git environment overrides, and prunes `.git`
  traversal. A repository discovery error is reported instead of silently
  discarding tracked-file protection. Without Git metadata, conventional build
  directory exclusions apply.
- Fetch-supplied URL/VCS source paths are matched by full relative path, so a
  downloaded `upstream.sh` does not hide `helpers/upstream.sh`. Tracked files and
  essential packaging files retain packaging checks. Explicit source targets
  retain source-detector routing even when also scanned as packaging.
- Fetch discovery's `LocalFile` origin does not establish an upstream download;
  local helpers keep packaging checks as well as their existing source routing.
- Generated content is excluded from this packaging stage, not declared safe.
  Explicit file scans remain available, including files inside `src/` or `pkg/`.

The current source stage runs source-capable detectors on the files supplied by
the fetch pipeline. It does not reconstruct build execution, recursively unpack
all source archives, or classify every upstream script's execution context. A
future source-analysis stage can reuse the inventory boundary without applying
packaging assumptions to arbitrary generated test/runtime scripts.

Redirect findings distinguish reads from filesystem writes using Bash AST
operators. Input redirects and descriptor duplication are not writes; output,
append, clobber, combined output, and read/write redirects retain system-path
checks. Commands nested inside redirects are still analyzed.

Result-cache identity includes content, target kind/path/source origin or archive
member, and full package scan context (name, version, AUR metadata), plus ruleset
version and detector epoch. Identical bytes at a different path or in a different
package cannot inherit cached evidence or classification. Detector epoch 6
invalidates earlier results, including the clean-commit fetch ledger.

## pacman hook integration

### What it does

The ALPM pacman hook at `/usr/share/libalpm/hooks/aurscan.hook` runs `aurscan scan-artifact --hook` on every package install/upgrade transaction (PreTransaction stage).

The hook:
- Runs before pacman modifies the filesystem
- Reads the target package *names* from stdin (`Type = Package` hooks receive
  names, never archive paths, regardless of how the install was invoked)
- Skips names found in the sync repos (one batched `LC_ALL=C pacman -Si`
  query, read-only): pacman already verified their signatures, and scanning
  every repo upgrade made a full `-Syu` crawl. A summary line reports the
  skip count. If the query cannot run, everything is treated as foreign —
  the failure direction is scan-too-much, never skip-a-foreign-package.
- Resolves each remaining (foreign) name to a built `.pkg.tar.zst`: pacman's
  download cache (`/var/cache/pacman/pkg/`), then the invoking user's paru
  clone cache (`~/.cache/paru/clone/`, via `SUDO_USER` — AUR builds installed
  with `pacman -U` never enter pacman's cache), then `PKGDEST` from
  makepkg.conf. Several cached versions resolve to the newest build.
- Warns visibly when a *foreign* package resolves nowhere (it was not
  scanned); an unresolved repo package is unremarkable, pacman verified its
  signature
- Scans resolved archives for payload hashes, setuid bits, suspicious archive
  layout
- Exits non-zero only on a Block verdict, aborting the transaction. Advisory
  findings print and the install proceeds (same contract as the paru gate);
  scan errors also proceed, so an aurscan defect cannot brick unrelated
  transactions

This is the stage 3 gate: it catches compromises that occurred during build but after PKGBUILD execution (e.g., build environment compromise, binary hijacking).

### Hook location

The AUR package installs the hook to `/usr/share/libalpm/hooks/aurscan.hook`, the **package-owned** hook directory. pacman reads it for all transactions and updates the file on package upgrade.

For cargo-install users (no package to deliver the file), `aurscan setup` installs the same hook to `/etc/pacman.d/hooks/aurscan.hook`, the **admin-owned** hook directory. When run without root it prints the command to do so. Only one of the two locations should hold the hook: pacman reads both, and a copy in each would run the scan twice per transaction. `setup` therefore skips the `/etc` install when the package-owned hook exists.

### Hook file

The hook is defined in `data/aurscan.hook` (checked into the repository, also installed by the AUR package):

```ini
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = *

[Action]
Description = Scanning packages for known AUR malware...
When = PreTransaction
Exec = /usr/bin/aurscan scan-artifact --hook
NeedsTargets
AbortOnFail
```

**Fields:**
- `Trigger` — fires on all Install and Upgrade operations
- `When = PreTransaction` — runs before pacman touches the filesystem
- `Exec = /usr/bin/aurscan scan-artifact --hook` — runs aurscan in hook mode (reads from stdin)
- `NeedsTargets` — pacman provides the list of packages being installed
- `AbortOnFail` — non-zero exit aborts the transaction

### Helper-agnostic protection

The hook is installed by the aurscan AUR package and runs for **all** package operations, regardless of which AUR helper (paru, yay, etc.) invoked pacman. This protects yay users (whose helper does not have PreBuildCommand support) and manual `pacman -U` operations.

## Workflow diagram

```text
User: paru -S firefox aspell-en
│
├─ paru resolves AUR tree (RPC)
├─ paru clones PKGBUILDs to ~/.cache/paru/clone/
│
├─ [paru PreBuildCommand per package]
│  ├─ firefox: aurscan check --hook .
│  │  ├─ stage 1: scan PKGBUILD (tree-sitter-bash AST, ioc_tokens, etc.)
│  │  ├─ verdict: clean → continue
│  │
│  ├─ aspell-en: aurscan check --hook .
│  │  ├─ stage 1, 2: ...
│  │  ├─ verdict: advisory → prompt user y/N
│  │  ├─ user allows → continue
│
├─ paru runs makepkg for each PKGBUILD (builds firefox-*.pkg.tar.zst, aspell-en-*.pkg.tar.zst)
│
├─ paru calls pacman -U firefox-*.pkg.tar.zst aspell-en-*.pkg.tar.zst
│  │
│  ├─ [ALPM PreTransaction hook]
│  │  ├─ aurscan scan-artifact --hook (reads from stdin)
│  │  ├─ stage 3: scan archive members (payload_hashes, elf_inspect, archive_layout, etc.)
│  │  ├─ firefox: clean → allow
│  │  ├─ aspell-en: advisory → print findings, allow
│  │  ├─ hook exits: if any Block → abort transaction, otherwise allow
│  │
│  ├─ [pacman installs packages]
```

## Verdict logic & interactive prompts

### Text output (interactive, TTY)

When running interactively (with a TTY), findings are printed to stdout and the user is prompted:

```text
firefox: CLEAN

aspell-en: ADVISORY
  [HIGH] Source URL uses shortener; cannot verify upstream authenticity
    ↳ PKGBUILD:8 (https://bit.ly/2kL9sP)

Proceed with install? [y/N]
```

- **Clean** → no prompt, continue
- **Advisory** → prompt y/N (allow → continue, deny → abort)
- **Block** → no prompt, abort

### Non-TTY / --json (CI, cron, scripted)

When stdout is not a TTY or `--json` is used, no interactive prompt occurs:

- **Clean** → exit 0
- **Advisory** → exit 1 (caller must decide)
- **Block** → exit 2 (caller must interpret as error)

Useful for CI pipelines and automated scans:

```bash
aurscan check $PACKAGES --json > scan.json
EXITCODE=$?
if [ $EXITCODE -eq 2 ]; then
  echo "Build blocked by security findings" >&2
  exit 1
fi
```

## Acknowledged findings

Users can acknowledge specific findings to suppress re-alerts for the same content. Acknowledgements are stored in `~/.config/aurscan/acknowledged.toml` and keyed by `(package, detector_id, evidence_hash)`.

Example:

```toml
# Acknowledged findings are suppressed from text output but still recorded in JSON

[[acks]]
package = "aspell-en"
detector = "source_provenance"
evidence_hash = "abc123..."  # SHA256(location + excerpt)
reason = "Reviewed and acceptable"
acknowledged_at = "2026-07-07T12:34:56Z"
```

To acknowledge a finding interactively:

```bash
aurscan check aspell-en
# Output shows a finding...
# Prompt: "Acknowledge this finding? [y/N]"
# User answers "y" → finding is added to acknowledged.toml
```

To remove acknowledgements:

```bash
rm ~/.config/aurscan/acknowledged.toml  # Clear all
# OR edit the file manually
```

Acknowledgements auto-expire when the evidence changes (e.g., a URL is fixed, a binary is rebuilt), so re-alerts trigger for the updated package.

## Caveats & known limitations

### Advisory prompts in hook mode

The paru hook prompts for advisories when stdin is a terminal; it writes the
prompt to stderr because paru captures stdout. In unattended mode advisories
proceed. The ALPM hook does not prompt.

The practical consequence: **Block aborts the build; Advisory prompts [y/N] at a terminal and proceeds unattended.** There is no interactive override for a Block at the hook. Use `aurscan ack <package>` to acknowledge advisories — acks survive version bumps and expire when the matched content changes, or `aurscan install --allow` for a Block you have judged safe.

### VCS sources (-git packages)

The paru hook scans the PKGBUILD and local packaging helpers. It does not fetch
or recursively audit VCS source trees. Name-based `check` and `install` use a
separate fetch pipeline and scan the materialized source files that pipeline
returns. `makepkg --verifysource` sources PKGBUILD code, so fetching is not an
execution isolation boundary. Comprehensive, execution-aware upstream source
analysis remains follow-up work.

### Recursive dependencies

If package A depends on package B (both AUR), paru installs B first, then A. Each runs through PreBuildCommand + ALPM hook independently. There is no cross-package verdict (verdict is per-package), so you can allow A but block B.

### Non-AUR packages

The hook filters to foreign (AUR-installed) packages via the pacman database. Native repository packages (core, extra, community) are not scanned, as they are cryptographically signed by Arch maintainers.

If you wish to audit non-AUR packages, use `aurscan audit` manually.

## Troubleshooting

### "PreBuildCommand not found" error

Ensure paru v2.1.0 or later is installed. Check `paru --version` and `man paru.conf` for PreBuildCommand documentation.

If upgrading paru, re-run `aurscan setup` to restore the configuration (paru may overwrite paru.conf during upgrade).

### Hook not triggering on pacman -U

Verify the hook file is installed:

```bash
ls -la /usr/share/libalpm/hooks/aurscan.hook
```

If missing, re-run `sudo aurscan setup` or reinstall the aurscan AUR package.

### Scanning isn't happening at all

Most often the `PreBuildCommand` is in the wrong paru.conf section, or a user config is shadowing the one you edited. Diagnose with:

```bash
aurscan setup --check
```

It reports which of these applies and exits non-zero when the gate is inactive:

- `PreBuildCommand is under [options], but paru only reads it from [bin]` — move it
- `no PreBuildCommand in paru.conf` — run `aurscan setup`
- `no paru config found` — run `aurscan setup`

Remember that paru reads only the **first** config it finds, so a `~/.config/paru/paru.conf` makes `/etc/paru.conf` irrelevant.

### Prompts don't appear in the hook

The paru hook prompts only when stdin is a terminal. The ALPM hook does not prompt. See "Advisory prompts in hook mode" above.

For an interactive flow, use the `aurscan install` wrapper, which runs in the foreground.

### Override a blocked package

`--allow` is a flag on `install` (not on `check`):

```bash
aurscan install aspell-en --allow aspell-en
```

This overrides Block verdicts for the named package. It is an explicit allow-list and works regardless of TTY — including under `--json` and in scripts.

## Security notes

- The scanner itself is distributed via the AUR — verify the first install manually (inspect the PKGBUILD source).
- The hook runs unprivileged for stages 1–3; system audit (stage 4) may require elevated privileges.
- Cache identity hashes content, target identity, and scan context. Cache entries are not signed or authenticated.
- Acknowledged findings are never silently dropped; they are logged and summarized in text output ("N findings acknowledged").
