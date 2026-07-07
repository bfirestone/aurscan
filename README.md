# aurscan

Read-only scanner for the **June 2026 "atomic-lockfile" AUR supply-chain attack**
([aur-general thread](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/)).

Attackers adopted hundreds of orphaned AUR packages (2026-06-09 → 06-12) and
injected the rogue Node packages `atomic-lockfile` (npm) / `js-digest` (bun),
whose preinstall hook drops an ELF infostealer + eBPF rootkit. **Official Arch
repos were not affected — only AUR (foreign) packages.**

## Usage

```bash
./aurscan.py                 # scan this system (uses bundled 512-name list)
./aurscan.py --fetch-list    # also pull the live consolidated list before scanning
./aurscan.py --json          # machine-readable output
./aurscan.py --root /mnt     # scan an offline image / mounted disk
sudo ./aurscan.py            # also reads other users' caches + root-owned artifacts
```

Exit code is `1` if anything MEDIUM-or-worse is found, `0` otherwise — so it
works as a cron / pre-update gate. INFO findings (e.g. "installed during the
attack window") never fail the exit code; they are review hints only.

## What it checks (strongest signal first)

| Signal | Severity | Source |
|---|---|---|
| Malware ELF on disk matches a known payload SHA256 | CRITICAL | `iocs.txt` hashes |
| Cached `PKGBUILD`/`.install` contains `atomic-lockfile`/`js-digest` | CRITICAL | content scan |
| Installed foreign package is on the confirmed-compromised list | CRITICAL | `known_bad_packages.txt` (512 names) |
| `/sys/fs/bpf/hidden_*` eBPF rootkit pin present | CRITICAL | host artifact |
| Malicious npm/bun package in `~/.npm` / `~/.bun` cache | HIGH | cache scan |
| Foreign package installed/upgraded during the attack window | INFO | local pacman DB `%INSTALLDATE%` |

## Files

- `aurscan.py` — the scanner (stdlib only, no dependencies).
- `known_bad_packages.txt` — bundled offline list, consolidated from
  [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check).
  Refresh it with `--fetch-list` or replace via `--list-file`.

## If it finds something

1. Don't trust the flagged package(s).
2. Inspect the cited PKGBUILD evidence.
3. Rotate secrets the infostealer targets: SSH keys, browser sessions/cookies,
   Discord/Slack/Telegram tokens, API tokens.
4. A CRITICAL **host artifact** (payload on disk / eBPF pin) implies full
   compromise — isolate and rebuild rather than clean in place.
