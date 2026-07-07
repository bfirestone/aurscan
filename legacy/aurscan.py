#!/usr/bin/env python3
"""
aurscan — scan an Arch Linux system for AUR packages compromised in the
June 2026 "atomic-lockfile" supply-chain attack.

Background
----------
Between 2026-06-09 and 2026-06-12, attackers adopted hundreds of orphaned AUR
packages and pushed malicious commits that injected the rogue Node packages
`atomic-lockfile` (npm) and `js-digest` (bun) into PKGBUILDs. Their preinstall
hooks drop an ELF that deploys an infostealer + eBPF rootkit. Official Arch
repositories were NOT affected — only AUR (foreign) packages.

Reference thread:
  https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/
Community IOC consolidation:
  https://github.com/lenucksi/aur-malware-check

This tool is read-only. It does NOT remove packages or modify your system; it
reports findings and exits non-zero if anything actionable is found, so it can
gate CI / cron / pre-update hooks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- #
# Indicators of compromise (IOCs)
# --------------------------------------------------------------------------- #
# The attack window during which malicious commits were pushed. Foreign
# packages installed OR upgraded inside this window warrant scrutiny even if
# their name is not (yet) on the published list.
ATTACK_WINDOW_START = datetime(2026, 6, 9, 0, 0, tzinfo=timezone.utc)
ATTACK_WINDOW_END = datetime(2026, 6, 13, 0, 0, tzinfo=timezone.utc)

# Substrings that, if present in a PKGBUILD/.install/.SRCINFO, are damning.
# These are the malicious npm/bun packages and how they get invoked.
MALICIOUS_CONTENT_TOKENS = (
    "atomic-lockfile",
    "js-digest",
    "npm install atomic-lockfile",
    "bun install js-digest",
)

# Confirmed-compromised package names pulled from the aur-general thread.
# This is a SMALL embedded fallback. The authoritative, growing list lives in
# the community repo and is fetched at runtime via --fetch-list (recommended).
EMBEDDED_KNOWN_BAD = {
    "runescape-launcher",
    "oracle-bin",
    "tesseract-gui",
    "python-starsessions",
    "python-sklearn-pandas",
    "python-pymilvus",
    "python-pluginmgr",
    "python-jsmin",
    "python-pychromecast-git",
    "cling-git",
}

# SHA256 of the dropped ELF payloads. A file hash match is the single highest-
# confidence signal in this whole tool: it means the actual malware binary is
# sitting on disk, independent of any package name or list.
KNOWN_PAYLOAD_SHA256 = {
    "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b":
        "atomic-lockfile ELF payload (deps)",
    "7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316":
        "js-digest ELF payload",
    "47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204":
        "atomic-lockfile cryptominer variant",
}

# Locations where the payload / its package cache is known to land. Scanned for
# both the content tokens and the payload hashes above.
PAYLOAD_HUNT_DIRS = (
    "~/.npm/_cacache",
    "~/.bun/install/cache",
    "/var/lib",
)

# Default source for the full consolidated package list (one name per line,
# '#' comments allowed). Override with --list-url or --list-file.
DEFAULT_LIST_URL = (
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/main/package_list.txt"
)

# Bundled offline copy of the consolidated list, shipped next to this script so
# the scanner has strong coverage with no network access.
BUNDLED_LIST_FILE = "known_bad_packages.txt"

# Filesystem artifacts the post-exploitation payload is known to leave behind.
HOST_ARTIFACT_GLOBS = (
    ("/sys/fs/bpf", "hidden_*"),  # eBPF rootkit pin points
)

# Directories AUR helpers cache cloned PKGBUILDs in. We scan these for the
# malicious content tokens. Expanded per-user at runtime.
AUR_CACHE_DIRS = (
    "~/.cache/yay",
    "~/.cache/paru/clone",
    "~/.cache/aurutils",
    "~/.cache/pikaur/aur_repos",
    "/var/cache/pacman/aur",
)

SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    severity: str  # CRITICAL | HIGH | MEDIUM | INFO
    package: str  # package name, or "<host>" for system-level artifacts
    reason: str  # human-readable explanation
    evidence: str = ""  # path, matched line, commit, etc.


@dataclass
class ForeignPackage:
    name: str
    version: str
    install_date: datetime | None = None
    pkgbuild_paths: list[Path] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# System inspection (read-only)
# --------------------------------------------------------------------------- #
def read_local_db(db_root: Path) -> list[ForeignPackage]:
    """Enumerate foreign (AUR) packages straight from pacman's local DB.

    We deliberately avoid shelling out to `pacman -Qm`/`-Qi`: the local DB at
    /var/lib/pacman/local/<name>-<ver>/desc is plain text, contains a raw epoch
    %INSTALLDATE%, and a %VALIDATION% field of "None" for foreign packages.
    Reading it directly is locale-proof and works against an arbitrary --root.
    """
    pkgs: list[ForeignPackage] = []
    local = db_root / "var/lib/pacman/local"
    if not local.is_dir():
        raise FileNotFoundError(f"pacman local DB not found at {local}")

    for entry in sorted(local.iterdir()):
        desc = entry / "desc"
        if not desc.is_file():
            continue
        fields = _parse_desc(desc)
        # Foreign == not validated by a signature from a sync DB.
        if fields.get("VALIDATION", "").strip().lower() not in ("none", ""):
            continue
        name = fields.get("NAME", "").strip()
        if not name:
            continue
        install_date = None
        raw = fields.get("INSTALLDATE", "").strip()
        if raw.isdigit():
            install_date = datetime.fromtimestamp(int(raw), tz=timezone.utc)
        pkgs.append(
            ForeignPackage(
                name=name,
                version=fields.get("VERSION", "").strip(),
                install_date=install_date,
            )
        )
    return pkgs


def _parse_desc(path: Path) -> dict[str, str]:
    """Parse a pacman `desc` file (%KEY%\\nvalue\\n\\n) into a flat dict."""
    out: dict[str, str] = {}
    key = None
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("%") and line.endswith("%"):
            key = line.strip("%")
            out[key] = ""
        elif key and line:
            out[key] = (out[key] + "\n" + line).strip() if out[key] else line
    return out


def load_known_bad(
    list_file: str | None, list_url: str | None, do_fetch: bool
) -> set[str]:
    """Build the known-bad name set: embedded + bundled file + optional source."""
    names = set(EMBEDDED_KNOWN_BAD)

    # Always fold in the bundled offline list if it sits next to this script.
    bundled = Path(__file__).resolve().parent / BUNDLED_LIST_FILE
    if bundled.is_file():
        for line in bundled.read_text(errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                names.add(line)

    text = None
    if list_file:
        text = Path(list_file).read_text(errors="replace")
    elif do_fetch:
        url = list_url or DEFAULT_LIST_URL
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 — network is best-effort
            print(
                f"warning: could not fetch list from {url}: {exc}\n"
                f"         falling back to {len(names)} embedded names only.",
                file=sys.stderr,
            )
    if text:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                names.add(line)
    return names


def find_pkgbuild_files(pkg_names: set[str]) -> dict[str, list[Path]]:
    """Locate cached PKGBUILD/.install/.SRCINFO files for the given packages.

    Maps package-name -> list of build-script paths found in AUR helper caches.
    """
    targets = ("PKGBUILD", ".install", ".SRCINFO")
    found: dict[str, list[Path]] = {}
    roots = [Path(os.path.expanduser(d)) for d in AUR_CACHE_DIRS]
    # Also include other users' home caches if we can read them (running as root).
    for home in Path("/home").glob("*"):
        roots.append(home / ".cache/yay")
        roots.append(home / ".cache/paru/clone")

    for root in roots:
        if not root.is_dir():
            continue
        for name in pkg_names:
            pkgdir = root / name
            if not pkgdir.is_dir():
                continue
            for f in pkgdir.rglob("*"):
                if f.is_file() and (
                    f.name in targets or f.suffix == ".install"
                ):
                    found.setdefault(name, []).append(f)
    return found


def scan_file_for_tokens(path: Path) -> list[str]:
    """Return matched IOC tokens (with line context) found in a build file."""
    hits: list[str] = []
    try:
        for lineno, line in enumerate(
            path.read_text(errors="replace").splitlines(), 1
        ):
            for token in MALICIOUS_CONTENT_TOKENS:
                if token in line:
                    hits.append(f"{path}:{lineno}: {line.strip()[:160]}")
    except OSError:
        pass
    return hits


def hunt_payload_files(db_root: Path) -> list[Finding]:
    """Hash-match suspected payload files against KNOWN_PAYLOAD_SHA256.

    Also flags the malicious npm/bun package caches by name. We bound the walk
    to known landing dirs and skip oversized files so this stays fast.
    """
    findings: list[Finding] = []
    max_bytes = 16 * 1024 * 1024  # payloads are ~3 MB; skip anything large.
    seen: set[Path] = set()

    roots = [Path(os.path.expanduser(d)) for d in PAYLOAD_HUNT_DIRS]
    for home in Path("/home").glob("*"):
        roots.append(home / ".npm/_cacache")
        roots.append(home / ".bun/install/cache")

    for root in roots:
        # Honor --root for offline-image scans of absolute paths.
        if root.is_absolute() and db_root != Path("/"):
            root = db_root / root.relative_to("/")
        if not root.is_dir():
            continue
        for f in root.rglob("*"):
            if f in seen or not f.is_file() or f.is_symlink():
                continue
            seen.add(f)
            # Name-based tell for the cached malicious npm/bun package.
            if "atomic-lockfile" in f.as_posix() or "js-digest" in f.as_posix():
                findings.append(
                    Finding("HIGH", "<host>", "Malicious package cache artifact", str(f))
                )
            try:
                if f.stat().st_size > max_bytes:
                    continue
                digest = hashlib.sha256(f.read_bytes()).hexdigest()
            except OSError:
                continue
            if digest in KNOWN_PAYLOAD_SHA256:
                findings.append(
                    Finding(
                        "CRITICAL",
                        "<host>",
                        f"Malware payload on disk: {KNOWN_PAYLOAD_SHA256[digest]}",
                        f"{f} (sha256 {digest})",
                    )
                )
    return findings


def scan_systemd_persistence(db_root: Path) -> list[Finding]:
    """Detect the malware's systemd persistence units.

    From iocs.txt, the payload installs a service for persistence with these
    tells, ALL together:
        Restart=always
        RestartSec=30
        ExecStart=<a generated-name binary under /var/lib/... or a user's home>
    and it lands in either:
        /etc/systemd/system/<generated>.service           (root)
        ~/.config/systemd/user/<generated>.service         (user)

    THE TRADE-OFF (this is why it's left for you):
      `Restart=always` alone is extremely common in legitimate units, so
      matching on it naively floods the report with false positives and
      destroys trust in the tool. The art is choosing how many of the weak
      tells must co-occur, and how suspicious the ExecStart path must be,
      before you raise a finding — and at what severity.

    TODO(you): implement the heuristic. Return a list[Finding]. Suggested shape:
      1. Collect candidate unit files from the dirs above (use db_root as prefix
         so --root works; glob ~/.config/systemd/user across /home/* too).
      2. For each, parse the [Service] keys (a couple of `line.startswith(...)`
         checks are enough — no need for a full INI parser).
      3. Decide your rule. e.g. require Restart=always AND RestartSec=30 AND an
         ExecStart pointing outside the usual /usr/bin|/usr/lib locations
         (e.g. into /var/lib or a home dir). Pick the severity:
            - all three tells + suspicious path  -> "HIGH"
            - Restart=always + RestartSec=30 only -> "MEDIUM" or "INFO"?
      4. Build Finding(severity, "<host>", reason, evidence=str(unit_path)).

    Returning [] (the current placeholder) simply means "persistence check not
    yet enabled" — the rest of the scanner works without it.
    """
    findings: list[Finding] = []
    # --- BEGIN implementation ---

    # 1. Collect candidate unit files: root units + every user's session units.
    unit_dirs = [db_root / "etc/systemd/system"]
    home_root = db_root / "home"
    if home_root.is_dir():
        for home in home_root.glob("*"):
            unit_dirs.append(home / ".config/systemd/user")
    # Also the running user's units when not scanning an alternate --root.
    if db_root == Path("/"):
        unit_dirs.append(Path(os.path.expanduser("~/.config/systemd/user")))

    # Paths we consider "normal" for a service binary. An ExecStart pointing
    # OUTSIDE these is the suspicious tell the malware exhibits.
    trusted_prefixes = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/")

    seen_units: set[Path] = set()
    for udir in unit_dirs:
        if not udir.is_dir():
            continue
        for unit in udir.glob("*.service"):
            real = unit.resolve()
            if real in seen_units or not unit.is_file():
                continue
            seen_units.add(real)

            restart = restart_sec = exec_start = ""
            try:
                for line in unit.read_text(errors="replace").splitlines():
                    s = line.strip()
                    if s.startswith("Restart=") and not s.startswith("RestartSec="):
                        restart = s.split("=", 1)[1].strip()
                    elif s.startswith("RestartSec="):
                        restart_sec = s.split("=", 1)[1].strip()
                    elif s.startswith("ExecStart=") and not exec_start:
                        exec_start = s.split("=", 1)[1].strip()
            except OSError:
                continue

            # 2. The two weak tells the payload sets.
            tells = restart == "always" and restart_sec in ("30", "30s")
            if not tells:
                continue

            # 3. Extract the binary path from ExecStart, stripping the leading
            #    special prefixes systemd allows (- @ + ! :).
            binary = exec_start.lstrip("-@+!:").lstrip().split()[0] if exec_start else ""
            suspicious_path = bool(binary) and not binary.startswith(trusted_prefixes)

            # 4. Severity: both tells + a binary outside the trusted dirs is the
            #    full malware signature -> HIGH. Both tells with a normal-looking
            #    ExecStart is only weakly suspicious -> INFO (review, no gate).
            if suspicious_path:
                findings.append(
                    Finding(
                        "HIGH",
                        "<host>",
                        "systemd unit matches malware persistence pattern "
                        "(Restart=always, RestartSec=30, ExecStart outside /usr)",
                        f"{unit}  ExecStart={binary}",
                    )
                )
            else:
                findings.append(
                    Finding(
                        "INFO",
                        "<host>",
                        "systemd unit has Restart=always + RestartSec=30 "
                        "(common in legit units; verify ExecStart)",
                        f"{unit}  ExecStart={binary or '?'}",
                    )
                )

    # --- END implementation ---
    return findings


def scan_host_artifacts() -> list[Finding]:
    """Look for post-exploitation traces on the host (best-effort, read-only)."""
    findings: list[Finding] = []
    for base, pattern in HOST_ARTIFACT_GLOBS:
        bpath = Path(base)
        if not bpath.is_dir():
            continue
        try:
            for match in bpath.glob(pattern):
                findings.append(
                    Finding(
                        "CRITICAL",
                        "<host>",
                        "eBPF rootkit pin artifact present",
                        str(match),
                    )
                )
        except PermissionError:
            findings.append(
                Finding(
                    "INFO",
                    "<host>",
                    f"cannot read {base} (run as root for full host check)",
                    base,
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Risk assessment policy
# --------------------------------------------------------------------------- #
def assess_package(
    pkg: ForeignPackage,
    known_bad: set[str],
    content_hits: list[str],
) -> list[Finding]:
    """Combine the available signals for ONE foreign package into findings.

    This is the policy heart of the scanner: how do we weigh a name match vs.
    an install-window hit vs. an actual malicious string in the build file?
    The trade-off is precision vs. recall during an *active* incident:
      - Too aggressive  -> alert fatigue, users ignore real CRITICALs.
      - Too conservative -> a freshly-compromised package slips through because
        its name hasn't reached the public list yet.

    Signal strength, strongest first:
      1. content_hits   -> the malicious token is literally in YOUR build file.
      2. name in known_bad -> confirmed-compromised package is installed.
      3. installed/upgraded inside the attack window -> circumstantial.
    """
    findings: list[Finding] = []

    # --- Signal 1: smoking gun — malicious payload string in the build file.
    if content_hits:
        findings.append(
            Finding(
                "CRITICAL",
                pkg.name,
                "Malicious payload token found in cached build script",
                content_hits[0],
            )
        )

    # --- Signal 2: name appears on the confirmed-compromised list.
    if pkg.name in known_bad:
        findings.append(
            Finding(
                "CRITICAL",
                pkg.name,
                "Installed package is on the confirmed-compromised list",
                f"version {pkg.version}",
            )
        )

    # --- Signal 3: touched during the attack window (circumstantial).
    # On its own this is weak — a routine `pacman -Syu` trips it for EVERY
    # foreign package. So an uncorroborated window hit is INFO (review-only,
    # does not fail the exit code). If a stronger signal already fired above,
    # the window date is reported as corroborating context instead.
    install_date = pkg.install_date
    in_window = (
        install_date is not None
        and ATTACK_WINDOW_START <= install_date < ATTACK_WINDOW_END
    )
    if in_window and install_date is not None:
        when = f"install date {install_date.date()}"
        if findings:
            findings.append(
                Finding("HIGH", pkg.name, "...and touched during the attack window", when)
            )
        else:
            findings.append(
                Finding(
                    "INFO",
                    pkg.name,
                    "Installed during attack window — inspect PKGBUILD to clear",
                    when,
                )
            )

    return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
COLORS = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "INFO": "\033[36m",
    "_reset": "\033[0m",
}


def render_report(findings: list[Finding], total_foreign: int, use_color: bool) -> None:
    def c(sev: str) -> str:
        return COLORS.get(sev, "") if use_color else ""

    reset = COLORS["_reset"] if use_color else ""
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)

    print(f"\nScanned {total_foreign} foreign (AUR) package(s).")
    actionable = [f for f in findings if f.severity != "INFO"]
    if not actionable:
        print(f"{c('INFO')}No indicators of the June 2026 AUR compromise found.{reset}")
    else:
        print(f"{c('CRITICAL')}{len(actionable)} finding(s) require attention:{reset}\n")

    for f in findings:
        marker = f"{c(f.severity)}[{f.severity}]{reset}"
        print(f"{marker} {f.package}: {f.reason}")
        if f.evidence:
            print(f"        ↳ {f.evidence}")

    if actionable:
        print(
            "\nRecommended response:\n"
            "  1. Do NOT trust the affected package(s). Note them.\n"
            "  2. Inspect the cached PKGBUILD evidence above before doing anything else.\n"
            "  3. Rotate secrets that the infostealer targets: SSH keys, browser\n"
            "     sessions/cookies, and Discord/Slack/Telegram tokens.\n"
            "  4. Treat a CRITICAL host artifact as a full compromise — isolate the\n"
            "     machine and rebuild rather than clean in place.\n"
            "  5. Cross-check against the live list: " + DEFAULT_LIST_URL
        )


def render_json(findings: list[Finding], total_foreign: int) -> None:
    print(
        json.dumps(
            {
                "scanned_foreign_packages": total_foreign,
                "findings": [vars(f) for f in findings],
            },
            indent=2,
        )
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="aurscan",
        description="Scan for AUR packages compromised in the June 2026 "
        "atomic-lockfile supply-chain attack.",
    )
    p.add_argument(
        "--root",
        default="/",
        help="Filesystem root to scan (default: /). Useful for offline images.",
    )
    p.add_argument(
        "--fetch-list",
        action="store_true",
        help="Fetch the live consolidated compromised-package list (recommended).",
    )
    p.add_argument("--list-url", help="Override the URL for --fetch-list.")
    p.add_argument(
        "--list-file", help="Use a local file of compromised names instead of fetching."
    )
    p.add_argument(
        "--no-host-check",
        action="store_true",
        help="Skip filesystem artifact (eBPF/rootkit) checks.",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument(
        "--no-color", action="store_true", help="Disable ANSI color in text output."
    )
    args = p.parse_args(argv)

    db_root = Path(args.root)
    try:
        foreign = read_local_db(db_root)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    known_bad = load_known_bad(args.list_file, args.list_url, args.fetch_list)

    # Only bother hunting for build files for packages we'd flag on; but during
    # an active incident, scan build files for ALL foreign packages so an
    # unknown-but-compromised one still trips the content signature.
    all_names = {p.name for p in foreign}
    pkgbuilds = find_pkgbuild_files(all_names)

    findings: list[Finding] = []
    for pkg in foreign:
        hits: list[str] = []
        for path in pkgbuilds.get(pkg.name, []):
            hits.extend(scan_file_for_tokens(path))
        findings.extend(assess_package(pkg, known_bad, hits))

    if not args.no_host_check:
        findings.extend(scan_host_artifacts())
        findings.extend(hunt_payload_files(db_root))
        findings.extend(scan_systemd_persistence(db_root))

    use_color = not args.no_color and sys.stdout.isatty()
    if args.json:
        render_json(findings, len(foreign))
    else:
        render_report(findings, len(foreign), use_color)

    # Exit non-zero if anything actionable was found (gates cron / CI / hooks).
    worst = max((SEVERITY_ORDER[f.severity] for f in findings), default=0)
    return 1 if worst >= SEVERITY_ORDER["MEDIUM"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
