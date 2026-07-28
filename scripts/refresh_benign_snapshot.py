#!/usr/bin/env python3
"""Refresh the vendored top-N AUR PKGBUILD snapshot used as the false-positive floor.

The synthetic `benign/` fixtures only cover shapes someone thought to write
down. This snapshot covers shapes the AUR actually contains: it is the corpus
that caught the `/dev/null` Block on `paru` and the `git apply` noise on
`gtk2`, neither of which any hand-written fixture had.

Run it deliberately, review the diff, commit it. It is NOT run by CI: a live
fetch in the PR gate would make CI flaky and would let third-party content
change the build without review. The weekly `aur-sweep` workflow watches the
*live* AUR instead, and reports rather than gates.

    python3 scripts/refresh_benign_snapshot.py            # top 50
    python3 scripts/refresh_benign_snapshot.py --top 100

Only PKGBUILDs are vendored -- no sources, no builds, nothing is executed.
"""

import argparse
import gzip
import hashlib
import json
import shutil
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

# The plain metadata dump is ~10MB and already carries Popularity/NumVotes.
# The `-ext` variant adds depends/conflicts/license arrays a ranking does not
# need, at several times the size.
META_URL = "https://aur.archlinux.org/packages-meta-v1.json.gz"
# cgit serves a single file straight out of the package's git repo, so this is
# one small GET per package rather than a full clone.
PKGBUILD_URL = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={}"
UA = "aurscan-snapshot-refresh (+https://github.com/bfirestone/aur_package_scanner)"

DEFAULT_SNAPSHOT_DIR = (
    Path(__file__).resolve().parent.parent
    / "crates/aurscan-cli/tests/fixtures/benign-snapshot"
)
# Rebound by main(); the vendoring helpers write here.
SNAPSHOT_DIR = DEFAULT_SNAPSHOT_DIR


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def top_packages(n: int) -> list[dict]:
    """The n most popular package *bases*, deduplicated.

    Ranking is by PackageBase, not Name: a split package contributes several
    names backed by one PKGBUILD, and vendoring it once is the point.
    """
    print(f"fetching {META_URL} ...", file=sys.stderr)
    meta = json.loads(gzip.decompress(fetch(META_URL)))
    bases: dict[str, dict] = {}
    for pkg in meta:
        base = pkg["PackageBase"]
        if base not in bases or pkg["Popularity"] > bases[base]["Popularity"]:
            bases[base] = pkg
    ranked = sorted(bases.values(), key=lambda p: -p["Popularity"])
    print(f"{len(meta)} packages, {len(bases)} bases; taking top {n}", file=sys.stderr)
    return ranked[:n]


def vendor(pkg: dict) -> dict | None:
    base = pkg["PackageBase"]
    try:
        body = fetch(PKGBUILD_URL.format(base))
    except Exception as e:  # noqa: BLE001 - report and skip, one bad package is not fatal
        print(f"  SKIP {base}: {e}", file=sys.stderr)
        return None
    if not body.strip():
        print(f"  SKIP {base}: empty PKGBUILD", file=sys.stderr)
        return None
    dest = SNAPSHOT_DIR / base
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "PKGBUILD").write_bytes(body)
    return {
        "pkgbase": base,
        "popularity": round(pkg["Popularity"], 4),
        "num_votes": pkg["NumVotes"],
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--top", type=int, default=50, help="how many bases to vendor")
    ap.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_SNAPSHOT_DIR,
        help="where to write (the weekly live sweep points this at a temp dir)",
    )
    args = ap.parse_args()

    global SNAPSHOT_DIR
    SNAPSHOT_DIR = args.out

    packages = top_packages(args.top)

    # Drop the previous snapshot so packages that fell out of the top N are
    # removed rather than lingering. README.md is ours, not vendored content.
    if SNAPSHOT_DIR.exists():
        for child in SNAPSHOT_DIR.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"vendoring {len(packages)} PKGBUILDs ...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=4) as pool:  # modest: be polite to aur.archlinux.org
        entries = [e for e in pool.map(vendor, packages) if e]

    entries.sort(key=lambda e: e["pkgbase"])
    manifest = {
        "_comment": (
            "Vendored third-party AUR PKGBUILDs, ranked by popularity at fetch time. "
            "Regenerate with scripts/refresh_benign_snapshot.py and review the diff."
        ),
        "fetched": date.today().isoformat(),
        "source": META_URL,
        "count": len(entries),
        "packages": entries,
    }
    (SNAPSHOT_DIR / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(entries)} packages to {SNAPSHOT_DIR}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
