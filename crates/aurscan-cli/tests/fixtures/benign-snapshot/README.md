# Benign snapshot — vendored third-party AUR PKGBUILDs

**Everything in the subdirectories here is third-party content**, copied
verbatim from the AUR. It is not written by this project, not reviewed line by
line, and not covered by this repository's licence. It exists only as test
input.

Nothing in here is ever executed. Only `PKGBUILD` files are vendored — no
`source=()` payloads are fetched and no package is ever built. `aurscan` reads
these as text.

## Why this exists

The `../benign/` fixtures are hand-written. They are modelled on real packaging
patterns, which means they only cover shapes somebody thought to write down.
Real PKGBUILDs keep inventing shapes nobody thought of:

| Idiom | Found in | Was |
|---|---|---|
| `install -Dm644 /dev/stdin "$pkgdir/…"` | `worktrunk-bin` | false Block |
| `make > /dev/null` | `paru`, `shelly-bin`, `xrizer` | false Block |
| `git apply -3 ../0001.patch` in `prepare()` | `gtk2`, `libsoup`, `lib32-gstreamer` | false Medium |

Each of those was a false positive on a package real users install. The first
was caught by accident during unrelated testing; the rest were caught by this
snapshot the first time it ran.

## The gate

`tests/e2e_benign_snapshot.rs` asserts **zero Block verdicts** across this
corpus. That assertion is not negotiable — a Block against a top-50 AUR package
is a detector bug until proven otherwise. Do not add exemptions to make it
pass; fix the detector.

Advisory and Info findings are *not* asserted. Real packages legitimately raise
them (`spotify` genuinely fetches over plain HTTP, and that finding is
correct). They are recorded in `ADVISORIES.json` as a reviewable artifact —
regenerate with:

    cargo test -p aurscan --test e2e_benign_snapshot -- --ignored

## Refreshing

    python3 scripts/refresh_benign_snapshot.py --top 50

Run it deliberately and review the diff. It is not wired into CI: a live fetch
in the PR gate would be flaky and would let third-party content change the
build without review. `MANIFEST.json` records what was fetched, when, each
package's popularity at fetch time, and a SHA-256 of every vendored file.

The complementary discovery layer is `.github/workflows/aur-sweep.yml`, which
scans the *live* top-N weekly and reports — it never gates.
