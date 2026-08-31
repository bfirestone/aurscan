# Publishing aurscan to the AUR

The submission itself is a five-minute task once the one-time setup is done.
Everything repo-side (release asset, checksums, `.SRCINFO`) is kept
submission-ready by the release drill; this document covers the AUR-side
steps, which need a human and an AUR account.

> **Status 2026-08-31:** new AUR account registration is temporarily closed
> (HTTP 503, "a wave of automated account creation"). Reopening is announced
> on [aur-general](https://lists.archlinux.org/mailman3/lists/aur-general.lists.archlinux.org/)
> and the [Arch news feed](https://archlinux.org/news/); the notice asks that
> the registration page itself not be polled. Steps 1 and 3 below can be done
> now; step 2 waits.

## One-time setup

### 1. Create a dedicated SSH key

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_aur -C "aur:bfirestone"
```

A dedicated on-disk key sidesteps agent problems entirely. This matters on a
machine whose agent (1Password here) holds many keys: the AUR's sshd drops
the connection after ~6 offered keys with `Too many authentication failures`,
which is exactly how the first submission attempt failed in July 2026.

### 2. Register the key on the AUR account

https://aur.archlinux.org → *My Account* → **SSH Public Key** → paste the
contents of `~/.ssh/id_aur.pub`. That field is the entire credential; there
is no password auth on the git side.

### 3. Pin the key in ~/.ssh/config

Add above any `Host *` catch-all:

```
Host aur.archlinux.org
    User aur
    IdentityFile ~/.ssh/id_aur
    IdentitiesOnly yes
```

`IdentitiesOnly yes` is the line that keeps the agent's other keys from being
offered first.

### 4. Test

```bash
ssh -T aur@aur.archlinux.org
```

Success prints `Interactive shell is disabled.` and exits non-zero — both
expected. On first connect, verify the host key fingerprint against the ones
published in the [AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines)
rather than blind-accepting. Fitting habit for this particular tool.

## First submission

```bash
git clone ssh://aur@aur.archlinux.org/aurscan.git ~/aur-aurscan
# "warning: You appear to have cloned an empty repository" is expected --
# the package is created by the first push, not the clone.

cd ~/aur-aurscan
cp ~/devspace/personal/bfirestone/aur_package_scanner/{PKGBUILD,.SRCINFO,aurscan.install} .
git add PKGBUILD .SRCINFO aurscan.install
git commit -m "Initial import: aurscan <version>"
git push origin HEAD:master
```

Three gotchas are baked into those commands:

- **Copy all three files.** makepkg reads `install=` (`aurscan.install`) from
  the repo directory, not the source tarball. Omitting it breaks the build
  for every user.
- **Push `HEAD:master`.** The AUR accepts only a `master` branch, and a local
  clone of an empty repo names its branch from `init.defaultBranch` (usually
  `main`), so a bare `git push` is rejected.
- `.SRCINFO` must be present and consistent in every commit; the AUR's
  server-side hook validates it. CI keeps ours in sync with the PKGBUILD, so
  a copy of both files passes.

## Immediately after

1. Check https://aur.archlinux.org/packages/aurscan renders with the
   description, dependencies, and sources from `.SRCINFO`.
2. **Pin a comment** routing support to GitHub, to cap the maintenance
   surface:

   > Bug reports and feature requests: https://github.com/bfirestone/aurscan/issues
   >
   > Note the bootstrap-trust caveat in the README: this tool arrives through
   > the channel it scans. Verify your first install manually.

3. The victory-lap test from any machine: `paru -S aurscan` — the
   PreBuildCommand gate scans the scanner on its way in.

## Publishing an update

The same loop minus setup. In the main repo, the release drill has already
bumped `pkgver`, pinned `sha256sums` to the published asset, and regenerated
`.SRCINFO` (see the `chore: release` / `build(pkgbuild)` commit pairs in git
history for the pattern). Then:

```bash
cd ~/aur-aurscan
cp ~/devspace/personal/bfirestone/aur_package_scanner/{PKGBUILD,.SRCINFO,aurscan.install} .
git add -A
git commit -m "Update to <version>"
git push
```

Never push a version whose asset is not already published and
container-verified: the AUR PKGBUILD downloads the GitHub release asset by
checksum, so the release must exist first. `docs/integration.md` and the
tracker's release-epic notes carry the full verification checklist.
