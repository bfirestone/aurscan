# Maintainer: Ben Firestone <ben.firestone@gmail.com>
pkgname=aurscan
pkgver=0.1.0
pkgrel=1
pkgdesc="High-performance AUR package scanner with PKGBUILD and artifact malware detection"
arch=('x86_64')
url="https://github.com/bfirestone/aurscan"
license=('MIT')
# glibc and gcc-libs are what the binary actually links against (namcap
# flags them as implicitly satisfied otherwise). pacman is a runtime
# dependency namcap cannot see: aurscan reads the local ALPM database for
# `audit` and ships a libalpm hook.
depends=('pacman' 'glibc' 'gcc-libs')
optdepends=('paru: for paru-native PreBuildCommand integration')
makedepends=('cargo' 'git')
# !lto is required, not a preference. Arch's stock makepkg.conf enables LTO,
# which puts -flto=auto in CFLAGS. The tree-sitter crate builds its bundled C
# core via the cc crate, so those objects become LTO bitcode -- but rustc
# drives the final link with lld and has no matching plugin setup, so every
# ts_* symbol comes back undefined. `cargo build` never sees these flags, so
# this only reproduces under makepkg.
options=('!lto')
# Sources the uploaded release asset, not GitHub's /archive/ URL. Those
# tarballs are generated on demand rather than stored, and a 2023 change to
# GitHub's tar/gzip settings silently altered their checksums, breaking
# PKGBUILDs across several distros. An uploaded asset is a fixed byte string.
# Rebuild it with: git archive --format=tar.gz --prefix=$pkgname-$pkgver/ v$pkgver
source=("$url/releases/download/v$pkgver/$pkgname-$pkgver.tar.gz")
sha256sums=('5f597fb3ab7afb1aa11e003e393341a40dee99ac4d17b8edc2bab5920799f912')

build() {
	cd "$pkgname-$pkgver"
	cargo build --release --locked --bin aurscan
}

package() {
	cd "$pkgname-$pkgver"

	# Install the binary
	install -Dm755 "target/release/aurscan" "$pkgdir/usr/bin/aurscan"

	# Install the pacman hook
	# Note: This installs to /usr/share/libalpm/hooks/ (package-owned, system-wide).
	# The `aurscan setup` subcommand writes an additional hook to /etc/pacman.d/hooks/
	# (user-owned) for users who prefer that location. Both hook directories are valid;
	# the ALPM system checks both.
	install -Dm644 "data/aurscan.hook" "$pkgdir/usr/share/libalpm/hooks/aurscan.hook"

	# Install documentation
	install -Dm644 "README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"

	# Install license. MIT is a custom license under Arch packaging guidelines,
	# so a copy is required in /usr/share/licenses/$pkgname/. Unconditional on
	# purpose: a missing LICENSE must fail the build, not ship a package that
	# silently violates the guidelines.
	install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
