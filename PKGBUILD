# Maintainer: Ben Firestone <ben.firestone@gmail.com>
pkgname=aurscan
pkgver=0.1.0
pkgrel=1
pkgdesc="High-performance AUR package scanner with PKGBUILD and artifact malware detection"
arch=('x86_64')
url="https://github.com/bfirestone/aurscan"
license=('MIT')
depends=('pacman')
optdepends=('paru: for paru-native PreBuildCommand integration')
makedepends=('cargo' 'git')
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

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

	# Install license (if LICENSE file exists; otherwise skip)
	if [ -f "LICENSE" ]; then
		install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
	fi
}
