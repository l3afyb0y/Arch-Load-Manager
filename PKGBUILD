# Maintainer: Porker Roland <gitporker@gmail.com>
pkgname=arch-load-manager
pkgver=2.1.0
pkgrel=1
pkgdesc="Advanced load manager and process optimizer for Linux"
arch=('x86_64')
url="https://github.com/gitporker/Arch-Load-Manager"
license=('MIT')
depends=('gtk3' 'json-c')
makedepends=('gcc' 'make' 'pkg-config' 'uthash')
source=('arch-load-manager.c'
        'arch-load-daemon.c'
        'config.c'
        'config.h'
        'common.h'
        'arch-load-manager.desktop'
        'arch-load-daemon.service'
        'Arch Load Manager.png'
        'Makefile')
sha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP')

build() {
	cd "$srcdir"
	make all
}

package() {
	cd "$srcdir"
	make DESTDIR="$pkgdir" PREFIX=/usr install
}
