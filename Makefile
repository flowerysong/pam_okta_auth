TARGET_PROFILE = release
INSTALL = install -p

datarootdir = ${prefix}/share
exec_prefix = ${prefix}
libdir = ${exec_prefix}/lib
mandir = ${datarootdir}/man
prefix = /usr/local

.MAKE: all

.PHONY: build install package rpm

all: build COPYING.dependencies

COPYING.dependencies: Cargo.lock
	env RUSTC_BOOTSTRAP=1 cargo tree -Z avoid-dev-deps --edges no-build,no-dev,no-proc-macro --no-dedupe --prefix none --format "{l}: {p}" | sed -e "s: ($(pwd)[^)]*)::g" -e "s: / :/:g" -e "s:/: OR :g" | sort -u > COPYING.dependencies

build:
	cargo build --locked --profile $(TARGET_PROFILE)

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(libdir)/security
	$(INSTALL) -m 0755 target/$(TARGET_PROFILE)/libpam_okta_auth.so $(DESTDIR)$(libdir)/security/pam_okta_auth.so
	$(INSTALL) -m 0755 -d $(DESTDIR)$(mandir)/man8
	$(INSTALL) -m 0644 doc/pam_okta_auth.8 $(DESTDIR)$(mandir)/man8

package:
	cargo package --no-verify

rpm: package
	rpmbuild -ta target/package/pam_okta_auth-0.1.0.crate

deb: build
	mkdir -p deb
	nfpm package -p deb -f packaging/deb/nfpm.yaml -t deb
