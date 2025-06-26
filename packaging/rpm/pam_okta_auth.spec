%define _debugsource_template %{nil}
%global rawversion 0.1.0

Name: pam_okta_auth
Version: %(v=%{rawversion}; echo ${v/-/\~})
Release: 1%{?dist}
Summary: PAM module for Okta
# Not supported on EL8
#SourceLicense: MIT
# Generated summary with `env RUSTC_BOOTSTRAP=1 cargo tree -Z avoid-dev-deps --edges no-build,no-dev,no-proc-macro --no-dedupe --prefix none --format "# {l}" | sed -e "s: / :/:g" -e "s:/: OR :g" | sort -u`
License: MIT AND Apache-2.0 AND ISC AND BSD-3-Clause AND CDLA-Permissive-2.0 AND GPL-3.0
URL: https://github.com/flowerysong/pam_okta_auth
Source: %{name}-%{rawversion}.crate
BuildRequires: rust-toolset

%description
PAM module for Okta.

%prep
%autosetup -n %{name}-%{rawversion} -p1

%build
make TARGET_PROFILE=rpm

%install
%make_install \
    TARGET_PROFILE=rpm \
    prefix=%{_prefix} \
    libdir=%{_libdir} \
    mandir=%{_mandir}

%files
%license COPYING COPYING.dependencies
%doc README.md CHANGELOG.md
%{_mandir}/man8/pam_okta_auth.8*
%defattr(-,root,root)
%{_libdir}/security/pam_okta_auth.so

%changelog
* %(date "+%a %b %d %Y") (Automated RPM build) - %{version}-%{release}
- See git log for actual changes.
