# RPM spec file for died (diec scan daemon)
# Build with:
#   cargo build --release --package diec-server
#   rpmbuild -ba packaging/died.spec
# Or use cargo-rpm if available.

Name:           died
Version:        0.3.0
Release:        1%{?dist}
Summary:        HTTP/JSON scan service for diec (Detect It Easy)

License:        MIT
URL:            https://github.com/chennqqi/diec-rust
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.88
BuildRequires:  cargo
Requires:       glibc >= 2.17

%description
died (die daemon) is the HTTP/JSON scan service for diec (Detect It Easy).
It provides a REST API for local and remote file identification, reusing
the rule database across requests to avoid repeated loading overhead.

%prep
%setup -q

%build
cargo build --release --package diec-server

%install
install -D -m 755 target/release/died %{buildroot}%{_bindir}/died
install -D -m 644 README.md %{buildroot}%{_defaultdocdir}/%{name}/README.md
install -D -m 644 LICENSE %{buildroot}%{_defaultdocdir}/%{name}/LICENSE
install -D -m 644 crates/diec-server/packaging/died.service %{buildroot}%{_unitdir}/died.service

%pre
getent group died >/dev/null || groupadd -r died
getent passwd died >/dev/null || useradd -r -g died -d /var/lib/died -s /sbin/nologin died

%post
%systemd_post died.service

%preun
%systemd_preun died.service

%postun
%systemd_postun died.service

%files
%{_bindir}/died
%{_unitdir}/died.service
%{_defaultdocdir}/%{name}/README.md
%{_defaultdocdir}/%{name}/LICENSE

%changelog
* Mon Aug 04 2026 diec-rust maintainers - 0.2.2-1
- Initial RPM package for died (die daemon)
