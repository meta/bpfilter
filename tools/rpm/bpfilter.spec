Name:       bpfilter
# Placeholder: tools/rpm/mock-build and Packit set the version from the latest tag.
Version:    0.0.0
Release:    %autorelease
Summary:    BPF-based packet filtering framework

License:    GPL-2.0-only
URL:        https://bpfilter.io
Source:     https://github.com/meta/bpfilter/archive/refs/tags/v%{version}.tar.gz#/bpfilter-%{version}.tar.gz

BuildRequires: bison
BuildRequires: clang
BuildRequires: cmake
BuildRequires: flex
BuildRequires: gcc
BuildRequires: libbpf-devel
BuildRequires: libcmocka-devel
BuildRequires: /usr/bin/xxd

# Only those two architectures are supported by bpfilter.
ExclusiveArch: %{x86_64} %{arm64}

%global soname_version %%(echo %%{version} | cut -d. -f1)

%global _description %{expand:
BPF-based packet filtering framework to convert text-format filtering rules
into BPF programs attach to your kernel.}

%description    %{_description}

%package devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       pkgconfig

%description    devel %{_description}

The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%autosetup -p1

%build
%cmake -DWITH_DOCS=OFF -DWITH_TESTS=OFF -DWITH_TESTS_UNIT=ON
%cmake_build

%check
%ctest

%install
%cmake_install


%files
%license COPYING
%{_sbindir}/bfcli
%{_libdir}/libbpfilter.so.%{soname_version}
%{_libdir}/libbpfilter.so.%{version}

%files devel
%{_includedir}/bpfilter/
%{_libdir}/libbpfilter.so
%{_libdir}/pkgconfig/bpfilter.pc

%changelog
%autochangelog
