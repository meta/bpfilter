Build from sources
==================

This document describes the process to build ``bpfilter`` from sources. While ``bpfilter`` can be built on most systems, a recent (6.6+) Linux kernel is required with ``libbpf`` 1.2+ to run ``bpfilter``. ``bpfilter`` officially supports Fedora 40+, CentOS Stream 9+, and Ubuntu 24.04+. There is also a nix flake which supports all the make targets except for ``doc``.

If you want to perform a full build of ``bpfilter`` (including all test tests, code check, benchmarks, and documentation), the following dependencies are required:

.. code-block:: shell

    # Fedora 40+
    sudo dnf -y install \
        autoconf \
        automake \
        gawk \
        bpftool \
        bison \
        clang \
        clang-tools-extra \
        cmake \
        compiler-rt \
        doxygen \
        flex \
        gcc \
        gcc-c++ \
        git-core \
        google-benchmark-devel \
        iproute \
        iputils \
        jq \
        lcov \
        libbpf-devel \
        libcmocka-devel \
        libgit2-devel \
        libtool \
        procps-ng \
        python3-breathe \
        python3-dateutil \
        python3-furo \
        python3-GitPython \
        python3-linuxdoc \
        python3-scapy \
        python3-sphinx \
        sed \
        xxd

    # Ubuntu 24.04+
    sudo apt-get install -y \
        autoconf \
        automake \
        bison \
        clang \
        clang-tidy \
        clang-format \
        cmake \
        doxygen \
        flex \
        furo \
        g++ \
        git \
        iproute2 \
        iputils-ping \
        lcov \
        libbenchmark-dev \
        libbpf-dev \
        libc-dev \
        libcmocka-dev \
        libclang-rt-20-dev \
        libfuzzer-20-dev \ # Exact version depends on Ubuntu version
        libgit2-dev \
        libtool \
        linux-tools-common \
        make \
        pkgconf \
        procps \
        python3-breathe \
        python3-dateutil \
        python3-git \
        python3-pip \
        python3-scapy \
        python3-sphinx \
        sed \
        xxd

    # Nix (this is experimental)
    nix develop
    # or
    nix build

You can then use CMake to generate the build system:

.. code-block:: shell

    cmake -S $BPFILTER_SOURCE -B $BUILD_DIRECTORY

The usual CMake options are allowed (e.g. ``CMAKE_BUILD_TYPE``, ``CMAKE_INSTALL_PREFIX``...). The build configuration is modular, so you're free to enable/disable some parts of the projects according to your needs. The ``WITH_*`` options define a set of targets, and CMake will look for their dependencies when it configures the project:

- ``-DWITH_DOCS``: the documentation, including the coverage and benchmarks report. Enabled by default.
- ``-DWITH_TESTS``: the default value of the ``WITH_TESTS_*`` options below. Enabled by default.
- ``-DWITH_TESTS_UNIT``: the unit tests.
- ``-DWITH_TESTS_E2E``: the end-to-end tests.
- ``-DWITH_TESTS_INTEGRATION``: the integration tests.
- ``-DWITH_TESTS_FUZZING``: the fuzzing targets.
- ``-DWITH_TESTS_CHECKS``: the style check and static analyzer.
- ``-DWITH_TESTS_BENCHMARKS``: the benchmarks.

A ``WITH_TESTS_*`` option you've set always takes precedence over ``WITH_TESTS``, and CMake will keep it for the next configurations: use ``-UWITH_TESTS_UNIT`` to restore the default value of ``WITH_TESTS_UNIT``. If you only want the unit tests, use ``-DWITH_TESTS=OFF -DWITH_TESTS_UNIT=ON``. The ``WITH_TESTS_*`` options are not listed by ``cmake -L``, but CMake prints their value when it configures the project.

The ``ENABLE_*`` options modify the way the project is built:

- ``-DENABLE_COVERAGE``: build with code coverage support, and define the ``coverage`` target. Disabled by default.

A full configuration (without any part disabled) will provide the following targets:

- ``libbpfilter``, ``bfcli``: the ``bpfilter`` binaries.
- ``test_bin``: build the binaries needed to run the tests (below).
- ``test``: run all the tests. This command will run ``unit``, ``check``, ``e2e``, and ``integration`` targets. See :doc:`tests` for more information.
- ``fuzzing``: fuzz the CLI parser indefinitely. Use ``fuzzing_quick`` for a quick, 60-second fuzzing session.
- ``check``: run ``clang-tidy`` and ``clang-format`` against the source files.
- ``benchmark``: run the benchmarks on ``bpfilter``.

The build artifacts are located in ``$BUILD_DIRECTORY/output``.
