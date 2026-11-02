# Instructions for Claude

## Project overview

bpfilter is an eBPF-based packet filtering framework that translates filtering rules into optimized BPF programs. Licensed under GPLv2, maintained by Meta.

**Components:**
- `libbpfilter` - Core library containing all filtering logic, BPF code generation, and program lifecycle management
- `bfcli` - CLI for defining and managing filtering rules via `libbpfilter`

**Requirements:** Linux 6.6+, libbpf 1.2+

## Directory structure

```
src/
├── libbpfilter/          # Core library (shared object)
│   ├── include/bpfilter/ # Public API headers
│   ├── cgen/             # BPF code generation engine
│   │   ├── matcher/      # Packet matcher codegen (ip4, ip6, tcp, udp, icmp, meta, set)
│   │   └── prog/         # Program linking (link, map)
│   └── bpf/              # eBPF stub programs
│   └── *.c               # Implementation (chain, matcher, rule, hook, set, bpf, btf, ctx...)
├── bfcli/                # CLI (parser.y, lexer.l, opts, print, chain, ruleset)
└── external/             # External deps (mpack)

tests/
├── unit/                 # cmocka tests for libbpfilter API
├── e2e/                  # Bash scripts testing full filtering behavior
├── integration/          # API stability tests
├── check/                # clang-tidy and clang-format validation
└── harness/              # Test utilities (test.h, mock.h, fake.h, C++ wrappers)

doc/
├── usage/                # User guides (bfcli)
└── developers/           # Dev docs (build, style, tests, modules/)
```

## Communication

### Tone
- Target system development and network experts, not beginners
- Factual observations, no drama
- Frame issues as questions about code, not accusations
- Call issues "regressions" not "bugs" or "critical"

## Building and testing

```bash
# Configure (use debug + coverage during development)
cmake -S . -B build -DCMAKE_BUILD_TYPE=debug -DENABLE_COVERAGE=1

# Build
make -C build

# Run all tests (build test_bin first)
make -C build test_bin test

# Run specific suite: unit, e2e, integration, check
make -C build unit e2e integration check

# Run specific test (path from tests/, replace / with .)
ctest --test-dir build --output-on-failure -R e2e.parsing.ip4

# Coverage and docs
make -C build coverage
make -C build doc
```

**Build options:**
- `-DWITH_DOCS=OFF`, `-DWITH_TESTS=OFF`: skip the documentation or all the tests
- `-DWITH_TESTS_<TYPE>=ON|OFF`: override `WITH_TESTS` for `UNIT`, `E2E`, `INTEGRATION`, `FUZZING`, `CHECKS`, or `BENCHMARKS`
- `-DENABLE_COVERAGE=1`: build with code coverage support

## Code style

Enforced by `.clang-format` (run `make -C build check` or `make -C build fixstyle`). CI uses latest Fedora's ClangFormat version. See `doc/developers/style.rst` for complete guidelines.

- 4 spaces (no tabs), 80 char line limit
- String literals: don't split (easier to grep)

### Naming
- Functions/variables: `bf_` prefix, lowercase with underscores (`bf_chain_new()`)
- Static/internal: leading underscore (`_bf_ctx_free()`)
- CLI utilities: `bfc_` prefix
- Macros: uppercase (`EMIT()`, `TAKE_PTR()`, `ARRAY_SIZE()`)
- Enum values: uppercase with enum prefix (`BF_LOG_DBG`)
- Sentinel values: `_*_MAX` suffix (`_BF_LOG_MAX`)

### Functions
- Return `0` on success, negative errno on failure (`-ENOMEM`, `-EINVAL`, `-EEXIST`)
- Cleanup functions: return `void`, take double pointer, set `*ptr` to `NULL`
- Error checking: `if (r)` or `if (r < 0)`
- Use `assert()` for pointer preconditions only

### Memory management
- Use `__attribute__((cleanup))` extensively
- Cleanup macros: `_free_*` for heap, `_clean_*` for stack
- Ownership transfer: `TAKE_PTR()`, `TAKE_FD()`, `TAKE_STRUCT()`

### Logging
- Levels: `bf_dbg()`, `bf_info()`, `bf_warn()`, `bf_err()`, `bf_abort()`
- Log and return: `bf_err_r(-ENOMEM, "message")`

### Comments
- Single-line: `//`
- Multi-line: `/* */` with aligned asterisks, close on last text line
- Doxygen: `@brief`, `@param`, `@return`; skip trivial getters/setters
- Doxygen multi-line: first and last lines empty (unlike regular comments)

### Includes
Use `#pragma once` for header guards. Prefer forward declarations over includes when only a pointer is needed.

### Commit messages
Format: `component: subcomponent: short description`
- Components: `lib`, `cli`, `tests`, `build`, `tools`, `doc`
- Lowercase, imperative mood, no period, under 72 chars
- Description explains "why", code shows "what"
- No reference to Claude or Claude as co-author

Examples:
```
lib: matcher: add meta.flow_hash matcher
lib: cgen: link: add support for dual-stack Netfilter chains
tests: e2e: fix end-to-end tests leaving files behind
```

## Testing requirements

**Unit tests** (`tests/unit/`): cmocka framework, test every public libbpfilter function

**E2E tests** (`tests/e2e/`): Bash scripts, test complete filtering behavior with namespace isolation

**Coverage:**
- New lines: minimum 70% covered
- New functions: 100% covered
- Generate report: `make -C build coverage`

## Allowed short identifiers

From `.clang-tidy`:
- Variables: `_`, `i`, `fd`, `r`, `j0`-`j9`, `op`, `ns`, `n`
- Parameters: `ip`, `fd`, `op`, `id`, `cb`, `ns`, `n`
