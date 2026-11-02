---
allowed-tools: Bash(git *), Bash(make *), Bash(cmake *), Bash(ctest *), Bash(grep *), Bash(lcov *), Bash(sudo make *), Bash(gcov *), Bash(ls *), Grep, Read, Glob, Task
argument-hint: <pr-number>
description: Review a pull request
---

Review pull request #$ARGUMENTS

## Setup

1. Fetch the PR: `git fetch origin pull/$ARGUMENTS/head:pr-$ARGUMENTS` (try `upstream` if `origin` fails)
2. Create a worktree: `git worktree add /tmp/bpfilter-pr-$ARGUMENTS pr-$ARGUMENTS`
3. Get commit info: `git log main..pr-$ARGUMENTS --oneline`
4. Get the diff: `git diff --stat main...pr-$ARGUMENTS`
5. Read the style guide @doc/developers/style.rst

## Review steps

- Build and tests should be done in both modes `debug` and `release`.
- Configure: `cmake -S . -B <build_dir> -DCMAKE_BUILD_TYPE=<mode>`
    - `build_dir`: `/tmp/bpfilter-pr-$ARGUMENTS`
    - Use `-DENABLE_COVERAGE=1` for coverage information

### Code review

Review code changes for quality and safety.

- Warn on ABI/API breakage (in libbpfilter)
- No buffer overflows
- Input validation at boundaries
- No command injection risks
- No hardcoded credentials
- Pay extra attention to the new BPF bytecode generated, be careful about: register misuse, sub-optimal constructs

Report:
1. Issues found, grouped by severity
    1. Issues that must be addressed
    2. Suggestions for improvement
    3. Minor style notes
2. Overall status (PASS/FAIL)

### Build

Configure and build the project, reporting any issues.

Build:
```bash
make -C <build_dir>
```

Report:
1. Configuration status
2. Warning count
3. List all warnings with file:line
4. List all errors with context
5. Build status (PASS/FAIL)

### Test

Test:
```bash
make -C <build_dir> unit # Unit tests
make -C <build_dir> e2e # End-to-end tests
make -C <build_dir> integration # Integration tests
make -C <build_dir> check # Style check and linter

ctest --test-dir build --output-on-failure -R <pattern> # Run a specific test
```

- New functions should be tested using unit tests for libbpfilter, end-to-end tests for matchers
- New matchers should have a corresponding E2E test in `tests/e2e/matchers/`
- Use your best judgement to assess if a given function should be tested or not

Report:
1. Which suites were run
2. Pass/fail counts
3. Any failures with their output
4. Overall status (PASS/FAIL)

### Style

Do not run the check target again, use your knowledge of the style guide.

Report:
1. Style violations
2. Overall status (PASS/FAIL)

### Documentation

Generate documentation:
```bash
make -C <build_dir> doc
```

- Documentation should be generated without warning or issue
- Important or complex functions should be documented
- Do not document trivial functions (e.g. getters, setters)

Report:
1. Any warnings or errors
2. Overall status (PASS/FAIL)

### Coverage

Generate coverage information:
```bash
make -C <build_dir> coverage
```

- Requires `-DENABLE_COVERAGE=1` and unit tests to have run
- Only analyse the coverage of the lines changed in the PR
- Use gcov to check specific file coverage: `gcov -p <build_dir>/src/libbpfilter/CMakeFiles/libbpfilter.dir/<file>.o`
- New lines: minimum 70% covered
- New functions: 100% covered

Report:
1. New lines coverage (percentage per function)
2. New functions coverage (list uncovered functions)
3. Overall status (PASS/FAIL)

### Commit

Validate commit messages against project guidelines.

Get commit message:
```bash
git log -1 --format='%s' <ref>
git log -1 --format='%b' <ref>
```

Get changed files:
```bash
git diff --stat <ref>^..<ref>
```

Report:
1. Overall status (PASS/FAIL)

## Cleanup

After review, clean up the worktree and branch:
1. `git worktree remove /tmp/bpfilter-pr-$ARGUMENTS`
2. `git branch -D pr-$ARGUMENTS`

## Output format

Structure the final report as follows:

1. **Description**: A short paragraph describing what the PR does
2. **Code Review**: Issues grouped by severity (must address / suggestions / minor notes)
3. **Build**: Table with Mode, Status, Warnings, Errors columns
4. **Test**: Table with Suite, Passed, Failed columns
5. **Style**: PASS/FAIL with any violations listed
6. **Documentation**: PASS/FAIL with any warnings
7. **Coverage**: Table showing coverage percentage per new function
8. **Commit**: PASS/FAIL with validation details
9. **Overall Status**: PASS, FAIL, or PASS (conditional) with summary

Guidelines:
- Use markdown tables for build and test results
- Reference issues with `function_name` in `file:line` format
- Focus on what should be improved, ignore what is already good
- Only report issues for which you have high confidence
- Use "PASS (conditional)" when code is correct but improvements are recommended
