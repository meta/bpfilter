# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Argument parser, optimization loop, and main entry point for bfoptimizer."""

from __future__ import annotations

import argparse
import asyncio
import logging
import pathlib
import sys
import traceback
from typing import Any

import git

from tests.benchmarks.bfbencher import compare_table

from .ai import generate_commit_message, query_implementation, query_proposal
from .api import api_key, models
from .build import MakeTarget, benchmark, configure, make
from .log import RenderAs
from .models import (
    DEFAULT_MODEL,
    AttemptResult,
    AttemptStep,
    CommitInfo,
    Config,
    Effort,
    History,
)
from .tui import Optimizer

DEFAULT_EXCLUDE_FLAGS = ["use_set", "use_log", "userspace_only"]

# (step, log message, make target, failure result) for each validation stage
# run after an implementation pass, in order.
_VALIDATION_STAGES = [
    (
        AttemptStep.BUILD,
        "Building bpfilter",
        MakeTarget.BUILD,
        AttemptResult.BUILD_FAILED,
    ),
    (
        AttemptStep.BUILD,
        "Running fixstyle",
        MakeTarget.FIXSTYLE,
        AttemptResult.BUILD_FAILED,
    ),
    (
        AttemptStep.TEST,
        "Running the tests",
        MakeTarget.TEST,
        AttemptResult.TEST_FAILED,
    ),
]

# Build/test output fed back to the implementation model is truncated to this
# many trailing lines: errors are reported last, and full logs would grow the
# prompt without bound across retries.
FAILURE_LOG_MAX_LINES = 100


def _tail(logs: list[str]) -> str:
    if len(logs) <= FAILURE_LOG_MAX_LINES:
        return "\n".join(logs)
    skipped = len(logs) - FAILURE_LOG_MAX_LINES
    return "\n".join(
        [f"[... {skipped} lines truncated ...]", *logs[-FAILURE_LOG_MAX_LINES:]]
    )


def _reset_worktree(repo: git.Repo, ref: str) -> None:
    """Discard commits, uncommitted changes, and untracked files, back to ref.

    Gitignored files (build directory, caches) are preserved. Attempts start
    from a clean tree, so anything dangling was created by the current run.
    """

    repo.git.reset("--hard", ref)
    repo.git.clean("-fd")


async def _optimization_loop(history: History) -> None:
    log = logging.getLogger("bfoptimizer")

    r = await asyncio.to_thread(
        configure, history.config.sources_dir, history.config.build_dir
    )
    if r.returncode != 0:
        log.error(f"failed to configure bpfilter sources:\n{r.stderr}")
        raise RuntimeError("failed to configure bpfilter sources")

    with git.Repo(history.config.sources_dir) as repo:
        for attempt in history.iter_attempts():
            log.info("Starting attempt")
            attempt.start()

            # Every failure path resets to the attempt's start commit:
            # an absolute ref stays correct even if the attempt died
            # half-way through creating its commit.
            start_sha = await asyncio.to_thread(lambda: repo.head.commit.hexsha)
            try:
                await query_proposal(history)

                if not attempt.plan:
                    log.error("proposal phase produced no plan, skipping attempt")
                    await asyncio.to_thread(_reset_worktree, repo, start_sha)
                    attempt.complete(AttemptResult.PLAN_FAILED)
                    continue

                failures: list[dict[str, Any]] = []
                for _ in range(5):
                    attempt.step = AttemptStep.IMPLEMENT
                    await query_implementation(history, failures)

                    for step, message, target, failure in _VALIDATION_STAGES:
                        attempt.step = step
                        log.info(message)
                        (returncode, logs) = await make(
                            history.config.build_dir, target
                        )
                        if returncode != 0:
                            failures.append({"failure": failure, "reason": _tail(logs)})
                            break
                    else:
                        break
                else:
                    await asyncio.to_thread(_reset_worktree, repo, start_sha)
                    attempt.complete(failures[-1]["failure"])
                    continue

                log.info("Changes are valid, committing")

                await asyncio.to_thread(repo.git.add, ".")
                diff = await asyncio.to_thread(repo.git.diff, "--staged")
                commit_msg = await generate_commit_message(history, attempt.plan, diff)
                log.info(f"Commit: {commit_msg}")
                commit = await asyncio.to_thread(repo.index.commit, commit_msg)

                subject, _, body = commit_msg.partition("\n")
                attempt.commit = CommitInfo(
                    sha=commit.hexsha,
                    parent_sha=start_sha,
                    subject=subject.strip(),
                    body=body.strip(),
                    diff=diff,
                )

                attempt.step = AttemptStep.EVALUATE
                log.info("Running the benchmarks")
                attempt.benchmark_results = await asyncio.to_thread(
                    benchmark,
                    history.config,
                    "HEAD~1",
                    "HEAD",
                    lambda line: log.info(line, extra={"render_as": RenderAs.RICH}),
                )

                log.info(
                    "",
                    extra={
                        "renderable": compare_table(
                            attempt.benchmark_results, start_sha, commit.hexsha
                        )
                    },
                )

                result = (
                    AttemptResult.SUCCESS
                    if attempt.delta_pct < 0.0
                    else AttemptResult.REGRESSION
                )
                if result == AttemptResult.REGRESSION:
                    await asyncio.to_thread(_reset_worktree, repo, start_sha)

                attempt.complete(result)

                log.info(
                    f"Completing attempt: {attempt.result} with {attempt.delta_pct:.3f}%"
                )
            except Exception:
                # A failed attempt must not take down the run or leave an
                # unvalidated commit at HEAD.
                log.error(f"attempt failed:\n{traceback.format_exc()}")
                if attempt.result == AttemptResult.IN_PROGRESS:
                    await asyncio.to_thread(_reset_worktree, repo, start_sha)
                    attempt.complete(AttemptResult.FAILED)

        log.info("Optimization completed!")


def _check_models(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject the model IDs that would fail only once their phase starts."""

    try:
        catalog = models()
    except RuntimeError as error:
        parser.error(str(error))

    for option, model, needs_tools in (
        ("--proposal-model", args.proposal_model, True),
        ("--impl-model", args.impl_model, True),
        ("--commit-model", args.commit_model, False),
    ):
        # Presets ("@preset/...") and variants (":nitro") are not catalog
        # entries: check the model they apply to, if the ID names one.
        base = model.partition("@")[0]
        if not base:
            continue
        entry = catalog.get(base) or catalog.get(base.partition(":")[0])
        if entry is None:
            parser.error(f"{option}: {model} is not an OpenRouter model ID")
        if needs_tools and "tools" not in entry.get("supported_parameters", []):
            parser.error(f"{option}: {model} does not support tool calling")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bfoptimizer",
        description="LLM-driven BPF bytecode optimization loop for bpfilter.",
    )

    src_g = parser.add_argument_group("Sources")
    _ = src_g.add_argument(
        "--sources-dir",
        type=pathlib.Path,
        default=pathlib.Path("."),
        help="Path to the bpfilter source checkout (default: %(default)s).",
    )
    _ = src_g.add_argument(
        "--build-dir",
        type=pathlib.Path,
        default=None,
        help="Path to the bpfilter build directory (default: ${SOURCES_DIR}/build).",
    )

    ai_g = parser.add_argument_group("LLM / AI")
    _ = ai_g.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="Number of optimization attempts (default: %(default)s).",
    )
    _ = ai_g.add_argument(
        "--proposal-model",
        default=DEFAULT_MODEL,
        metavar="MODEL",
        help="OpenRouter model ID for proposals (default: %(default)s).",
    )
    _ = ai_g.add_argument(
        "--impl-model",
        default=DEFAULT_MODEL,
        metavar="MODEL",
        help="OpenRouter model ID for implementation (default: %(default)s).",
    )
    _ = ai_g.add_argument(
        "--commit-model",
        default=None,
        metavar="MODEL",
        help="OpenRouter model ID for commit messages (default: --impl-model).",
    )
    _ = ai_g.add_argument(
        "--effort",
        type=Effort,
        default=Effort.MEDIUM,
        choices=list(Effort),
        help="Thinking effort level (default: %(default)s).",
    )
    _ = ai_g.add_argument(
        "--hint",
        default=None,
        help="Free-text direction passed to the proposal model (default: %(default)s).",
    )

    bench_g = parser.add_argument_group("Benchmark")
    _ = bench_g.add_argument(
        "--benchmark-host",
        type=str,
        default=None,
        help="Remote host to run benchmarks on (default: run locally).",
    )
    _ = bench_g.add_argument(
        "--benchmark-ssh-key",
        type=pathlib.Path,
        default=None,
        metavar="PATH",
        help="SSH private key used to authenticate to the benchmark host "
        "(default: look up the host in the SSH agent).",
    )
    _ = bench_g.add_argument(
        "--benchmark-bind-node",
        type=int,
        default=None,
        metavar="N",
        help="NUMA node to bind the benchmark to (default: %(default)s).",
    )
    _ = bench_g.add_argument(
        "--benchmark-cpu-pin",
        type=int,
        default=None,
        metavar="N",
        help="CPU to pin the benchmark to (default: %(default)s).",
    )
    _ = bench_g.add_argument(
        "--benchmark-no-preempt",
        action="store_true",
        help="Use real-time scheduling (chrt) for benchmarks (default: %(default)s).",
    )
    _ = bench_g.add_argument(
        "--benchmark-slice",
        type=str,
        default=None,
        metavar="SLICE",
        help="systemd slice to run the benchmark in (default: %(default)s).",
    )
    _ = bench_g.add_argument(
        "--benchmark-exclude",
        action="append",
        default=None,
        dest="benchmark_exclude_flags",
        metavar="FLAG",
        help="Exclude benchmarks with this flag; replaces the default exclusions "
        f"(repeatable; default: {', '.join(DEFAULT_EXCLUDE_FLAGS)}).",
    )

    args = parser.parse_args()

    try:
        api_key()
    except RuntimeError as error:
        parser.error(str(error))

    if args.commit_model is None:
        args.commit_model = args.impl_model
    if args.build_dir is None:
        args.build_dir = args.sources_dir / "build"
    if args.benchmark_exclude_flags is None:
        args.benchmark_exclude_flags = list(DEFAULT_EXCLUDE_FLAGS)

    # The first benchmark runs long after startup; fail on a bad key path now
    # rather than at the end of the first attempt.
    if args.benchmark_ssh_key and not args.benchmark_ssh_key.expanduser().is_file():
        print(f"SSH key not found: {args.benchmark_ssh_key}", file=sys.stderr)
        sys.exit(1)

    # The optimization loop commits with 'git add .' and reverts regressions
    # with 'git reset --hard': uncommitted user changes would be folded into
    # the first attempt's commit, then destroyed on revert.
    with git.Repo(args.sources_dir) as repo:
        if repo.is_dirty(untracked_files=True):
            print(
                "the working tree is dirty, commit or stash your changes first:",
                file=sys.stderr,
            )
            print(repo.git.status("--short"), file=sys.stderr)
            sys.exit(1)

    _check_models(parser, args)

    history = History(Config(**vars(args)))
    Optimizer(history, lambda: _optimization_loop(history)).run()


if __name__ == "__main__":
    main()
