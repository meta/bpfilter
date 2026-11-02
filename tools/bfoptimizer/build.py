# Copyright (c) Meta Platforms, Inc. and affiliates.
import asyncio
import enum
import logging
import pathlib
import subprocess
from collections.abc import Callable

from tests.benchmarks.bfbencher import Renderer, Report, compare

from .models import Config

log = logging.getLogger("bfoptimizer")


class MakeTarget(enum.StrEnum):
    FIXSTYLE = "fixstyle"
    BUILD = "all"
    TEST = "test"


def configure(
    sources: pathlib.Path, build_dir: pathlib.Path
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "cmake",
            "-S",
            str(sources),
            "-B",
            str(build_dir),
            "-DWITH_DOCS=OFF",
            "-DCMAKE_BUILD_TYPE=release",
        ],
        capture_output=True,
        text=True,
    )


async def make(
    build_dir: pathlib.Path,
    target: MakeTarget,
) -> tuple[int, list[str]]:
    logs = []

    def emit(lines: list[bytes]) -> None:
        # One log record per chunk, not per line: each record is rendered
        # individually by the TUI, and a full build emits thousands of lines.
        if not lines:
            return
        texts = [line.decode(errors="replace").rstrip() for line in lines]
        logs.extend(texts)
        log.info("\n".join(texts))

    proc = await asyncio.create_subprocess_exec(
        "make",
        "-C",
        str(build_dir),
        str(target),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    # Read in chunks rather than lines: readline() raises on lines longer
    # than the stream's 64KiB limit, which build output can exceed.
    buffer = b""
    while chunk := await proc.stdout.read(64 * 1024):
        buffer += chunk
        *lines, buffer = buffer.split(b"\n")
        emit(lines)
    emit([buffer] if buffer else [])

    await proc.wait()

    return (proc.returncode, logs)


class _LoggingRenderer(Renderer):
    def __init__(self, log_fn: Callable[[str], None]) -> None:
        super().__init__()
        self._log_fn = log_fn

    def log(self, message: str) -> None:
        self._log_fn(message)


def benchmark(
    config: Config,
    base_sha: str,
    ref_sha: str,
    log_fn: Callable[[str], None] | None = None,
) -> list[Report.CompareRow]:
    kwargs = dict(
        sources=config.sources_dir,
        cache_dir=config.sources_dir / ".cache" / "bfbencher",
        ssh_key=config.benchmark_ssh_key,
        bind_node=config.benchmark_bind_node,
        no_preempt=config.benchmark_no_preempt,
        cpu_pin=config.benchmark_cpu_pin,
        slice=config.benchmark_slice,
        # Re-benchmark both commits instead of reusing the base's cached
        # result: measuring base and ref back-to-back keeps the comparison
        # immune to machine drift between attempts, at the cost of running
        # the benchmarks twice.
        retry=["all"],
    )

    if config.benchmark_host:
        kwargs["host"] = config.benchmark_host

    if log_fn is not None:
        kwargs["renderer"] = _LoggingRenderer(log_fn)

    results = compare(base_sha, ref_sha, **kwargs)

    exclude = set(config.benchmark_exclude_flags)
    return [r for r in results if not any(getattr(r, f, False) for f in exclude)]
