from __future__ import annotations

import argparse
import dataclasses
import errno
import getpass
import json
import multiprocessing
import pathlib
import select
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Sequence

import diskcache  # type: ignore[import-untyped]
import git
import jinja2
import numpy
import paramiko  # type: ignore[import-untyped]
import pint
import rich
import rich.console
import rich.table

DEFAULT_FIRST_COMMIT_REF = "HEAD~10"
DEFAULT_LAST_COMMIT_REF = "wip"
DEFAULT_SOURCE_PATH = pathlib.Path(".")
DEFAULT_CACHE_PATH = pathlib.Path(".cache/bfbencher")
DEFAULT_USERNAME = getpass.getuser()
DEFAULT_REPORT_TEMPLATE_PATH = pathlib.Path("tests/benchmarks/results.html.j2")
DEFAULT_PR_REPORT_TEMPLATE_PATH = pathlib.Path("tests/benchmarks/summary.html.j2")
DEFAULT_HOST = [socket.gethostname(), "localhost"]
SHORT_SHA_LEN = 7

ureg: pint.UnitRegistry = pint.UnitRegistry()


def is_wip(ref: str) -> bool:
    """Return True if `ref` is the sentinel for the uncommitted changes."""
    return ref.lower() == "wip"


class Stats:
    """Tracks benchmark execution statistics for a host."""

    def __init__(self, host: str):
        self.host = host
        self.n_successes = 0
        self.n_failures = 0
        self.n_cache_hits = 0
        self.n_cache_misses = 0
        self.failed_shas: set[str] = set()

    def success(self, from_cache: bool = False) -> None:
        if from_cache:
            self.n_cache_hits += 1
        else:
            self.n_cache_misses += 1
        self.n_successes += 1

    def failure(self, commit_sha: str | None = None, from_cache: bool = False) -> None:
        if from_cache:
            self.n_cache_hits += 1
        else:
            self.n_cache_misses += 1
        self.n_failures += 1
        if commit_sha is not None:
            self.failed_shas.add(commit_sha)


def compare_table(
    rows: list[Report.CompareRow], base_sha: str, ref_sha: str
) -> rich.table.Table:
    """Build the base/ref comparison table (negative Δ = faster = green)."""

    def format_pct(pct: float) -> str:
        color = "green" if pct < 0 else ("red" if pct > 0 else "white")
        return f"[{color}]{pct:+.1f}%[/{color}]"

    table = rich.table.Table(
        title=f"{base_sha[:SHORT_SHA_LEN]} → {ref_sha[:SHORT_SHA_LEN]}",
        show_header=True,
    )
    table.add_column("Benchmark", style="cyan")
    table.add_column("Base", justify="right")
    table.add_column("Ref", justify="right")
    table.add_column("ΔTime", justify="right")
    table.add_column("ΔTime%", justify="right")
    table.add_column("Base Insn", justify="right")
    table.add_column("Ref Insn", justify="right")
    table.add_column("ΔInsn", justify="right")
    table.add_column("ΔInsn%", justify="right")

    for row in rows:
        table.add_row(
            row.name,
            row.base_time_str,
            row.ref_time_str,
            row.delta_time_str,
            format_pct(row.delta_time_pct),
            str(row.base_insn) if row.base_insn is not None else "-",
            str(row.ref_insn) if row.ref_insn is not None else "-",
            f"{row.delta_insn:+d}" if row.delta_insn is not None else "-",
            format_pct(row.delta_insn_pct) if row.delta_insn_pct is not None else "-",
        )

    return table


class Renderer:
    """Console output handler for benchmark progress and results."""

    def __init__(self) -> None:
        self._console = rich.console.Console(log_path=False)

    def log(self, message: str) -> None:
        self._console.log(message)

    @property
    def console(self) -> rich.console.Console:
        return self._console

    def print_report(self, rows: list[Report.BenchmarkRow], terms: list[int]):
        def format_delta(term_stats: Report.TermStats | None) -> str:
            if not term_stats:
                return ""
            pct = term_stats.pct_change
            if term_stats.is_significant:
                color = "green" if pct < 0 else "red"
            else:
                color = "white"
            return f"[{color}]{pct:+.1f}%[/{color}]"

        table = rich.table.Table(title="Benchmark Summary", show_header=True)
        table.add_column("Benchmark", style="cyan")
        table.add_column("Time", justify="right")
        table.add_column("Instructions", justify="right")
        for term in terms:
            table.add_column(f"Δ Time ({term})", justify="right")
            table.add_column(f"Δ Insn ({term})", justify="right")

        for row in rows:
            columns = [row.name, row.time_str, row.insn_str or "-"]
            for term in terms:
                term_data = row.terms.get(term, {"time": None, "nInsn": None})
                columns.append(format_delta(term_data["time"]))
                columns.append(format_delta(term_data["nInsn"]))
            table.add_row(*columns)

        self.console.print(table)

    def print_compare_report(
        self,
        rows: list[Report.CompareRow],
        base_sha: str,
        ref_sha: str,
    ) -> None:
        self.console.print(compare_table(rows, base_sha, ref_sha))


renderer: Renderer = Renderer()


class Analyzer:
    """Statistical analyzer for detecting significant performance changes.

    Uses robust statistics (median/MAD) to handle outliers and determines
    if the latest result represents a statistically significant change.
    """

    def __init__(
        self, last_result: float, results: Sequence[int | float], threshold: float = 2.5
    ):
        # Use robust statistics (median/MAD) to handle outliers
        arr = numpy.array(results)
        self.mean = numpy.median(arr)
        mad = numpy.median(numpy.abs(arr - self.mean))
        self.std = mad * 1.4826 if mad else 0
        self.noise = self.std / self.mean if self.mean else 0
        self.pct_change = (
            ((last_result - self.mean) / self.mean) * 100 if self.mean else 0
        )

        if self.std == 0:
            # No variance in history - can't determine significance
            self.z_score = 0
            self.is_significant = False
        else:
            self.z_score = (last_result - self.mean) / self.std
            self.is_significant = (
                abs(self.z_score) > threshold and abs(self.pct_change) > 2.0
            )


class Result:
    """Single benchmark result for a specific commit."""

    @classmethod
    def from_json(cls, commit: git.Commit, json: dict) -> "Result":
        return Result(
            commit,
            json["name"],
            json["iterations"],
            json["real_time"] * ureg(json["time_unit"]),
            json["cpu_time"] * ureg(json["time_unit"]),
            json.get("nInsn", 0),
            json.get("label", ""),
            bool(json.get("use_set", 0)),
            bool(json.get("use_log", 0)),
            bool(json.get("userspace_only", 0)),
        )

    def __init__(
        self,
        commit: git.Commit,
        benchmark_name: str,
        iterations: int,
        real_time: pint.Quantity,
        cpu_time: pint.Quantity,
        n_insn: int,
        label: str,
        use_set: bool = False,
        use_log: bool = False,
        userspace_only: bool = False,
    ):
        self.commit_sha = commit.hexsha
        self.commit_summary = commit.summary
        self.benchmark_name = benchmark_name
        self.iterations = iterations
        self.real_time = real_time
        self.cpu_time = cpu_time
        self.nInsn = n_insn
        self.label = label
        self.use_set = use_set
        self.use_log = use_log
        self.userspace_only = userspace_only

    @property
    def short_commit_sha(self) -> str:
        return self.commit_sha[:SHORT_SHA_LEN]

    @property
    def time(self) -> pint.Quantity:
        return self.cpu_time


class Benchmark:
    """Collection of benchmark results across multiple commits."""

    def __init__(self, name: str):
        self._name = name
        self._results: list[Result] = []
        self._label = ""

    def add_result(self, result: Result) -> None:
        self._results.append(result)
        self._label = result.label

    @property
    def name(self) -> str:
        return self._name

    @property
    def label(self) -> str:
        return self._label

    def get_stats(self, n: int) -> dict | None:
        if len(self._results) < n + 1:
            return None

        times = [x.time.to("nanoseconds").magnitude for x in self._results]
        nInsns = self.nInsns

        return {
            "time": Analyzer(times[-1], times[-n - 1 : -1]),
            "nInsn": Analyzer(nInsns[-1], nInsns[-n - 1 : -1]) if nInsns else None,
        }

    @property
    def last(self) -> Result | None:
        return self._results[-1] if self._results else None

    @property
    def results(self) -> list[Result]:
        return list(self._results)

    @property
    def times(self) -> list[int]:
        return [x.time.to(ureg.ns).magnitude for x in self._results]

    @property
    def nInsns(self) -> list[int] | None:
        """Return instruction counts, or None if any result lacks instruction data."""
        nInsns = [x.nInsn for x in self._results]
        # nInsn defaults to 0 when missing from JSON, so treat 0 as missing data
        if any(n == 0 for n in nInsns):
            return None
        return nInsns

    @property
    def use_set(self) -> bool:
        return self.last.use_set if self.last else False

    @property
    def use_log(self) -> bool:
        return self.last.use_log if self.last else False

    @property
    def userspace_only(self) -> bool:
        return self.last.userspace_only if self.last else False

    @property
    def commits_sha(self) -> list[str]:
        return [x.commit_sha for x in self._results]

    @property
    def short_commits_sha(self) -> list[str]:
        return [x.short_commit_sha for x in self._results]

    @property
    def commit_subjects(self) -> list[str]:
        return [str(x.commit_summary) for x in self._results]


class History:
    """Manages benchmark results history across all commits."""

    def __init__(self) -> None:
        self._benchmarks: dict[str, Benchmark] = {}
        self._last_order: list[str] = []

    def add_results(self, results: list[Result]) -> None:
        order: list[str] = []

        for result in results:
            benchmark_name = result.benchmark_name

            # If the benchmark doesn't exist yet, create it
            if benchmark_name not in self._benchmarks:
                self._benchmarks[benchmark_name] = Benchmark(benchmark_name)

            self._benchmarks[benchmark_name].add_result(result)
            order.append(benchmark_name)

        self._last_order = order

    @property
    def benchmarks(self) -> dict[str, Benchmark]:
        return self._benchmarks

    def sorted_benchmarks(self) -> list[Benchmark]:
        return [self._benchmarks[name] for name in self._last_order]


def get_cache_key(commit: git.Commit, host: str) -> str:
    return f"{commit.hexsha}-{host}"


class Executor(ABC):
    """
    Context to execute the benchmark.

    The Executor transparently handle local or remote commands.
    """

    def __init__(self, args: argparse.Namespace, renderer: Renderer | None = None):
        self._host: str = args.host
        self._workdir: pathlib.Path = (
            pathlib.Path(tempfile.gettempdir()) / f"bpfilter-{uuid.uuid4().hex[:8]}"
        )
        self._local_workdir: pathlib.Path = self._workdir
        self._cache_dir: pathlib.Path = args.cache_dir
        self._stats = Stats(self._host)
        self._cache = diskcache.Cache(self._cache_dir)
        self._local_workdir.mkdir()
        self._retry_shas: set[str] = set()
        self._commits: list[git.Commit] = []
        self._renderer = renderer
        self._source = FilesystemSource(
            args.sources, self._local_workdir / "bpfilter", renderer
        )
        self._results = History()
        self._args = args

        self._current_commit: git.Commit | None = None

    @property
    def retry_shas(self) -> set[str]:
        return self._retry_shas

    def resolve(self, ref: str) -> str:
        """Resolve a commit ref to a SHA, including the "wip" sentinel."""
        return self._source.resolve(ref)

    @property
    def commits(self) -> list[git.Commit]:
        return self._commits

    @property
    def results(self) -> History:
        return self._results

    @property
    def current_commit(self) -> git.Commit | None:
        return self._current_commit

    @current_commit.setter
    def current_commit(self, commit: git.Commit):
        self._current_commit = commit

    @property
    def host(self) -> str:
        return self._host

    @property
    def srcdir(self) -> pathlib.Path:
        return self._local_workdir / "bpfilter"

    @property
    def cache(self) -> diskcache.Cache:
        return self._cache

    @property
    def is_remote(self) -> bool:
        return self._host not in DEFAULT_HOST

    @property
    def stats(self) -> Stats:
        return self._stats

    @property
    def work_dir(self) -> pathlib.Path:
        return self._workdir

    def __enter__(self) -> Executor:
        self.log(f'Preparing sources from "{self._source.local}"')

        self._commits, self._retry_shas = self._source.prepare(
            since=self._args.since,
            until=self._args.until,
            include=self._args.include,
            retry=self._args.retry,
        )

        if not self.commits:
            self.log("No commits found in the specified range")
            raise FileNotFoundError

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._cache.close()
        self._current_commit = None
        shutil.rmtree(self._local_workdir)

    def log(self, msg: str):
        if commit := self._current_commit:
            index = self.commits.index(commit)
            log = f"\\[[yellow bold]{commit.hexsha[:SHORT_SHA_LEN]}[/], {index + 1}/{len(self.commits)}] {msg}"
        else:
            log = msg
        (self._renderer or renderer).log(log)

    @abstractmethod
    def _run(self, cmd: list[str], timeout: int | None = None) -> int:
        pass

    def _substitute_workdir(self, cmd: list[str]) -> list[str]:
        """Replace {WORKDIR} placeholder in command arguments."""
        return [str(item).replace("{WORKDIR}", str(self._workdir)) for item in cmd]

    def run(self, cmd: list[str], timeout: int | None = None) -> int:
        return self._run(self._substitute_workdir(cmd), timeout)

    def run_benchmark_cmd(
        self,
        message: str,
        commit: git.Commit,
        cmd: list[str],
        timeout: int | None = None,
    ) -> bool:
        self.log(f"[blue bold]{message}[/]")

        r = self._run(self._substitute_workdir(cmd), timeout)
        if r:
            self.log(f"[red bold]{message} failed[/]")
            self.stats.failure(commit_sha=commit.hexsha, from_cache=False)
            self.cache[get_cache_key(commit, self._host)] = {"success": False}

        return r == 0

    def add_results(self, commit: git.Commit, results: dict):
        self._results.add_results([Result.from_json(commit, raw) for raw in results])
        self.cache[get_cache_key(commit, self.host)] = {
            "success": True,
            "results": results,
        }


class RemoteExecutor(Executor):
    """Executor that runs benchmarks on a remote host via SSH."""

    def __enter__(self) -> RemoteExecutor:
        super().__enter__()

        self.log(f"Connecting to remote host {self._host}")
        self._remote_workdir = self._workdir
        self._agent: paramiko.Agent | None = None

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.WarningPolicy())

        if self._args.ssh_key:
            self._client.connect(
                self._host,
                username=DEFAULT_USERNAME,
                key_filename=str(self._args.ssh_key.expanduser()),
                allow_agent=False,
                look_for_keys=False,
            )
        else:
            self._agent = paramiko.Agent()
            for key in self._agent.get_keys():
                if self._host.lower() in key.comment.lower():
                    pkey = key
                    break
            else:
                raise RuntimeError(f"No SSH agent key found matching '{self._host}'")

            self._client.connect(
                self._host,
                username=DEFAULT_USERNAME,
                pkey=pkey,
                allow_agent=False,
            )

        # From now on, all self.run() commands are run on the remote host
        self.run(["hostname"])

        self.run(["mkdir", "-p", str(self._remote_workdir)])
        r = self.run(
            [
                "sshfs",
                f"{DEFAULT_USERNAME}@{DEFAULT_HOST[0]}:{self._local_workdir}",
                str(self._remote_workdir),
                "-C",
                "-o",
                "allow_other,default_permissions,exec,user,identityfile=~/.ssh/id_ed25519",
            ]
        )
        if r:
            raise RuntimeError(
                f"Failed to mount local workdir on remote host (sshfs exit code: {r})"
            )

        return self

    def _run(self, cmd: list[str], timeout: int | None = None) -> int:
        transport = self._client.get_transport()
        if transport is None:
            raise RuntimeError("SSH transport is not connected")
        channel = transport.open_session()
        channel.set_combine_stderr(True)
        channel.settimeout(timeout)

        try:
            channel.exec_command(shlex.join(cmd))
            while data := channel.recv(1024):
                for line in data.decode("utf-8").splitlines():
                    self.log(line)
        except socket.timeout:
            self.log(f"Command timed out after {timeout}s")
            return errno.ETIMEDOUT
        except KeyboardInterrupt:
            # Forward Ctrl+C to the process
            channel.send(b"\x03")
            channel.close()
            raise

        # Ensure the process is terminated
        channel.recv_exit_status()

        return channel.exit_status

    def __exit__(self, exc_type, exc_value, traceback):
        self.run(["umount", "-l", str(self._remote_workdir)])
        self.run(["rm", "-rf", str(self._remote_workdir)])
        self._client.close()
        if self._agent:
            self._agent.close()
        super().__exit__(exc_type, exc_value, traceback)


class LocalExecutor(Executor):
    """Executor that runs benchmarks on the local host."""

    def _run(self, cmd: list[str], timeout: int | None = None) -> int:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        if p.stdout is None:
            raise RuntimeError("Failed to capture subprocess stdout")

        start_time = time.time()

        while True:
            if timeout and (time.time() - start_time) > timeout:
                p.kill()
                p.wait()
                self.log(f"Command timed out after {timeout}s")
                return errno.ETIMEDOUT

            ready, _, _ = select.select([p.stdout], [], [], 0.1)
            if ready:
                line = p.stdout.readline()
                if not line:
                    break
                line = line.rstrip()
                if line:
                    self.log(line)
            elif p.poll() is not None:
                break

        p.wait()
        return p.returncode if p.returncode is not None else 1


class FilesystemSource:
    """Manages source repository for benchmarking, including WIP commits."""

    def __init__(
        self,
        path: str,
        local_src_dir: pathlib.Path,
        renderer: Renderer | None = None,
    ) -> None:
        self._path = pathlib.Path(path)
        self._local = local_src_dir
        self._renderer = renderer

        shutil.copytree(self._path, self._local, dirs_exist_ok=True)
        self._detach_if_worktree()
        self._repo: git.Repo = git.Repo(self._local)
        self._retry_all: bool = False
        self._retry_failed: bool = False
        self._resolved: dict[str, str] = {}

    def _log(self, msg: str) -> None:
        (self._renderer or renderer).log(msg)

    def _detach_if_worktree(self) -> None:
        """Convert a copied git worktree into a standalone repository.

        In a git worktree the .git entry is a file containing a gitdir pointer
        to the original repo's worktree-specific state. shutil.copytree copies
        that file verbatim, so all git operations on the copy would mutate the
        original worktree's HEAD and index. Detect that case and replace the
        .git file with a self-contained .git directory built from the
        worktree-specific state (HEAD, index) and the shared commondir
        (objects, refs, config, ...).
        """
        git_entry = self._local / ".git"
        if not git_entry.is_file():
            return

        content = git_entry.read_text().strip()
        if not content.startswith("gitdir:"):
            return

        wt_gitdir = pathlib.Path(content.split(":", 1)[1].strip())
        if not wt_gitdir.is_absolute():
            wt_gitdir = (self._local / wt_gitdir).resolve()

        commondir_file = wt_gitdir / "commondir"
        if commondir_file.exists():
            commondir = (wt_gitdir / commondir_file.read_text().strip()).resolve()
        else:
            commondir = wt_gitdir

        git_entry.unlink()
        shutil.copytree(commondir, self._local / ".git")

        # Drop worktrees/: entries are specific to the original repo.
        worktrees_dir = self._local / ".git" / "worktrees"
        if worktrees_dir.exists():
            shutil.rmtree(worktrees_dir)

        # Apply this worktree's HEAD and index, which differ from the main
        # worktree's equivalents.
        for fname in ("HEAD", "index"):
            src = wt_gitdir / fname
            if src.exists():
                shutil.copy2(src, self._local / ".git" / fname)

    @property
    def local(self) -> pathlib.Path:
        """Local path to the source repository copy."""
        return self._local

    def _rev_parse(self, ref: str) -> str:
        """Resolve `ref` to a SHA and cache the result."""
        sha: str = self._repo.git.rev_parse(ref)
        self._resolved[ref] = sha
        return sha

    def resolve(self, ref: str) -> str:
        """Resolve a commit ref to a SHA, including the "wip" sentinel.

        prepare() caches the SHA of every ref it resolves, before the WIP
        commit is created. Reusing that cache keeps refs such as "HEAD"
        pointing to the commit they designated back then, and maps "wip" to
        the commit holding the uncommitted changes.

        Args:
            ref: Commit ref, or "wip" for the uncommitted changes.

        Returns:
            The commit SHA.
        """
        if is_wip(ref):
            if "wip" not in self._resolved:
                raise ValueError('"wip" can only be resolved once prepared')
            return self._resolved["wip"]

        return self._resolved.get(ref) or self._rev_parse(ref)

    def _commit_wip(self) -> git.Commit:
        """Commit uncommitted changes as WIP and return the commit."""
        if self._repo.is_dirty(untracked_files=True):
            self._log("Committing uncommitted changes as WIP")
            self._repo.git.add(A=True)
            self._repo.index.commit("bfbencher: WIP")
        return self._repo.head.commit

    def prepare(
        self,
        since: str,
        until: str,
        include: list[str],
        retry: list[str],
    ) -> tuple[list[git.Commit], set[str]]:
        """
        Prepare the source repository and return commits to benchmark.

        Args:
            since: Oldest commit ref, or "wip" for uncommitted changes
            until: Newest commit ref, or "wip" for uncommitted changes
            include: Extra commit refs to include, supports "wip"
            retry: Commit refs to retry (ignore cache for these)

        Returns:
            Tuple of (commits in topological order, set of retry commit SHAs)
        """

        self._retry_all = "all" in retry
        self._retry_failed = "failed" in retry

        include = include or []
        retry = retry or []
        has_wip = is_wip(since) or is_wip(until) or any(is_wip(ref) for ref in include)

        # Resolve non-wip refs to SHAs BEFORE committing WIP (so HEAD refers to
        # the original HEAD, not the WIP commit)
        since_sha = None if is_wip(since) else self._rev_parse(since)
        until_sha = None if is_wip(until) else self._rev_parse(until)
        include_shas = [
            None if is_wip(ref) else self._rev_parse(ref) for ref in include
        ]
        retry_shas = set()
        for ref in retry:
            if ref in ("all", "failed"):
                continue
            try:
                retry_shas.add(self._repo.git.rev_parse(ref))
            except git.exc.GitCommandError:
                self._log(f"Warning: could not resolve retry ref '{ref}'")

        # Handle uncommitted changes
        if self._repo.is_dirty(untracked_files=True):
            if has_wip:
                self._commit_wip()
            else:
                self._log("Discarding uncommitted changes in source directory")
                self._repo.git.reset("--hard", "HEAD")
                self._repo.git.clean("-fd")

        # Resolve refs (wip -> HEAD which now points to the WIP commit)
        self._resolved["wip"] = self._repo.head.commit.hexsha
        since_ref = since_sha or self._resolved["wip"]
        until_ref = until_sha or self._resolved["wip"]

        # Get commits in range
        commits = list(
            self._repo.iter_commits(f"{since_ref}^..{until_ref}", reverse=True)
        )
        commit_set = {c.hexsha for c in commits}

        # Process included commits (use pre-resolved SHAs)
        for ref, sha in zip(include, include_shas):
            # sha is None for "wip" refs, use the resolved WIP commit
            commit_sha = sha or self._resolved["wip"]
            commit = self._repo.commit(commit_sha)

            if commit.hexsha not in commit_set:
                commits.append(commit)
                commit_set.add(commit.hexsha)
                self._log(
                    f"Including commit {commit.hexsha[:SHORT_SHA_LEN]}: {str(commit.summary)}"
                )
            else:
                self._log(f"Commit {ref} already in range, skipping")

        # Sort commits in topological order (oldest first)
        if len(commits) > 1:
            all_shas = [c.hexsha for c in commits]
            ordered_shas = self._repo.git.rev_list(
                "--topo-order", "--reverse", *all_shas, "--"
            ).splitlines()
            sha_to_commit = {c.hexsha: c for c in commits}
            commits = [
                sha_to_commit[sha] for sha in ordered_shas if sha in sha_to_commit
            ]

        if include:
            self._log(
                f"Found {len(commits)} commits ({since_ref}..{until_ref} + {len(include)} included)"
            )
        else:
            self._log(f"Found {len(commits)} commits ({since_ref}..{until_ref})")

        return commits, retry_shas

    @property
    def repo(self) -> git.Repo:
        return self._repo

    @property
    def retry_all(self) -> bool:
        return self._retry_all

    @property
    def retry_failed(self) -> bool:
        return self._retry_failed


def has_significant_change(
    benchmark: Benchmark, terms: list[int], direction: str = "any"
) -> bool:
    """Check if a benchmark has any statistically significant change.

    Args:
        benchmark: The benchmark to check.
        terms: List of term lengths to check.
        direction: One of "any", "better", or "worse".
            - "any": any significant change
            - "better": significant improvement (negative pct_change)
            - "worse": significant regression (positive pct_change)
    """
    for term in terms:
        stats = benchmark.get_stats(term)
        if not stats:
            continue
        for analyzer in [stats["time"], stats["nInsn"]]:
            if not analyzer or not analyzer.is_significant:
                continue
            if direction == "any":
                return True
            elif direction == "better" and analyzer.pct_change < 0:
                return True
            elif direction == "worse" and analyzer.pct_change > 0:
                return True
    return False


class BenchmarkContext:
    """Context manager for benchmarking a single commit."""

    def __init__(self, executor: Executor, commit: git.Commit):
        self._executor: Executor = executor
        self._commit: git.Commit = commit

    def __enter__(self) -> "BenchmarkContext":
        self._executor._source.repo.git.checkout(self._commit)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        return True

    @property
    def short_commit_sha(self) -> str:
        """Shortened commit SHA for display and directory names."""
        return self._commit.hexsha[:SHORT_SHA_LEN]

    @property
    def build_dir(self) -> pathlib.Path:
        return self._executor.work_dir / self.short_commit_sha

    @property
    def results_path(self) -> pathlib.Path:
        return self.build_dir / "results.json"

    @property
    def commit(self) -> git.Commit:
        return self._commit

    @property
    def source_dir(self) -> pathlib.Path:
        return self._executor.work_dir / "bpfilter"

    @property
    def bfcli_path(self) -> pathlib.Path:
        return self.build_dir / "output/sbin/bfcli"

    def configure(self, doc: bool = False, checks: bool = False) -> bool:
        cmd: list[str] = [
            "cmake",
            "-S",
            str(self.source_dir),
            "-B",
            str(self.build_dir),
        ]

        # Older commits only know about the NO_* options.
        if not doc:
            cmd += ["-DWITH_DOCS=OFF", "-DNO_DOCS=1"]
        if not checks:
            cmd += ["-DWITH_TESTS_CHECKS=OFF", "-DNO_CHECKS=1"]

        return self._executor.run_benchmark_cmd("Configuring CMake", self._commit, cmd)

    def make(self, target: str) -> bool:
        cmd = [
            "make",
            "-C",
            str(self.build_dir),
            "-j",
            str(multiprocessing.cpu_count()),
            target,
        ]

        return self._executor.run_benchmark_cmd(f"Building {target}", self._commit, cmd)

    def flush(self) -> bool:
        cmd = ["sudo", "rm", "-rf", "/sys/fs/bpf/bpfilter"]

        return self._executor.run_benchmark_cmd(
            "Flushing leftover chains", self._commit, cmd
        )

    def run_benchmark(
        self,
        bind_node: int | None = None,
        no_preempt: bool = False,
        cpu_pin: int | None = None,
        slice: str | None = None,
    ) -> bool:
        cmd = [
            str(self.build_dir / "output/sbin/benchmark_bin"),
            "--cli",
            str(self.bfcli_path),
            "--srcdir",
            str(self.source_dir),
            "--outfile",
            str(self.results_path),
        ]

        if cpu_pin is not None:
            cmd = ["taskset", "-c", str(cpu_pin)] + cmd
        if no_preempt:
            cmd = ["chrt", "-f", "99"] + cmd
        if bind_node is not None:
            cmd = [
                "numactl",
                "--membind",
                str(bind_node),
                "--cpunodebind",
                str(bind_node),
            ] + cmd

        systemd_cmd = ["sudo", "systemd-run"]
        if slice:
            systemd_cmd += ["--slice", slice]
        systemd_cmd += ["--scope"]
        cmd = systemd_cmd + cmd

        return self._executor.run_benchmark_cmd("Running benchmarks", self._commit, cmd)

    @property
    def results(self) -> dict | None:
        if not self.results_path.exists():
            return None

        with open(self.results_path, "r") as results_file:
            return json.load(results_file)["benchmarks"]

    @classmethod
    def commits(cls, executor, **kwargs):
        for commit in executor.commits:
            executor.current_commit = commit

            cache_key = f"{commit.hexsha}-{executor.host}"
            skip_cache = (
                executor._source.retry_all or commit.hexsha in executor.retry_shas
            )
            cached_data = None if skip_cache else executor.cache.get(cache_key, {})

            # Handle the cache, restore data if possible
            if cached_data and cached_data.get("success", False):
                executor.log("Using cached results")
                executor.stats.success(from_cache=True)
                executor._results.add_results(
                    [Result.from_json(commit, raw) for raw in cached_data["results"]]
                )
                continue
            elif cached_data and not executor._source.retry_failed:
                executor.log("Skipping (cached failure)")
                executor.stats.failure(commit_sha=commit.hexsha, from_cache=True)
                continue

            executor.log(
                f'[yellow bold]Benchmarking "{commit.summary}" ({commit.hexsha[:SHORT_SHA_LEN]})[/]'
            )

            with cls(executor, commit, **kwargs) as ctx:
                yield ctx


class Report:
    """Generates benchmark reports in various formats (HTML, console)."""

    @dataclasses.dataclass
    class TermStats:
        """Statistics for a single term (e.g., 5 or 15 commits)."""

        pct_change: float
        is_significant: bool
        mean: float
        noise: float

    @dataclasses.dataclass
    class BenchmarkRow:
        """Prepared data for a single benchmark row."""

        name: str
        label: str
        time_str: str
        insn_str: str | None
        terms: dict[
            int, dict[str, Report.TermStats | None]
        ]  # term -> {"time": ..., "nInsn": ...}
        runtime_ns: float = 0  # Runtime in nanoseconds for sorting
        insn_count: int = 0  # Instruction count for sorting
        use_set: bool = False
        use_log: bool = False
        userspace_only: bool = False

    @dataclasses.dataclass
    class CompareRow:
        """Prepared data for a single benchmark row in compare mode."""

        name: str
        label: str
        base_time_str: str
        ref_time_str: str
        delta_time_str: str
        delta_time_pct: float
        base_insn: int | None
        ref_insn: int | None
        delta_insn: int | None
        delta_insn_pct: float | None
        base_time_ns: float
        ref_time_ns: float
        use_set: bool = False
        use_log: bool = False
        userspace_only: bool = False

    def __init__(self, history: History):
        self._history = history

    def _get_benchmark_rows(self, terms: list[int]) -> list[BenchmarkRow]:
        """Prepare benchmark data for rendering in any format."""
        rows = []
        for benchmark in self._history.sorted_benchmarks():
            last = benchmark.last
            if not last:
                continue

            time_str = f"{last.time:~.2f}"
            insn_str = f"{last.nInsn:.0f}" if last.nInsn else None
            runtime_ns = last.time.to("ns").magnitude
            insn_count = last.nInsn or 0

            term_data = {}
            for term in terms:
                bench_stats = benchmark.get_stats(term)
                if bench_stats:
                    time_analyzer = bench_stats["time"]
                    insn_analyzer = bench_stats["nInsn"]
                    term_data[term] = {
                        "time": Report.TermStats(
                            pct_change=time_analyzer.pct_change,
                            is_significant=time_analyzer.is_significant,
                            mean=time_analyzer.mean,
                            noise=time_analyzer.noise,
                        ),
                        "nInsn": Report.TermStats(
                            pct_change=insn_analyzer.pct_change,
                            is_significant=insn_analyzer.is_significant,
                            mean=insn_analyzer.mean,
                            noise=insn_analyzer.noise,
                        )
                        if insn_analyzer
                        else None,
                    }
                else:
                    term_data[term] = {"time": None, "nInsn": None}

            rows.append(
                Report.BenchmarkRow(
                    name=benchmark.name,
                    label=benchmark.label,
                    time_str=time_str,
                    insn_str=insn_str,
                    terms=term_data,
                    runtime_ns=runtime_ns,
                    insn_count=insn_count,
                    use_set=benchmark.use_set,
                    use_log=benchmark.use_log,
                    userspace_only=benchmark.userspace_only,
                )
            )

        return rows

    def write_report(
        self,
        commits: list[git.Commit],
        stats: Stats,
        template_path: pathlib.Path,
        report_path: pathlib.Path,
        terms: list[int],
    ):
        if not commits:
            raise ValueError("Cannot generate report with empty commits list")

        rows = self._get_benchmark_rows(terms)

        env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_path.parent))
        template = env.get_template(template_path.name)

        with open(report_path, "w") as f:
            f.write(
                template.render(
                    history=self._history,
                    rows=rows,
                    hostname=stats.host,
                    first_commit_sha=commits[0].hexsha,
                    last_commit_sha=commits[-1].hexsha,
                    n_commits=len(commits),
                    stats=stats,
                    terms=terms,
                    ureg=ureg,
                    get_class=lambda stats: (
                        "neutral"
                        if not stats.is_significant
                        else "is-significant text-danger"
                        if stats.pct_change > 0
                        else "is-significant text-success"
                    ),
                )
            )

    def write_pr_report(
        self,
        commits: list[git.Commit],
        stats: Stats,
        template_path: pathlib.Path,
        report_path: pathlib.Path,
        terms: list[int],
    ):
        rows = self._get_benchmark_rows(terms)

        env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_path.parent))
        template = env.get_template(template_path.name)

        def format_delta(s) -> str:
            pct = f"{s.pct_change:+.2f}%"
            if not s.is_significant:
                return f"<code>{pct}</code>"
            emoji = "🔴" if s.pct_change > 0 else "🟢"
            return f"<code><strong>{pct}</strong></code> {emoji}"

        def has_significant_change(row):
            for term_data in row.terms.values():
                time_stats = term_data.get("time")
                insn_stats = term_data.get("nInsn")
                if (time_stats and time_stats.is_significant) or (
                    insn_stats and insn_stats.is_significant
                ):
                    return True
            return False

        summary_rows = [r for r in rows if has_significant_change(r)]

        with open(report_path, "w") as f:
            f.write(
                template.render(
                    rows=summary_rows,
                    terms=terms,
                    stats=stats,
                    format_delta=format_delta,
                )
            )

    def print_report(self, terms: list[int]):
        rows = self._get_benchmark_rows(terms)
        renderer.print_report(rows, terms)

    def get_compare_rows(self, base_sha: str, ref_sha: str) -> list[CompareRow]:
        """Build per-benchmark base/ref comparison rows."""
        rows = []
        for benchmark in self._history.sorted_benchmarks():
            base_result = next(
                (r for r in benchmark.results if r.commit_sha == base_sha), None
            )
            ref_result = next(
                (r for r in benchmark.results if r.commit_sha == ref_sha), None
            )
            if not base_result or not ref_result:
                continue

            base_ns: float = float(base_result.time.to("ns").magnitude)
            ref_ns: float = float(ref_result.time.to("ns").magnitude)
            delta_ns: float = ref_ns - base_ns
            delta_pct: float = (delta_ns / base_ns * 100) if base_ns else 0.0

            base_insn = int(base_result.nInsn) if base_result.nInsn else None
            ref_insn = int(ref_result.nInsn) if ref_result.nInsn else None
            if base_insn is not None and ref_insn is not None:
                delta_insn: int | None = ref_insn - base_insn
                delta_insn_pct: float | None = (
                    (delta_insn / base_insn * 100) if base_insn else 0.0
                )
            else:
                delta_insn = None
                delta_insn_pct = None

            rows.append(
                Report.CompareRow(
                    name=benchmark.name,
                    label=benchmark.label,
                    base_time_str=f"{base_result.time:~.2f}",
                    ref_time_str=f"{ref_result.time:~.2f}",
                    delta_time_str=(
                        f"{(delta_ns * ureg.ns).to_compact():+~.2f}"
                        if abs(delta_ns) >= 1
                        else f"{delta_ns * ureg.ns:+~.2f}"
                    ),
                    delta_time_pct=delta_pct,
                    base_insn=base_insn,
                    ref_insn=ref_insn,
                    delta_insn=delta_insn,
                    delta_insn_pct=delta_insn_pct,
                    base_time_ns=base_ns,
                    ref_time_ns=ref_ns,
                    use_set=benchmark.use_set,
                    use_log=benchmark.use_log,
                    userspace_only=benchmark.userspace_only,
                )
            )

        return rows

    def print_compare_report(self, base_sha: str, ref_sha: str) -> None:
        rows = self.get_compare_rows(base_sha, ref_sha)
        renderer.print_compare_report(rows, base_sha, ref_sha)

    def write_compare_json(
        self,
        path: pathlib.Path,
        base_sha: str,
        ref_sha: str,
        host: str,
    ) -> None:
        rows = self.get_compare_rows(base_sha, ref_sha)
        data = {
            "base": base_sha,
            "ref": ref_sha,
            "host": host,
            "benchmarks": [
                {
                    "name": r.name,
                    "base_time_ns": r.base_time_ns,
                    "ref_time_ns": r.ref_time_ns,
                    "delta_time_ns": r.ref_time_ns - r.base_time_ns,
                    "delta_time_pct": r.delta_time_pct,
                    "base_insn": r.base_insn,
                    "ref_insn": r.ref_insn,
                    "delta_insn": r.delta_insn,
                    "delta_insn_pct": r.delta_insn_pct,
                    "use_set": r.use_set,
                    "use_log": r.use_log,
                    "userspace_only": r.userspace_only,
                }
                for r in rows
            ],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)


def _benchmark_commits(executor: Executor, args: argparse.Namespace) -> None:
    """Run the configure -> build -> benchmark pipeline for each commit."""
    for ctx in BenchmarkContext.commits(executor):
        if not ctx.configure():
            continue
        if not ctx.make("bfcli"):
            continue
        if not ctx.make("benchmark_bin"):
            continue
        if not ctx.flush():
            continue
        if not ctx.run_benchmark(
            args.bind_node, args.no_preempt, args.cpu_pin, args.slice
        ):
            continue

        results = ctx.results
        if not results:
            executor.log(f"could not find {ctx.results_path}")
            continue

        executor.add_results(ctx.commit, results)
        executor.log("Done!")


def run_benchmarks(args: argparse.Namespace):
    executor = (
        LocalExecutor(args) if args.host in DEFAULT_HOST else RemoteExecutor(args)
    )

    with executor:
        _benchmark_commits(executor, args)

        report = Report(executor._results)
        if args.report_path:
            report.write_report(
                executor.commits,
                executor.stats,
                args.report_template_path,
                args.report_path,
                [20],
            )
        if args.pr_report_path:
            report.write_pr_report(
                executor.commits,
                executor.stats,
                args.pr_report_template_path,
                args.pr_report_path,
                [20],
            )
        report.print_report([20])

    failed_shas = executor.stats.failed_shas
    if args.fail_on_last_commit_failure and executor.commits:
        last_sha = executor.commits[-1].hexsha
        if last_sha in failed_shas:
            renderer.log(
                f"[red bold]The last commit ({last_sha[:SHORT_SHA_LEN]}) failed "
                f"to build or run; failing the bfbencher invocation.[/]"
            )
            raise SystemExit(1)

    if args.fail_on_any_commit_failure and failed_shas:
        renderer.log(
            f"[red bold]{len(failed_shas)} commit(s) failed to build or run; "
            f"failing the bfbencher invocation.[/]"
        )
        raise SystemExit(1)

    if args.fail_on_significant_change:
        terms = [20]
        for benchmark in executor.results.sorted_benchmarks():
            if has_significant_change(
                benchmark, terms, args.fail_on_significant_change
            ):
                raise SystemExit(1)


def run_compare(args: argparse.Namespace) -> None:
    # _benchmark_commits walks the history range; treat base+ref as a
    # two-commit "range" by anchoring both ends on base and including ref.
    args.since = args.base
    args.until = args.base
    args.include = [args.ref]

    executor = (
        LocalExecutor(args) if args.host in DEFAULT_HOST else RemoteExecutor(args)
    )

    with executor:
        # Resolve once the sources are prepared: "wip" is a commit only after
        # the uncommitted changes have been committed.
        base_sha: str = executor.resolve(args.base)
        ref_sha: str = executor.resolve(args.ref)

        if base_sha == ref_sha:
            renderer.log(
                f"[red bold]{args.base} and {args.ref} are the same commit "
                f"({base_sha[:SHORT_SHA_LEN]}), nothing to compare.[/]"
            )
            raise SystemExit(1)

        _benchmark_commits(executor, args)

        report = Report(executor._results)
        report.print_compare_report(base_sha, ref_sha)

        if args.json_output:
            report.write_compare_json(
                args.json_output, base_sha, ref_sha, executor.host
            )


def compare(
    base: str,
    ref: str,
    *,
    sources: pathlib.Path = DEFAULT_SOURCE_PATH,
    host: str = DEFAULT_HOST[0],
    ssh_key: pathlib.Path | None = None,
    cache_dir: pathlib.Path = DEFAULT_CACHE_PATH,
    bind_node: int | None = None,
    no_preempt: bool = False,
    cpu_pin: int | None = None,
    slice: str | None = None,
    retry: list[str] | None = None,
    renderer: Renderer | None = None,
) -> list[Report.CompareRow]:
    """Programmatic compare API.

    Runs benchmarks for `base` and `ref` (with cache reuse when possible)
    and returns one CompareRow per benchmark with delta_time / delta_insn
    fields. This is the fitness signal consumed by tools like bfoptimize.
    Progress messages go to `renderer`, or the module default when None.
    """
    args = argparse.Namespace(
        sources=sources,
        host=host,
        ssh_key=ssh_key,
        cache_dir=cache_dir,
        bind_node=bind_node,
        no_preempt=no_preempt,
        cpu_pin=cpu_pin,
        slice=slice,
        retry=list(retry) if retry else [],
        fail_on_significant_change=None,
        fail_on_last_commit_failure=False,
        fail_on_any_commit_failure=False,
        base=base,
        ref=ref,
        since=base,
        until=base,
        include=[ref],
        json_output=None,
    )

    executor = (
        LocalExecutor(args, renderer)
        if args.host in DEFAULT_HOST
        else RemoteExecutor(args, renderer)
    )

    with executor:
        base_sha = executor.resolve(base)
        ref_sha = executor.resolve(ref)

        _benchmark_commits(executor, args)
        return Report(executor._results).get_compare_rows(base_sha, ref_sha)


def main():
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "--sources",
        type=pathlib.Path,
        help=f'path to the bpfilter sources directory. Defaults to "{DEFAULT_SOURCE_PATH}".',
        default=DEFAULT_SOURCE_PATH,
    )
    shared.add_argument(
        "--host",
        type=str,
        help=f'host to run the benchmark on. bfbencher will connect to the host using SSH, copy the project sources on it, and run the benchmarks. Defaults to "{DEFAULT_HOST[0]}" (current host).',
        default=DEFAULT_HOST[0],
    )
    shared.add_argument(
        "--ssh-key",
        type=pathlib.Path,
        help="path to the SSH private key used to authenticate to the remote host. If not set, the key is looked up in the SSH agent by matching the host name against the key comments.",
        default=None,
    )
    shared.add_argument(
        "--cache-dir",
        type=pathlib.Path,
        help=f"path to the directory containing the cached results. The cache is used to store benchmark results based on the hostname and the commit SHA, it is stored on the host running bfbencher. Defaults to {DEFAULT_CACHE_PATH}.",
        default=DEFAULT_CACHE_PATH,
    )
    shared.add_argument(
        "--retry",
        "-r",
        type=str,
        action="append",
        default=[],
        help='retry benchmarks for specific commits, ignoring cached results. Use "failed" to retry all failed commits, "all" to retry everything, or a commit ref to retry a specific commit. Can be specified multiple times.',
    )
    shared.add_argument(
        "--fail-on-significant-change",
        choices=["better", "worse", "any"],
        help="exit with non-zero status if any benchmark has a statistically significant change (better=improvement, worse=regression, any=either)",
        default=None,
    )
    shared.add_argument(
        "--fail-on-last-commit-failure",
        action="store_true",
        help="exit with non-zero status if the last (newest) commit failed to build or run, including cached failures.",
        default=False,
    )
    shared.add_argument(
        "--fail-on-any-commit-failure",
        action="store_true",
        help="exit with non-zero status if any commit failed to build or run, including cached failures.",
        default=False,
    )
    shared.add_argument(
        "--bind-node",
        type=int,
        help="CPU and memory node to bind the benchmark to.",
        default=None,
    )
    shared.add_argument(
        "--no-preempt",
        action="store_true",
        help="if set, use chrt to run the benchmark with real-time scheduling policy at the highest priority. This option should reduce jitter as only kernel threads could preempt it.",
        default=False,
    )
    shared.add_argument(
        "--cpu-pin",
        type=int,
        help="if set, defines the CPU to pin the benchmark to. If the CPU is isolated, it will reduce variability between runs.",
        default=None,
    )
    shared.add_argument(
        "--slice",
        type=str,
        help="systemd slice to run the benchmark into. Required if --cpu-pin is isolated at the systemd level.",
        default=None,
    )

    parser = argparse.ArgumentParser(
        prog="bfbencher",
        description="Benchmark bpfilter performance across git commits.",
    )
    subparsers = parser.add_subparsers(dest="command")

    history_parser = subparsers.add_parser(
        "history",
        parents=[shared],
        help="benchmark performance across a range of commits",
        description="Benchmark bpfilter performance across a range of commits and report changes over time.",
    )
    history_parser.add_argument(
        "--since",
        type=str,
        help=f'oldest commit to benchmark. Use "wip" to start from the uncommitted changes (committed as "bfbencher: WIP"). Must be older than --until, or the same. Defaults to "{DEFAULT_FIRST_COMMIT_REF}"',
        default=DEFAULT_FIRST_COMMIT_REF,
    )
    history_parser.add_argument(
        "--until",
        type=str,
        help=f'newest commit to benchmark. Use "wip" to include uncommitted changes (committed as "bfbencher: WIP"). Must be newer than --since, or the same. Defaults to "{DEFAULT_LAST_COMMIT_REF}"',
        default=DEFAULT_LAST_COMMIT_REF,
    )
    history_parser.add_argument(
        "--include",
        type=str,
        action="append",
        default=[],
        help='include an extra commit outside the range. Can be specified multiple times. Use "wip" to include uncommitted changes. Commits are sorted in git order with the range commits.',
    )
    history_parser.add_argument(
        "--report-template-path",
        type=pathlib.Path,
        help=f'path to the Jinja2 template use to generate the HTML report. Defaults to "{DEFAULT_REPORT_TEMPLATE_PATH}"',
        default=DEFAULT_REPORT_TEMPLATE_PATH,
    )
    history_parser.add_argument(
        "--report-path",
        type=pathlib.Path,
        help="path of the final HTML report.",
    )
    history_parser.add_argument(
        "--pr-report-template-path",
        type=pathlib.Path,
        help=f'path to the Jinja2 template use to generate the HTML pull-request report. Defaults to "{DEFAULT_PR_REPORT_TEMPLATE_PATH}"',
        default=DEFAULT_PR_REPORT_TEMPLATE_PATH,
    )
    history_parser.add_argument(
        "--pr-report-path",
        type=pathlib.Path,
        help="path of the HTML summary report for pull requests (shows only significant changes).",
    )

    compare_parser = subparsers.add_parser(
        "compare",
        parents=[shared],
        help="compare performance between two specific commits",
        description="Benchmark two specific commits and report the performance difference.",
    )
    compare_parser.add_argument(
        "base",
        type=str,
        help='baseline commit ref. Use "wip" for uncommitted changes.',
    )
    compare_parser.add_argument(
        "ref",
        type=str,
        help='commit ref to compare against the baseline. Use "wip" for uncommitted changes.',
    )
    compare_parser.add_argument(
        "--json-output",
        type=pathlib.Path,
        help="write comparison results to a JSON file.",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        raise SystemExit(1)

    try:
        if args.command == "history":
            run_benchmarks(args)
        elif args.command == "compare":
            run_compare(args)
    except KeyboardInterrupt:
        renderer.log("Command interrupted by user")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
