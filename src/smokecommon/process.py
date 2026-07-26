"""Async subprocess helper shared by every binary-backed probe.

Wraps subprocess.run() in a thread executor with the three things probes
always need and always get wrong:

* a hard timeout that actually kills the child (and its children),
* stdout/stderr captured as text without deadlocking on full pipes,
* a clean "binary is not installed" signal instead of a raw OSError.

subprocess.run() is used (not asyncio.create_subprocess_exec) because probes
like mtr fork helper processes (mtr-packet) that inherit the stdout pipe FD.
asyncio's SIGCHLD handler doesn't reliably reap the parent mtr zombie while
that pipe is still held open, causing zombies to accumulate. subprocess.run()
calls os.waitpid(pid, 0) directly, so every child is reaped unconditionally.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field

IS_WINDOWS = sys.platform == "win32"

# One shared pool; probes are I/O-bound so 16 threads handles bursts easily.
_thread_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=16, thread_name_prefix="probe"
)


class ToolMissingError(FileNotFoundError):
    """Raised when the probe's binary is not on PATH."""

    def __init__(self, binary: str):
        super().__init__(f"required binary not found on PATH: {binary}")
        self.binary = binary


@dataclass(slots=True)
class CommandOutput:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def combined(self) -> str:
        return f"{self.stdout}\n{self.stderr}".strip()


@dataclass(slots=True)
class _WhichCache:
    """PATH lookups are syscalls; probes run on a tight loop, so memoise.

    Negative results are cached too but re-checked periodically, so installing
    ``mtr`` while the agent runs is picked up without a restart.
    """

    ttl_s: float = 60.0
    _entries: dict[str, tuple[float, str | None]] = field(default_factory=dict)

    def resolve(self, binary: str) -> str | None:
        now = time.monotonic()
        cached = self._entries.get(binary)
        if cached and now - cached[0] < self.ttl_s:
            return cached[1]
        path = shutil.which(binary)
        self._entries[binary] = (now, path)
        return path

    def clear(self) -> None:
        self._entries.clear()


_which_cache = _WhichCache()


def which(binary: str) -> str | None:
    """Cached :func:`shutil.which`."""
    return _which_cache.resolve(binary)


def clear_which_cache() -> None:
    _which_cache.clear()


async def run_command(
    argv: list[str],
    timeout: float,
    *,
    env: dict[str, str] | None = None,
    stdin: bytes | None = None,
    encoding: str = "utf-8",
) -> CommandOutput:
    """Run ``argv`` and capture its output.

    Raises :class:`ToolMissingError` when the executable does not exist.  A
    timeout is *not* an exception -- it comes back as
    ``CommandOutput(timed_out=True)`` because for a latency prober a timeout is
    a perfectly normal measurement, not an error condition.
    """
    if which(argv[0]) is None and not os.path.isabs(argv[0]):
        raise ToolMissingError(argv[0])

    full_env = {**os.environ, **(env or {})}
    # Force C locale so we parse "time=12.3 ms" and not a localised variant.
    full_env.setdefault("LC_ALL", "C")
    full_env["LANG"] = "C"

    # Put the child in its own process group so a timeout kills the whole tree.
    kwargs: dict[str, object] = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True

    def _run() -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            timeout=timeout,
            env=full_env,
            **kwargs,  # type: ignore[arg-type]
        )

    started = time.perf_counter()
    loop = asyncio.get_running_loop()
    timed_out = False
    returncode: int | None = None
    stdout_b = stderr_b = b""

    try:
        # +2 s outer guard: subprocess.run kills+reaps on TimeoutExpired, so
        # the thread finishes shortly after the inner timeout fires.
        result = await asyncio.wait_for(
            loop.run_in_executor(_thread_pool, _run),
            timeout=timeout + 2.0,
        )
        stdout_b = result.stdout
        stderr_b = result.stderr
        returncode = result.returncode
    except subprocess.TimeoutExpired:
        # subprocess.run already killed and reaped the child before raising.
        timed_out = True
    except FileNotFoundError as exc:
        raise ToolMissingError(argv[0]) from exc
    except TimeoutError:
        # Outer asyncio guard fired — thread is still blocked but child is dead.
        timed_out = True
    finally:
        duration_ms = (time.perf_counter() - started) * 1000.0

    return CommandOutput(
        argv=list(argv),
        returncode=returncode,
        stdout=stdout_b.decode(encoding, errors="replace"),
        stderr=stderr_b.decode(encoding, errors="replace"),
        duration_ms=duration_ms,
        timed_out=timed_out,
    )
