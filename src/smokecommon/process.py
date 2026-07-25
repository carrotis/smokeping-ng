"""Async subprocess helper shared by every binary-backed probe.

Wraps :func:`asyncio.create_subprocess_exec` with the three things probes
always need and always get wrong:

* a hard timeout that actually kills the child (and its children),
* stdout/stderr captured as text without deadlocking on full pipes,
* a clean "binary is not installed" signal instead of a raw OSError.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import sys
import time
from dataclasses import dataclass, field

IS_WINDOWS = sys.platform == "win32"


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

    started = time.perf_counter()
    # On POSIX put the child in its own process group so a timeout can kill
    # the whole tree (mtr in particular spawns helpers).
    creation: dict[str, object] = {}
    if IS_WINDOWS:
        creation["creationflags"] = getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        creation["start_new_session"] = True

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=full_env,
            **creation,  # type: ignore[arg-type]
        )
    except FileNotFoundError as exc:  # race: binary vanished after the which()
        raise ToolMissingError(argv[0]) from exc

    timed_out = False
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(input=stdin), timeout=timeout)
    except TimeoutError:
        timed_out = True
        stdout_b, stderr_b = b"", b""
        await _terminate(proc)
    finally:
        duration_ms = (time.perf_counter() - started) * 1000.0

    return CommandOutput(
        argv=list(argv),
        returncode=proc.returncode,
        stdout=stdout_b.decode(encoding, errors="replace"),
        stderr=stderr_b.decode(encoding, errors="replace"),
        duration_ms=duration_ms,
        timed_out=timed_out,
    )


async def _terminate(proc: asyncio.subprocess.Process, grace_s: float = 1.0) -> None:
    """SIGTERM the process group, then SIGKILL whatever survives."""
    if proc.returncode is not None:
        return
    try:
        if IS_WINDOWS:
            proc.terminate()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass

    try:
        await asyncio.wait_for(proc.wait(), timeout=grace_s)
        return
    except TimeoutError:
        pass

    try:
        if IS_WINDOWS:
            proc.kill()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    # Reap so we do not leak a zombie.  The child is SIGKILLed, so this
    # cannot hang for long.
    try:
        await asyncio.wait_for(proc.wait(), timeout=grace_s)
    except TimeoutError:
        pass
