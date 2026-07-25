"""Probe abstraction and plugin registry.

A probe is a small class that turns "measure this target" into a
:class:`~smokecommon.models.ProbeResult`.  Everything else -- scheduling,
retries, shipping, storage -- is somebody else's problem.

Writing one
-----------
::

    from smokeagent.probes.base import Probe, ProbeTarget, register_probe
    from smokecommon.models import ProbeResult

    @register_probe
    class MyProbe(Probe):
        name = "myprobe"
        default_options = {"timeout": 5.0}

        async def probe(self, target: ProbeTarget) -> ProbeResult:
            ...
            return ProbeResult(success=True, rtts_ms=[1.23])

Drop that file into any directory listed under ``plugin_dirs`` in the agent
config and it is picked up at startup -- no packaging step required.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from smokecommon.errors import ErrorType
from smokecommon.logging import get_logger
from smokecommon.models import ProbeResult
from smokecommon.process import ToolMissingError, which

log = get_logger(__name__)


@dataclass(slots=True)
class ProbeTarget:
    """What to measure.

    ``address`` is whatever the probe needs: a hostname for ping, a URL for
    curl, ``host:port`` semantics come from options.
    """

    name: str
    address: str
    group: str = "/"
    #: Fully merged options (probe defaults <- group <- target).  Probes read
    #: their own options from ``self.options``; this copy is here so a probe
    #: can see target-scoped extras it did not declare a default for.
    options: dict[str, Any] = field(default_factory=dict)


class Probe(ABC):
    """Base class for all probes."""

    #: Unique probe identifier; also the value stored in ``measurements.probe``.
    name: ClassVar[str] = ""
    #: External binary this probe shells out to, if any.  Used for the
    #: startup preflight check and for a clear TOOL_MISSING error.
    required_binary: ClassVar[str | None] = None
    #: Option defaults.  Merged under group/target overrides by the config
    #: layer, so a probe can always read ``self.options[...]`` without a
    #: ``.get()`` dance for anything declared here.
    default_options: ClassVar[dict[str, Any]] = {"timeout": 5.0}
    #: Human-readable one-liner surfaced by ``smoke-agent probes``.
    description: ClassVar[str] = ""
    #: Set by probes that can measure many targets in one invocation (fping).
    #: The scheduler then groups targets that share a probe, options and
    #: interval into a single job instead of one task per target.
    supports_batch: ClassVar[bool] = False

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        merged: dict[str, Any] = {}
        # Walk the MRO backwards so a subclass's defaults win over its parent's.
        for klass in reversed(type(self).__mro__):
            merged.update(getattr(klass, "default_options", {}) or {})
        merged.update(options or {})
        self.options = merged

    # -- lifecycle ---------------------------------------------------------

    @property
    def timeout(self) -> float:
        return float(self.options.get("timeout", 5.0))

    @classmethod
    def is_available(cls) -> bool:
        """Whether this probe can run on this host right now."""
        if cls.required_binary is None:
            return True
        return which(cls.required_binary) is not None

    def validate(self) -> None:
        """Raise :class:`ValueError` for a nonsensical option combination.

        Called once at agent startup so misconfiguration fails fast instead of
        producing an endless stream of failed measurements.
        """
        if self.timeout <= 0:
            raise ValueError(f"{self.name}: timeout must be > 0, got {self.timeout}")

    @abstractmethod
    async def probe(self, target: ProbeTarget) -> ProbeResult:
        """Perform one measurement cycle.  Implemented by each probe."""

    async def run(self, target: ProbeTarget) -> ProbeResult:
        """Call :meth:`probe` with a safety net.

        Guarantees a ProbeResult for every call: a crashing probe records an
        INTERNAL failure rather than killing the scheduler loop.  This is the
        method the scheduler calls.
        """
        started = time.perf_counter()
        try:
            result = await self.probe(target)
        except asyncio.CancelledError:
            raise
        except ToolMissingError as exc:
            result = ProbeResult.failure(ErrorType.TOOL_MISSING, str(exc))
        except TimeoutError:
            result = ProbeResult.failure(
                ErrorType.TIMEOUT, f"{self.name} exceeded {self.timeout}s"
            )
        except Exception as exc:
            log.exception(
                "probe raised", extra={"probe": self.name, "target": target.address}
            )
            result = ProbeResult.failure(
                ErrorType.INTERNAL, f"{type(exc).__name__}: {exc}"
            )

        if result.duration_ms is None:
            result.duration_ms = (time.perf_counter() - started) * 1000.0
        return result

    async def probe_many(self, targets: list[ProbeTarget]) -> dict[str, ProbeResult]:
        """Measure several targets at once, keyed by ``ProbeTarget.name``.

        The default implementation just fans out concurrently, which is correct
        for every probe; batch-capable probes (fping) override it with a single
        process invocation.
        """
        results = await asyncio.gather(*(self.probe(t) for t in targets), return_exceptions=True)
        out: dict[str, ProbeResult] = {}
        for target, result in zip(targets, results, strict=True):
            if isinstance(result, BaseException):
                out[target.name] = ProbeResult.failure(
                    ErrorType.INTERNAL, f"{type(result).__name__}: {result}"
                )
            else:
                out[target.name] = result
        return out

    async def run_many(self, targets: list[ProbeTarget]) -> dict[str, ProbeResult]:
        """Batch counterpart of :meth:`run`: never raises, always fully keyed."""
        started = time.perf_counter()
        try:
            results = await self.probe_many(targets)
        except asyncio.CancelledError:
            raise
        except ToolMissingError as exc:
            results = {
                t.name: ProbeResult.failure(ErrorType.TOOL_MISSING, str(exc)) for t in targets
            }
        except Exception as exc:
            log.exception("batch probe raised", extra={"probe": self.name, "count": len(targets)})
            results = {
                t.name: ProbeResult.failure(ErrorType.INTERNAL, f"{type(exc).__name__}: {exc}")
                for t in targets
            }

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        for target in targets:
            result = results.get(target.name)
            if result is None:
                result = ProbeResult.failure(
                    ErrorType.INTERNAL, f"{self.name} returned no result for {target.name}"
                )
                results[target.name] = result
            if result.duration_ms is None:
                result.duration_ms = elapsed_ms
        return results

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} name={self.name!r} timeout={self.timeout}>"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, type[Probe]] = {}

#: Modules shipped with the agent.  Imported lazily by :func:`load_builtin_probes`.
BUILTIN_MODULES = (
    "smokeagent.probes.ping",
    "smokeagent.probes.fping",
    "smokeagent.probes.dig",
    "smokeagent.probes.curl",
    "smokeagent.probes.nc",
    "smokeagent.probes.mtr",
)


def register_probe(cls: type[Probe]) -> type[Probe]:
    """Class decorator that adds a probe to the registry."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must define a non-empty `name`")
    existing = _REGISTRY.get(cls.name)
    if existing is not None and existing is not cls:
        log.warning(
            "probe name collision, replacing",
            extra={"probe": cls.name, "old": existing.__module__, "new": cls.__module__},
        )
    _REGISTRY[cls.name] = cls
    return cls


def get_probe_class(name: str) -> type[Probe]:
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "(none loaded)"
        raise KeyError(f"unknown probe {name!r}; registered probes: {known}") from None


def registered_probes() -> dict[str, type[Probe]]:
    return dict(_REGISTRY)


def load_builtin_probes() -> None:
    """Import the shipped probe modules so their decorators fire."""
    for module in BUILTIN_MODULES:
        importlib.import_module(module)


def load_entry_point_probes(group: str = "smokeping.probes") -> None:
    """Load probes published by third-party packages via entry points."""
    from importlib.metadata import entry_points

    for ep in entry_points(group=group):
        try:
            obj = ep.load()
        except Exception:
            log.exception("failed to load probe entry point", extra={"entry_point": ep.name})
            continue
        if isinstance(obj, type) and issubclass(obj, Probe):
            register_probe(obj)


def load_plugin_dir(directory: str | Path) -> list[str]:
    """Import every ``*.py`` in ``directory`` so it can self-register.

    Returns the names of the modules that were loaded.  A plugin that fails to
    import is logged and skipped -- one bad file should not take the agent down.
    """
    path = Path(directory)
    if not path.is_dir():
        log.warning("plugin dir does not exist", extra={"path": str(path)})
        return []

    loaded: list[str] = []
    for file in sorted(path.glob("*.py")):
        if file.name.startswith("_"):
            continue
        module_name = f"smokeagent.probes.plugins.{file.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, file)
            if spec is None or spec.loader is None:
                raise ImportError(f"cannot build import spec for {file}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception:
            log.exception("failed to load probe plugin", extra={"path": str(file)})
            sys.modules.pop(module_name, None)
            continue
        loaded.append(module_name)
        log.info("loaded probe plugin", extra={"path": str(file)})
    return loaded


def load_all_probes(plugin_dirs: list[str] | None = None) -> dict[str, type[Probe]]:
    """Load builtin, entry-point and directory plugins, in that order.

    Later sources win, so an operator can shadow a builtin probe by dropping a
    same-named class into a plugin dir.
    """
    load_builtin_probes()
    load_entry_point_probes()
    for directory in plugin_dirs or []:
        load_plugin_dir(directory)
    return registered_probes()
