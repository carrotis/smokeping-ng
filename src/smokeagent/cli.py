"""``smoke-agent`` command line interface."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import signal
import sys
from typing import Any

from smokeagent.config import AgentConfig, TargetSpec, load_agent_config
from smokeagent.probes.base import load_all_probes, registered_probes
from smokeagent.scheduler import Scheduler, run_once
from smokeagent.shipper import Shipper
from smokecommon.configfile import ConfigError
from smokecommon.logging import get_logger, setup_logging
from smokecommon.version import __version__

log = get_logger(__name__)

DEFAULT_CONFIG = "/etc/smokeping/agent.yaml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smoke-agent",
        description="SmokePing-style measurement agent: runs probes and ships results.",
    )
    parser.add_argument("--version", action="version", version=f"smoke-agent {__version__}")
    sub = parser.add_subparsers(dest="command")

    def with_config(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument("-c", "--config", default=DEFAULT_CONFIG, help="path to agent.yaml/.toml")
        p.add_argument("--log-level", default=None, help="override logging.level")
        p.add_argument(
            "--log-format", default=None, choices=["json", "text"], help="override logging.format"
        )
        return p

    with_config(sub.add_parser("run", help="run the agent (default)"))
    with_config(sub.add_parser("check", help="validate the config and exit"))

    test = with_config(sub.add_parser("test", help="run one probe once and print the result"))
    test.add_argument("--target", help="target key from the config, e.g. /kr/kt-dns#ping")
    test.add_argument("--probe", help="probe name, when testing an ad-hoc target")
    test.add_argument("--host", help="address/URL, when testing an ad-hoc target")
    test.add_argument(
        "-o",
        "--option",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="probe option override; repeatable. Values are parsed as JSON when possible.",
    )

    probes = sub.add_parser("probes", help="list available probes")
    probes.add_argument("--plugin-dir", action="append", default=[], help="extra plugin directory")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "run"

    if command == "probes":
        return _cmd_probes(args)

    try:
        config = load_agent_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    setup_logging(
        level=args.log_level or config.logging.level,
        service="smoke-agent",
        fmt=args.log_format or config.logging.format,
        static_fields={
            "agent_id": config.agent.id,
            "agent_location": config.agent.location,
        },
    )
    load_all_probes(config.plugin_dirs)

    if command == "check":
        return _cmd_check(config)
    if command == "test":
        return asyncio.run(_cmd_test(config, args))
    return asyncio.run(_cmd_run(config))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _cmd_probes(args: argparse.Namespace) -> int:
    load_all_probes(args.plugin_dir)
    rows = []
    for name, cls in sorted(registered_probes().items()):
        rows.append(
            {
                "probe": name,
                "available": cls.is_available(),
                "binary": cls.required_binary or "-",
                "batch": cls.supports_batch,
                "description": cls.description or cls.__doc__ or "",
            }
        )
    width = max(len(r["probe"]) for r in rows) if rows else 8
    print(f"{'PROBE'.ljust(width)}  AVAIL  BATCH  BINARY      DESCRIPTION")
    for row in rows:
        avail = "yes" if row["available"] else "NO "
        batch = "yes" if row["batch"] else "no "
        desc = str(row["description"]).strip().splitlines()[0][:70]
        print(
            f"{row['probe'].ljust(width)}  {avail}    {batch}    "
            f"{str(row['binary']).ljust(10)}  {desc}"
        )
    missing = [r["probe"] for r in rows if not r["available"]]
    if missing:
        print(f"\nUnavailable (binary missing): {', '.join(missing)}", file=sys.stderr)
    return 0


def _cmd_check(config: AgentConfig) -> int:
    scheduler = Scheduler(config, sink=_NullSink())
    try:
        jobs = scheduler.build_jobs()
    except (KeyError, ValueError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    by_probe: dict[str, int] = {}
    for target in config.targets:
        by_probe[target.probe] = by_probe.get(target.probe, 0) + 1

    print(f"agent id      : {config.agent.id}")
    print(f"agent location: {config.agent.location}")
    print(f"server        : {config.server.url}")
    print(f"targets       : {len(config.targets)}")
    print(f"jobs          : {len(jobs)} ({sum(1 for j in jobs if j.batched)} batched)")
    print("probes        :")
    for probe_name, count in sorted(by_probe.items()):
        print(f"  - {probe_name}: {count} target(s)")

    problems = scheduler.preflight()
    if problems:
        print("\nWarnings:", file=sys.stderr)
        for problem in problems:
            print(f"  ! {problem}", file=sys.stderr)
        # Not fatal: the other probes still work.
        return 1
    print("\nconfig OK")
    return 0


async def _cmd_test(config: AgentConfig, args: argparse.Namespace) -> int:
    try:
        spec = _resolve_test_target(config, args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    outcome = await run_once(config, spec)
    print(json.dumps(outcome.measurement.model_dump(mode="json"), indent=2, ensure_ascii=False))
    return 0 if outcome.result.success else 1


async def _cmd_run(config: AgentConfig) -> int:
    shipper = Shipper(config=config.server, identity=config.agent)
    scheduler = Scheduler(config, sink=shipper)

    try:
        scheduler.build_jobs()
    except (KeyError, ValueError) as exc:
        log.error("cannot build jobs", extra={"detail": str(exc)})
        return 2

    for problem in scheduler.preflight():
        log.warning("preflight", extra={"detail": problem})

    await shipper.start()
    stop_signal = asyncio.Event()
    _install_signal_handlers(stop_signal)

    runner = asyncio.create_task(scheduler.run(), name="scheduler")
    reporter = asyncio.create_task(_report_stats(scheduler, shipper, stop_signal), name="stats")

    await stop_signal.wait()
    log.info("shutting down")

    await scheduler.stop()
    with contextlib.suppress(asyncio.CancelledError):
        await runner
    reporter.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await reporter

    # Drain whatever is queued so a rolling restart does not lose a cycle.
    await shipper.stop(drain=True)
    log.info("stopped", extra={"shipper": shipper.stats.as_dict()})
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _NullSink:
    async def submit(self, measurements: Any) -> None:  # pragma: no cover - trivial
        return None


async def _report_stats(
    scheduler: Scheduler, shipper: Shipper, stop: asyncio.Event, every_s: float = 60.0
) -> None:
    """Periodic heartbeat so a running agent is observable from its logs alone."""
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=every_s)
            return
        except TimeoutError:
            pass
        log.info(
            "heartbeat",
            extra={"scheduler": scheduler.stats.as_dict(), "shipper": shipper.stats.as_dict()},
        )


def _install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for signal_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, signal_name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            # Windows' ProactorEventLoop has no add_signal_handler; the
            # synchronous handler is good enough there.
            signal.signal(sig, lambda *_: stop.set())


def _resolve_test_target(config: AgentConfig, args: argparse.Namespace) -> TargetSpec:
    overrides = _parse_options(args.option)

    if args.target:
        matches = [
            t
            for t in config.targets
            if args.target in (t.key, f"{t.group.rstrip('/')}/{t.name}", t.name)
        ]
        if not matches:
            available = ", ".join(sorted(t.key for t in config.targets)[:20])
            raise ConfigError(f"no target matches {args.target!r}. Known: {available} ...")
        if len(matches) > 1:
            raise ConfigError(
                f"{args.target!r} is ambiguous: {', '.join(m.key for m in matches)}"
            )
        spec = matches[0]
        spec.options = {**spec.options, **overrides}
        return spec

    if not (args.probe and args.host):
        raise ConfigError("give either --target, or both --probe and --host")

    return TargetSpec(
        name="adhoc",
        group="/",
        host=args.host,
        probe=args.probe,
        interval=60.0,
        options={**(config.probe_defaults.get(args.probe) or {}), **overrides},
    )


def _parse_options(pairs: list[str]) -> dict[str, Any]:
    """Parse ``-o key=value`` overrides, decoding JSON values where possible.

    So ``-o count=10`` gives an int, ``-o expect_status=[200,204]`` a list, and
    ``-o user_agent=curl/8`` stays a plain string.
    """
    options: dict[str, Any] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            raise ConfigError(f"option {pair!r} must be KEY=VALUE")
        try:
            options[key.strip()] = json.loads(value)
        except json.JSONDecodeError:
            options[key.strip()] = value
    return options


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
