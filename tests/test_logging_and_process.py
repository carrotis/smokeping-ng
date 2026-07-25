"""Structured logging and the subprocess helper."""

from __future__ import annotations

import json
import logging
import sys

import pytest

from smokecommon.logging import JsonFormatter, PlainFormatter, bind_context, setup_logging
from smokecommon.process import ToolMissingError, clear_which_cache, run_command, which


def record(message: str = "hello", **extra):
    rec = logging.LogRecord(
        name="smoke.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(rec, key, value)
    return rec


class TestJsonFormatter:
    def test_emits_one_json_object_per_line(self):
        line = JsonFormatter(service="smoke-agent").format(record())
        payload = json.loads(line)

        assert payload["message"] == "hello"
        assert payload["level"] == "INFO"
        assert payload["service"] == "smoke-agent"
        assert payload["logger"] == "smoke.test"
        assert payload["ts"].endswith("+00:00")

    def test_extra_fields_become_top_level_keys(self):
        payload = json.loads(
            JsonFormatter().format(record(target="8.8.8.8", latency_ms=12.5, probe="ping"))
        )
        assert payload["target"] == "8.8.8.8"
        assert payload["latency_ms"] == 12.5
        assert payload["probe"] == "ping"

    def test_static_fields_are_attached_to_every_line(self):
        formatter = JsonFormatter(static_fields={"agent_id": "seoul-1"})
        assert json.loads(formatter.format(record()))["agent_id"] == "seoul-1"

    def test_exceptions_are_structured(self):
        try:
            raise ValueError("boom")
        except ValueError:
            rec = record("failed")
            rec.exc_info = sys.exc_info()

        payload = json.loads(JsonFormatter().format(rec))
        assert payload["error"]["type"] == "ValueError"
        assert payload["error"]["message"] == "boom"
        assert "Traceback" in payload["error"]["stack"]

    def test_unserialisable_values_do_not_kill_the_line(self):
        payload = json.loads(JsonFormatter().format(record(weird=object())))
        assert isinstance(payload["weird"], str)

    def test_non_ascii_is_preserved(self):
        payload = json.loads(JsonFormatter().format(record(location="서울")))
        assert payload["location"] == "서울"


class TestBoundContext:
    def test_fields_are_added_inside_the_block(self):
        formatter = JsonFormatter()
        with bind_context(request_id="abc123"):
            payload = json.loads(formatter.format(record()))
        assert payload["request_id"] == "abc123"

    def test_context_is_removed_on_exit(self):
        formatter = JsonFormatter()
        with bind_context(request_id="abc123"):
            pass
        assert "request_id" not in json.loads(formatter.format(record()))

    def test_nesting_merges_and_unwinds(self):
        formatter = JsonFormatter()
        with bind_context(a="1"):
            with bind_context(b="2"):
                inner = json.loads(formatter.format(record()))
            outer = json.loads(formatter.format(record()))

        assert inner == {**inner, "a": "1", "b": "2"}
        assert outer["a"] == "1"
        assert "b" not in outer


class TestSetupLogging:
    def test_is_idempotent(self):
        setup_logging(level="INFO", service="t")
        setup_logging(level="INFO", service="t")
        assert len(logging.getLogger().handlers) == 1

    def test_text_format_is_human_readable(self):
        line = PlainFormatter().format(record(target="8.8.8.8"))
        assert "hello" in line
        assert "target=8.8.8.8" in line


class TestWhich:
    def test_finds_a_real_binary(self):
        clear_which_cache()
        assert which(sys.executable.split("/")[-1]) or which("sh") or which("cmd")

    def test_missing_binary_returns_none(self):
        clear_which_cache()
        assert which("definitely-not-a-real-binary-xyz") is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell commands")
class TestRunCommand:
    async def test_captures_stdout_and_exit_code(self):
        output = await run_command(["sh", "-c", "echo hello; exit 0"], timeout=5)
        assert output.ok is True
        assert output.stdout.strip() == "hello"
        assert output.returncode == 0
        assert output.duration_ms > 0

    async def test_captures_stderr_and_nonzero_exit(self):
        output = await run_command(["sh", "-c", "echo oops >&2; exit 3"], timeout=5)
        assert output.ok is False
        assert output.returncode == 3
        assert "oops" in output.stderr

    async def test_timeout_is_a_result_not_an_exception(self):
        # For a latency prober a timeout is a normal measurement outcome.
        output = await run_command(["sh", "-c", "sleep 10"], timeout=0.3)
        assert output.timed_out is True
        assert output.ok is False

    async def test_timeout_actually_kills_the_process_tree(self):
        # A child that outlives the timeout would leak a process per cycle.
        import time

        started = time.monotonic()
        await run_command(["sh", "-c", "sleep 30 & sleep 30"], timeout=0.3)
        assert time.monotonic() - started < 5.0

    async def test_missing_binary_raises_tool_missing(self):
        with pytest.raises(ToolMissingError) as exc:
            await run_command(["definitely-not-a-real-binary-xyz"], timeout=1)
        assert exc.value.binary == "definitely-not-a-real-binary-xyz"

    async def test_locale_is_forced_to_c(self):
        # So "time=12.3 ms" is never rendered in a locale we cannot parse.
        output = await run_command(["sh", "-c", "echo $LC_ALL"], timeout=5)
        assert output.stdout.strip() == "C"

    async def test_combined_property(self):
        output = await run_command(["sh", "-c", "echo out; echo err >&2"], timeout=5)
        assert "out" in output.combined
        assert "err" in output.combined
