"""On-disk spool for measurements that could not be shipped.

A latency monitor is most valuable precisely when the network is broken -- and
that is exactly when the agent cannot reach the server.  Dropping those
measurements would erase the evidence of the outage, so failed batches are
written to disk and replayed once the server comes back.

Format: one file per batch, newline-delimited JSON, written to ``*.tmp`` and
renamed into place so a crash mid-write can never leave a half-parsed batch.
Files are drained oldest-first, and the oldest are also what gets discarded
when the spool hits its size cap.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

from smokecommon.logging import get_logger
from smokecommon.models import Measurement

log = get_logger(__name__)

SPOOL_SUFFIX = ".jsonl"
TEMP_SUFFIX = ".tmp"


class Spool:
    """A bounded, crash-safe FIFO of measurement batches on disk."""

    def __init__(self, directory: str | Path, max_bytes: int = 256 * 1024 * 1024) -> None:
        self.directory = Path(directory)
        self.max_bytes = max_bytes
        self.directory.mkdir(parents=True, exist_ok=True)
        self._cleanup_temp_files()

    # -- writing -----------------------------------------------------------

    def append(self, measurements: list[Measurement]) -> Path | None:
        """Persist a batch.  Returns the file it landed in, or None if empty."""
        if not measurements:
            return None

        # Monotonic-ish name: the timestamp orders files, the uuid prevents
        # collisions when two flushes fail in the same millisecond.
        stem = f"{time.time_ns():020d}-{uuid.uuid4().hex[:8]}"
        temp_path = self.directory / f"{stem}{TEMP_SUFFIX}"
        final_path = self.directory / f"{stem}{SPOOL_SUFFIX}"

        payload = "\n".join(m.model_dump_json() for m in measurements) + "\n"
        try:
            temp_path.write_text(payload, encoding="utf-8")
            os.replace(temp_path, final_path)
        except OSError:
            log.exception("failed to write spool file", extra={"path": str(final_path)})
            temp_path.unlink(missing_ok=True)
            return None

        log.info(
            "spooled measurements",
            extra={"count": len(measurements), "file": final_path.name},
        )
        self.enforce_limit()
        return final_path

    # -- reading -----------------------------------------------------------

    def files(self) -> list[Path]:
        """Spool files, oldest first."""
        return sorted(self.directory.glob(f"*{SPOOL_SUFFIX}"))

    def peek_oldest(self) -> tuple[Path, list[Measurement]] | None:
        """Load the oldest batch without removing it.

        A file that cannot be parsed is quarantined rather than retried
        forever -- one corrupt file must not block the whole queue.
        """
        for path in self.files():
            try:
                measurements = self._read(path)
            except (OSError, ValueError):
                log.exception("corrupt spool file, quarantining", extra={"file": path.name})
                self._quarantine(path)
                continue
            if not measurements:
                path.unlink(missing_ok=True)
                continue
            return path, measurements
        return None

    def remove(self, path: Path) -> None:
        path.unlink(missing_ok=True)

    @staticmethod
    def _read(path: Path) -> list[Measurement]:
        measurements: list[Measurement] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    measurements.append(Measurement.model_validate(json.loads(line)))
                except Exception as exc:
                    raise ValueError(f"{path.name}:{line_no}: {exc}") from exc
        return measurements

    def _quarantine(self, path: Path) -> None:
        try:
            path.rename(path.with_suffix(".corrupt"))
        except OSError:
            path.unlink(missing_ok=True)

    # -- housekeeping ------------------------------------------------------

    def total_bytes(self) -> int:
        total = 0
        for path in self.files():
            try:
                total += path.stat().st_size
            except OSError:
                continue
        return total

    def count(self) -> int:
        return len(self.files())

    def enforce_limit(self) -> int:
        """Drop the oldest files until the spool fits its cap.

        Dropping the *oldest* is the right trade-off: during a long outage the
        most recent data is what you need to see recovery, and old data has
        usually already been superseded by the next cycle.

        The newest file is never dropped.  If a single batch is larger than
        ``max_bytes`` the alternative would be an always-empty spool that
        silently discards everything while looking configured -- far worse
        than briefly exceeding the cap.
        """
        dropped = 0
        total = self.total_bytes()
        if total <= self.max_bytes:
            return 0
        for path in self.files()[:-1]:
            if total <= self.max_bytes:
                break
            try:
                size = path.stat().st_size
                path.unlink()
            except OSError:
                continue
            total -= size
            dropped += 1
        if dropped:
            log.warning(
                "spool over limit, dropped oldest batches",
                extra={"dropped_files": dropped, "max_bytes": self.max_bytes},
            )
        return dropped

    def _cleanup_temp_files(self) -> None:
        """Remove ``.tmp`` leftovers from a crash during a previous write."""
        for path in self.directory.glob(f"*{TEMP_SUFFIX}"):
            path.unlink(missing_ok=True)
