"""Spool: the on-disk buffer that survives a server outage.

This is the component that makes the tool trustworthy during exactly the
events it exists to observe, so the crash-safety properties are tested
explicitly rather than assumed.
"""

from __future__ import annotations

from smokeagent.spool import SPOOL_SUFFIX, TEMP_SUFFIX, Spool

from conftest import make_measurement


class TestRoundTrip:
    def test_append_and_read_back(self, tmp_path):
        spool = Spool(tmp_path)
        originals = [make_measurement(target_name=f"t{i}") for i in range(3)]
        spool.append(originals)

        entry = spool.peek_oldest()
        assert entry is not None
        path, restored = entry
        assert [m.target_name for m in restored] == ["t0", "t1", "t2"]
        assert restored[0].id == originals[0].id
        assert path.suffix == SPOOL_SUFFIX

    def test_details_and_hops_survive(self, tmp_path):
        from smokecommon.models import HopResult

        spool = Spool(tmp_path)
        original = make_measurement(
            probe="mtr",
            details={"path": ["1.1.1.1", "2.2.2.2"], "path_signature": "abc123"},
            hops=[HopResult(hop_no=1, ip="1.1.1.1", loss_pct=0.0, avg_ms=1.5)],
        )
        spool.append([original])

        entry = spool.peek_oldest()
        assert entry is not None
        restored = entry[1][0]
        assert restored.details["path"] == ["1.1.1.1", "2.2.2.2"]
        assert restored.hops[0].ip == "1.1.1.1"
        assert restored.hops[0].avg_ms == 1.5

    def test_empty_batch_writes_nothing(self, tmp_path):
        spool = Spool(tmp_path)
        assert spool.append([]) is None
        assert spool.count() == 0


class TestFifoOrdering:
    def test_oldest_is_drained_first(self, tmp_path):
        spool = Spool(tmp_path)
        for i in range(3):
            spool.append([make_measurement(target_name=f"batch{i}")])

        for expected in ("batch0", "batch1", "batch2"):
            entry = spool.peek_oldest()
            assert entry is not None
            path, measurements = entry
            assert measurements[0].target_name == expected
            spool.remove(path)

        assert spool.peek_oldest() is None

    def test_remove_is_idempotent(self, tmp_path):
        spool = Spool(tmp_path)
        spool.append([make_measurement()])
        entry = spool.peek_oldest()
        assert entry is not None
        spool.remove(entry[0])
        spool.remove(entry[0])  # must not raise
        assert spool.count() == 0


class TestCrashSafety:
    def test_partial_writes_are_never_visible(self, tmp_path):
        # Files are written to .tmp and renamed, so a reader can only ever see
        # a complete batch.
        spool = Spool(tmp_path)
        spool.append([make_measurement()])
        assert list(tmp_path.glob(f"*{TEMP_SUFFIX}")) == []
        assert len(list(tmp_path.glob(f"*{SPOOL_SUFFIX}"))) == 1

    def test_leftover_temp_files_are_cleaned_at_startup(self, tmp_path):
        (tmp_path / f"12345{TEMP_SUFFIX}").write_text("half a batch", encoding="utf-8")
        Spool(tmp_path)
        assert list(tmp_path.glob(f"*{TEMP_SUFFIX}")) == []

    def test_corrupt_file_is_quarantined_not_retried_forever(self, tmp_path):
        # One bad file must not wedge the whole queue.
        spool = Spool(tmp_path)
        (tmp_path / f"00000000000000000001-aaaaaaaa{SPOOL_SUFFIX}").write_text(
            "{not json at all\n", encoding="utf-8"
        )
        spool.append([make_measurement(target_name="good")])

        entry = spool.peek_oldest()
        assert entry is not None
        assert entry[1][0].target_name == "good"
        assert len(list(tmp_path.glob("*.corrupt"))) == 1

    def test_empty_file_is_discarded(self, tmp_path):
        spool = Spool(tmp_path)
        (tmp_path / f"00000000000000000001-bbbbbbbb{SPOOL_SUFFIX}").write_text("", encoding="utf-8")
        assert spool.peek_oldest() is None
        assert spool.count() == 0


class TestSizeLimit:
    def test_oldest_batches_are_dropped_when_over_the_cap(self, tmp_path):
        # During a long outage, recent data matters more than old data.
        spool = Spool(tmp_path, max_bytes=1)
        for i in range(4):
            spool.append([make_measurement(target_name=f"batch{i}")])

        entry = spool.peek_oldest()
        assert entry is not None
        assert entry[1][0].target_name == "batch3"
        assert spool.count() == 1

    def test_under_the_cap_nothing_is_dropped(self, tmp_path):
        spool = Spool(tmp_path, max_bytes=100 * 1024 * 1024)
        for i in range(3):
            spool.append([make_measurement(target_name=f"b{i}")])
        assert spool.count() == 3
        assert spool.enforce_limit() == 0

    def test_total_bytes_reflects_content(self, tmp_path):
        spool = Spool(tmp_path, max_bytes=100 * 1024 * 1024)
        assert spool.total_bytes() == 0
        spool.append([make_measurement()])
        assert spool.total_bytes() > 0


class TestDirectoryHandling:
    def test_creates_the_directory(self, tmp_path):
        target = tmp_path / "deeply" / "nested" / "spool"
        Spool(target)
        assert target.is_dir()
