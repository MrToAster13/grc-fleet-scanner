"""Tests for grc_auditor.cli helpers (run-id collision resistance)."""

from __future__ import annotations

import re

from grc_auditor.cli import _run_id


def test_run_id_is_timestamp_sortable_with_random_suffix():
    # 20260629T161000Z-ab12cd : a sortable UTC stamp (history ordering relies on
    # `run_id < ?` string comparison) plus a short random hex suffix.
    rid = _run_id()
    assert re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", rid), rid


def test_run_ids_are_unique_within_the_same_second():
    # Two runs started back-to-back in the same wall-clock second must still mint
    # distinct ids, so one can never overwrite another's evidence dir / DB row.
    # Uniqueness rests on the 24-bit random suffix (the timestamp prefix is
    # identical across microsecond-apart calls); asserting >= len-1 proves the
    # suffix genuinely varies (a constant/low-entropy suffix would collapse this
    # toward 1) without flaking on the ~1-in-13k birthday collision of two equal
    # suffixes -- losing two pairs at once is ~1e-8, effectively never.
    ids = {_run_id() for _ in range(50)}
    assert len(ids) >= 49
