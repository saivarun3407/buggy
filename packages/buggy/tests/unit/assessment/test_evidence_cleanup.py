from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from buggy.sandbox_kernel.assessment import AssessmentError, AssessmentStore


@pytest.mark.parametrize("failing_descriptor", [0, 1, 2])
def test_evidence_cleanup_closes_all_descriptors_when_one_close_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing_descriptor: int
) -> None:
    store = AssessmentStore(tmp_path)
    store.dispatch(
        "initialize",
        {
            "engagement_name": "cleanup-fixture",
            "profile": "external",
            "allowed_hosts": ["app.example.test"],
        },
    )
    store.dispatch(
        "import",
        {
            "operations": [{"url": "https://app.example.test/", "method": "GET"}],
            "source": {"id": "fixture", "kind": "manual", "status": "ok"},
        },
    )
    case = next(
        case
        for case in store.dispatch("report", {})["cases"]
        if case["control_id"] == "http.nosniff"
    )
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "proof.txt").write_text("Synthetic evidence only")
    real_open, real_close, real_fdopen = os.open, os.close, os.fdopen
    opened: list[int] = []

    def tracked_open(path, flags, *args, **kwargs):
        descriptor = real_open(path, flags, *args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def failing_close(descriptor):
        real_close(descriptor)
        if failing_descriptor != 2 and descriptor == opened[failing_descriptor]:
            raise OSError("Synthetic directory close failure after release")

    @contextmanager
    def failing_file(*args, **kwargs):
        with real_fdopen(*args, **kwargs) as stream:
            try:
                yield stream
            finally:
                if failing_descriptor == 2:
                    stream.close()
                    raise OSError("Synthetic file close failure after release")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", tracked_open)
            patch.setattr(os, "close", failing_close)
            patch.setattr(os, "fdopen", failing_file)
            patch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {tracked_open})
            with pytest.raises(AssessmentError):
                store.dispatch(
                    "record",
                    {
                        "case_id": case["case_id"],
                        "status": "pass",
                        "evidence_paths": ["evidence/proof.txt"],
                        "rationale": "Synthetic cleanup regression",
                    },
                )
        assert len(opened) == 3
        for descriptor in opened:
            with pytest.raises(OSError):
                os.fstat(descriptor)
        assert store.dispatch("report", {})["revision"] == 2
    finally:
        for descriptor in opened:
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            real_close(descriptor)
