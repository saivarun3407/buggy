"""Exclusive workspace-local workflow evidence with externally anchored manifest hashes."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from buggy.sandbox_kernel.assessment import (
    AssessmentError,
    AssessmentStore,
    _dump,
    _json_object,
    _relative_path,
    _sha,
)


class DefensiveWorkflowError(ValueError):
    """Invalid workflow input or unavailable trustworthy workflow state."""


class WorkflowInputError(DefensiveWorkflowError):
    """A workflow request violates its fixed input contract."""


class WorkflowStorageError(DefensiveWorkflowError):
    """Safe, immutable workspace evidence storage is unavailable."""


LIMIT = 2 * 1024 * 1024
NON_ASSURANCE: dict[str, Any] = {
    "assurance": "none",
    "independent_verification": False,
    "baseline_coverage_updated": False,
}


@contextmanager
def _directory_descriptor(parent: int, component: str) -> Iterator[int]:
    if component in {"", ".", ".."} or os.path.basename(component) != component:
        raise WorkflowStorageError("Invalid workflow directory component")
    descriptor = os.open(
        os.path.basename(component), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
    )
    try:
        yield descriptor
    finally:
        os.close(descriptor)


class WorkflowStorage:
    def __init__(self, workspace: str | Path) -> None:
        try:
            self.workspace = AssessmentStore(workspace).workspace
            self._identity: tuple[int, int] | None = None
            with self.directory(()) as descriptor:
                info = os.fstat(descriptor)
                self._identity = (info.st_dev, info.st_ino)
        except (AssessmentError, OSError, AttributeError) as exc:
            raise WorkflowStorageError("Secure workflow workspace is unavailable") from exc

    @contextmanager
    def directory(self, parts: tuple[str, ...], *, create: bool = False) -> Iterator[int]:
        try:
            parent = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY)
            try:
                # Replace the owned parent handle instead of retaining every ancestor.
                # Each child has a lexical lifetime; depth uses neither extra FDs nor recursion.
                for part in self.workspace.parts[1:]:
                    with _directory_descriptor(parent, part) as child:
                        os.dup2(child, parent, inheritable=False)
                info = os.fstat(parent)
                if self._identity is not None and (info.st_dev, info.st_ino) != self._identity:
                    raise WorkflowStorageError("Workflow workspace identity changed")
                for part in parts:
                    if part in {"", ".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", part):
                        raise WorkflowStorageError("Invalid workflow directory")
                    if create:
                        try:
                            os.mkdir(part, mode=0o700, dir_fd=parent)
                        except FileExistsError:
                            if not stat.S_ISDIR(
                                os.stat(part, dir_fd=parent, follow_symlinks=False).st_mode
                            ):
                                raise WorkflowStorageError("Workflow directory is unsafe") from None
                        else:
                            os.fsync(parent)
                    with _directory_descriptor(parent, part) as child:
                        os.dup2(child, parent, inheritable=False)
                yield parent
            finally:
                os.close(parent)
        except (OSError, AttributeError) as exc:
            raise WorkflowStorageError(
                "Workflow storage is missing, unsafe, or unavailable"
            ) from exc

    def read(self, value: Any, *, maximum: int = LIMIT) -> tuple[dict[str, Any], bytes]:
        try:
            path = _relative_path(value)
            if str(path) != value or path.name == "-":
                raise WorkflowInputError(
                    "artifact_path must be a canonical workspace-relative file"
                )
            candidate = os.path.normpath(os.path.join(str(self.workspace), str(path)))
            if not candidate.startswith(str(self.workspace).rstrip(os.sep) + os.sep):
                raise WorkflowInputError("Artifact path escapes the workflow workspace")
            with self.directory(path.parts[:-1]) as parent:
                descriptor = os.open(
                    os.path.basename(candidate),
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent,
                )
                try:
                    with os.fdopen(descriptor, "rb", closefd=False) as stream:
                        before = os.fstat(stream.fileno())
                        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                            raise WorkflowStorageError("Artifact must be a bounded regular file")
                        raw = stream.read(maximum + 1)
                        after = os.fstat(stream.fileno())
                        if len(raw) != before.st_size or any(
                            getattr(before, field) != getattr(after, field)
                            for field in (
                                "st_dev",
                                "st_ino",
                                "st_size",
                                "st_mtime_ns",
                                "st_ctime_ns",
                            )
                        ):
                            raise WorkflowStorageError("Artifact changed while being read")
                finally:
                    os.close(descriptor)
            return {"path": str(path), "sha256": _sha(raw), "size_bytes": len(raw)}, raw
        except AssessmentError as exc:
            raise WorkflowInputError(
                "artifact_path must be a workspace-relative local file"
            ) from exc
        except OSError as exc:
            raise WorkflowStorageError("Artifact is missing, unreadable, or symlinked") from exc

    def abort_present(self) -> bool:
        with self.directory(()) as parent:
            try:
                os.stat(".abort", dir_fd=parent, follow_symlinks=False)
                return True
            except FileNotFoundError:
                return False

    @contextmanager
    def observation_lock(self) -> Iterator[None]:
        try:
            import fcntl
        except ImportError as exc:
            raise WorkflowStorageError("Exclusive observation locking is unavailable") from exc
        with self.directory(("assessment", "workflows")) as parent:
            descriptor = os.open(
                ".observation.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=parent,
            )
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise WorkflowStorageError(
                        "Observation lock must be a regular unlinked-alias-free file"
                    )
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
            finally:
                os.close(descriptor)

    def new_run(self) -> str:
        nonce = uuid4().hex
        with self.directory(("assessment", "workflows"), create=True) as parent:
            os.mkdir(nonce, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        return nonce

    def write(self, nonce: str, name: str, raw: bytes) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{32}", nonce) or not re.fullmatch(r"[a-z0-9_.-]+", name):
            raise WorkflowStorageError("Invalid internal evidence name")
        if len(raw) > LIMIT:
            raise WorkflowStorageError("Workflow evidence exceeds the storage bound")
        parts = ("assessment", "workflows", nonce)
        with self.directory(parts) as parent:
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o400)
                    os.fsync(stream.fileno())
            finally:
                os.close(descriptor)
            os.fsync(parent)
        return {"path": "/".join((*parts, name)), "sha256": _sha(raw), "size_bytes": len(raw)}

    def finish(self, manifest: dict[str, Any]) -> str:
        reference = self.write(manifest["run_nonce"], "manifest.json", _dump(manifest).encode())
        return manifest["run_nonce"] + "." + reference["sha256"]

    def report(self, run_id: str) -> dict[str, Any]:
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}\.[0-9a-f]{64}", run_id):
            raise WorkflowInputError("Invalid workflow run_id")
        nonce, digest = run_id.split(".")
        path = f"assessment/workflows/{nonce}/manifest.json"
        fallback = NON_ASSURANCE | {
            "run_id": run_id,
            "status": "inconclusive",
            "observations": [],
            "evidence_integrity": "untrusted",
            "integrity_errors": [{"path": path, "code": "MANIFEST_INTEGRITY"}],
        }
        try:
            reference, raw = self.read(path)
            if reference["sha256"] != digest:
                return fallback
            manifest = _json_object(raw)
            if manifest.get("run_nonce") != nonce:
                return fallback
            errors = []
            references = list(manifest["evidence"])
            if manifest.get("source_artifact") is not None:
                references.append(manifest["source_artifact"])
            for expected in references:
                try:
                    actual, _ = self.read(expected["path"])
                    if any(actual[key] != expected[key] for key in ("sha256", "size_bytes")):
                        errors.append({"path": expected["path"], "code": "EVIDENCE_CHANGED"})
                except DefensiveWorkflowError:
                    errors.append({"path": expected["path"], "code": "EVIDENCE_UNAVAILABLE"})
            result = (
                manifest
                | NON_ASSURANCE
                | {
                    "run_id": run_id,
                    "manifest": reference,
                    "evidence_integrity": "untrusted" if errors else "verified",
                    "integrity_errors": errors,
                }
            )
            if errors:
                result.update(status="inconclusive", recorded_status=manifest["status"])
            return result
        except (DefensiveWorkflowError, AssessmentError, KeyError, TypeError, ValueError):
            return fallback
