"""Batch exporter — BUGGY FORK: the network sender is permanently removed.

Buggy does not phone home. This module keeps ``BatchExporter`` and the
``Transport`` type so existing imports resolve, but:

* :func:`_http_post` — the one HTTP sender — is now an inert no-op. It imports
  no ``urllib``/``socket``/``requests``, opens no connection, and returns
  without doing anything. There is no code path here that can reach the network.
* ``BatchExporter`` is never constructed in practice (``TelemetryConfig.enabled``
  is hard-wired ``False``, so ``TelemetrySink`` never builds one). If something
  constructs it directly, its default transport is the inert ``_http_post``, so
  a flush still sends nothing.

The buffering logic is retained only so the type stays drop-in; it moves bytes
between in-memory lists and never off the box.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from typing import Any

log = logging.getLogger("buggy.telemetry.exporter")

# (url, json_body) -> None. In Buggy this is always a no-op; nothing is sent.
Transport = Callable[[str, bytes], None]


def _http_post(url: str, body: bytes) -> None:
    """Buggy: telemetry removed — inert no-op. Opens no socket, sends nothing."""
    return None


class BatchExporter:
    """Thread-safe Tier-A event buffer with size/timer-triggered flushing."""

    def __init__(
        self,
        *,
        endpoint: str,
        envelope: Callable[[list[dict[str, Any]]], dict[str, Any]],
        batch_size: int = 50,
        flush_interval_s: float = 30.0,
        max_queue: int = 1000,
        transport: Transport | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._envelope = envelope
        self._batch_size = batch_size
        self._max_queue = max_queue
        self._transport = transport or _http_post
        self._buf: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._closed = False
        self._timer: threading.Timer | None = None
        self._flush_interval_s = flush_interval_s
        self._arm_timer()

    def _arm_timer(self) -> None:
        if self._closed or self._flush_interval_s <= 0:
            return
        self._timer = threading.Timer(self._flush_interval_s, self._on_timer)
        self._timer.daemon = True
        self._timer.start()

    def _on_timer(self) -> None:
        self.flush()
        with self._lock:
            if not self._closed:
                self._arm_timer()

    def record(self, event: dict[str, Any]) -> None:
        """Enqueue one Tier-A event; flush inline when the batch is full."""
        with self._lock:
            if self._closed:
                return
            if len(self._buf) >= self._max_queue:
                self._buf.pop(0)  # bounded buffer — drop oldest, never grow unbounded
            self._buf.append(event)
            full = len(self._buf) >= self._batch_size
        if full:
            self.flush()

    def flush(self) -> None:
        """Ship the current buffer. Swallows all errors (offline-tolerant)."""
        with self._lock:
            if not self._buf:
                return
            batch = self._buf
            self._buf = []
        try:
            body = json.dumps(self._envelope(batch), separators=(",", ":")).encode("utf-8")
            self._transport(self._endpoint, body)
        except (OSError, ValueError) as exc:
            # Drop the batch — the default transport is an inert no-op, so this
            # only guards an injected custom transport.
            log.debug("telemetry flush failed (%s events dropped): %s", len(batch), exc)

    def close(self) -> None:
        """Final flush and stop the timer."""
        with self._lock:
            self._closed = True
            timer = self._timer
            self._timer = None
        if timer is not None:
            timer.cancel()
        self.flush()
