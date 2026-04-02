"""Structured audit logging for security-sensitive Chef operations.

Every action that touches external systems (Caldera, LimaCharlie) or
mutates state is recorded as a JSON-Lines entry so the full execution
history can be reviewed, correlated, and fed into a SIEM.
"""

from __future__ import annotations

import atexit
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from chef_pantry.config import get_settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------

class AuditEvent(BaseModel):
    """Single audit record written as one JSON line.

    Attributes:
        timestamp:  UTC wall-clock time; auto-populated on creation.
        event_type: Category such as ``caldera.operation``, ``recipe.execute``,
                    or ``detection.deploy``.
        actor:      Subsystem that initiated the action (e.g.
                    ``caldera_client``, ``recipe_orchestrator``).
        action:     Human-readable verb phrase (e.g. ``create_operation``).
        target:     Optional resource identifier the action applies to
                    (e.g. an operation ID, rule name, agent paw).
        detail:     Optional bag of key/value metadata for the event.
        dry_run:    Whether the action was simulated rather than executed.
        success:    Whether the action completed without error.
    """

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    actor: str
    action: str
    target: Optional[str] = None
    detail: Optional[Dict[str, Any]] = None
    dry_run: bool = False
    success: bool = True


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Append-only JSONL writer for :class:`AuditEvent` records.

    Usage::

        with AuditLogger(Path("audit.jsonl")) as audit:
            audit.log("caldera.operation", "caldera_client", "create_operation",
                      target="op-123", detail={"adversary": "apt29"})

    The logger is **thread-safe**; multiple callers may invoke :meth:`log`
    concurrently.
    """

    def __init__(self, log_path: Path) -> None:
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, mode="a", encoding="utf-8")  # noqa: SIM115
        self._lock = threading.Lock()
        self._closed = False

    # -- public API --------------------------------------------------------

    def log(
        self,
        event_type: str,
        actor: str,
        action: str,
        *,
        target: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        success: bool = True,
    ) -> AuditEvent:
        """Create an :class:`AuditEvent` and persist it as a JSON line.

        Returns the event instance so callers can inspect or forward it.

        Raises:
            ValueError: If the logger has already been closed.
        """
        event = AuditEvent(
            event_type=event_type,
            actor=actor,
            action=action,
            target=target,
            detail=detail,
            dry_run=dry_run,
            success=success,
        )
        line = event.model_dump_json() + "\n"

        with self._lock:
            if self._closed:
                raise ValueError("AuditLogger is closed")
            self._fh.write(line)
            self._fh.flush()

        logger.debug("audit: %s %s %s", event_type, actor, action)
        return event

    def close(self) -> None:
        """Flush and close the underlying file handle.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        with self._lock:
            if not self._closed:
                self._closed = True
                self._fh.flush()
                self._fh.close()

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> AuditLogger:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        self.close()

    # -- helpers -----------------------------------------------------------

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"<AuditLogger path={self._path!s} {state}>"


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_singleton_lock = threading.Lock()
_singleton: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Return (or create) a module-level singleton :class:`AuditLogger`.

    The log path is read from :pydata:`ChefSettings.safety.audit_log`.
    The singleton is registered with :func:`atexit.register` so it is
    closed automatically when the interpreter shuts down.

    Call :func:`_reset_audit_logger` in tests to replace the singleton.
    """
    global _singleton  # noqa: PLW0603

    if _singleton is not None and not _singleton._closed:
        return _singleton

    with _singleton_lock:
        # Double-check after acquiring lock.
        if _singleton is not None and not _singleton._closed:
            return _singleton

        settings = get_settings()
        audit = AuditLogger(settings.safety.audit_log)
        atexit.register(audit.close)

        _singleton = audit
        logger.info("Audit logger initialised: %s", settings.safety.audit_log)
        return audit


def _reset_audit_logger() -> None:
    """Close the current singleton (if any) and clear it.

    Intended **only** for test teardown so each test can start fresh.
    """
    global _singleton  # noqa: PLW0603

    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
            _singleton = None
