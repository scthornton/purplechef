"""Chef Pantry error hierarchy.

Every exception inherits from :class:`ChefError` so callers can catch
the whole family with a single ``except ChefError``.
"""

from __future__ import annotations


class ChefError(Exception):
    """Base exception for all Chef operations."""

    def __str__(self) -> str:
        return self.args[0] if self.args else self.__class__.__name__


class ConfigError(ChefError):
    """Raised when Chef configuration is missing or invalid."""


class CalderaError(ChefError):
    """Raised when a Caldera API call fails."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(message)

    def __str__(self) -> str:
        return f"Caldera {self.status_code}: {self.message}"


class LimaCharlieError(ChefError):
    """Raised when a LimaCharlie API call fails."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(message)

    def __str__(self) -> str:
        return f"LimaCharlie {self.status_code}: {self.message}"


class RecipeError(ChefError):
    """Raised when recipe parsing or execution fails."""

    def __init__(self, recipe_name: str, detail: str = "") -> None:
        self.recipe_name = recipe_name
        self.detail = detail
        super().__init__(detail or f"Recipe failed: {recipe_name}")

    def __str__(self) -> str:
        msg = f"Recipe '{self.recipe_name}'"
        if self.detail:
            msg += f": {self.detail}"
        return msg


class ValidationError(ChefError):
    """Raised when input validation fails."""

    def __init__(self, field: str, detail: str) -> None:
        self.field = field
        self.detail = detail
        super().__init__(detail)

    def __str__(self) -> str:
        return f"Validation error on '{self.field}': {self.detail}"


class DryRunBlockedError(ChefError):
    """Signals that dry-run mode prevented execution.

    This is not a failure -- it indicates the safety guardrail is working.
    Callers should log the message and continue.
    """

    def __init__(self, action: str = "") -> None:
        self.action = action
        super().__init__(action or "Blocked by dry-run mode")

    def __str__(self) -> str:
        if self.action:
            return f"[DRY RUN] Blocked: {self.action}"
        return "[DRY RUN] Execution blocked"
