"""Chef Pantry configuration via environment variables and .env files.

All settings are prefixed with CHEF_ and grouped by subsystem.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CalderaSettings(BaseSettings):
    """Connection and auth settings for the Caldera C2 server."""

    model_config = SettingsConfigDict(env_prefix="CHEF_CALDERA_")

    url: str = "http://localhost:8888"
    api_key: str = ""
    allowed_groups: list[str] = Field(default_factory=list)


class LimaCharlieSettings(BaseSettings):
    """Connection and auth settings for LimaCharlie."""

    model_config = SettingsConfigDict(env_prefix="CHEF_LC_")

    oid: str = ""
    api_key: str = ""


class LLMSettings(BaseSettings):
    """LLM provider settings."""

    model_config = SettingsConfigDict(env_prefix="CHEF_LLM_")

    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o"


class SafetySettings(BaseSettings):
    """Guardrails that apply across the entire Chef pipeline."""

    model_config = SettingsConfigDict(env_prefix="CHEF_SAFETY_")

    dry_run: bool = True
    audit_log: Path = Path("chef_audit.log")


class ChefSettings(BaseSettings):
    """Root settings object that aggregates all subsystem configs.

    Loads values from environment variables (CHEF_* prefix) and from a
    ``.env`` file in the working directory if one exists.
    """

    model_config = SettingsConfigDict(
        env_prefix="CHEF_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    caldera: CalderaSettings = Field(default_factory=CalderaSettings)
    limacharlie: LimaCharlieSettings = Field(default_factory=LimaCharlieSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    safety: SafetySettings = Field(default_factory=SafetySettings)


@lru_cache(maxsize=1)
def get_settings() -> ChefSettings:
    """Return a cached singleton of :class:`ChefSettings`.

    Call ``get_settings.cache_clear()`` in tests to force a reload.
    """
    return ChefSettings()
