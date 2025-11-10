from __future__ import annotations

import os
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _cwd() -> str:
    return os.getcwd()


class Settings(BaseSettings):
    """Central configuration pulled from environment or defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="allow",
    )

    ANALYSIS_SESSIONS_ROOT: str = Field(default="/tmp/decompai_analysis_sessions")
    AGENT_WORKSPACE_NAME: str = Field(default="agent_workspace")
    DECOMPAI_RUNNER_IMAGE: str = Field(default="louisgauthier/decompai-runner:1.0.0")
    DECOMPAI_RUNNER_BUILD: str = Field(default="auto")
    DECOMPAI_HOST_ROOT: str = Field(default_factory=_cwd)
    DECOMPAI_BINARIES_HOST_DIR: str | None = None
    DECOMPAI_SOURCE_HOST_DIR: str | None = None
    DECOMPAI_SESSIONS_HOST_DIR: str | None = None
    GRADIO_SERVER_NAME: str = Field(default="0.0.0.0")
    GRADIO_SERVER_PORT: int = Field(default=7860)
    GRADIO_SHARE: bool = Field(default=False)


settings = Settings()

__all__ = ["settings", "Settings"]
