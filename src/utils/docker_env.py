from __future__ import annotations

import os
import shlex
from typing import Dict
import subprocess

from src.config import settings

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _host_dir(subdir: str) -> str:
    return os.path.join(settings.DECOMPAI_HOST_ROOT, subdir)


def get_runner_mounts() -> Dict[str, str]:
    """Return default host->container mounts for the runner."""
    mounts: Dict[str, str] = {}
    sessions_host = settings.DECOMPAI_SESSIONS_HOST_DIR or _host_dir("decompai_analysis_sessions")
    mounts[sessions_host] = settings.ANALYSIS_SESSIONS_ROOT
    binaries_host = settings.DECOMPAI_BINARIES_HOST_DIR or _host_dir("binaries")
    mounts[binaries_host] = "/binaries"
    source_host = settings.DECOMPAI_SOURCE_HOST_DIR or _host_dir("source_code")
    mounts[source_host] = "/source_code"
    return mounts


def format_mount_flags(mounts: Dict[str, str] | None = None) -> str:
    """Format docker -v flags for the provided mount mapping."""
    mounts = mounts or get_runner_mounts()
    return "".join(
        f" -v {shlex.quote(host)}:{container}"
        for host, container in mounts.items()
        if host
    )


def runner_image_exists() -> bool:
    """Check whether the configured runner image already exists locally."""
    try:
        subprocess.run(
            ["docker", "image", "inspect", settings.DECOMPAI_RUNNER_IMAGE],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def should_build_runner_image() -> bool:
    """Determine whether to build the runner image locally."""
    mode = (settings.DECOMPAI_RUNNER_BUILD or "auto").lower()
    if mode in _TRUE_VALUES:
        return True
    if mode in _FALSE_VALUES:
        return False
    return not runner_image_exists()
