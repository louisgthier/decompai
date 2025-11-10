import logging
import platform
import warnings
from typing import Any, Dict, List, Optional, Type, Union

from langchain_core.callbacks import CallbackManagerForToolRun
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)


class SandboxedShellInput(BaseModel):
    """Commands for the Bash Shell tool."""

    commands: List[str] = Field(
        ...,
        description="List of shell commands to run. Deserialized using json.loads",
    )

    @model_validator(mode="before")
    @classmethod
    def _validate_commands(cls, values: dict) -> Any:
        """Validate commands."""
        commands = values.get("commands")
        if not isinstance(commands, list):
            values["commands"] = [commands]
        warnings.warn(
            "The shell tool has no safeguards by default. Use at your own risk."
        )
        return values


def _get_platform() -> str:
    """Get platform."""
    return "Kali Linux"


def _get_dockerized_bash_process(
    mounted_dirs: Optional[Dict] = None,
    workdir: Optional[str] = None,
    runner_image: str = "decompai-runner",
    docker_platform: str = "linux/amd64",
    privileged: bool = True,
) -> Any:
    """Get a new Dockerized Bash process with the specified mounted_dirs and workdir."""
    from src.tools.sandboxed_shell.dockerized_bash import DockerizedBashProcess
    return DockerizedBashProcess(
        return_err_output=True,
        persistent=True,
        mounted_dirs=mounted_dirs,
        workdir=workdir,
        runner_image=runner_image,
        docker_platform=docker_platform,
        privileged=privileged,
    )


class SandboxedShellTool(BaseTool):
    """Tool to run shell commands."""

    name: str = "kali_stateful_shell"
    description: str = f"Run shell commands on this {_get_platform()} machine."
    args_schema: Type[BaseModel] = SandboxedShellInput
    ask_human_input: bool = False

    # Instance default for mounted directories.
    mounted_dirs: Dict = Field(default_factory=dict)
    runner_image: str = Field(default="decompai-runner")
    docker_platform: str = Field(default="linux/amd64")
    privileged: bool = Field(default=True)

    # Mapping from process ID to DockerizedBashProcess instances.
    processes: Dict[str, Any] = Field(default_factory=dict)

    def _run(
        self,
        commands: Union[str, List[str]],
        process_id: Optional[str] = None,
        mounted_dirs: Optional[Dict] = None,
        workdir: Optional[str] = None,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> Optional[str]:
        """Run commands and return final output.

        If a process with the specified process_id doesn't exist, it will be created
        with the given mounted_dirs and workdir. If process_id is not provided,
        a default process id "default" is used.
        """
        # Use default process id if none is provided.
        process_id = process_id or "default"
        # Determine which mounted_dirs to use: the one passed to this call or the instance default.
        dirs_to_use = mounted_dirs if mounted_dirs is not None else self.mounted_dirs

        # If the process doesn't exist, create it.
        if process_id not in self.processes:
            self.processes[process_id] = _get_dockerized_bash_process(
                mounted_dirs=dirs_to_use,
                workdir=workdir,
                runner_image=self.runner_image,
                docker_platform=self.docker_platform,
                privileged=self.privileged,
            )

        process = self.processes[process_id]

        print(f"Executing command in process '{process_id}':\n{commands}")  # noqa: T201

        try:
            if self.ask_human_input:
                user_input = input(
                    "Proceed with command execution? (y/n): ").lower()
                if user_input == "y":
                    return process.run(commands)
                else:
                    logger.info("User aborted command execution.")
                    return None
            else:
                return process.run(commands)

        except Exception as e:
            # TODO: Fix [Errno 32] Broken pipe
            logger.error(f"Error during command execution: {e}")
            return f"Error during command execution: {e}"
