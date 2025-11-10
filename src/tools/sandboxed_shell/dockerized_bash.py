import subprocess
import uuid
import logging
import shlex
import re
from typing import Dict, List, Union

logger = logging.getLogger(__name__)


def _format_mount_flags(mounts: Dict[str, str] | None = None) -> str:
    """Return docker volume flags for the provided mount mapping."""
    if not mounts:
        return ""
    return "".join(
        f" -v {shlex.quote(host)}:{container}" for host, container in mounts.items()
    )

class DockerizedBashProcess:
    """
    A Dockerized bash process that can run commands inside a sandboxed Docker container
    using the decompai-runner image.
    
    In nonpersistent mode, each command is executed in a one-off container.
    In persistent mode, a container is started once and an interactive shell is opened
    inside it; subsequent commands are piped into that shell so that state is preserved.
    """
    def __init__(
        self,
        strip_newlines: bool = False,
        return_err_output: bool = False,
        persistent: bool = False,
        workdir: str = "/",
        mounted_dirs: Dict[str, str] | None = None,
        runner_image: str = "decompai-runner",
        docker_platform: str = "linux/amd64",
        privileged: bool = True,
    ):
        """
        Initialize the DockerizedBashProcess.

        Args:
            strip_newlines (bool): Whether to strip newline characters from output.
            return_err_output (bool): Whether to return output even on command errors.
            persistent (bool): If True, a persistent Docker container and shell will be used.
        """
        self.strip_newlines = strip_newlines
        self.return_err_output = return_err_output
        self.persistent = persistent
        self.container_id = None
        self.persistent_process = None  # Will hold our persistent shell subprocess
        self.workdir = workdir
        self.mounted_dirs = mounted_dirs or {}
        self.runner_image = runner_image
        self.docker_platform = docker_platform
        self.privileged = privileged
        if persistent:
            # Create a unique container name and initialize the persistent container.
            self.container_name = f"sandbox_{uuid.uuid4().hex[:8]}"
            self.container_id = None

    def _initialize_persistent_container(self, container_name: str) -> str:
        """
        Starts a persistent Docker container and returns its container ID.
        The container is run with a dummy command (tail -f /dev/null) to keep it alive.
        """
        
        mounted_dirs_args = _format_mount_flags(self.mounted_dirs)
        workdir_arg = f" -w {self.workdir}" if self.workdir else ""
        privileged_arg = " --privileged" if self.privileged else ""

        docker_run_command = (
            f"docker run --rm -d{privileged_arg} --name {container_name}{mounted_dirs_args}{workdir_arg}"
            f" --platform {self.docker_platform} {self.runner_image} tail -f /dev/null"
        )
        try:
            result = subprocess.run(
                docker_run_command,
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            container_id = result.stdout.decode().strip()
            logger.info(f"Started persistent container {container_name} with ID: {container_id}")
            return container_id
        except subprocess.CalledProcessError as e:
            logger.error(f"Error starting persistent container: {e.stderr.decode()}")
            raise

    def _initialize_persistent_shell(self):
        """
        Opens an interactive bash shell inside the persistent container using docker exec.
        This process will remain open and be used for all _run_persistent calls.
        """
        docker_exec_command = f"docker exec -i {self.container_id} bash"
        try:
            self.persistent_process = subprocess.Popen(
                docker_exec_command,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )
            # Optionally, you could read any initial output here if needed.
            logger.info("Persistent shell initialized.")
        except Exception as e:
            logger.error(f"Error initializing persistent shell: {e}")
            raise

    def run(self, commands: Union[str, List[str]], filter_color_codes: bool = True) -> str:
        """
        Runs a command or a list of commands.

        Args:
            commands (str or List[str]): The shell command(s) to execute.
            filter_color_codes (bool): Whether to filter ANSI color codes from output.

        Returns:
            str: The output from executing the command(s).
        """
        if isinstance(commands, str):
            commands = [commands]
        joined_commands = ";".join(commands)
        if self.persistent:
            if not self.container_id:
                self.container_id = self._initialize_persistent_container(self.container_name)
                self._initialize_persistent_shell()
            if self.container_id and self.persistent_process:
                output = self._run_persistent(joined_commands)
        else:
            output = self._run(joined_commands)
        if filter_color_codes:
            output = self._remove_color_codes(output)
        return output

    def _run(self, command: str) -> str:
        """
        Runs a command in a one-off Docker container (non-persistent mode).

        Args:
            command (str): The command to run.

        Returns:
            str: The command output.
        """
        # Use shlex.quote to safely escape the command.
        safe_command = shlex.quote(command)
        mounted_dirs_args = _format_mount_flags(self.mounted_dirs)
        workdir_arg = f" -w {self.workdir}" if self.workdir else ""
        privileged_arg = " --privileged" if self.privileged else ""
        docker_run_command = (
            f"docker run --rm{privileged_arg}{mounted_dirs_args}{workdir_arg} --platform {self.docker_platform} "
            f"{self.runner_image} bash -c {safe_command}"
        )
        try:
            result = subprocess.run(
                docker_run_command,
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout = result.stdout.decode()
            stderr = result.stderr.decode()
            output = stdout
            if stderr:
                output += f"\n=== STDERR ===\n" + stderr
        except subprocess.CalledProcessError as error:
            if self.return_err_output:
                stdout = error.stdout.decode() if error.stdout else ''
                stderr = error.stderr.decode() if error.stderr else ''
                output = stdout
                if stderr:
                    output += f"\n=== STDERR ===\n" + stderr
                return output
            return str(error)
        if self.strip_newlines:
            output = output.strip()
        return output

    def _run_persistent(self, command: str) -> str:
        """
        Runs the command inside the already running persistent Docker container,
        using the persistent shell. The same shell session is used, so state is maintained
        (e.g., if you run 'cd /tmp' followed by 'ls', the second command will list /tmp).

        A unique marker is appended to each command to signal the end of the command's output.
        """
        if self.persistent_process is None or self.persistent_process.stdin is None or self.persistent_process.stdout is None:
            raise ValueError("Persistent process is not properly initialized.")
        # Generate a unique marker to indicate the command completion.
        marker = f"__COMMAND_DONE__{uuid.uuid4().hex}"
        # Append an echo of the marker.
        full_command = f"{command}; echo {marker}"
        # Send the command followed by a newline.
        self.persistent_process.stdin.write(full_command + "\n")
        self.persistent_process.stdin.flush()

        output_lines = []
        # Read lines until we encounter the marker.
        while True:
            line = self.persistent_process.stdout.readline()
            if not line:
                # In case the process unexpectedly ends.
                break
            if marker in line:
                # Optionally, remove the marker from the output if needed.
                break
            output_lines.append(line)
        output = ''.join(output_lines)
        # Now, try to read from stderr if available
        stderr = ''
        if self.persistent_process.stderr:
            try:
                # Non-blocking read of stderr
                import select
                rlist, _, _ = select.select([self.persistent_process.stderr], [], [], 0.1)
                if rlist:
                    stderr = self.persistent_process.stderr.read()
            except Exception:
                pass
        if stderr:
            output += f"\n=== STDERR ===\n" + stderr
        if self.strip_newlines:
            output = output.strip()
        return output

    def stop_persistent_container(self):
        """
        Stops the persistent Docker container and terminates the persistent shell process.
        """
        if self.persistent_process:
            try:
                self.persistent_process.terminate()
                self.persistent_process.wait(timeout=5)
                logger.info("Persistent shell terminated.")
            except Exception as e:
                logger.error(f"Error terminating persistent shell: {e}")
        if self.container_id:
            docker_stop_command = f"docker stop {self.container_id}"
            try:
                subprocess.run(
                    docker_stop_command,
                    shell=True,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                logger.info(f"Stopped container {self.container_id}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Error stopping container: {e.stderr.decode()}")
            self.container_id = None
    
    def __enter__(self):
        # Enables use in a 'with' statement.
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # Ensure cleanup on exiting the context.
        self.stop_persistent_container()

    def __del__(self):
        # Fallback cleanup if not used as a context manager.
        self.stop_persistent_container()

    @staticmethod
    def _remove_color_codes(text: str) -> str:
        """Remove ANSI color codes from the given text."""
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)
