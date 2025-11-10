import os
import subprocess
from typing_extensions import Optional, Annotated, List, Dict, Type, Callable, Any, Union
from langchain_core.tools import tool, InjectedToolCallId
from langchain_community.tools.file_management.write import WriteFileTool, WriteFileInput, BaseFileToolMixin
from langchain_core.messages import (
    AIMessage,
    AnyMessage,
    ToolCall,
    ToolMessage,
    convert_to_messages,
)
from langgraph.prebuilt import InjectedState, InjectedStore
from langchain_core.callbacks import CallbackManagerForToolRun
from langgraph.config import get_stream_writer
import json
from pydantic import BaseModel, Field, create_model
from inspect import Signature, Parameter

from src.config import settings
import src.utils as utils
from src.utils import disassemble_function
from src.state import State
from src.tools.sandboxed_shell import SandboxedShellTool
from src.utils.docker_env import get_runner_mounts

def get_agent_workspace_path(state: State) -> str:
    """Ensure the workspace folder exists and return its path."""
    session_path = state.get("session_path")
    if not session_path:
        raise ValueError("Workspace path not set in state.")
    agent_workspace_path = os.path.join(
        session_path, settings.AGENT_WORKSPACE_NAME)
    os.makedirs(agent_workspace_path, exist_ok=True)
    return agent_workspace_path


def create_tool_function(cls: Type) -> Callable:
    """
    Factory that creates a tool function from a given class.
    The generated function will:
      - Accept `state` and parameters defined by cls.args_schema.
      - Be decorated with @tool.
      - Have a name and docstring based on cls attributes.
    """
    # Instantiate the class to access its attributes
    cls_instance = cls()
    args_schema: Type[BaseModel] = cls_instance.args_schema
    func_name: str = cls_instance.name
    func_doc: str = cls_instance.description

    # Define the function without decoration first
    def dynamic_tool(
        state: Annotated[Any, InjectedState],
        **kwargs: Any
    ) -> Any:
        session_path = state["session_path"]
        instance = cls(root_dir=os.path.join(
            session_path, settings.AGENT_WORKSPACE_NAME))
        return instance._run(**kwargs)

    # Set the function's name and docstring before decoration
    dynamic_tool.__name__ = func_name
    dynamic_tool.__doc__ = func_doc

    class NewSchema(args_schema):
        state: Annotated[State, InjectedState]

    # Now apply the @tool decorator with the description
    dynamic_tool = tool(args_schema=NewSchema)(dynamic_tool)

    return dynamic_tool


@tool
def get_agent_workspace_directory_tree(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """Return a JSON-formatted tree of files in the agent workspace subfolder."""
    agent_workspace_path = get_agent_workspace_path(state)
    tree = {}
    for root, dirs, files in os.walk(agent_workspace_path):
        rel_root = os.path.relpath(root, agent_workspace_path)
        tree[rel_root] = files
    return ToolMessage(content=json.dumps(tree, indent=2), tool_call_id=tool_call_id)


@tool
def summarize_assembly(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """List functions in the binary at binary_path."""
    summary = str(utils.summarize_assembly(binary_path=state["binary_path"]))
    return ToolMessage(content=f"Summary of assembly code:\n\n{summary}", tool_call_id=tool_call_id)


@tool
def disassemble_binary(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """Disassemble the binary at binary_path."""
    assembly_code = utils.disassemble_binary(binary_path=state["binary_path"])

    if utils.count_tokens(assembly_code, state["model_name"]) > state["model_context_length"] // 2:
        raise ValueError("Disassembly too long for model context length.")

    return ToolMessage(content=f"Disassembly of binary:\n\n{assembly_code}", tool_call_id=tool_call_id)


@tool
def disassemble_section(
    section_name: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """Disassemble a section of the binary at binary_path."""
    assembly_code = utils.disassemble_section(
        binary_path=state["binary_path"], section_name=section_name)

    if utils.count_tokens(assembly_code, state["model_name"]) > state["model_context_length"] // 2:
        raise ValueError("Disassembly too long for model context length.")

    return ToolMessage(content=f"Disassembly of section {section_name}:\n\n{assembly_code}", tool_call_id=tool_call_id)


@tool
def disassemble_function(
    function_name: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """Disassemble a function from the binary at binary_path."""
    assembly_code = utils.disassemble_function(
        binary_path=state["binary_path"], function_name=function_name)

    if utils.count_tokens(assembly_code, state["model_name"]) > state["model_context_length"] // 2:
        raise ValueError("Disassembly too long for model context length.")

    return ToolMessage(content=f"Disassembly of function {function_name}:\n\n{assembly_code}", tool_call_id=tool_call_id)


@tool
def dump_memory(
    address: str,
    length: int,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Reads a specified number of bytes from the binary at a given address.
    Returns the dumped bytes as a hex string.
    """
    if address.startswith("0x"):
        address = address[2:]
    address = int(address, 16)

    data = utils.dump_memory(state["binary_path"], address, length)
    return ToolMessage(content=data.hex(), tool_call_id=tool_call_id)


@tool
def get_string_at_address(
    address: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Reads a null-terminated string from the binary starting at the given address.
    """
    if address.startswith("0x"):
        address = address[2:]
    address = int(address, 16)
    return ToolMessage(content=utils.get_string_at_address(state["binary_path"], address), tool_call_id=tool_call_id)

# Dynamically create an extended args schema that adds the 'state' field.
def extend_args_schema(parent_schema: Type[BaseModel]) -> Type[BaseModel]:
    return create_model(
        'Extended' + parent_schema.__name__,
        state=(Annotated[State, InjectedState], ...),  # required field
        __base__=parent_schema,
    )

import src.tools.sandboxed_shell.tool as src_tools_sandboxed_shell_tool
class CustomSandboxedShellTool(SandboxedShellTool):
    args_schema: Type[BaseModel] = extend_args_schema(src_tools_sandboxed_shell_tool.SandboxedShellInput)
    runner_image: str = settings.DECOMPAI_RUNNER_IMAGE

    def _run(
        self,
        commands: Union[str, List[str]],
        state: Annotated[State, InjectedState],
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> Optional[str]:
        # Extract required values from state.
        agent_workspace_path = get_agent_workspace_path(state)
        process_id = state.get("session_path")
        mounted_dirs = get_runner_mounts()
        mounted_dirs[agent_workspace_path] = agent_workspace_path
        workdir = agent_workspace_path
        return super()._run(commands, process_id, mounted_dirs, workdir, run_manager)

@tool
def run_ghidra_post_script(
    script_path: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
    script_args: str = ""
) -> str:
    """
    Runs a Ghidra post-script using analyzeHeadless.
    Args:
        script_path: Path to the script relative to the agent workspace
        script_args: Arguments to pass to the script
    """
    agent_workspace_path = get_agent_workspace_path(state)
    full_script_path = os.path.join(agent_workspace_path, script_path)
    
    if not os.path.exists(full_script_path):
        return ToolMessage(content=f"Script not found at {script_path}", tool_call_id=tool_call_id)
    
    try:
        result = utils.run_ghidra_post_script(utils.get_binary_path_in_workspace(state["binary_path"]), full_script_path, script_args)
        return ToolMessage(content=result, tool_call_id=tool_call_id)
    except Exception as e:
        return ToolMessage(content=f"Error running Ghidra script: {str(e)}", tool_call_id=tool_call_id)

# Instantiate the existing tool
kali_stateful_shell = CustomSandboxedShellTool().as_tool()

@tool
def decompile_function_with_ghidra(
    function_name: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Decompiles a function using Ghidra's headless mode.
    Args:
        function_name: Name of the function to decompile
    """
    try:
        writer = get_stream_writer()
        writer(f"Decompiling function {function_name}...\n")
        result = utils.decompile_function_with_ghidra(utils.get_binary_path_in_workspace(state["binary_path"]), function_name)
        return ToolMessage(content=result, tool_call_id=tool_call_id)
    except Exception as e:
        return ToolMessage(content=f"Error decompiling function: {str(e)}", tool_call_id=tool_call_id)

@tool
def r2_stateless_shell(
    commands: Union[str, List[str]],
    state: Annotated[State, InjectedState],
    ) -> str:
    """
    Executes one or several commands using r2 in quiet mode with the -c option. Each call to this tool will start a new r2 instance.
    The r2 environment includes the r2dec and r2ghidra plugins for decompilation and analysis.
    """
    if isinstance(commands, str):
        commands = [commands]
        
    # Prepend the command with 'r2 -qc'
    full_command = f"r2 -e bin.relocs.apply=true -qc \"{'; '.join(commands)}\" {utils.get_binary_path_in_workspace(state['binary_path'])}"
    # Invoke the existing shell tool with the modified command
    return kali_stateful_shell.invoke({"commands": full_command, "state": state})

@tool
def r2_stateful_shell(
    commands: Union[str, List[str]],
    state: Annotated[State, InjectedState],
) -> str:
    """
    Executes one or several commands using r2 in quiet mode with the -c option, maintaining state by replaying all previous commands in this session.
    The r2 environment includes the r2dec and r2ghidra plugins for decompilation and analysis.
    Tracks the number of lines returned so that only new output is returned each call.
    """
    if isinstance(commands, str):
        commands = [commands]
    # Retrieve or initialize the command history
    history_key = 'r2_stateful_shell_history'
    if history_key not in state:
        state[history_key] = []
    # Append new commands to the history
    state[history_key].extend(commands)
    # Build the full command string
    all_commands = '; '.join(state[history_key])
    full_command = f"r2 -e bin.relocs.apply=true -qc \"{all_commands}\" {utils.get_binary_path_in_workspace(state['binary_path'])}"

    # Retrieve or initialize the output line count
    output_line_count_key = 'r2_stateful_shell_output_line_count'
    prev_line_count = state.get(output_line_count_key, 0)

    # Invoke the shell tool
    output = kali_stateful_shell.invoke({"commands": full_command, "state": state})

    # Split output into lines
    output_lines = output.splitlines()
    new_lines = output_lines[prev_line_count:] if prev_line_count < len(output_lines) else []

    # Update the state with the new line count
    state[output_line_count_key] = len(output_lines)

    # Return only the new lines
    return '\n'.join(new_lines)

@tool
def run_python_script(
    script_content: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
    script_name: Optional[str] = None
) -> str:
    """
    Writes a Python script to the workspace and executes it in the sandboxed environment.
    
    Args:
        script_content: The content of the Python script to execute
        state: The current state containing workspace information
        tool_call_id: The ID of the tool call
        script_name: Optional name for the script file. If not provided, will use an incremental name with 'script_' prefix
    """
    workspace_path = get_agent_workspace_path(state)
    
    # Generate script name if not provided
    if script_name is None:
        # Find the next available script number
        script_number = 1
        while os.path.exists(os.path.join(workspace_path, f"script_{script_number}.py")):
            script_number += 1
        script_name = f"script_{script_number}.py"
    elif not script_name.endswith('.py'):
        script_name += '.py'
    
    # Write the script directly to the workspace
    script_path = os.path.join(workspace_path, script_name)
    try:
        with open(script_path, 'w') as f:
            f.write(script_content)
        script_info = f"Successfully wrote Python script to {script_path}"
    except Exception as e:
        return ToolMessage(content=f"Failed to write Python script: {str(e)}", tool_call_id=tool_call_id)
    
    # Execute the script using the sandboxed shell
    try:
        result = kali_stateful_shell.invoke({"commands": f"python {script_path}", "state": state})
        return ToolMessage(content=f"{script_info}\n\nScript output:\n{result}", tool_call_id=tool_call_id)
    except Exception as e:
        return ToolMessage(content=f"{script_info}\n\nError running Python script: {str(e)}", tool_call_id=tool_call_id)
