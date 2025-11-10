import sys
import os
import subprocess
import re
import pprint
import hashlib
import shutil
import json
import uuid
import shlex

from src.config import settings
from src.utils.docker_env import (
    format_mount_flags,
    get_runner_mounts,
    should_build_runner_image,
)

os.makedirs(settings.ANALYSIS_SESSIONS_ROOT, exist_ok=True)

image_built = False


def build_docker_image():
    global image_built
    if image_built or not should_build_runner_image():
        return
    docker_build_command = (
        f"docker buildx build --platform linux/amd64 -f Dockerfile.runner "
        f"-t {settings.DECOMPAI_RUNNER_IMAGE} . --load"
    )
    subprocess.run(docker_build_command, shell=True, check=True)
    image_built = True

def get_binary_path_in_workspace(binary_path: str) -> str:
    return os.path.join(os.path.dirname(binary_path), settings.AGENT_WORKSPACE_NAME, os.path.basename(binary_path))

class CommandResult:
    def __init__(self, stdout: str, stderr: str, combined: str):
        self.stdout = stdout
        self.stderr = stderr
        self.combined = combined

    def __str__(self):
        return self.combined


def run_command_in_docker(command: str) -> CommandResult:
    build_docker_image()

    container_name = "decompai-runner-" + str(uuid.uuid4())

    mount_flags = format_mount_flags(get_runner_mounts())
    docker_run_command = (
        f"docker run --rm --name {container_name}"
        f"{mount_flags} "
        f"--platform linux/amd64 -w / {settings.DECOMPAI_RUNNER_IMAGE} "
        f"/bin/sh -c {shlex.quote(command)}"
    )
    
    print(f"Running command in docker: {docker_run_command}")
    
    result = subprocess.run(
        docker_run_command,
        shell=True,
        capture_output=True,
        text=True,
        check=False
    )
    
    # Combine outputs with separator if stderr is not empty
    combined = result.stdout
    if result.stderr:
        combined += "\n=== STDERR ===\n" + result.stderr
    
    return CommandResult(
        stdout=result.stdout,
        stderr=result.stderr,
        combined=combined
    )


def hash_file(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def create_session_for_binary(binary_source_path: str) -> str:
    # Compute the hash for the binary
    binary_hash = hash_file(binary_source_path)
    # Create session directory if it doesn't exist
    session_path = os.path.join(settings.ANALYSIS_SESSIONS_ROOT, binary_hash)
    os.makedirs(session_path, exist_ok=True)
    # Create agent workspace directory if it doesn't exist
    agent_workspace_path = os.path.join(
        session_path, settings.AGENT_WORKSPACE_NAME)
    os.makedirs(agent_workspace_path, exist_ok=True)
    # Copy the binary into the session directory
    binary_filename = os.path.basename(binary_source_path)
    session_binary_path = os.path.join(session_path, binary_filename)
    if binary_source_path != session_binary_path:
        shutil.copy2(binary_source_path, session_binary_path)
    # Give execution permission to the binary
    os.chmod(session_binary_path, 0o770)
    # Copy the binary into the agent workspace directory (for the agent to use without affecting the original binary)
    agent_binary_path = os.path.join(agent_workspace_path, binary_filename)
    shutil.copy2(binary_source_path, agent_binary_path)
    # Give execution permission to the agent binary
    os.chmod(agent_binary_path, 0o770)
    return session_path


def compile(target: str, c_code_path: str, binary_path: str):
    # TODO: Fix this to put the source code in the session directory
    run_command_in_docker(
        f"gcc -o /{binary_path} /{c_code_path} -lm"
    )


def detect_architecture(binary_path: str) -> str:
    result = run_command_in_docker(f"file {binary_path}")
    output = result.stdout.strip()
    if "MIPS" in output:
        if "MSB" in output:
            return "mips:big"
        return "mips:little"
    elif "ARM" in output:
        return "arm"
    elif "x86-64" in output:
        return "x86_64"
    elif "Intel 80386" in output:
        return "i386"
    else:
        return "unknown"

def objdump(args: str) -> str:
    """
    Runs the objdump command with auto-detected architecture based on the binary in args.
    Args:
        args (str): The arguments to pass to objdump, including the binary path.
    Returns:
        str: The output from objdump.
    """
    # Extract binary path (assume it's the last argument in args)
    tokens = args.strip().split()
    binary_path = tokens[-1]

    arch = detect_architecture(binary_path)
    arch_flag = ""

    objdump_command = "objdump"
    if arch.startswith("mips"):
        objdump_command = "mips-linux-gnu-objdump"
        arch_flag = "-m mips -EL"
    elif arch == "arm":
        arch_flag = "-m arm"
    elif arch == "i386":
        arch_flag = "-m i386"
    # no arch_flag needed for x86_64 or unknown

    full_command = f"{objdump_command} {arch_flag} {args}"

    try:
        result = run_command_in_docker(full_command)
        return result.combined
    except subprocess.CalledProcessError as e:
        print(f"[objdump] Error on {binary_path}: {e.stderr}")
        return ""
    
    
def disassemble_binary(binary_path, function_name=None, target_platform: str = "linux"):
    asm = objdump(f"-ds {binary_path}")

    if function_name is None:
        return asm
    else:
        return disassemble_function(asm, function_name)
    

def disassemble_section(binary_path, section_name):
    input_asm = disassemble_binary(binary_path)

    pattern = rf"Disassembly of section {re.escape(section_name)}:\n(.*?)(?=\nDisassembly of|$)"

    # Use re.DOTALL to match across multiple lines
    match = re.search(pattern, input_asm, re.DOTALL)

    # Return the matched content if found
    if match:
        return match.group(1).strip()
    else:
        return None


def disassemble_function(binary_path, function_name):
    input_asm = disassemble_binary(binary_path)

    # Split the disassembled output into blocks separated by double newlines
    blocks = input_asm.split('\n\n')

    # Look for a block whose first line ends with the function marker
    for block in blocks:
        lines = block.splitlines()
        if not lines:
            continue
        first_line = lines[0]
        if first_line.rstrip().endswith(f"<{function_name}>:"):
            return block

    raise ValueError(f"Function {function_name} not found in the assembly.")


def compile_and_disassemble_c_code(c_code_path, function_name, target_platform):
    binary_path = os.path.join(settings.ANALYSIS_SESSIONS_ROOT, "compiled_binary")

    if target_platform == "mac":
        function_name = "_" + function_name

    # Compile the C code
    compile(target_platform, c_code_path, binary_path)

    # Disassemble the binary
    input_asm = disassemble_binary(binary_path, function_name, target_platform)

    return input_asm


def disassemble(input_path, function_name):
    # If the root sessions directory does not exist, create it
    if not os.path.exists(settings.ANALYSIS_SESSIONS_ROOT):
        os.makedirs(settings.ANALYSIS_SESSIONS_ROOT)

    # Copy the C code or binary to the workspace for reference
    input_basename = os.path.basename(input_path)
    workspace_input_path = os.path.join(settings.ANALYSIS_SESSIONS_ROOT, input_basename)
    if not os.path.exists(workspace_input_path):
        os.system(f"cp {input_path} {workspace_input_path}")

    target_platform = "linux"

    if input_path.endswith(".c"):
        print("Input detected as C code. Compiling and disassembling...")
        disassembled_code = compile_and_disassemble_c_code(
            input_path, function_name, target_platform)
    else:
        print("Input detected as binary. Disassembling...")
        disassembled_code = disassemble_binary(
            input_path, function_name, target_platform)

    return disassembled_code


def summarize_assembly(objdump_output=None, binary_path=None):
    """
    Summarizes the key details from assembly code or the output of objdump.
    Args:
        objdump_output (str): The output of objdump as a string.
        binary_path (str): Path to the binary to analyze. If provided, objdump will be run.
    Returns:
        dict: A summary containing architecture, start address, sections, functions, and more.
    """
    if binary_path:
        # Assume objdump is defined elsewhere
        objdump_output = objdump(f"-dstrx {binary_path}")

    if not objdump_output:
        return {"error": "No objdump output or binary path provided."}

    summary = {}

    # Extract architecture and start address
    arch_match = re.search(r"architecture:\s+([^\n,]+)", objdump_output)
    start_addr_match = re.search(
        r"start address\s+(0x[0-9a-fA-F]+)", objdump_output)
    summary["architecture"] = arch_match.group(1) if arch_match else "Unknown"
    summary["start_address"] = start_addr_match.group(
        1) if start_addr_match else "Unknown"

    # Extract program headers
    program_headers = re.findall(
        r"([A-Z]+)\s+off\s+(0x[0-9a-f]+)\s+vaddr\s+(0x[0-9a-f]+)\s+paddr\s+(0x[0-9a-f]+)\s+align\s+2\*\*(\d+).*?\n\s+filesz\s+(0x[0-9a-f]+)\s+memsz\s+(0x[0-9a-f]+)\s+flags\s+([rwx\-]+)",
        objdump_output,
        re.S,
    )
    summary["program_headers"] = [
        {
            "type": ph[0],
            "offset": ph[1],
            "virtual_address": ph[2],
            "physical_address": ph[3],
            "alignment": int(ph[4]),
            "file_size": ph[5],
            "memory_size": ph[6],
            "flags": ph[7],
        }
        for ph in program_headers
    ]

    # Extract dynamic section
    dynamic_section_match = re.search(
        r"Dynamic Section:(.*?)Version References:", objdump_output, re.S)
    if dynamic_section_match:
        dynamic_entries = re.findall(
            r"([A-Z_]+)\s+(0x[0-9a-f]+|.+)", dynamic_section_match.group(1))
        summary["dynamic_section"] = {entry[0]: entry[1]
                                      for entry in dynamic_entries}

    # Extract sections and their properties
    sections = re.findall(
        r"(\d+)\s+([\.\w]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+2\*\*(\d+)\s+(.*)",
        objdump_output,
    )
    summary["sections"] = [
        {
            "index": int(sec[0]),
            "name": sec[1],
            "size": sec[2],
            "vma": sec[3],
            "lma": sec[4],
            "file_offset": sec[5],
            "alignment": int(sec[6]),
            "flags": sec[7],
        }
        for sec in sections
    ]

    # Extract symbol table
    # symbol_table_match = re.search(
    #     r"SYMBOL TABLE:(.*?)Contents of section", objdump_output, re.S)
    # if symbol_table_match:
    #     # symbols = re.findall(
    #     #     r"([0-9a-f]+)\s+\w\s+([\.\w]+)\s+([0-9a-f]+)\s+(.*)", symbol_table_match.group(1)
    #     # )
    #     symbols = re.findall(
    #         r"([0-9a-f]{8})\s[\w\s]{7}\s([\.\w]+|\*ABS\*|\*UND\*)\s+([0-9a-f]+)\s+(.*)",
    #         symbol_table_match.group(1)
    #     )
    #     summary["symbol_table"] = [
    #         {"address": sym[0], "section": sym[1], "size": sym[2], "name": sym[3]} for sym in symbols
    #     ]

    # # Extract disassembled functions
    # disassembly = {}
    # disassembled_sections = re.findall(r"Disassembly of section (.*?):\n(.*?)(?=\n\n|\Z)", objdump_output, re.S)
    # for section, content in disassembled_sections:
    #     functions = re.findall(r"([0-9a-f]+) <([^>]+)>:\n((?:.+\n)+?)(?=\n[0-9a-f]+ <|$)", content)
    #     disassembly[section] = [
    #         {"address": func[0], "name": func[1], "instructions": func[2].strip()} for func in functions
    #     ]
    # summary["disassembly"] = disassembly

    return summary


def dump_memory(binary_path: str, address: int, length: int) -> bytes:
    """
    Uses radare2 to dump a specified number of bytes from the binary at a given virtual address.
    The command 'pxj' outputs a JSON array of byte values.
    """
    cmd = f"r2 -qc 'pxj {length} @ {hex(address)}; quit' {binary_path}"
    result = run_command_in_docker(cmd)
    try:
        data = json.loads(result.stdout)
        return bytes(data)
    except Exception as e:
        return result.combined


def get_string_at_address(binary_path: str, address: int) -> str:
    """
    Uses radare2 to retrieve a null-terminated string from the binary at a given virtual address.
    """
    cmd = f"r2 -qc 'psz @ {hex(address)}; quit' {binary_path}"
    result = run_command_in_docker(cmd)
    return result.combined.strip()


def run_ghidra_post_script(binary_path: str, script_path: str, script_args: str = "") -> str:
    """
    Runs a Ghidra post-script using analyzeHeadless.
    Args:
        binary_path: Path to the binary to analyze
        script_path: Path to the script to run
        script_args: Arguments to pass to the script
    Returns:
        str: Combined output from stdout and stderr, preserving order
    """
    print(f"Running Ghidra analyzeHeadless on {binary_path} with script {script_path} and args {script_args}")
    
    # Create Ghidra project directory
    project_dir = os.path.dirname(binary_path)
    project_name = "ghidra_project"
    
    # Check if project already exists
    project_exists = os.path.exists(os.path.join(project_dir, f"{project_name}.gpr"))
    
    # Build the command
    command_parts = [
        "analyzeHeadless",
        project_dir,
        project_name
    ]
    
    # Only add import if project doesn't exist
    if not project_exists:
        print(f"Importing {binary_path} into Ghidra project {project_name}")
        command_parts.extend(["-import", binary_path])
    else:
        print(f"Ghidra project {project_name} already exists")
        command_parts.extend(["-process", os.path.basename(binary_path)])
    
    # Add script parameters
    command_parts.extend([
        "-scriptPath", os.path.dirname(script_path),
        "-postScript", os.path.basename(script_path),
        script_args
    ])
    
    # Run Ghidra analyzeHeadless
    command = " ".join(command_parts)
    result = run_command_in_docker(command)
    return result.combined


def decompile_function_with_ghidra(binary_path: str, function_name: str) -> str:
    """
    Decompiles a function using Ghidra's headless mode.
    Args:
        binary_path: Path to the binary
        function_name: Name of the function to decompile
    Returns:
        str: Decompiled function code
    """
    # Get the source script path
    source_script_path = os.path.join(os.path.dirname(__file__), "ghidra_scripts", "decompile_function.py")
    
    # Copy the script to the workspace
    workspace_script_path = os.path.join(os.path.dirname(binary_path), "decompile_function.py")
    shutil.copy2(source_script_path, workspace_script_path)
    
    # Run the script
    return run_ghidra_post_script(binary_path, workspace_script_path, function_name)


if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=2)

    # print(objdump("-sdxtr binary_workspaces/uploaded_binary.bin"))

    # pp.pprint(summarize_assembly(binary_path="binary_workspaces/uploaded_binary.bin"))

    print(disassemble_section("binary_workspaces/uploaded_binary.bin", ".init"))
