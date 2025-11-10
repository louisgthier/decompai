# DecompAI: Binary Analysis and Decompilation Agent

DecompAI is a LangGraph & Gradio-based LLM agent that automates binary analysis and decompilation workflows. Whether you’re a newcomer to reverse engineering or an experienced practitioner, DecompAI helps you explore, debug, and decompile x86 Linux binaries in a conversational interface.

---

## Table of Contents

- [DecompAI: Binary Analysis and Decompilation Agent](#decompai-binary-analysis-and-decompilation-agent)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Setup \& Configuration](#setup--configuration)
  - [Docker \& First-Run Build](#docker--first-run-build)
  - [Running the Application](#running-the-application)
  - [Usage Overview](#usage-overview)
    - [1. Upload a Binary](#1-upload-a-binary)
    - [2. Automatic Analysis](#2-automatic-analysis)
    - [3. Interactive Chat](#3-interactive-chat)
  - [Filesystem \& Sessions](#filesystem--sessions)
  - [Supported Binaries \& Future Plans](#supported-binaries--future-plans)
  - [Testing \& Benchmarks](#testing--benchmarks)
  - [Contributing](#contributing)
  - [Authors](#authors)
  - [Ethics \& Legal](#ethics--legal)

---

## Features

- **AI-Driven Decompilation**: Step-by-step decompilation assistance via a ReAct-style agent.
- **Binary Analysis**: List functions, disassemble sections, summarize assembly.
- **Tool Integration**: Leverage `objdump`, `gdb`, Ghidra (with custom AI hooks), and dozens of Kali-provided tools.
- **Interactive Chat**: Ask the agent questions, request specific tool runs, or direct decompilation actions.
- **Session Persistence**: Uploading the same binary restores your previous workspace.
- **Frameworks**: Built on LangGraph, LangChain and Gradio.

---

## Setup & Configuration

1. **Clone & Dependencies**

```bash
git clone https://github.com/louisgthier/decompai.git
cd decompai
pip install -r requirements.txt
```

2. **Environment Variables**  
   Create a `.env` file in the project root with your API keys and model choice:

```dotenv
OPENAI_API_KEY=sk-proj-ABC...
GEMINI_API_KEY=ya29.A0AR...
LLM_MODEL=gemini-2.5-pro      # or gemini-2.5-flash for cost-effective usage
```

Other OpenAI or Gemini models work too, and providers using the OpenAI client can be used with minor code tweaks.

3. **Containers (recommended)**  
   Build/run the stack locally (the runner image builds automatically the first time):

   ```bash
   DECOMPAI_HOST_ROOT=$PWD docker compose up -d
   ```

   This compiles the Python app image, builds the Kali runner once (the build takes a while because it installs Ghidra, radare2 plugins, and other tooling), mounts your workspace, forwards port 7860, and reuses the host Docker daemon through `/var/run/docker.sock`. Windows PowerShell users can run `DECOMPAI_HOST_ROOT=$(Get-Location) docker compose up -d`.

4. **Local Python (optional)**  
   Prefer working outside Docker? Install the deps (step 1) and run `python run.py`; the app will still launch runner containers for tooling, and you can switch images via `export DECOMPAI_RUNNER_IMAGE=...`.

---

## Docker & First-Run Build

- **Prebuilt Images**  
  `louisgauthier/decompai:1.0.0` (app) and `louisgauthier/decompai-runner:1.0.0` (Kali runner) are pushed for every release. Update locally with `docker compose pull`.
- **Runner Lifecycle**  
  The app creates short-lived runner containers whenever it needs to execute `objdump`, `gdb`, or Ghidra tooling. Override the tag with `DECOMPAI_RUNNER_IMAGE=<user/image:tag>` if you are testing a custom build.
- **Local Dockerfile Iteration**  
  After editing `Dockerfile.runner`, rebuild and reuse cached layers:

  ```bash
  DOCKER_BUILDKIT=1 docker buildx build --platform linux/amd64 \
    -f Dockerfile.runner -t decompai-runner:dev .
  export DECOMPAI_RUNNER_IMAGE=decompai-runner:dev
  python run.py   # or docker compose up -d
  ```
- Set `DECOMPAI_RUNNER_BUILD=true` if you want the app to rebuild `Dockerfile.runner` automatically before executing tools.
- **App Image Build & Publish**  
  Release both images together so contributors can pull matching tags:

  ```bash
  docker buildx build --platform linux/amd64 -f Dockerfile -t louisgauthier/decompai:1.0.0 .
  docker push louisgauthier/decompai:1.0.0

  docker buildx build --platform linux/amd64 -f Dockerfile.runner -t louisgauthier/decompai-runner:1.0.0 .
  docker push louisgauthier/decompai-runner:1.0.0
  ```
- **Privileged Execution**  
  Runner containers still require `--privileged` to expose low-level tooling; audit any dependency additions before publishing.

---

## Running the Application

- **Standard**

```bash
python run.py
```

- **Hot Reload (Gradio CLI)**

```bash
gradio run.py
```

- **Access**  
  Open your browser to:

```bash
http://localhost:7860
```

---

## Usage Overview

### 1. Upload a Binary

Drag & drop or click to select your executable file. The agent will initialize a session based on the file’s hash to ensure persistent workspaces across uploads.

### 2. Automatic Analysis

Depending on the binary’s size, the agent will begin by disassembling or summarizing the file. Tool-specific setups and session environment are launched in the background.

### 3. Interactive Chat

Start a conversation with the agent to:

- Understand what the binary does.
- Decompile functions step by step.
- Explore potential vulnerabilities or attack surfaces.
- Request disassembly or function listings.
- Use integrated tools like `gdb`, `ghidra`, or `objdump` explicitly by asking the agent to do so.
- Combine stateful and stateless shell interactions to inspect the binary from different angles.

Whether you're a beginner curious about how compiled code works, or a reverse engineer accelerating your workflow, the agent is designed to adapt to your requests naturally.

![Interface Screenshot](assets/interface.png)

---

## Filesystem & Sessions

- **Workspace Storage**  
  Sessions are stored under the path configured by `ANALYSIS_SESSIONS_ROOT` in `config.py`.
- **Session Keys**  
  Workspaces are keyed by the SHA-256 hash of the binary; re-uploading restores your previous work.
- **Persistence Warning**  
  Data in `/tmp` (or your custom `ANALYSIS_SESSIONS_ROOT`) is ephemeral and cleared on reboot.

---

## Supported Binaries & Future Plans

- **Current Support**:
- x86 Linux ELF binaries only.
- **Roadmap**:
- QEMU-backed multiplatform support (ARM, MIPS, Windows PE, etc.).
- UI-based workspace export/download.

---

## Testing & Benchmarks

Validated on CTF challenges (e.g., [Root-Me](https://www.root-me.org/)), consistently solving **3/5 difficulty** exercises in an automated or semi-automated fashion.

---

## Contributing

We welcome pull requests!

- **New Tools**: Add scripts or wrappers in `src/tools/`.
- **CI/CD**: Help automate Docker builds and registry publishing.
- **Bugfixes & Enhancements**: Fork, commit against `main`, and open a PR.

---

## Authors

- **Louis Gauthier** - [@louisgthier](https://github.com/louisgthier)
- **Clément Florval** - [@ClementFrvl](https://github.com/ClementFrvl)

Project developed as part of a school research initiative. Check out other projects at [Digiwave](https://dgwave.net/portfolio).

---

## Ethics & Legal

> **Disclaimer:** DecompAI is intended **only** for lawful reverse engineering, educational use, and security research. The authors **do not** assume liability for misuse. Always comply with software licenses and local laws.
