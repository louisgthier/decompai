# Repository Guidelines

DecompAI pairs a LangGraph-powered agent with a Gradio UI and a privileged Docker sandbox, so every contribution should reinforce deterministic tooling and safe binary handling. Follow the practices below to keep agent behaviors reproducible across both local and containerized runs.

## Project Structure & Module Organization
Core logic lives in `src/`: `main.py` wires the LangGraph graph, `state.py` defines the conversation payloads, and `tools/` plus `utils/` host tool runners (radare2 shells, Ghidra hooks, etc.). UI wiring sits in `run.py`, assets reside under `assets/`, and reference binaries or decompositions belong in `binaries/` and `decompai_analysis_sessions/`. Python tests are under `tests/`, while `Dockerfile` and `requirements.txt` define the runtime stack—add new modules beside the existing patterns instead of creating parallel trees.

## Build, Test, and Development Commands
- `pip install -r requirements.txt` — sync Python deps for local hacking.
- `DECOMPAI_HOST_ROOT=$PWD docker compose up -d` — pull the published app/runner images, bind the host Docker socket, and expose Gradio on :7860.
- `python run.py` — launch the Gradio interface with the default settings.
- `gradio run.py` — enable hot reload when iterating on UI callbacks.
- `docker buildx build --platform linux/amd64 -f Dockerfile.runner -t decompai-runner:dev .` — rebuild the Kali runner locally when testing new tools; pair with `DECOMPAI_RUNNER_IMAGE=decompai-runner:dev`.
- `pytest` or `pytest tests/test_disassemble.py -k <name>` — run the unit suite or a scoped check before pushing.

## Coding Style & Naming Conventions
Stick to PEP 8, 4-space indents, and type hints where state crosses process boundaries (see `State` in `src/state.py`). Modules, functions, and files use `snake_case`, classes use `PascalCase`, and environment variables (defined in `.env`/`config.py`) stay `UPPER_SNAKE_CASE`. Keep tool adapters small, comment only when behavior is non-obvious, and run your formatter/linter before submitting.

## Testing Guidelines
All new tooling or agent behaviors need Pytest coverage alongside regression cases for failure paths (e.g., malformed binaries or missing tools). Name tests descriptively like `test_disassemble_reports_unknown_sections` to mirror user-facing outcomes. Tests should run in <1 minute and avoid mutating real session directories; use fixtures or temporary paths under `tests/` when a filesystem is required.

## Commit & Pull Request Guidelines
Commits follow Conventional Commits (`feat:`, `refactor:`, `chore:`) as seen in recent history; write imperatively and keep scope narrow. Every PR should describe the user problem, summarize the fix, link the tracking issue, and mention any UI/demo screenshots or new CLI arguments. Run Pytest and, when applicable, a local Docker build before requesting review, then note the results in the PR template.

## Security & Configuration Tips
Store secrets in `.env` only, never in code or sample binaries. The Docker image runs privileged tools (`gdb`, `objdump`, `ghidra`), so audit any new package installs and keep downloads pinned. When touching `ANALYSIS_SESSIONS_ROOT` or related settings, document cleanup steps so stale artifacts do not leak between user uploads.
