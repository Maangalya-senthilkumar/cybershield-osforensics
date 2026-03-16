# OSForensics: Linux Digital Forensics Platform

## Project Overview
OSForensics is a high-performance, Linux-focused digital forensics and incident response (DFIR) platform. It provides a suite of automated tools for analyzing live systems, mounted directories, and raw disk images. The platform features a sophisticated **Multi-Agent Orchestration Framework** that leverages **Ollama (llama3.2)** to conduct intelligent, autonomous forensic investigations.

### Main Technologies
- **Core Language:** Python 3.10+
- **API Framework:** FastAPI with Pydantic for data validation.
- **Forensics Engine:** Integrates `pytsk3` (Sleuthkit) for filesystem analysis and **Volatility 3** for memory forensics.
- **AI Integration:** Uses **Ollama** (via `ollama` Python SDK) with a ReAct (Reasoning and Acting) pattern.
- **Remote Acquisition:** Supports live remote analysis via SSH snapshots and SSHFS read-only mounts.
- **Reporting:** Generates comprehensive forensic reports in HTML and PDF formats.

### Architecture
The project follows a modular "src" layout:
- `api.py`: Main entry point exposing REST endpoints for analysis, exploration, and agent interaction.
- `orchestrator.py`: Implements the `OrchestratorAgent` which coordinates specialized sub-agents.
- `agent_core.py`: Core logic for the ReAct investigation agent.
- `extractor.py`: Provides the `FilesystemAccessor` abstraction for transparently handling local paths and disk images.
- **Domain Modules:** Specialized logic for `browser`, `timeline`, `persistence`, `multimedia`, `services`, `config` (security audits), and `tails` (Tails OS specifics).

---

## Building and Running

### Prerequisites
- Python 3.10+
- `uv` package manager.
- External tools: `sleuthkit` (for pytsk3), `sshfs` (for remote mounts), `lsblk` (for USB detection), `volatility3` (for memory analysis).
- **Ollama** running with the `llama3.2` model.

### Environment Variables
- `OLLAMA_URL`: The URL of the Ollama server (e.g., `http://100.73.207.125:11434/`).
- `OLLAMA_MODEL`: The model to use (defaults to `llama3.2`).

### Key Commands
- **Install Dependencies:**
  ```bash
  uv pip install -r requirements.txt
  uv pip install ollama
  ```
- **Run the API:**
  ```bash
  uvicorn osforensics.api:app --host 0.0.0.0 --port 8000
  ```
- **Run Tests:**
  ```bash
  pytest
  ```
  *(Note: No explicit test suite was found in the analyzed files, but pytest is the standard for this architecture.)*

---

## Development Conventions

### Filesystem Access
Always use the `FilesystemAccessor` class from `extractor.py` to interact with target evidence. It ensures that analysis remains forensic-safe and works seamlessly across local directories and disk images.

### AI Agent Protocol
- **ReAct Pattern:** Agents must follow the `{thought, action, args}` or `{thought, action, answer}` JSON protocol.
- **Tool Registry:** New forensic capabilities should be registered in `agent_tools.py` using the `@_tool` decorator to make them available to the AI.
- **Safety:** Safety filters are relaxed (`BLOCK_NONE`) in `agent_core.py` to allow the LLM to process technical descriptions of malware and exploits.

### Forensic Integrity
- **Read-Only:** All analysis tools must operate in a read-only manner.
- **Evidence Integrity:** The API automatically computes SHA256/SHA1 hashes for evidence files and attaches legal-awareness metadata to all findings.
- **Audit Logs:** Major analysis steps are logged in an audit trail within the case metadata.
