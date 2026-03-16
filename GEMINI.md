# OSForensics — Digital Forensic Analysis Prototype

This project is a forensic analysis backend and frontend designed for automated collection, analysis, and investigation of digital evidence. It supports local disk images, mounted filesystems, and remote live acquisition over SSH.

## Project Overview

- **Backend:** Python 3.12+ / FastAPI
- **Frontend:** React / Vite / TailwindCSS (inferred)
- **AI Agent:** ReAct-pattern investigator using Ollama (local LLM)
- **Key Features:**
  - Full filesystem analysis (OS, tools, timeline, deleted files, persistence, config, services, browsers, multimedia).
  - Remote SSH live forensics (snapshot acquisition via SFTP/SSHFS).
  - Memory analysis (Volatility 3 integration, live RAM stats).
  - Specialized Tails OS heuristics.
  - Comprehensive reporting (HTML, PDF, JSON).
  - AI-powered investigation agent with specialized forensic tools.
  - Legal awareness (integrity verification, chain of custody, audit logging).

## Repository Structure

- `src/osforensics/`: Core Python package.
  - `api.py`: FastAPI application and endpoints.
  - `agent_core.py`: AI investigation agent (ReAct loop).
  - `extractor.py`: Filesystem abstraction (local vs pytsk3).
  - `detector.py`, `classifier.py`, `report.py`: Analysis modules.
  - `remote.py`: SSH acquisition and remote host info.
  - `cases.py`: Case management and persistence.
- `ui/`: React frontend (Vite).
- `main.py`: Entry point for the backend server.
- `requirements.txt`: Backend dependencies.

## Building and Running

### Backend

1. **Prerequisites:** Python 3.12, `libtsk` (for pytsk3), `sshfs` (for remote mounting).
2. **Setup:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Run:**
   ```bash
   python main.py
   # or for development with reload:
   uvicorn src.osforensics.api:app --host 127.0.0.1 --port 8000 --reload
   ```

### Frontend

1. **Prerequisites:** Node.js (v18+).
2. **Setup:**
   ```bash
   cd ui
   npm install
   ```
3. **Run:**
   ```bash
   npm run dev
   ```

### AI Agent (Ollama)

The investigation agent requires an Ollama server.
1. Ensure Ollama is running (default: `http://localhost:11434`).
2. Set `OLLAMA_URL` and `OLLAMA_MODEL` in a `.env` file if they differ from defaults (`llama3.2`).

## Development Conventions

- **Surgical Updates:** When modifying analysis modules, ensure the `FilesystemAccessor` abstraction is used to maintain compatibility between local and image-based analysis.
- **Legal Metadata:** Every analysis run should include integrity hashes and audit logs using `_attach_legal_context`.
- **Non-Destructive:** All forensic operations must be read-only.
- **AI Tools:** New capabilities should be registered in `agent_tools.py` and documented in `Implementation.md`.
- **Testing:** No formal test suite exists yet. Use `verify_tools.py` or manual API testing for validation.
