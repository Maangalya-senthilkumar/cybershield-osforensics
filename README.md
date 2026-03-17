OS Forensics — Prototype
=========================

This repository contains a prototype forensic analysis backend  and frontend that uses
Sleuth Kit (pytsk3) where available, or a mounted filesystem for
development. It exposes a FastAPI endpoint to analyze an image or a mounted
filesystem directory and returns a structured JSON forensic report.

Quickstart
----------

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the API server:

```bash
python main.py
```

3. POST JSON to `http://127.0.0.1:8000/analyze` with a body like:

```json
{ "image_path": "/path/to/mounted/fs_or_image" }
```

Notes
-----
- This is an initial scaffold. Detection is heuristic-based and intended as a
	starting point for further enhancements (deep artifact parsing, package DB
	parsing, timeline analysis, etc.).
- The tool is intentionally non-destructive: it only reads filesystem
	artefacts.

Project structure (recommended: src layout)
----------------------------------------

This project uses the `src/` layout which keeps the importable package code
out of the repository root. The repository layout is:

```
OSForensics/
├─ .venv/                # optional virtual environment (ignored in VCS)
├─ main.py               # runner that starts the FastAPI server
├─ pyproject.toml        # project metadata
├─ requirements.txt      # runtime dependencies for prototype
├─ README.md             # this file
├─ src/                  # source root for package code
│  └─ osforensics/       # the importable package
│     ├─ __init__.py
│     ├─ extractor.py
│     ├─ detector.py
│     ├─ classifier.py
│     ├─ report.py
│     └─ api.py
└─ osforensics/          # legacy top-level folder (kept as a small shim)
```

The real package code lives under `src/osforensics/`. A lightweight shim
remains at the top-level to help local development. You can remove the
top-level `osforensics/` directory if you prefer, but the `src` layout is the
recommended, professional structure for Python projects.


## Important Commands
```bash
uvicorn src.osforensics.api:app --host 127.0.0.1 --port 8000 --reload
```

