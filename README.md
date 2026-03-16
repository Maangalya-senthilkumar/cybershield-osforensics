OS Forensics — Prototype
=========================

This repository contains a prototype forensic analysis backend that uses
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

## Remote SSH Live Forensics

The backend can acquire a bounded snapshot from a remote Linux machine over
SSH, then run the standard forensic pipeline on that snapshot.

Endpoint: `POST /analyze/ssh`

Example request body:

```json
{
	"host": "192.168.56.10",
	"username": "forensic",
	"port": 22,
	"key_path": "/home/user/.ssh/id_ed25519",
	"include_paths": ["/etc", "/var/log", "/home", "/root"],
	"max_total_mb": 1024,
	"max_file_mb": 32,
	"max_files": 25000,
	"timeline": true,
	"deleted": true,
	"persistence": true,
	"config": true,
	"services": true,
	"browsers": true,
	"multimedia": false
}
```

Case workflow endpoint: `POST /cases/{case_id}/analyze/ssh`

## Legal Awareness Features

The backend now includes legal/procedural metadata to support forensic workflow quality:

- Evidence integrity verification:
	- For file-based evidence, SHA256 and SHA1 are computed and attached under `evidence_integrity`.
	- Includes acquisition timestamp and evidence path.
- Chain of custody tracking:
	- Case records now maintain `chain_of_custody` entries for source ingestion/removal.
	- Each source gets an evidence id (`EV-001`, `EV-002`, ...).
- Evidence provenance:
	- Case sources store a `provenance` object describing source and extraction method.
	- Analysis responses include `evidence_provenance` in report output.
- Audit logging:
	- Case records include `audit_log` events for case/source and analysis actions.
	- Analysis responses include per-run `audit_log` metadata.
- Legal disclaimer block:
	- Reports include `legal_disclaimer` with forensic-safe handling notes and corroboration guidance.

## Comprehensive Reporting Module

The application now supports structured export of a full forensic dossier:

- `POST /report/export/html`
	- Input: report payload plus optional metadata (`report_title`, `case_name`, `source_path`, `generated_by`, `case_data`, `intro_text`, `report_variant`, `include_raw_json`).
	- Output: downloadable HTML report with sectioned tables for tools, timeline, deleted artifacts, persistence, config, services, browser data, multimedia, Tails, containers, and legal metadata.

- `POST /report/export/pdf`
	- Input: same payload as HTML export (except `include_raw_json`, which is HTML-specific).
	- Output: downloadable PDF report suitable for sharing and legal documentation workflows.

Report variants:
	- `comprehensive`: full technical details and legal metadata.
	- `legal`: case-oriented report with custody/audit emphasis.
	- `executive`: concise summary-focused format for leadership briefings.

Case-level behavior:
	- If `case_data` is provided, the exporter builds a case-level report by aggregating all source reports under that case.
	- Includes intro narrative, case information, source rollup, and merged findings across all sources.

UI workflow:

- Open `Report` view after analysis.
- Use export buttons in header:
	- `JSON` (raw report)
	- `HTML` (comprehensive structured dossier)
	- `PDF` (portable report document)
	- `Exec PDF` (concise executive summary format)

