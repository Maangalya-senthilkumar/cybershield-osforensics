"""Quick run helper to analyze a mounted filesystem directory or a disk image.

Usage:
  python quick_run.py /path/to/mounted/dir_or_image

This script ensures the `src/` layout is importable, runs the detector,
classifier and report builder, and prints a JSON report.
"""
import sys
import os
import json

# Ensure src/ is on sys.path so imports work from the repo root
ROOT = os.path.dirname(__file__)
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

try:
    from osforensics.extractor import FilesystemAccessor
    from osforensics.detector import detect_os, detect_tools
    from osforensics.classifier import classify_findings
    from osforensics.report import build_report
except Exception as e:
    print("Failed to import osforensics package from src/:", e)
    sys.exit(2)


def main():
    if len(sys.argv) < 2:
        print("Usage: python quick_run.py /path/to/mounted/dir_or_image")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print("Path does not exist:", path)
        sys.exit(1)

    try:
        fs = FilesystemAccessor(path)
    except Exception as e:
        print("Failed to open path:", e)
        sys.exit(1)

    os_info = detect_os(fs)
    findings = detect_tools(fs)
    classified = classify_findings(findings)
    report = build_report(os_info, classified)

    # print nice JSON (use pydantic v2 API when available)
    try:
        out = report.model_dump_json(indent=2)
    except Exception:
        # fallback for older pydantic versions
        out = report.json(indent=2)
    print(out)


if __name__ == "__main__":
    main()
