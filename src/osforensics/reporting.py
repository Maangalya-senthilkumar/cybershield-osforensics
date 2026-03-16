"""Comprehensive report rendering utilities (HTML + PDF)."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import importlib
import io
import json
from typing import Any, Dict, List, Optional, Sequence

REPORT_VARIANTS = {
    "comprehensive": "Comprehensive",
    "executive": "Executive",
    "legal": "Legal-Ready",
}


def _safe_text(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=True)
    return str(value)


def _html_text(value: Any) -> str:
    return escape(_safe_text(value))


def _coerce_records(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [x for x in value if isinstance(x, dict)]


def _combine_case_reports(case_data: Optional[Dict[str, Any]], fallback_report: Dict[str, Any]) -> Dict[str, Any]:
    """Merge source-level reports into a single case-level report.

    If case_data is absent or has no sources, fallback_report is returned as-is.
    """
    if not isinstance(case_data, dict):
        return fallback_report

    sources = [s for s in (case_data.get("data_sources") or []) if isinstance(s, dict)]
    if not sources:
        return fallback_report

    merged: Dict[str, Any] = {
        "os_info": fallback_report.get("os_info") or {},
        "summary": {},
        "findings": [],
        "timeline": [],
        "deleted": [],
        "persistence": [],
        "config": [],
        "services": [],
        "browsers": [],
        "multimedia": [],
        "tails": [],
        "containers": {},
        "evidence_provenance": [],
        "chain_of_custody": case_data.get("chain_of_custody") or [],
        "audit_log": case_data.get("audit_log") or [],
        "source_rollup": [],
        "case_info": {
            "id": case_data.get("id"),
            "name": case_data.get("name"),
            "number": case_data.get("number"),
            "examiner": case_data.get("examiner"),
            "description": case_data.get("description"),
            "created_at": case_data.get("created_at"),
            "updated_at": case_data.get("updated_at"),
            "source_count": len(sources),
        },
    }

    summary_totals = {
        "total_tools": 0,
        "total_high": 0,
        "timeline_events": 0,
        "deleted_files": 0,
        "persistence_items": 0,
        "services_count": 0,
        "tails_findings": 0,
        "high_tails": 0,
    }
    evidence_integrity: Dict[str, Any] = {}

    for src in sources:
        src_report = src.get("report") if isinstance(src.get("report"), dict) else {}
        if not src_report:
            continue
        src_summary = src_report.get("summary") or {}
        src_id = src.get("id") or "-"
        src_label = src.get("label") or src.get("path") or src_id
        prefix = f"[{src_label}]"

        merged["findings"].extend(_coerce_records(src_report.get("findings")))
        merged["timeline"].extend(_coerce_records(src_report.get("timeline")))
        merged["deleted"].extend(_coerce_records(src_report.get("deleted")))
        merged["persistence"].extend(_coerce_records(src_report.get("persistence")))
        merged["config"].extend(_coerce_records(src_report.get("config")))
        merged["services"].extend(_coerce_records(src_report.get("services")))
        merged["browsers"].extend(_coerce_records(src_report.get("browsers")))
        merged["multimedia"].extend(_coerce_records(src_report.get("multimedia")))
        merged["tails"].extend(_coerce_records(src_report.get("tails")))

        containers = src_report.get("containers")
        if isinstance(containers, dict) and containers:
            merged["containers"][src_id] = {
                "label": src_label,
                "path": src.get("path") or "-",
                "data": containers,
            }

        evidence = src.get("evidence") or {}
        hashes = evidence.get("hashes") or {}
        merged["source_rollup"].append(
            {
                "source_id": src_id,
                "label": src_label,
                "path": src.get("path") or "-",
                "added_at": src.get("added_at") or "-",
                "evidence_id": evidence.get("evidence_id") or "-",
                "acquisition_time": evidence.get("acquisition_time") or "-",
                "sha256": hashes.get("sha256") or "",
                "sha1": hashes.get("sha1") or "",
                "total_high": src_summary.get("total_high", 0),
                "timeline_events": src_summary.get("timeline_events", 0),
                "tools": src_summary.get("total_tools", 0),
            }
        )
        if hashes:
            evidence_integrity[src_label] = hashes

        merged["evidence_provenance"].append(
            {
                "artifact": src_label,
                "source": src.get("path") or "-",
                "extraction_method": (src.get("provenance") or {}).get("extraction_method") or "-",
            }
        )

        summary_totals["total_tools"] += int(src_summary.get("total_tools", 0) or 0)
        summary_totals["total_high"] += int(src_summary.get("total_high", 0) or 0)
        summary_totals["timeline_events"] += int(src_summary.get("timeline_events", 0) or 0)
        summary_totals["deleted_files"] += int(src_summary.get("deleted_findings", 0) or src_summary.get("deleted_files", 0) or 0)
        summary_totals["persistence_items"] += int(src_summary.get("persistence_findings", 0) or src_summary.get("persistence_items", 0) or 0)
        summary_totals["services_count"] += int(src_summary.get("service_count", 0) or src_summary.get("services_count", 0) or 0)
        summary_totals["tails_findings"] += int(src_summary.get("tails_findings", 0) or 0)
        summary_totals["high_tails"] += int(src_summary.get("high_tails", 0) or 0)

        for bucket in ("timeline", "deleted", "persistence", "config", "services", "multimedia", "tails"):
            for item in merged[bucket]:
                if not isinstance(item, dict):
                    continue
                if not item.get("source"):
                    item["source"] = src_label
                if not item.get("detail") and item.get("evidence"):
                    item["detail"] = f"{prefix} {_safe_text(item.get('evidence'))}"

    merged["summary"] = summary_totals
    merged["evidence_integrity"] = evidence_integrity
    if not merged["findings"] and fallback_report:
        return fallback_report
    return merged


def _intro_section(intro_text: str, report_variant: str) -> str:
    variant_label = REPORT_VARIANTS.get(report_variant, REPORT_VARIANTS["comprehensive"])
    narrative = intro_text.strip() if intro_text else (
        "This report consolidates digital forensic findings into an evidence-focused narrative. "
        "It emphasizes investigative context, traceability, and legally relevant handling details."
    )
    return (
        "<section class='report-section'>"
        "<h2>Investigation Introduction</h2>"
        f"<p class='intro'>{escape(narrative)}</p>"
        f"<div class='meta'><span>Report format: {escape(variant_label)}</span></div>"
        "</section>"
    )


def _table_from_records(title: str, rows: Sequence[Dict[str, Any]], columns: Sequence[str], limit: int = 300) -> str:
    if not rows:
        return (
            f"<section class='report-section'><h2>{escape(title)}</h2>"
            "<div class='empty'>No records available.</div></section>"
        )

    clipped = rows[:limit]
    th = "".join(f"<th>{escape(col)}</th>" for col in columns)
    tr_chunks = []
    for row in clipped:
        tds = "".join(f"<td>{_html_text(row.get(col))}</td>" for col in columns)
        tr_chunks.append(f"<tr>{tds}</tr>")

    note = ""
    if len(rows) > limit:
        note = f"<div class='table-note'>Showing first {limit} of {len(rows)} rows.</div>"

    return (
        f"<section class='report-section'><h2>{escape(title)}</h2>{note}"
        f"<div class='table-wrap'><table><thead><tr>{th}</tr></thead>"
        f"<tbody>{''.join(tr_chunks)}</tbody></table></div></section>"
    )


def _summary_cards(summary: Dict[str, Any]) -> str:
    cards = [
        ("Tools", summary.get("total_tools", 0)),
        ("High/Critical", summary.get("total_high", 0)),
        ("Timeline Events", summary.get("timeline_events", 0)),
        ("Deleted Artifacts", summary.get("deleted_files", 0)),
        ("Persistence Hits", summary.get("persistence_items", 0)),
        ("Services", summary.get("services_count", 0)),
    ]
    blocks = "".join(
        f"<div class='card'><div class='card-value'>{_html_text(v)}</div><div class='card-label'>{escape(k)}</div></div>"
        for k, v in cards
    )
    return f"<section class='report-section'><h2>Executive Summary</h2><div class='cards'>{blocks}</div></section>"


def _kv_table(title: str, mapping: Dict[str, Any]) -> str:
    rows = []
    for k, v in mapping.items():
        rows.append(f"<tr><td>{escape(str(k))}</td><td>{_html_text(v)}</td></tr>")
    if not rows:
        return (
            f"<section class='report-section'><h2>{escape(title)}</h2>"
            "<div class='empty'>No values available.</div></section>"
        )
    return (
        f"<section class='report-section'><h2>{escape(title)}</h2>"
        f"<div class='table-wrap'><table><tbody>{''.join(rows)}</tbody></table></div></section>"
    )


def _browser_section(browsers: Sequence[Dict[str, Any]]) -> str:
    if not browsers:
        return "<section class='report-section'><h2>Browser Forensics</h2><div class='empty'>No browser data.</div></section>"

    rows: List[Dict[str, Any]] = []
    for p in browsers:
        rows.append(
            {
                "browser": p.get("browser_label") or p.get("browser") or "-",
                "user": p.get("user") or "-",
                "profile": p.get("profile") or "-",
                "flags": ", ".join(p.get("flags") or []),
                "history": len(p.get("history") or []),
                "downloads": len(p.get("downloads") or []),
                "cookies": len(p.get("cookies") or []),
                "extensions": len(p.get("extensions") or []),
            }
        )
    return _table_from_records(
        "Browser Forensics",
        rows,
        ["browser", "user", "profile", "flags", "history", "downloads", "cookies", "extensions"],
    )


def _containers_section(containers: Dict[str, Any]) -> str:
    if not containers:
        return "<section class='report-section'><h2>Container Analysis</h2><div class='empty'>No container report.</div></section>"

    # Case-level rollup: keyed by source id with {label, data}
    if all(isinstance(v, dict) and "data" in v for v in containers.values()):
        chunks = ["<section class='report-section'><h2>Container Analysis (Case Rollup)</h2>"]
        for _, block in containers.items():
            label = block.get("label") or "Source"
            chunks.append(f"<h3>{escape(str(label))}</h3>")
            chunks.append(_containers_section(block.get("data") or {}))
        chunks.append("</section>")
        return "".join(chunks)

    parts = [_kv_table("Container Risk Summary", containers.get("risk") or {})]
    inventory = containers.get("inventory") or []
    if isinstance(inventory, list):
        parts.append(
            _table_from_records(
                "Container Inventory",
                [x for x in inventory if isinstance(x, dict)],
                ["name", "role", "image", "risk_score", "status"],
            )
        )
    chain = containers.get("attack_chain") or []
    if isinstance(chain, list):
        parts.append(
            _table_from_records(
                "Container Attack Chain",
                [x for x in chain if isinstance(x, dict)],
                ["container", "role", "reasons"],
            )
        )
    return "".join(parts)


def _html_styles() -> str:
    return """
<style>
:root {
  --bg: #f5f8fc;
  --card: #ffffff;
  --ink: #1d2939;
  --muted: #475467;
  --line: #d0d5dd;
  --primary: #0b4f6c;
  --accent: #f59e0b;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: radial-gradient(circle at 10% 0%, #eaf4ff, transparent 45%), var(--bg);
  color: var(--ink);
  font-family: "Segoe UI", "Noto Sans", sans-serif;
}
.wrapper {
  max-width: 1200px;
  margin: 24px auto;
  padding: 0 18px 26px;
}
.hero {
  background: linear-gradient(130deg, #0b4f6c 0%, #176087 60%, #1d6b8e 100%);
  color: #fff;
  border-radius: 14px;
  padding: 20px;
  box-shadow: 0 8px 20px rgba(11, 79, 108, 0.2);
}
.hero h1 { margin: 0 0 8px; font-size: 24px; }
.hero p { margin: 0; opacity: .95; font-size: 14px; }
.meta { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; font-size: 12px; }
.meta span { background: rgba(255,255,255,.16); border: 1px solid rgba(255,255,255,.25); padding: 4px 8px; border-radius: 999px; }
.report-section {
  margin-top: 16px;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 14px;
  box-shadow: 0 1px 4px rgba(16, 24, 40, 0.06);
}
.report-section h2 {
  margin: 0 0 10px;
  font-size: 16px;
  color: var(--primary);
}
.report-section h3 {
    margin: 10px 0 8px;
    font-size: 14px;
    color: #0f172a;
}
.intro {
    margin: 0;
    line-height: 1.6;
    color: #334155;
    font-size: 13px;
}
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 10px;
}
.card {
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 10px;
  background: #fff;
}
.card-value { font-size: 20px; font-weight: 700; }
.card-label { font-size: 12px; color: var(--muted); margin-top: 4px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td {
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid #eaecf0;
  padding: 7px 8px;
  font-size: 12px;
}
th {
  position: sticky;
  top: 0;
  background: #f9fafb;
  color: #344054;
  font-weight: 600;
}
.empty {
  font-size: 13px;
  color: var(--muted);
  border: 1px dashed var(--line);
  border-radius: 8px;
  padding: 10px;
  background: #fcfcfd;
}
.table-note { margin: 0 0 8px; font-size: 12px; color: #b54708; }
details { margin-top: 10px; }
pre {
  margin: 6px 0 0;
  background: #0f172a;
  color: #dbeafe;
  border-radius: 10px;
  padding: 12px;
  font-size: 11px;
  overflow-x: auto;
}
@media print {
  .wrapper { max-width: none; margin: 0; padding: 0; }
  .report-section, .hero { box-shadow: none; }
}
</style>
"""


def render_report_html(
    report: Dict[str, Any],
    *,
    report_title: str = "OS Forensics Comprehensive Report",
    case_name: str = "",
    source_path: str = "",
    generated_by: str = "OSForensics",
    case_data: Optional[Dict[str, Any]] = None,
    intro_text: str = "",
    report_variant: str = "comprehensive",
    include_raw_json: bool = True,
) -> str:
    merged_report = _combine_case_reports(case_data, report)
    summary = merged_report.get("summary") or {}
    os_info = merged_report.get("os_info") or {}
    case_info = merged_report.get("case_info") or {}
    variant = report_variant if report_variant in REPORT_VARIANTS else "comprehensive"
    is_case_level = bool(case_info)

    case_info_rows = {
        "Case Name": case_info.get("name") or case_name or "-",
        "Case Number": case_info.get("number") or "-",
        "Case ID": case_info.get("id") or "-",
        "Examiner": case_info.get("examiner") or "-",
        "Created": case_info.get("created_at") or "-",
        "Updated": case_info.get("updated_at") or "-",
        "Sources": case_info.get("source_count") or len(merged_report.get("source_rollup") or []),
        "Description": case_info.get("description") or "-",
    }

    source_rollup = _coerce_records(merged_report.get("source_rollup"))

    sections = [
        _intro_section(intro_text, variant),
        _kv_table("Case Information", case_info_rows) if is_case_level or case_name else "",
        _table_from_records(
            "Evidence Source Overview",
            source_rollup,
            ["label", "path", "evidence_id", "acquisition_time", "tools", "timeline_events", "total_high"],
        ) if source_rollup else "",
        _summary_cards(summary),
        _kv_table("OS Profile", os_info),
        _table_from_records("Tool Findings", merged_report.get("findings") or [], ["tool", "risk", "category", "evidence"]),
        _table_from_records("Timeline", merged_report.get("timeline") or [], ["timestamp", "source", "event_type", "detail", "severity"]),
    ]

    if variant != "executive":
        sections.extend(
            [
                _table_from_records("Deleted Artifacts", merged_report.get("deleted") or [], ["path", "type", "detail", "severity", "recoverable"]),
                _table_from_records("Persistence Findings", merged_report.get("persistence") or [], ["source", "category", "detail", "severity"]),
                _table_from_records("Configuration Findings", merged_report.get("config") or [], ["config", "category", "detail", "severity", "recommendation"]),
                _table_from_records("Service Findings", merged_report.get("services") or [], ["display_name", "name", "category", "state", "severity", "run_user"]),
                _browser_section(merged_report.get("browsers") or []),
                _table_from_records("Multimedia Findings", merged_report.get("multimedia") or [], ["path", "media_type", "ext", "severity", "flags"]),
                _table_from_records("Tails Indicators", merged_report.get("tails") or [], ["source", "category", "detail", "severity", "evidence"]),
                _containers_section(merged_report.get("containers") or {}),
            ]
        )

    if variant in {"comprehensive", "legal"}:
        sections.extend(
            [
                _kv_table("Evidence Integrity", merged_report.get("evidence_integrity") or {}),
                _table_from_records("Evidence Provenance", merged_report.get("evidence_provenance") or [], ["artifact", "source", "extraction_method"]),
                _table_from_records("Chain of Custody", merged_report.get("chain_of_custody") or [], ["timestamp", "action", "collected_by", "verified_by", "evidence_id", "notes"]),
                _table_from_records("Audit Log", merged_report.get("audit_log") or [], ["timestamp", "actor", "action", "details"]),
            ]
        )

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    pretty_json = escape(json.dumps(merged_report, indent=2, ensure_ascii=True))
    header_meta = [
        f"<span>Generated: {escape(generated_at)}</span>",
        f"<span>Generator: {escape(generated_by)}</span>",
    ]
    if case_name:
        header_meta.append(f"<span>Case: {escape(case_name)}</span>")
    if source_path:
        header_meta.append(f"<span>Source: {escape(source_path)}</span>")

    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{escape(report_title)}</title>{_html_styles()}</head><body>"
        "<div class='wrapper'>"
        f"<header class='hero'><h1>{escape(report_title)}</h1>"
        "<p>Comprehensive digital forensics report with structured module outputs and legal evidence context.</p>"
        f"<div class='meta'>{''.join(header_meta)}</div></header>"
        f"{''.join(s for s in sections if s)}"
        + (
            "<section class='report-section'><h2>Raw JSON Appendix</h2>"
            "<details><summary>Expand full report JSON</summary>"
            f"<pre>{pretty_json}</pre></details></section>"
            if include_raw_json
            else ""
        )
        + "</div></body></html>"
    )


def _mk_pdf_table(records: Sequence[Dict[str, Any]], columns: Sequence[str], max_rows: int = 140):
    colors = importlib.import_module("reportlab.lib.colors")
    units = importlib.import_module("reportlab.lib.units")
    platypus = importlib.import_module("reportlab.platypus")
    cm = units.cm
    Table = platypus.Table
    TableStyle = platypus.TableStyle

    head = [str(c) for c in columns]
    body = []
    for row in records[:max_rows]:
        body.append([_safe_text(row.get(c)) for c in columns])
    if not body:
        body = [["No records", "-", "-", "-"][: len(columns)]]
    data = [head] + body

    table = Table(data, repeatRows=1)
    table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B4F6C")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d5dd")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
    )
    table.setStyle(table_style)
    if len(columns) > 0:
        width = 18.5 * cm / len(columns)
        table._argW = [width] * len(columns)
    return table


def render_report_pdf(
    report: Dict[str, Any],
    *,
    report_title: str = "OS Forensics Comprehensive Report",
    case_name: str = "",
    source_path: str = "",
    generated_by: str = "OSForensics",
    case_data: Optional[Dict[str, Any]] = None,
    intro_text: str = "",
    report_variant: str = "comprehensive",
) -> bytes:
    try:
        colors = importlib.import_module("reportlab.lib.colors")
        pagesizes = importlib.import_module("reportlab.lib.pagesizes")
        styles_mod = importlib.import_module("reportlab.lib.styles")
        units = importlib.import_module("reportlab.lib.units")
        platypus = importlib.import_module("reportlab.platypus")
        A4 = pagesizes.A4
        ParagraphStyle = styles_mod.ParagraphStyle
        getSampleStyleSheet = styles_mod.getSampleStyleSheet
        cm = units.cm
        Paragraph = platypus.Paragraph
        SimpleDocTemplate = platypus.SimpleDocTemplate
        Spacer = platypus.Spacer
    except ImportError as exc:
        raise RuntimeError("PDF export requires 'reportlab'. Install it with: pip install reportlab") from exc

    stream = io.BytesIO()
    doc = SimpleDocTemplate(
        stream,
        pagesize=A4,
        leftMargin=1.2 * cm,
        rightMargin=1.2 * cm,
        topMargin=1.0 * cm,
        bottomMargin=1.0 * cm,
        title=report_title,
        author=generated_by,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("r-title", parent=styles["Heading1"], textColor=colors.HexColor("#0B4F6C"), fontSize=17)
    h2_style = ParagraphStyle("r-h2", parent=styles["Heading2"], textColor=colors.HexColor("#0B4F6C"), fontSize=12)
    meta_style = ParagraphStyle("r-meta", parent=styles["Normal"], textColor=colors.HexColor("#475467"), fontSize=8)

    merged_report = _combine_case_reports(case_data, report)
    summary = merged_report.get("summary") or {}
    os_info = merged_report.get("os_info") or {}
    case_info = merged_report.get("case_info") or {}
    source_rollup = _coerce_records(merged_report.get("source_rollup"))
    variant = report_variant if report_variant in REPORT_VARIANTS else "comprehensive"

    story: List[Any] = []
    story.append(Paragraph(escape(report_title), title_style))
    story.append(Paragraph(f"Generated by {escape(generated_by)} on {datetime.now(timezone.utc).isoformat(timespec='seconds')}", meta_style))
    story.append(Paragraph(f"Report format: {escape(REPORT_VARIANTS.get(variant, 'Comprehensive'))}", meta_style))
    if case_name:
        story.append(Paragraph(f"Case: {escape(case_name)}", meta_style))
    if source_path:
        story.append(Paragraph(f"Source: {escape(source_path)}", meta_style))
    if intro_text:
        story.append(Spacer(1, 6))
        story.append(Paragraph(escape(intro_text), styles["BodyText"]))
    story.append(Spacer(1, 10))

    if case_info:
        story.append(Paragraph("Case Information", h2_style))
        case_rows = [
            {"Field": "Case Name", "Value": case_info.get("name") or case_name or "-"},
            {"Field": "Case Number", "Value": case_info.get("number") or "-"},
            {"Field": "Case ID", "Value": case_info.get("id") or "-"},
            {"Field": "Examiner", "Value": case_info.get("examiner") or "-"},
            {"Field": "Created", "Value": case_info.get("created_at") or "-"},
            {"Field": "Updated", "Value": case_info.get("updated_at") or "-"},
            {"Field": "Source Count", "Value": case_info.get("source_count") or len(source_rollup)},
        ]
        story.append(_mk_pdf_table(case_rows, ["Field", "Value"]))
        story.append(Spacer(1, 8))

    if source_rollup:
        story.append(Paragraph("Evidence Source Overview", h2_style))
        story.append(_mk_pdf_table(source_rollup, ["label", "path", "evidence_id", "tools", "timeline_events", "total_high"]))
        story.append(Spacer(1, 8))

    summary_rows = [
        {"Metric": "Total Tools", "Value": summary.get("total_tools", 0)},
        {"Metric": "High/Critical", "Value": summary.get("total_high", 0)},
        {"Metric": "Timeline Events", "Value": summary.get("timeline_events", 0)},
        {"Metric": "Deleted Files", "Value": summary.get("deleted_files", 0)},
        {"Metric": "Persistence", "Value": summary.get("persistence_items", 0)},
        {"Metric": "Services", "Value": summary.get("services_count", 0)},
    ]
    story.append(Paragraph("Executive Summary", h2_style))
    story.append(_mk_pdf_table(summary_rows, ["Metric", "Value"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("OS Profile", h2_style))
    os_rows = [{"Field": k, "Value": _safe_text(v)} for k, v in os_info.items()]
    story.append(_mk_pdf_table(os_rows, ["Field", "Value"]))
    story.append(Spacer(1, 8))

    sections = [
        ("Tool Findings", merged_report.get("findings") or [], ["tool", "risk", "category", "evidence"]),
        ("Timeline", merged_report.get("timeline") or [], ["timestamp", "source", "event_type", "detail", "severity"]),
    ]

    if variant != "executive":
        sections.extend(
            [
                ("Deleted Artifacts", merged_report.get("deleted") or [], ["path", "type", "detail", "severity"]),
                ("Persistence", merged_report.get("persistence") or [], ["source", "category", "detail", "severity"]),
                ("Configuration", merged_report.get("config") or [], ["config", "category", "detail", "severity"]),
                ("Services", merged_report.get("services") or [], ["display_name", "state", "category", "severity"]),
                ("Tails Indicators", merged_report.get("tails") or [], ["source", "category", "detail", "severity"]),
            ]
        )

    if variant in {"comprehensive", "legal"}:
        sections.extend(
            [
                ("Evidence Provenance", merged_report.get("evidence_provenance") or [], ["artifact", "source", "extraction_method"]),
                ("Chain of Custody", merged_report.get("chain_of_custody") or [], ["timestamp", "action", "collected_by", "verified_by", "evidence_id"]),
                ("Audit Log", merged_report.get("audit_log") or [], ["timestamp", "actor", "action", "details"]),
            ]
        )

    for title, rows, cols in sections:
        story.append(Paragraph(escape(title), h2_style))
        story.append(_mk_pdf_table([r for r in rows if isinstance(r, dict)], cols))
        story.append(Spacer(1, 8))

    doc.build(story)
    return stream.getvalue()
