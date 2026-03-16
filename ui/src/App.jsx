import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  Search, FolderSearch, Trash2, Settings, Microscope,
  X, FolderOpen, AlertTriangle, CheckCircle, HardDrive, Activity,
  Clock, Shield, ShieldAlert, Eye, ChevronDown, ChevronRight, Hash, Terminal,
  Lock, Server, Key, Folder, FolderOpen as FolderOpenIcon, FileText,
  Wifi, Package, List, Database, Cpu, Box, Globe, Users, ChevronUp,
  File, Code, RefreshCw, Info, LayoutPanelLeft, BarChart2, BarChart3, Home,
  BookOpen, Plus, Filter, Bot, Send, Loader2, Zap,
  Image, Film, Music, MapPin, Camera, Layers, Download, Play,
  Sailboat,
  Usb,
  Share2, Paperclip, Link, Archive, Layers as LayersIcon,
  DollarSign, Files, Network
} from "lucide-react";

// ─── API ──────────────────────────────────────────────────────────────────────
const API = "http://127.0.0.1:8000";

const post = async (url, body) => {
  const res = await fetch(`${API}${url}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  return res.json();
};

const postBlob = async (url, body) => {
  const res = await fetch(`${API}${url}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  const disp = res.headers.get("content-disposition") || "";
  const match = disp.match(/filename=([^;]+)/i);
  const filename = match ? match[1].trim().replace(/^"|"$/g, "") : null;
  return { blob: await res.blob(), filename };
};

const get = async (url) => {
  const res = await fetch(`${API}${url}`);
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  return res.json();
};

const apiAnalyze     = (path)       => post("/analyze",        { image_path: path });
const apiAnalyzeTailsDeep = (path, opts = {}) => post("/analyze/tails/deep", { image_path: path, ...opts });
const apiAnalyzeLive = (scanTypes)   => post("/analyze/live",  scanTypes || {});
const apiAnalyzeSsh  = (body)        => post("/analyze/ssh",   body);
const apiAnalyzeSshfs = (body)       => post("/analyze/sshfs", body);
const apiSshInfo     = (body)        => post("/analyze/ssh/info", body);
const apiLiveInfo    = ()            => get("/live/info");
const apiFsBrowse    = (path)        => post("/fs/browse",      { path });
const apiUsbSources  = ()            => get("/fs/usb/sources");
const apiBrowse      = (img, path)   => post("/explore/browse", { image_path: img, path });
const apiStat        = (img, path)   => post("/explore/stat",   { image_path: img, path });
const apiRead        = (img, path)   => post("/explore/read",   { image_path: img, path });
const apiTree        = ()            => get("/explore/tree");

// ── Case management API ───────────────────────────────────────────────────────
const apiCasesList = () => get("/cases");
const apiCaseCreate = (body) => post("/cases", body);
const apiCaseGet = (id) => get(`/cases/${id}`);
const apiCaseDelete = (id) => fetch(`${API}/cases/${id}`, { method: "DELETE" }).then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); });
const apiCaseAnalyze = (caseId, imgPath) => post(`/cases/${caseId}/analyze`, { image_path: imgPath });
const apiCaseAnalyzeTails = (caseId, imgPath) => post(`/cases/${caseId}/analyze/tails`, { image_path: imgPath });
const apiCaseAnalyzeTailsDeep = (caseId, imgPath, opts = {}) => post(`/cases/${caseId}/analyze/tails/deep`, { image_path: imgPath, ...opts });
const apiCaseAnalyzeLive = (caseId, scanTypes) => post(`/cases/${caseId}/analyze/live`, scanTypes || {});
const apiCaseAnalyzeSsh  = (caseId, body)      => post(`/cases/${caseId}/analyze/ssh`, body);
const apiCaseAnalyzeSshfs = (caseId, body)     => post(`/cases/${caseId}/analyze/sshfs`, body);
const apiCaseDelSrc  = (caseId, srcId)   => fetch(`${API}/cases/${caseId}/sources/${srcId}`, { method: "DELETE" }).then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); });
const apiRecover     = (img, recoveryId) => post("/deleted/recover", { image_path: img, recovery_id: recoveryId });
const apiCarveGroups = ()                => get("/deleted/carve/groups");
const apiCarve       = (img, opts)       => post("/deleted/carve", { image_path: img, ...opts });
const apiMultimedia  = (path)            => post("/multimedia", { image_path: path });
const apiExportReportHtml = (body)       => postBlob("/report/export/html", body);
const apiExportReportPdf  = (body)       => postBlob("/report/export/pdf", body);
const apiMediaUrl    = (imgPath, filePath) =>
  `${API}/multimedia/view?image_path=${encodeURIComponent(imgPath)}&file_path=${encodeURIComponent(filePath)}`;

// ── Agent API ─────────────────────────────────────────────────────────────────
const apiAgentStatus = () => get("/agent/status");
const apiAgentReset = (sid) => fetch(`${API}/agent/reset/${sid}`, { method: "POST" }).then(r => r.json());
const apiTimelineAI = (events) => post("/timeline/ai-analysis", { events });
const apiMemoryLive = () => get("/memory/live");
const apiMemoryAI = () => post("/memory/ai-analysis", {});
const apiMemoryDumpUpload = (formData) => fetch(`${API}/memory/upload`, { method: "POST", body: formData }).then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); });
const apiMemoryDumpAI = (reportData) => post("/memory/analyze-dump/ai", { report_data: reportData });

// ─── Severity / icon helpers ──────────────────────────────────────────────────
const SEV_COLOR = { critical: "#7f1d1d", high: "#dc2626", medium: "#d97706", low: "#16a34a", info: "#2563eb" };
const SEV_BG = { critical: "#fef2f2", high: "#fff1f0", medium: "#fffbeb", low: "#f0fdf4", info: "#eff6ff" };

function SevBadge({ sev }) {
  const s = (sev || "info").toLowerCase();
  return <span className="sev-badge" style={{ background: SEV_COLOR[s] || "#6b7280" }}>{s}</span>;
}

const ICON_MAP = {
  HardDrive, Terminal, Lock, Server, Key, Folder, FileText, Wifi, Package, List,
  Database, Cpu, Box, Globe, Users, Clock, Shield, Activity, AlertTriangle, File,
  Hash, Eye, Search, FolderOpen: FolderOpenIcon,
};
function NodeIcon({ name, size = 14, style }) {
  const C = ICON_MAP[name] || File;
  return <C size={size} style={style} />;
}

function TailsLogo({ size = "md", withText = false }) {
  return (
    <span className={`tails-logo tails-logo-${size}`}>
      <span className="tails-logo-mark"><Sailboat size={size === "sm" ? 10 : 12} /></span>
      {withText && <span className="tails-logo-text">TailsOS</span>}
    </span>
  );
}

// ─── MODAL ────────────────────────────────────────────────────────────────────
function Modal({ title, onClose, children, width = 540 }) {
  const ref = useRef(null);
  useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const drag = useRef({ d: false, ox: 0, oy: 0 });
  const [pos, setPos] = useState(null);
  const onMD = (e) => { const r = ref.current.getBoundingClientRect(); drag.current = { d: true, ox: e.clientX - r.left, oy: e.clientY - r.top }; };
  const onMM = useCallback((e) => { if (!drag.current.d) return; setPos({ x: e.clientX - drag.current.ox, y: e.clientY - drag.current.oy }); }, []);
  const onMU = useCallback(() => { drag.current.d = false; }, []);
  useEffect(() => {
    window.addEventListener("mousemove", onMM);
    window.addEventListener("mouseup", onMU);
    return () => { window.removeEventListener("mousemove", onMM); window.removeEventListener("mouseup", onMU); };
  }, [onMM, onMU]);

  const style = pos ? { position: "fixed", left: pos.x, top: pos.y, transform: "none", width } : { width };
  return (
    <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal-window" ref={ref} style={style}>
        <div className="modal-titlebar" onMouseDown={onMD}>
          <span className="modal-title">{title}</span>
          <button className="modal-close" onClick={onClose}><X size={14} /></button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

const TAILS_CATEGORY_LABELS = {
  environment: "Environment",
  persistence: "Persistence",
  tor: "Tor Activity",
  browser: "Tor Browser",
  usb_origin: "USB Origin",
  memory: "Memory Artifacts",
  hidden_service: "Hidden Service",
  anti_forensics: "Anti-Forensics",
  timeline: "Session Timeline",
  misconfiguration: "Misconfiguration",
  operational_profile: "Operational Profile",
};

const CONTAINER_SECTIONS = [
  ["overview", "Overview"],
  ["inventory", "Containers"],
  ["images", "Images"],
  ["filesystem", "Filesystem"],
  ["execution", "Execution"],
  ["network", "Network"],
  ["privilege", "Privilege"],
  ["deleted", "Deleted"],
  ["timeline", "Timeline"],
  ["k8s", "Kubernetes"],
  ["risk", "Risk & Chain"],
];

function ContainerTab({ data = {} }) {
  const [section, setSection] = useState("overview");
  const inventory = data.inventory || [];
  const images = data.images || [];
  const fsChanges = (data.filesystem || {}).changes || [];
  const deleted = (data.deleted || []);
  const timeline = data.timeline || [];
  const privilegeFindings = ((data.privilege || {}).findings || []);
  const netConns = ((data.network || {}).connections || []);
  const execCmds = ((data.execution || {}).commands || []);
  const offensive = data.offensive_tools || [];
  const risk = data.risk || {};
  const riskChain = data.attack_chain || [];
  const k8sData = data.kubernetes || data.k8s || {};

  const renderEmpty = (message) => (
    <div className="empty-state">
      <Box size={28} />
      <p>{message}</p>
    </div>
  );

  return (
    <div className="tab-content">
      <div className="ct-toolbar" style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        {CONTAINER_SECTIONS.map(([id, label]) => (
          <button
            key={id}
            className={`case-tab ${section === id ? "active" : ""}`}
            onClick={() => setSection(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {section === "overview" && (
        <div className="ct-block" style={{ display: "grid", gap: 12 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10 }}>
            <div className="stat-card"><strong>{inventory.length}</strong><span>Containers</span></div>
            <div className="stat-card"><strong>{images.length}</strong><span>Images</span></div>
            <div className="stat-card"><strong>{fsChanges.length}</strong><span>Filesystem Changes</span></div>
            <div className="stat-card"><strong>{execCmds.length}</strong><span>Commands</span></div>
            <div className="stat-card"><strong>{netConns.length}</strong><span>Connections</span></div>
            <div className="stat-card"><strong>{deleted.length}</strong><span>Deleted Artifacts</span></div>
          </div>
          <table className="rp-table">
            <tbody>
              <tr><td>Cluster / Scope</td><td>{data.cluster || data.scope || "-"}</td></tr>
              <tr><td>Risk Score</td><td>{risk.score ?? risk.total ?? "-"}</td></tr>
              <tr><td>Attack Chain Nodes</td><td>{riskChain.length}</td></tr>
              <tr><td>Offensive Tool Hits</td><td>{offensive.length}</td></tr>
            </tbody>
          </table>
        </div>
      )}

      {section === "inventory" && (
        inventory.length === 0 ? renderEmpty("No containers in inventory.") : (
          <table className="rp-table">
            <thead><tr><th>Name</th><th>Role</th><th>Image</th><th>Risk</th><th>Status</th></tr></thead>
            <tbody>
              {inventory.map((c, i) => (
                <tr key={c.id || c.name || i}>
                  <td>{c.name || c.id || "-"}</td>
                  <td>{c.role || "General"}</td>
                  <td><code>{c.image || "-"}</code></td>
                  <td>{c.risk_score ?? "-"}</td>
                  <td>{c.status || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {section === "images" && (
        images.length === 0 ? renderEmpty("No images reported.") : (
          <table className="rp-table">
            <thead><tr><th>Image</th><th>Tag</th><th>Digest</th><th>Size</th></tr></thead>
            <tbody>
              {images.map((img, i) => (
                <tr key={img.id || img.name || i}>
                  <td>{img.name || img.repository || "-"}</td>
                  <td>{img.tag || "-"}</td>
                  <td><code>{img.digest || "-"}</code></td>
                  <td>{img.size || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {section === "filesystem" && (
        fsChanges.length === 0 ? renderEmpty("No filesystem changes detected.") : (
          <table className="rp-table">
            <thead><tr><th>Path</th><th>Change</th><th>Container</th><th>Detail</th></tr></thead>
            <tbody>
              {fsChanges.map((change, i) => (
                <tr key={change.path || i}>
                  <td><code>{change.path || "-"}</code></td>
                  <td>{change.type || change.change || "-"}</td>
                  <td>{change.container || "-"}</td>
                  <td>{change.detail || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {section === "execution" && (
        execCmds.length === 0 ? renderEmpty("No command execution history available.") : (
          <table className="rp-table">
            <thead><tr><th>Timestamp</th><th>Container</th><th>Command</th><th>User</th></tr></thead>
            <tbody>
              {execCmds.map((cmd, i) => (
                <tr key={i}>
                  <td>{fmtDate(cmd.timestamp)}</td>
                  <td>{cmd.container || "-"}</td>
                  <td><code>{cmd.command || cmd.cmd || "-"}</code></td>
                  <td>{cmd.user || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {section === "network" && (
        netConns.length === 0 ? renderEmpty("No network connections captured.") : (
          <table className="rp-table">
            <thead><tr><th>Container</th><th>Protocol</th><th>Source</th><th>Destination</th><th>State</th></tr></thead>
            <tbody>
              {netConns.map((conn, i) => (
                <tr key={i}>
                  <td>{conn.container || "-"}</td>
                  <td>{conn.protocol || "-"}</td>
                  <td><code>{conn.source || conn.src || "-"}</code></td>
                  <td><code>{conn.destination || conn.dst || "-"}</code></td>
                  <td>{conn.state || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {section === "privilege" && (
        privilegeFindings.length === 0 ? renderEmpty("No privilege findings reported.") : (
          <table className="rp-table">
            <thead><tr><th>Container</th><th>Severity</th><th>Finding</th><th>Detail</th></tr></thead>
            <tbody>
              {privilegeFindings.map((finding, i) => (
                <tr key={i}>
                  <td>{finding.container || "-"}</td>
                  <td>{finding.severity || "-"}</td>
                  <td>{finding.title || finding.finding || "-"}</td>
                  <td>{finding.detail || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {section === "deleted" && (
        deleted.length === 0 ? renderEmpty("No deleted artifacts were recovered.") : (
          <table className="rp-table">
            <thead><tr><th>Path</th><th>Container</th><th>Recovered</th><th>Detail</th></tr></thead>
            <tbody>
              {deleted.map((item, i) => (
                <tr key={item.path || i}>
                  <td><code>{item.path || "-"}</code></td>
                  <td>{item.container || "-"}</td>
                  <td>{item.recovered ? "Yes" : "No"}</td>
                  <td>{item.detail || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {section === "timeline" && (
        timeline.length === 0 ? renderEmpty("No timeline events available.") : (
          <table className="rp-table">
            <thead><tr><th>Timestamp</th><th>Container</th><th>Event</th><th>Detail</th></tr></thead>
            <tbody>
              {timeline.map((ev, i) => (
                <tr key={i}>
                  <td>{fmtDate(ev.timestamp)}</td>
                  <td>{ev.container || "-"}</td>
                  <td>{ev.event || ev.type || "-"}</td>
                  <td>{ev.detail || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {section === "k8s" && (
        Object.keys(k8sData).length === 0 ? renderEmpty("No Kubernetes metadata detected.") : (
          <div className="ct-block">
            <pre className="json-block" style={{ margin: 0 }}>{JSON.stringify(k8sData, null, 2)}</pre>
          </div>
        )
      )}

      {section === "risk" && (
        <div className="ct-block">
          <table className="rp-table" style={{ marginBottom: 10 }}>
            <thead><tr><th>Container</th><th>Role</th><th>Risk</th><th>Reasons</th></tr></thead>
            <tbody>
              {inventory.slice(0, 40).map((c, i) => (
                <tr key={c.id || c.name || i}>
                  <td>{c.name || "-"}</td>
                  <td>{c.role || "General"}</td>
                  <td>{c.risk_score ?? "-"}</td>
                  <td><code>{(c.risk_reasons || []).join(", ") || "-"}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
          <table className="rp-table">
            <thead><tr><th>Attack Chain Node</th><th>Role</th><th>Reasons</th></tr></thead>
            <tbody>
              {riskChain.map((a, i) => (
                <tr key={i}><td>{a.container || "-"}</td><td>{a.role || "-"}</td><td><code>{(a.reasons || []).join(", ") || "-"}</code></td></tr>
              ))}
            </tbody>
          </table>
          {offensive.length > 0 && (
            <div className="ct-inline-note">Offensive tools detected in containers: <code>{offensive.map((o) => `${o.container}=[${(o.tools || []).join(",")}]`).join(" | ")}</code></div>
          )}
        </div>
      )}
    </div>
  );
}

function TailsTab({ findings = [], summary = {} }) {
  const [search, setSearch] = useState("");
  const [sev, setSev] = useState("all");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (findings || []).filter((f) => {
      if (sev !== "all" && (f.severity || "info") !== sev) return false;
      if (!q) return true;
      return (
        (f.detail || "").toLowerCase().includes(q) ||
        (f.category || "").toLowerCase().includes(q) ||
        (f.evidence || []).some((e) => String(e).toLowerCase().includes(q))
      );
    });
  }, [findings, search, sev]);

  if (!findings || findings.length === 0) {
    return (
      <div className="tab-content">
        <div className="empty-state">
          <TailsLogo withText />
          <p style={{ marginTop: 10 }}>No TailsOS-specific artifacts were detected in this source.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="tab-content">
      <div className="tails-head">
        <div className="tails-head-title"><TailsLogo withText /> Dedicated Tails forensic indicators</div>
        <div className="tails-head-stats">
          <span className="tag"><AlertTriangle size={10} /> High: {summary.high_tails ?? 0}</span>
          <span className="tag"><List size={10} /> Findings: {summary.tails_findings ?? findings.length}</span>
        </div>
      </div>

      <div className="tails-filters">
        <select className="mm-select" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">All severity</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="info">Info</option>
        </select>
        <input
          className="mm-search"
          type="text"
          placeholder="Search Tails findings or evidence…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <table className="rp-table">
        <thead>
          <tr>
            <th>Category</th>
            <th>Severity</th>
            <th>Detail</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((f, i) => (
            <tr key={i}>
              <td>{TAILS_CATEGORY_LABELS[f.category] || f.category}</td>
              <td><SevBadge sev={f.severity || "info"} /></td>
              <td>{f.detail}</td>
              <td>
                {(f.evidence || []).length === 0 ? "-" : (
                  <ul className="evidence-list">
                    {(f.evidence || []).slice(0, 6).map((e, j) => <li key={j}><code>{e}</code></li>)}
                  </ul>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
// ─── Dialogs ──────────────────────────────────────────────────────────────────
function AnalyzeDialog({ onClose, onResult }) {
  const [path, setPath] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  async function run() {
    if (!path.trim()) return;
    setLoading(true); setErr(null);
    try { onResult(await apiAnalyze(path.trim()), path.trim()); onClose(); }
    catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  }
  return (
    <Modal title="Analyze — Open Image or Mountpoint" onClose={onClose} width={600}>
      <div className="dlg-field">
        <label>Path to image / mountpoint</label>
        <input autoFocus value={path} onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder="/mnt/snapshot  or  /path/to/disk.img  or  /" />
        <div className="dlg-hint">Use a mounted directory path for non-pytsk3 environments.</div>
      </div>
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button className="btn-primary" onClick={run} disabled={loading || !path.trim()}>
          <Search size={14} />{loading ? "Analyzing…" : "Analyze"}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

// ─── LIVE SCAN DIALOG ───────────────────────────────────────────────────────
const SCAN_TYPES = [
  { key: "timeline", label: "Timeline", hint: "File access / modification events", default: true },
  { key: "deleted", label: "Deleted Files", hint: "Recoverable deleted file detection", default: true },
  { key: "persistence", label: "Persistence", hint: "Cron, systemd, rc files, SUID, keys", default: true },
  { key: "services", label: "Services", hint: "Installed daemons and service units", default: true },
  { key: "config", label: "Config Audit", hint: "Security-relevant config file analysis", default: false },
  { key: "browsers", label: "Browser Artifacts", hint: "History, cookies, extensions", default: false },
  { key: "multimedia", label: "Multimedia", hint: "Image / video / audio metadata (slow)", default: false },
];

const REMOTE_DEFAULT_INCLUDE = "/etc, /var/log, /home, /root, /usr/bin, /usr/sbin, /opt";

function LiveScanDialog({ onClose, onResult, runScan, title = "Scan Live System" }) {
  const defaults = Object.fromEntries(SCAN_TYPES.map(t => [t.key, t.default]));
  const [types, setTypes] = useState(defaults);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  const toggle = (key) => setTypes(prev => ({ ...prev, [key]: !prev[key] }));
  const anyOn = Object.values(types).some(Boolean);

  async function run() {
    setLoading(true); setErr(null);
    try {
      let result;
      if (runScan) {
        result = await runScan(types);
      } else {
        const [info, report] = await Promise.all([apiLiveInfo(), apiAnalyzeLive(types)]);
        result = { info, report, path: "/" };
      }
      onResult(result.report, result.path || "/", result.info, result.source || null);
      onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal title={title} onClose={onClose} width={440}>
      <div className="lsd-body">
        <p className="lsd-intro">
          <Cpu size={13} /> Scanning <strong>/</strong> — select which analysis modules to run:
        </p>
        <div className="lsd-checks">
          {SCAN_TYPES.map(({ key, label, hint }) => (
            <label key={key} className="lsd-check">
              <input type="checkbox" checked={!!types[key]} onChange={() => toggle(key)} />
              <span className="lsd-check-info">
                <span className="lsd-check-label">{label}</span>
                <span className="lsd-check-hint">{hint}</span>
              </span>
            </label>
          ))}
        </div>
        <div className="lsd-select-row">
          <button className="lsd-sel-btn" onClick={() => setTypes(Object.fromEntries(SCAN_TYPES.map(t => [t.key, true])))}>
            Select all
          </button>
          <button className="lsd-sel-btn" onClick={() => setTypes(Object.fromEntries(SCAN_TYPES.map(t => [t.key, false])))}>
            Deselect all
          </button>
        </div>
      </div>
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button className="btn-primary" onClick={run} disabled={loading || !anyOn}>
          <Cpu size={14} />{loading ? "Scanning…" : "Start Scan"}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

function RemoteScanDialog({ onClose, onResult, runScan, title = "Remote Connect & Live Scan" }) {
  const defaults = Object.fromEntries(SCAN_TYPES.map(t => [t.key, t.default]));
  const [mode, setMode] = useState("ssh_snapshot");
    const [mountedPath, setMountedPath] = useState("/");
  const [host, setHost] = useState("");
  const [username, setUsername] = useState("");
  const [port, setPort] = useState(22);
  const [authMode, setAuthMode] = useState("key");
  const [password, setPassword] = useState("");
  const [keyPath, setKeyPath] = useState("~/.ssh/id_ed25519");
  const [keyPassphrase, setKeyPassphrase] = useState("");
  const [includePaths, setIncludePaths] = useState(REMOTE_DEFAULT_INCLUDE);
  const [types, setTypes] = useState(defaults);
  const [connectTimeout, setConnectTimeout] = useState(15);
  const [authTimeout, setAuthTimeout] = useState(120);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(null);
  const [connectedInfo, setConnectedInfo] = useState(null);
  const [err, setErr] = useState(null);

  const toggle = (key) => setTypes(prev => ({ ...prev, [key]: !prev[key] }));
  const anyOn = Object.values(types).some(Boolean);
  const canRun = mode === "mounted_path"
    ? !!host.trim() && !!username.trim() && !!mountedPath.trim()
    : !!host.trim() && !!username.trim() && anyOn;

  async function run() {
    setLoading(true);
    setStep("connecting");
    setConnectedInfo(null);
    setErr(null);
    try {
      if (mode === "mounted_path") {
        const authBody = {
          host: host.trim(),
          username: username.trim(),
          port: Number(port) || 22,
          connect_timeout: Number(connectTimeout) || 15,
          banner_timeout: Number(authTimeout) || 120,
          auth_timeout: Number(authTimeout) || 120,
        };
        if (authMode === "password") {
          authBody.password = password;
        } else {
          authBody.key_path = keyPath.trim();
          if (keyPassphrase.trim()) authBody.key_passphrase = keyPassphrase;
        }

        const info = await apiSshInfo(authBody);
        setConnectedInfo(info);
        setStep("scanning");

        const body = {
          ...authBody,
          remote_path: mountedPath.trim(),
        };

        let mountedResult;
        if (runScan) {
          mountedResult = await runScan({ mode: "mounted_path", ...body });
        } else {
          mountedResult = await apiAnalyzeSshfs(body);
        }
        const mountedReport = mountedResult?.report || mountedResult;
        const mountedInfo = mountedResult?.live_info || mountedResult?.info || info || null;
        const sourcePath = `sshfs://${authBody.username}@${authBody.host}:${authBody.port}${body.remote_path}`;
        onResult(mountedReport, sourcePath, mountedInfo, mountedResult?.source || null);
        onClose();
        return;
      }

      const include = includePaths
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);

      const authBody = {
        host: host.trim(),
        username: username.trim(),
        port: Number(port) || 22,
        connect_timeout: Number(connectTimeout) || 15,
        banner_timeout: Number(authTimeout) || 120,
        auth_timeout: Number(authTimeout) || 120,
      };

      if (authMode === "password") {
        authBody.password = password;
      } else {
        authBody.key_path = keyPath.trim();
        if (keyPassphrase.trim()) authBody.key_passphrase = keyPassphrase;
      }

      const body = {
        ...authBody,
        include_paths: include,
        max_total_mb: 1024,
        max_file_mb: 32,
        max_files: 25000,
        ...types,
      };

      const info = await apiSshInfo(authBody);
      setConnectedInfo(info);
      setStep("scanning");

      const result = runScan
        ? await runScan(body)
        : await apiAnalyzeSsh(body);

      const finalInfo = result.live_info || info || {
        hostname: body.host,
        os_name: result.os_info?.name || "Linux",
        kernel: "unknown",
        uptime_str: "-",
        load_avg: [],
        memory: { total_kb: 0, available_kb: 0, used_pct: 0 },
        interfaces: [],
        process_count: 0,
        users: [body.username],
        scheme: "remote_ssh",
      };
      const path = `ssh://${body.username}@${body.host}:${body.port}`;
      onResult(result.report || result, path, finalInfo, result.source || null);
      onClose();
    } catch (e) {
      setErr(String(e));
      setStep(null);
      setConnectedInfo(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal title={title} onClose={onClose} width={560}>
      <div className="lsd-body">
        <div className="dlg-field">
          <label>Mode</label>
          <div style={{ display: "flex", gap: 10, fontSize: 12 }}>
            <label><input type="radio" checked={mode === "ssh_snapshot"} onChange={() => setMode("ssh_snapshot")} /> SSH Snapshot</label>
            <label><input type="radio" checked={mode === "mounted_path"} onChange={() => setMode("mounted_path")} /> Mounted Path</label>
          </div>
        </div>

        {mode === "ssh_snapshot" ? (
          <>
            <div className="dlg-field">
              <label>Remote Host</label>
              <input autoFocus value={host} onChange={(e) => setHost(e.target.value)} placeholder="192.168.56.10 or server.example.com" />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 120px", gap: 10 }}>
              <div className="dlg-field">
                <label>Username</label>
                <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="forensic" />
              </div>
              <div className="dlg-field">
                <label>Port</label>
                <input type="number" min="1" max="65535" value={port} onChange={(e) => setPort(e.target.value)} />
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <div className="dlg-field">
                <label>Connect Timeout (s)</label>
                <input type="number" min="2" max="300" value={connectTimeout} onChange={(e) => setConnectTimeout(e.target.value)} />
              </div>
              <div className="dlg-field">
                <label>Auth / Banner Timeout (s)</label>
                <input type="number" min="5" max="600" value={authTimeout} onChange={(e) => setAuthTimeout(e.target.value)} />
              </div>
            </div>

            <div className="dlg-field">
              <label>Authentication</label>
              <div style={{ display: "flex", gap: 10, fontSize: 12 }}>
                <label><input type="radio" checked={authMode === "key"} onChange={() => setAuthMode("key")} /> SSH Key</label>
                <label><input type="radio" checked={authMode === "password"} onChange={() => setAuthMode("password")} /> Password</label>
              </div>
            </div>

            {authMode === "key" ? (
              <>
                <div className="dlg-field">
                  <label>Key Path</label>
                  <input value={keyPath} onChange={(e) => setKeyPath(e.target.value)} placeholder="~/.ssh/id_ed25519" />
                </div>
                <div className="dlg-field">
                  <label>Key Passphrase (optional)</label>
                  <input type="password" value={keyPassphrase} onChange={(e) => setKeyPassphrase(e.target.value)} placeholder="Optional" />
                </div>
              </>
            ) : (
              <div className="dlg-field">
                <label>Password</label>
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Remote account password" />
              </div>
            )}

            <div className="dlg-field">
              <label>Include Paths (comma/newline separated)</label>
              <textarea rows={2} value={includePaths} onChange={(e) => setIncludePaths(e.target.value)} />
            </div>

            <div className="lsd-checks">
              {SCAN_TYPES.map(({ key, label, hint }) => (
                <label key={key} className="lsd-check">
                  <input type="checkbox" checked={!!types[key]} onChange={() => toggle(key)} />
                  <span className="lsd-check-info">
                    <span className="lsd-check-label">{label}</span>
                    <span className="lsd-check-hint">{hint}</span>
                  </span>
                </label>
              ))}
            </div>
          </>
        ) : (
          <>
            <div className="dlg-field">
              <label>Remote Host</label>
              <input autoFocus value={host} onChange={(e) => setHost(e.target.value)} placeholder="192.168.56.10 or server.example.com" />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 120px", gap: 10 }}>
              <div className="dlg-field">
                <label>Username</label>
                <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="forensic" />
              </div>
              <div className="dlg-field">
                <label>Port</label>
                <input type="number" min="1" max="65535" value={port} onChange={(e) => setPort(e.target.value)} />
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <div className="dlg-field">
                <label>Connect Timeout (s)</label>
                <input type="number" min="2" max="300" value={connectTimeout} onChange={(e) => setConnectTimeout(e.target.value)} />
              </div>
              <div className="dlg-field">
                <label>Auth / Banner Timeout (s)</label>
                <input type="number" min="5" max="600" value={authTimeout} onChange={(e) => setAuthTimeout(e.target.value)} />
              </div>
            </div>

            <div className="dlg-field">
              <label>Authentication</label>
              <div style={{ display: "flex", gap: 10, fontSize: 12 }}>
                <label><input type="radio" checked={authMode === "key"} onChange={() => setAuthMode("key")} /> SSH Key</label>
                <label><input type="radio" checked={authMode === "password"} onChange={() => setAuthMode("password")} /> Password</label>
              </div>
            </div>

            {authMode === "key" ? (
              <>
                <div className="dlg-field">
                  <label>Key Path</label>
                  <input value={keyPath} onChange={(e) => setKeyPath(e.target.value)} placeholder="~/.ssh/id_ed25519" />
                </div>
                <div className="dlg-field">
                  <label>Key Passphrase (optional)</label>
                  <input type="password" value={keyPassphrase} onChange={(e) => setKeyPassphrase(e.target.value)} placeholder="Optional" />
                </div>
              </>
            ) : (
              <div className="dlg-field">
                <label>Password</label>
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Remote account password" />
              </div>
            )}

            <div className="dlg-field">
              <label>Remote Path To Mount</label>
              <input value={mountedPath} onChange={(e) => setMountedPath(e.target.value)} placeholder="/" />
            </div>
            <div className="dlg-note">
              Backend auto-mounts this path with SSHFS, runs analysis, then unmounts automatically.
            </div>
          </>
        )}
      </div>
      {mode === "ssh_snapshot" && step === "connecting" && !err && (
        <div className="dlg-note">Connecting to {host.trim() || "remote host"}...</div>
      )}
      {mode === "mounted_path" && step === "connecting" && !err && (
        <div className="dlg-note">Connecting to {host.trim() || "remote host"} for backend mount...</div>
      )}
      {mode === "mounted_path" && step === "scanning" && connectedInfo && !err && (
        <div className="dlg-note">Connected to {connectedInfo.hostname || host.trim()} ({connectedInfo.os_name || "Linux"}). Mounting {mountedPath.trim() || "/"} and running analysis...</div>
      )}
      {mode === "ssh_snapshot" && step === "scanning" && connectedInfo && !err && (
        <div className="dlg-note">Connected to {connectedInfo.hostname || host.trim()} ({connectedInfo.os_name || "Linux"}). Downloading snapshot and running analysis...</div>
      )}
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button className="btn-primary" onClick={run} disabled={loading || !canRun}>
          <Wifi size={14} />{loading ? (step === "scanning" ? "Scanning..." : "Connecting...") : (mode === "mounted_path" ? "Mount & Scan" : "Connect & Scan")}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

// ─── FILE PICKER DIALOG ──────────────────────────────────────────────────────
function FilePickerDialog({ onClose, onResult, analyzeOnPick = true }) {
  const [cwd, setCwd] = useState("/");
  const [children, setChildren] = useState([]);
  const [crumbs, setCrumbs] = useState([{ label: "/", path: "/" }]);
  const [selected, setSelected] = useState(null);   // { path, is_dir }
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [err, setErr] = useState(null);

  const navigate = useCallback(async (path) => {
    setLoading(true); setErr(null); setSelected(null);
    try {
      const data = await apiFsBrowse(path);
      setCwd(data.path);
      setChildren(data.children);
      setCrumbs(data.breadcrumbs);
    } catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { navigate("/"); }, [navigate]);

  async function confirm() {
    const target = selected ? selected.path : cwd;
    if (!analyzeOnPick) { onResult(null, target); onClose(); return; }
    setAnalyzing(true); setErr(null);
    try {
      onResult(await apiAnalyze(target), target);
      onClose();
    } catch (e) { setErr(String(e)); }
    finally { setAnalyzing(false); }
  }

  const FOLDER_CLR = "#d97706";
  const FILE_CLR = "#4b5563";

  return (
    <Modal title="Open — Select Image or Directory" onClose={onClose} width={700}>
      {/* Breadcrumb */}
      <div className="fp-crumbs">
        {crumbs.map((c, i) => (
          <React.Fragment key={c.path}>
            {i > 0 && <span className="fp-crumb-sep">/</span>}
            <button className="fp-crumb-btn" onClick={() => navigate(c.path)}>{c.label}</button>
          </React.Fragment>
        ))}
      </div>

      {/* File listing */}
      <div className="fp-listing">
        {loading && <div className="fp-loading">Loading…</div>}
        {!loading && children.length === 0 && <div className="fp-empty">Empty directory</div>}
        {!loading && children.map((entry) => {
          const isSel = selected?.path === entry.path;
          return (
            <div
              key={entry.path}
              className={`fp-entry ${isSel ? "selected" : ""}`}
              onClick={() => setSelected(entry)}
              onDoubleClick={() => entry.is_dir ? navigate(entry.path) : null}
            >
              <span className="fp-entry-icon">
                {entry.is_dir
                  ? <FolderSearch size={15} style={{ color: FOLDER_CLR }} />
                  : <File size={15} style={{ color: FILE_CLR }} />}
              </span>
              <span className="fp-entry-name">{entry.name}</span>
              {!entry.is_dir && entry.size != null && (
                <span className="fp-entry-size">{fmtSize(entry.size)}</span>
              )}
              {entry.is_dir && <span className="fp-entry-dir-tag">dir</span>}
            </div>
          );
        })}
      </div>

      {/* Selected path bar */}
      <div className="fp-selected-bar">
        <span className="fp-selected-label">Selected:</span>
        <code className="fp-selected-path">{selected ? selected.path : cwd}</code>
      </div>

      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button className="btn-primary" onClick={confirm} disabled={analyzing}>
          <Search size={14} />{analyzing ? "Analyzing…" : analyzeOnPick ? "Open & Analyze" : "Select"}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

// tiny helper used above
function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function AboutDialog({ onClose }) {
  return (
    <Modal title="About OS Forensics" onClose={onClose} width={420}>
      <div className="about-body">
        <div className="about-icon"><Microscope size={52} strokeWidth={1.4} /></div>
        <h2>OS Forensics</h2>
        <p className="about-ver">build 0.3.0 — Explorative Edition</p>
        <p>Advanced forensic detection and artifact exploration for Linux-based environments. Autopsy-style navigation with full inode metadata, file viewer, and analysis reports.</p>
        <p className="about-stack">Backend: Python · FastAPI · pytsk3<br />Frontend: React · Vite</p>
      </div>
      <div className="dlg-actions"><button className="btn-primary" onClick={onClose}>OK</button></div>
    </Modal>
  );
}

function SettingsDialog({ onClose }) {
  return (
    <Modal title="Preferences" onClose={onClose} width={460}>
      <div className="dlg-field">
        <label>API Server URL</label>
        <input defaultValue="http://127.0.0.1:8000" disabled />
        <div className="dlg-hint">Configurable in a future release.</div>
      </div>
      <div className="dlg-actions">
        <button className="btn-primary" onClick={onClose}>OK</button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

function ShortcutsDialog({ onClose }) {
  const shortcuts = [
    ["Ctrl + O", "Open Analyze dialog"],
    ["Ctrl + B", "Browse & Open file picker"],
    ["Ctrl + Shift + L", "Open Remote Connect dialog"],
    ["Ctrl + ,", "Preferences"],
    ["F1", "Help / About"],
    ["Escape", "Close current dialog"],
  ];
  return (
    <Modal title="Keyboard Shortcuts" onClose={onClose} width={400}>
      <table className="rp-table">
        <thead><tr><th>Key</th><th>Action</th></tr></thead>
        <tbody>{shortcuts.map(([k, v]) => <tr key={k}><td><kbd>{k}</kbd></td><td>{v}</td></tr>)}</tbody>
      </table>
      <div className="dlg-actions"><button className="btn-primary" onClick={onClose}>OK</button></div>
    </Modal>
  );
}

// ─── MENU BAR ─────────────────────────────────────────────────────────────────
function MenuBar({ onAction }) {
  const [open, setOpen] = useState(null);
  const barRef = useRef(null);
  useEffect(() => {
    const close = (e) => { if (!barRef.current?.contains(e.target)) setOpen(null); };
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, []);

  const menus = {
    File: [
      { label: "Analyze Image / Mountpoint…", key: "analyze",  shortcut: "Ctrl+O" },
      { label: "Browse & Open…",               key: "filepick", shortcut: "Ctrl+B" },
      { label: "Remote Connect…",              key: "remote_scan", shortcut: "Ctrl+Shift+L" },
      { type: "sep" },
      { label: "Export Report JSON…", key: "export" },
      { type: "sep" },
      { label: "Clear Analysis", key: "clear" },
    ],
    Cases: [
      { label: "New Case…", key: "new_case" },
      { label: "Open Cases View", key: "view_cases" },
    ],
    View: [
      { label: "Show Explorer", key: "view_explorer" },
      { label: "Show Report", key: "view_report" },
      { type: "sep" },
      { label: "Toggle Toolbar", key: "toolbar" },
      { label: "Toggle Status Bar", key: "statusbar" },
    ],
    Tools: [
      { label: "Analyze Image / Mountpoint…", key: "analyze" },
      { label: "Browse & Open…",               key: "filepick" },
      { label: "Remote Connect…",              key: "remote_scan" },
      { type: "sep" },
      { label: "Keyboard Shortcuts…", key: "shortcuts" },
    ],
    Help: [
      { label: "Keyboard Shortcuts…", key: "shortcuts", shortcut: "F1" },
      { type: "sep" },
      { label: "About OS Forensics…", key: "about" },
    ],
  };

  function pick(key) { setOpen(null); onAction(key); }
  return (
    <nav className="menubar" ref={barRef} role="menubar">
      {Object.entries(menus).map(([name, items]) => (
        <div key={name} className={`mb-item ${open === name ? "open" : ""}`}>
          <button className="mb-label" onClick={() => setOpen(open === name ? null : name)}
            onMouseEnter={() => open && setOpen(name)}>
            {name}
          </button>
          {open === name && (
            <ul className="mb-dropdown">
              {items.map((item, i) =>
                item.type === "sep" ? <li key={i} className="mb-sep" /> : (
                  <li key={i} className="mb-option" onClick={() => pick(item.key)}>
                    <span>{item.label}</span>
                    {item.shortcut && <span className="mb-shortcut">{item.shortcut}</span>}
                  </li>
                )
              )}
            </ul>
          )}
        </div>
      ))}
    </nav>
  );
}

// ─── TOOLBAR ──────────────────────────────────────────────────────────────────
function Toolbar({ visible, onAction }) {
  if (!visible) return null;
  const btns = [
    { Icon: Search, label: "Analyze", key: "analyze", title: "Analyze path (Ctrl+O)" },
    { Icon: FolderSearch, label: "Browse", key: "filepick", title: "Browse & Open (Ctrl+B)" },
    { type: "sep" },
    { Icon: LayoutPanelLeft, label: "Explorer", key: "view_explorer", title: "Explorer view" },
    { Icon: BarChart2, label: "Report", key: "view_report", title: "Report view" },
    { type: "sep" },
    { Icon: Trash2, label: "Clear", key: "clear", title: "Clear analysis" },
    { type: "sep" },
    { Icon: Settings, label: "Prefs", key: "settings", title: "Preferences" },
  ];
  return (
    <div className="toolbar">
      {btns.map((b, i) =>
        b.type === "sep" ? <div key={i} className="tb-sep" /> : (
          <button key={i} className="tb-btn" title={b.title} onClick={() => onAction(b.key)}>
            <span className="tb-icon"><b.Icon size={18} strokeWidth={1.6} /></span>
            <span className="tb-label">{b.label}</span>
          </button>
        )
      )}
    </div>
  );
}

// ─── STATUS BAR ───────────────────────────────────────────────────────────────
function StatusBar({ visible, status, report }) {
  if (!visible) return null;
  const totalHigh = report?.summary?.total_high ?? 0;
  return (
    <div className="statusbar">
      <Activity size={11} className="sb-icon" />
      <span className="sb-status">{status}</span>
      {report && (
        <>
          <span className="sb-sep" />
          <HardDrive size={11} className="sb-icon" />
          <span>OS: <strong>{report.os_info?.name || "Unknown"}</strong></span>
          <span className="sb-sep" />
          <span>Tools: <strong>{report.summary?.total_tools ?? 0}</strong></span>
          <span className="sb-sep" />
          <span>Timeline: <strong>{report.summary?.timeline_events ?? 0}</strong></span>
          <span className="sb-sep" />
          <span className={totalHigh > 0 ? "sb-high" : "sb-ok"}>
            {totalHigh > 0 ? <AlertTriangle size={11} className="sb-icon" /> : <CheckCircle size={11} className="sb-icon" />}
            High: {totalHigh}
          </span>
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPLORER SECTION
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Artifact Tree Node (left sidebar) ────────────────────────────────────────
function TreeNode({ node, depth = 0, onSelect, selectedId, expandedIds, onToggle }) {
  const hasChildren = node.children?.length > 0;
  const isExpanded = expandedIds.has(node.id);
  const isSelected = selectedId === node.id;
  const indent = depth * 14;

  return (
    <div>
      <div
        className={`tree-node ${isSelected ? "selected" : ""}`}
        style={{ paddingLeft: 8 + indent }}
        onClick={() => { onSelect(node); if (hasChildren) onToggle(node.id); }}
      >
        <span className="tree-expand-icon">
          {hasChildren
            ? (isExpanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />)
            : <span style={{ display: "inline-block", width: 11 }} />}
        </span>
        <span className="tree-node-icon">
          <NodeIcon
            name={isExpanded && hasChildren ? "FolderOpen" : node.icon}
            size={13}
            style={{ color: isSelected ? "#fff" : undefined }}
          />
        </span>
        <span className="tree-node-label">{node.label}</span>
      </div>
      {hasChildren && isExpanded && node.children.map((child) => (
        <TreeNode key={child.id} node={child} depth={depth + 1}
          onSelect={onSelect} selectedId={selectedId}
          expandedIds={expandedIds} onToggle={onToggle} />
      ))}
    </div>
  );
}

// ─── File List (middle pane) ──────────────────────────────────────────────────
function FileTypeIcon({ type, name }) {
  if (type === "directory") return <Folder size={13} style={{ color: "#f59e0b" }} />;
  const ext = name?.split(".").pop()?.toLowerCase();
  if (["log", "txt", "conf", "cfg", "ini", "md"].includes(ext)) return <FileText size={13} style={{ color: "#6366f1" }} />;
  if (["sh", "bash", "py", "rb", "pl"].includes(ext)) return <Code size={13} style={{ color: "#10b981" }} />;
  if (["service", "socket", "timer"].includes(ext)) return <Server size={13} style={{ color: "#8b5cf6" }} />;
  return <File size={13} style={{ color: "#9ca3af" }} />;
}

function FileList({ entries, onOpen, selectedPath, loading, path }) {
  if (loading) return <div className="pane-loading"><RefreshCw size={16} className="spin" />Loading…</div>;
  if (!entries) return <div className="pane-empty"><Folder size={32} /><p>Select an item in the tree to browse.</p></div>;
  if (entries.length === 0) return <div className="pane-empty"><Folder size={32} /><p>Directory is empty.</p></div>;

  return (
    <div className="file-list-wrap">
      <div className="file-list-header">
        <span className="fl-col-name">Name</span>
        <span className="fl-col-size">Size</span>
        <span className="fl-col-mtime">Modified</span>
        <span className="fl-col-mode">Permissions</span>
        <span className="fl-col-uid">UID</span>
      </div>
      <div className="file-list-body">
        {entries.map((e) => (
          <div
            key={e.path}
            className={`fl-row ${selectedPath === e.path ? "selected" : ""} ${e.type === "directory" ? "fl-dir" : ""}`}
            onClick={() => onOpen(e)}
            onDoubleClick={() => e.type === "directory" && onOpen(e, true)}
          >
            <span className="fl-col-name">
              <FileTypeIcon type={e.type} name={e.name} />
              <span className="fl-name-text">{e.name}</span>
              {e.symlink_target && <span className="fl-symlink"> → {e.symlink_target}</span>}
            </span>
            <span className="fl-col-size">{e.type === "directory" ? "—" : (e.size_human || "?")}</span>
            <span className="fl-col-mtime">{e.mtime || "—"}</span>
            <span className="fl-col-mode"><code className="mono-small">{e.mode || "—"}</code></span>
            <span className="fl-col-uid">{e.uid ?? "—"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Metadata / Content Viewer (right pane) ──────────────────────────────────
function MetaRow({ label, value, mono }) {
  if (value === undefined || value === null) return null;
  return (
    <tr>
      <td className="meta-key">{label}</td>
      <td className="meta-val">{mono ? <code className="mono-small">{String(value)}</code> : String(value)}</td>
    </tr>
  );
}

function ContentPane({ item, imgPath }) {
  const [tab, setTab] = useState("meta");
  const [content, setContent] = useState(null);
  const [loadingContent, setLoadingContent] = useState(false);
  const [contentErr, setContentErr] = useState(null);

  // Reset when item changes
  useEffect(() => {
    setTab("meta");
    setContent(null);
    setContentErr(null);
  }, [item?.path]);

  async function loadContent() {
    if (!item || !imgPath) return;
    setLoadingContent(true); setContentErr(null);
    try { setContent(await apiRead(imgPath, item.path)); }
    catch (e) { setContentErr(String(e)); }
    finally { setLoadingContent(false); }
  }

  useEffect(() => {
    if (tab === "content" && !content && item && !item.is_dir && imgPath) {
      loadContent();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, item?.path]);

  if (!item) {
    return (
      <div className="content-pane-empty">
        <Info size={32} style={{ opacity: .3 }} />
        <p>Select a file to view metadata and content.</p>
      </div>
    );
  }

  const suid_flags = [];
  if (item.is_suid) suid_flags.push("SUID");
  if (item.is_sgid) suid_flags.push("SGID");
  if (item.is_sticky) suid_flags.push("Sticky");

  return (
    <div className="content-pane">
      <div className="content-pane-header">
        <FileTypeIcon type={item.type} name={item.name} />
        <span className="content-pane-name" title={item.path}>{item.name || item.path}</span>
        <span className="content-pane-path" title={item.path}>{item.path}</span>
        {suid_flags.length > 0 && suid_flags.map(f => (
          <span key={f} className="sev-badge" style={{ background: "#dc2626", fontSize: 9 }}>{f}</span>
        ))}
      </div>
      <div className="content-pane-tabs">
        <button className={`cp-tab ${tab === "meta" ? "active" : ""}`} onClick={() => setTab("meta")}>
          <Info size={11} /> Metadata
        </button>
        {!item.is_dir && (
          <button className={`cp-tab ${tab === "content" ? "active" : ""}`} onClick={() => setTab("content")}>
            <FileText size={11} /> Content
          </button>
        )}
      </div>
      <div className="content-pane-body">
        {tab === "meta" && (
          <table className="meta-table">
            <tbody>
              <MetaRow label="Path" value={item.path} mono />
              <MetaRow label="Type" value={item.type} />
              <MetaRow label="Size" value={item.size_human ? `${item.size_human} (${item.size?.toLocaleString()} bytes)` : item.size} />
              <MetaRow label="Permissions" value={item.mode} mono />
              <MetaRow label="Mode (octal)" value={item.mode_octal} mono />
              <MetaRow label="Owner (UID)" value={item.uid} />
              <MetaRow label="Group (GID)" value={item.gid} />
              <MetaRow label="Inode" value={item.inode} />
              <MetaRow label="Hard Links" value={item.nlinks} />
              <MetaRow label="Modified" value={item.mtime} />
              <MetaRow label="Accessed" value={item.atime} />
              <MetaRow label="Changed" value={item.ctime} />
              {item.symlink_target && <MetaRow label="Symlink →" value={item.symlink_target} mono />}
              {suid_flags.length > 0 && <MetaRow label="Special Bits" value={suid_flags.join(", ")} />}
            </tbody>
          </table>
        )}
        {tab === "content" && (
          <div className="file-content-wrap">
            {loadingContent && <div className="pane-loading"><RefreshCw size={14} className="spin" />Reading file…</div>}
            {contentErr && <div className="dlg-error">{contentErr}</div>}
            {content && !loadingContent && (
              <>
                {content.truncated && (
                  <div className="content-truncated-warn">
                    <AlertTriangle size={12} /> Showing first {content.size_human || ""} — file truncated at 200 KB
                  </div>
                )}
                {content.error && <div className="dlg-error">{content.error}</div>}
                {content.content != null && (
                  <pre className={`file-content-pre ${content.encoding === "hex" ? "hex-view" : ""}`}>
                    {content.content}
                  </pre>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Pane Divider (drag-to-resize) ─────────────────────────────────────────────
function PaneDivider({ onDrag }) {
  const dragging = useRef(false);
  const lastX = useRef(0);

  const onMouseDown = useCallback((e) => {
    e.preventDefault();
    dragging.current = true;
    lastX.current = e.clientX;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    function onMove(e) {
      if (!dragging.current) return;
      const dx = e.clientX - lastX.current;
      lastX.current = e.clientX;
      onDrag(dx);
    }
    function onUp() {
      dragging.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    }
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }, [onDrag]);

  return <div className="pane-divider" onMouseDown={onMouseDown} />;
}


// ─── Plain File-System Directory Tree ───────────────────────────────────────
// Lazily loads subdirectories on expand. Works with apiBrowse.
function FsDirTreeNode({ imgPath, path, name, depth, selectedPath, onSelect }) {
  const [expanded, setExpanded] = useState(depth === 0);
  const [children, setChildren] = useState(null);  // null = not yet loaded
  const [loading, setLoading] = useState(false);

  async function toggle(e) {
    e.stopPropagation();
    if (!expanded && children === null) {
      setLoading(true);
      try {
        const dir = await apiBrowse(imgPath, path);
        setChildren(dir.children.filter(c => c.is_dir));
      } catch (_) {
        setChildren([]);
      } finally {
        setLoading(false);
      }
    }
    setExpanded(v => !v);
  }

  const isSelected = selectedPath === path;

  return (
    <div className="fs-tree-node-wrap">
      <div
        className={`fs-tree-node ${isSelected ? "selected" : ""}`}
        style={{ paddingLeft: 6 + depth * 14 }}
        onClick={() => onSelect({ path, name, is_dir: true })}
      >
        <span className="fs-tree-expand" onClick={toggle}>
          {loading
            ? <RefreshCw size={10} className="spin" />
            : (expanded
              ? <ChevronDown size={10} />
              : <ChevronRight size={10} />)}
        </span>
        <Folder size={11} style={{ color: "#eab308", flexShrink: 0 }} />
        <span className="fs-tree-label" title={path}>{name}</span>
      </div>
      {expanded && children != null && children.map(child => (
        <FsDirTreeNode
          key={child.path}
          imgPath={imgPath}
          path={child.path}
          name={child.name}
          depth={depth + 1}
          selectedPath={selectedPath}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}

// Root mounts to show at the top of the plain explorer tree
const FS_ROOTS = ["/", "/etc", "/var", "/home", "/root", "/tmp", "/opt", "/usr"];

function FsDirTree({ imgPath, selectedPath, onSelect }) {
  return (
    <div className="fs-dir-tree">
      {FS_ROOTS.map(r => (
        <FsDirTreeNode
          key={r}
          imgPath={imgPath}
          path={r}
          name={r === "/" ? "/ (root)" : r}
          depth={0}
          selectedPath={selectedPath}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}

// ─── Full Explorer (3-pane) ───────────────────────────────────────────────────
function Explorer({ imgPath }) {
  // "artifact" = category-based tree  |  "files" = plain directory browser
  const [explorerMode, setExplorerMode] = useState("artifact");

  // ── Artifact mode state ──
  const [tree, setTree] = useState(null);
  const [treeErr, setTreeErr] = useState(null);
  const [expandedIds, setExpanded] = useState(new Set(["os", "logs", "shell_history"]));
  const [selectedNode, setSelNode] = useState(null);

  // ── Shared state (both modes use these) ──
  const [browseEntries, setBrowse] = useState(null);
  const [browseLoading, setBrowseL] = useState(false);
  const [browsePath, setBrowsePath] = useState(null);
  const [selectedFile, setSelFile] = useState(null);
  const [navStack, setNavStack] = useState([]);
  const [treeWidth, setTreeWidth] = useState(230);
  const [metaWidth, setMetaWidth] = useState(300);

  // ── Files mode state ──
  const [fsTreeSel, setFsTreeSel] = useState(null);  // currently selected dir in fs tree

  // Load artifact tree once
  useEffect(() => {
    apiTree()
      .then(d => setTree(d.tree))
      .catch(e => setTreeErr(String(e)));
  }, []);

  function toggleExpand(id) {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  async function selectNode(node) {
    setSelNode(node);
    setSelFile(null);
    if (!node.path) return;
    setBrowseL(true); setBrowse(null); setBrowsePath(node.path);
    setNavStack([node.path]);
    try {
      const meta = await apiStat(imgPath, node.path);
      if (meta.is_dir) {
        const dir = await apiBrowse(imgPath, node.path);
        setBrowse(dir.children);
        setSelFile(meta);
      } else {
        setBrowse([{ name: node.path.split("/").pop(), path: node.path, type: meta.type, ...meta }]);
        setSelFile(meta);
      }
    } catch (e) {
      setBrowse([]);
    } finally {
      setBrowseL(false);
    }
  }

  async function selectFsDir(entry) {
    setFsTreeSel(entry.path);
    setSelFile(null);
    setBrowseL(true); setBrowse(null); setBrowsePath(entry.path);
    setNavStack([entry.path]);
    try {
      const dir = await apiBrowse(imgPath, entry.path);
      setBrowse(dir.children);
    } catch (_) {
      setBrowse([]);
    } finally {
      setBrowseL(false);
    }
  }

  async function openEntry(entry, navigate = false) {
    setSelFile(null);
    let meta;
    try { meta = await apiStat(imgPath, entry.path); }
    catch (_) { meta = entry; }
    setSelFile({ ...entry, ...meta });
    if (meta.is_dir && navigate) {
      setBrowseL(true);
      setBrowsePath(entry.path);
      setNavStack(prev => [...prev, entry.path]);
      try {
        const dir = await apiBrowse(imgPath, entry.path);
        setBrowse(dir.children);
      } catch (_) { setBrowse([]); }
      finally { setBrowseL(false); }
    }
  }

  async function navUp() {
    if (navStack.length <= 1) return;
    const newStack = navStack.slice(0, -1);
    const parentPath = newStack[newStack.length - 1];
    setNavStack(newStack);
    setBrowsePath(parentPath);
    setBrowseL(true);
    try {
      const dir = await apiBrowse(imgPath, parentPath);
      setBrowse(dir.children);
    } catch (_) { setBrowse([]); }
    finally { setBrowseL(false); }
  }

  // When switching modes, clear shared browse state
  function switchMode(mode) {
    setExplorerMode(mode);
    setBrowse(null);
    setBrowsePath(null);
    setNavStack([]);
    setSelFile(null);
    setSelNode(null);
    setFsTreeSel(null);
  }

  const clampTree = (w) => Math.max(140, Math.min(520, w));
  const clampMeta = (w) => Math.max(180, Math.min(620, w));

  return (
    <div className="explorer-shell">
      {/* Left: tree pane */}
      <div className="explorer-tree-pane" style={{ width: treeWidth }}>
        <div className="explorer-pane-header" style={{ gap: 4 }}>
          {explorerMode === "artifact"
            ? <><FolderOpenIcon size={12} /> Artifact Tree</>
            : <><Folder size={12} /> File System</>}
          <div className="explorer-mode-toggle">
            <button
              className={`mode-toggle-btn ${explorerMode === "artifact" ? "active" : ""}`}
              onClick={() => switchMode("artifact")}
              title="Category artifact view"
            >
              <LayoutPanelLeft size={11} />
            </button>
            <button
              className={`mode-toggle-btn ${explorerMode === "files" ? "active" : ""}`}
              onClick={() => switchMode("files")}
              title="Plain filesystem browser"
            >
              <Folder size={11} />
            </button>
          </div>
        </div>
        <div className="explorer-tree-scroll">
          {explorerMode === "artifact" ? (
            <>
              {treeErr && <div className="dlg-error" style={{ margin: 8, fontSize: 11 }}>{treeErr}</div>}
              {!tree && !treeErr && <div className="pane-loading"><RefreshCw size={12} className="spin" />Loading…</div>}
              {tree?.map(node => (
                <TreeNode key={node.id} node={node}
                  onSelect={selectNode} selectedId={selectedNode?.id}
                  expandedIds={expandedIds} onToggle={toggleExpand} />
              ))}
            </>
          ) : (
            <FsDirTree
              imgPath={imgPath}
              selectedPath={fsTreeSel}
              onSelect={selectFsDir}
            />
          )}
        </div>
      </div>

      <PaneDivider onDrag={(dx) => setTreeWidth(w => clampTree(w + dx))} />

      {/* Middle: file list */}
      <div className="explorer-files-pane">
        <div className="explorer-pane-header">
          <Folder size={12} />
          <span className="explorer-path-label" title={browsePath}>{browsePath || "—"}</span>
          {navStack.length > 1 && (
            <button className="nav-up-btn" onClick={navUp} title="Up one level">
              <ChevronUp size={11} /> Up
            </button>
          )}
        </div>
        <FileList
          entries={browseEntries}
          loading={browseLoading}
          path={browsePath}
          selectedPath={selectedFile?.path}
          onOpen={openEntry}
        />
      </div>

      <PaneDivider onDrag={(dx) => setMetaWidth(w => clampMeta(w - dx))} />

      {/* Right: metadata + content */}
      <div className="explorer-meta-pane" style={{ width: metaWidth }}>
        <div className="explorer-pane-header">
          <Info size={12} /> Properties
        </div>
        <ContentPane item={selectedFile} imgPath={imgPath} />
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT / ANALYSIS TABS
// ═══════════════════════════════════════════════════════════════════════════════

const SRC_ICON = { bash_history: Terminal, "auth.log": Lock, secure: Lock, syslog: Server, messages: Server, inode: Hash };
const PERSIST_ICONS = { crontab: Clock, systemd_service: Server, shell_startup: Terminal, ssh_authorized_keys: Key };
const PERSIST_LABELS = { crontab: "Suspicious Crontab Entries", systemd_service: "Unknown Systemd Services", shell_startup: "Shell Startup Modifications", ssh_authorized_keys: "SSH Authorized Keys" };
const DEL_TYPE_META = {
  deleted_inode: { label: "Deleted Inodes (TSK)", Icon: Trash2, color: "#dc2626", desc: "Files whose directory entry survives in the inode table but are flagged as unallocated." },
  trash: { label: "Trash / Recycle Bin", Icon: FolderOpenIcon, color: "#d97706", desc: "Files moved to the freedesktop Trash. Immediately recoverable." },
  open_deleted: { label: "Deleted-but-Open", Icon: Eye, color: "#7c3aed", desc: "Files unlinked from disk but still held open by a running process." },
  anti_forensics: { label: "Anti-Forensics Indicators", Icon: AlertTriangle, color: "#b45309", desc: "Evidence of intentional evidence destruction (rm, shred, wipe, etc.)." },
  scan_error: { label: "Scan Errors", Icon: Info, color: "#6b7280", desc: "" },
};

function EmptyState({ icon: Icon, message }) {
  return <div className="empty-state"><Icon size={36} strokeWidth={1.2} className="empty-icon" /><p>{message}</p></div>;
}

function SnippetBlock({ snippet }) {
  const [open, setOpen] = useState(false);
  if (!snippet) return null;
  return (
    <div className="snippet-wrap">
      <button className="snippet-toggle" onClick={() => setOpen(v => !v)}>
        {open ? <ChevronUp size={11} /> : <ChevronDown size={11} />} {open ? "Hide" : "Show"} snippet
      </button>
      {open && <pre className="snippet-code">{snippet}</pre>}
    </div>
  );
}

// ── Live System Info Banner ───────────────────────────────────────────────────
function LiveInfoBanner({ info }) {
  if (!info) return null;
  const memUsedGB = info.memory?.total_kb
    ? ((info.memory.total_kb - info.memory.available_kb) / 1024 / 1024).toFixed(1)
    : null;
  const memTotalGB = info.memory?.total_kb
    ? (info.memory.total_kb / 1024 / 1024).toFixed(1)
    : null;
  return (
    <div className="live-banner">
      <div className="live-banner-badge">
        {info.scheme === "remote_ssh" ? <Wifi size={12} /> : <Cpu size={12} />} {info.scheme === "remote_ssh" ? "REMOTE LIVE" : "LIVE SYSTEM"}
      </div>
      <div className="live-banner-cells">
        <div className="live-cell">
          <span className="live-cell-label">Hostname</span>
          <span className="live-cell-val">{info.hostname || "—"}</span>
        </div>
        <div className="live-cell">
          <span className="live-cell-label">OS</span>
          <span className="live-cell-val">{info.os_name || "—"}</span>
        </div>
        <div className="live-cell">
          <span className="live-cell-label">Kernel</span>
          <span className="live-cell-val live-mono">{info.kernel || "—"}</span>
        </div>
        <div className="live-cell">
          <span className="live-cell-label">Uptime</span>
          <span className="live-cell-val">{info.uptime_str || "—"}</span>
        </div>
        <div className="live-cell">
          <span className="live-cell-label">Load</span>
          <span className="live-cell-val live-mono">{info.load_avg?.join(" ") || "—"}</span>
        </div>
        {memTotalGB && (
          <div className="live-cell">
            <span className="live-cell-label">Memory</span>
            <span className="live-cell-val">{memUsedGB} / {memTotalGB} GB ({info.memory.used_pct}%)</span>
          </div>
        )}
        <div className="live-cell">
          <span className="live-cell-label">Processes</span>
          <span className="live-cell-val">{info.process_count ?? "—"}</span>
        </div>
        {info.users?.length > 0 && (
          <div className="live-cell">
            <span className="live-cell-label">Users</span>
            <span className="live-cell-val">{info.users.join(", ")}</span>
          </div>
        )}
        {info.interfaces?.length > 0 && (
          <div className="live-cell">
            <span className="live-cell-label">Interfaces</span>
            <span className="live-cell-val live-mono">{info.interfaces.join(", ")}</span>
          </div>
        )}
      </div>
    </div>
  );
}

function SummaryTab({ report, liveInfo }) {
  const { os_info, summary } = report;
  const totalHigh = summary?.total_high ?? 0;
  const threatLevel =
    totalHigh >= 10 ? { label: "CRITICAL", cls: "tl-critical" }
      : totalHigh >= 5 ? { label: "HIGH", cls: "tl-high" }
        : totalHigh >= 1 ? { label: "MEDIUM", cls: "tl-medium" }
          : { label: "CLEAN", cls: "tl-low" };
  const stats = [
    { label: "Tool Findings", value: summary?.total_tools ?? 0, danger: false },
    { label: "High-Risk Tools", value: summary?.high_risk_tools ?? 0, danger: true },
    { label: "Timeline Events", value: summary?.timeline_events ?? 0, danger: false },
    { label: "High Timeline", value: summary?.high_timeline ?? 0, danger: true },
    { label: "Deleted / Missing", value: summary?.deleted_findings ?? 0, danger: false },
    { label: "High Deleted", value: summary?.high_deleted ?? 0, danger: true },
    { label: "Persistence Hits", value: summary?.persistence_findings ?? 0, danger: false },
    { label: "High Persistence", value: summary?.high_persistence ?? 0, danger: true },
  ];
  return (
    <div className="tab-content">
      {liveInfo && <LiveInfoBanner info={liveInfo} />}
      <div className="sum-top">
        <div className="sum-os-card">
          <div className="sum-os-label">Operating System</div>
          <div className="sum-os-name">{os_info?.name || "Unknown"}</div>
          <div className="sum-os-meta">
            {os_info?.id && <span className="tag">{os_info.id}</span>}
            {os_info?.variant_tags?.map(t => <span key={t} className="tag tag-warn">{t}</span>)}
          </div>
          {os_info?.notes?.length > 0 && <ul className="sum-os-notes">{os_info.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>}
        </div>
        <div className={`sum-threat-card ${threatLevel.cls}`}>
          <div className="sum-threat-label">Threat Level</div>
          <div className="sum-threat-value">{threatLevel.label}</div>
          <div className="sum-threat-sub">{totalHigh} high-severity indicator{totalHigh !== 1 ? "s" : ""}</div>
        </div>
      </div>
      <div className="sum-stats-grid">
        {stats.map(({ label, value, danger }) => (
          <div key={label} className={`stat-card ${danger && value > 0 ? "stat-card-danger" : ""}`}>
            <div className="stat-value" style={{ color: danger && value > 0 ? SEV_COLOR.high : undefined }}>{value}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Timeline event-type metadata ─────────────────────────────────────────────
const ET_META = {
  attack_chain: { label: "Attack Chains", Icon: AlertTriangle },
  suspicious_command: { label: "Suspicious Cmds", Icon: Terminal },
  anti_forensics: { label: "Anti-Forensics", Icon: Shield },
  activity_profile: { label: "Activity Profile", Icon: BarChart2 },
  session_summary: { label: "Sessions", Icon: Clock },
  frequency_analysis: { label: "Frequency", Icon: Activity },
  timestamp_reconstruction: { label: "Timestamps", Icon: Info },
  file_modified: { label: "File Changes", Icon: FileText },
  log_event: { label: "Log Events", Icon: Server },
};

// ── Per-type card renderers ───────────────────────────────────────────────────
function AttackChainCard({ ev }) {
  const [expanded, setExpanded] = useState(false);
  const d = ev.data || {};
  const steps = d.steps || [];
  const lineNos = d.step_line_nos || [];
  const c = SEV_COLOR[ev.severity] || "#7f1d1d";
  const bg = SEV_BG[ev.severity] || "#fef2f2";
  return (
    <div className="tl-card" style={{ borderLeft: `4px solid ${c}`, background: bg }}>
      <div className="tl-card-header">
        <AlertTriangle size={14} style={{ color: c, flexShrink: 0 }} />
        <span className="tl-card-title" style={{ color: c }}>Attack Chain Detected</span>
        <span className="tl-card-user">{d.user || ""}</span>
        <SevBadge sev={ev.severity} />
        <span className="tl-ts-inline">{ev.timestamp !== "unknown" ? ev.timestamp : ""}</span>
        {steps.length > 0 && (
          <button className="tl-expand-btn" onClick={() => setExpanded(v => !v)}>
            {expanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
            {expanded ? "Collapse" : "Expand steps"}
          </button>
        )}
      </div>
      <div className="tl-chain-name">{d.chain || ev.detail}</div>
      {/* Collapsed: inline step pills */}
      {!expanded && steps.length > 0 && (
        <div className="tl-chain-steps">
          {steps.map((s, i) => (
            <React.Fragment key={i}>
              {i > 0 && <span className="tl-chain-arrow">→</span>}
              <code className="tl-chain-step">{s}</code>
            </React.Fragment>
          ))}
        </div>
      )}
      {/* Expanded: table with line numbers */}
      {expanded && steps.length > 0 && (
        <table className="tl-chain-table">
          <thead><tr><th>Step</th><th>Line #</th><th>Command</th></tr></thead>
          <tbody>
            {steps.map((s, i) => (
              <tr key={i}>
                <td className="tl-chain-step-no">Step {i + 1}</td>
                <td className="tl-chain-line-no">{lineNos[i] != null ? `L${lineNos[i]}` : "—"}</td>
                <td><code className="tl-chain-expanded-cmd">{s}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function ActivityProfileCard({ ev }) {
  const d = ev.data || {};
  const cats = d.categories || [];
  const HIGH_RISK_COLOR = "#dc2626";
  const maxCount = cats.reduce((m, c) => Math.max(m, c.count), 0);
  return (
    <div className="tl-card tl-card-profile">
      <div className="tl-card-header">
        <BarChart2 size={14} style={{ color: "#7c3aed", flexShrink: 0 }} />
        <span className="tl-card-title" style={{ color: "#7c3aed" }}>Activity Profile</span>
        <span className="tl-card-user">{d.user || ""}</span>
        <SevBadge sev={ev.severity} />
      </div>
      <div className="tl-profile-meta">{d.total || 0} commands &bull; {cats.length} categories &bull; Dominant: <strong style={{ color: d.high_risk_present ? HIGH_RISK_COLOR : undefined }}>{d.dominant}</strong></div>
      <table className="tl-profile-table">
        <thead>
          <tr><th>Category</th><th>Count</th><th>%</th><th style={{ width: 100 }}>Bar</th></tr>
        </thead>
        <tbody>
          {cats.map((cat) => (
            <tr key={cat.name} style={{ background: cat.high_risk ? "#fff1f0" : undefined }}>
              <td style={{ fontWeight: cat.high_risk ? 600 : undefined, color: cat.high_risk ? HIGH_RISK_COLOR : undefined }}>
                {cat.high_risk && <AlertTriangle size={10} style={{ marginRight: 4, verticalAlign: "middle" }} />}
                {cat.name}
              </td>
              <td style={{ textAlign: "right" }}>{cat.count}</td>
              <td style={{ textAlign: "right", color: "#6b7280" }}>{cat.pct}%</td>
              <td>
                <div style={{ background: "#e5e7eb", borderRadius: 3, height: 6, overflow: "hidden" }}>
                  <div style={{ width: `${Math.round(100 * cat.count / maxCount)}%`, height: "100%", background: cat.high_risk ? HIGH_RISK_COLOR : "#6366f1" }} />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SuspiciousCommandCard({ ev }) {
  const d = ev.data || {};
  const c = SEV_COLOR[ev.severity] || "#d97706";
  const bg = SEV_BG[ev.severity] || "#fffbeb";
  return (
    <div className="tl-card" style={{ borderLeft: `3px solid ${c}`, background: bg }}>
      <div className="tl-card-header">
        <Terminal size={13} style={{ color: c, flexShrink: 0 }} />
        {d.line_no != null && <span className="tl-lineno-badge">L{d.line_no}</span>}
        <span className="tl-card-user">{d.user || ""}</span>
        {d.category && d.category !== "General" && (
          <span className="tl-cat-badge" style={{ background: c }}>{d.category}</span>
        )}
        <span className="tl-card-label">{d.label || "Suspicious command"}</span>
        <SevBadge sev={ev.severity} />
        <span className="tl-ts-inline">{ev.timestamp !== "unknown" ? ev.timestamp : ""}</span>
      </div>
      {d.command && <code className="tl-cmd-code">{d.command}</code>}
    </div>
  );
}

function FrequencyCard({ ev }) {
  const d = ev.data || {};
  const c = SEV_COLOR[ev.severity] || "#d97706";
  return (
    <div className="tl-card" style={{ borderLeft: `3px solid ${c}`, background: SEV_BG[ev.severity] || "#fffbeb" }}>
      <div className="tl-card-header">
        <Activity size={13} style={{ color: c, flexShrink: 0 }} />
        <span className="tl-card-user">{d.user || ""}</span>
        <code className="tl-freq-tool">{d.tool || ""}</code>
        <span className="tl-freq-count" style={{ background: c }}>{d.count}×</span>
        <span className="tl-card-label">repeated invocations — possible scripted use</span>
        <SevBadge sev={ev.severity} />
      </div>
    </div>
  );
}

function AntiForensicsCard({ ev }) {
  return (
    <div className="tl-card" style={{ borderLeft: `4px solid #dc2626`, background: "#fff1f0" }}>
      <div className="tl-card-header">
        <Shield size={14} style={{ color: "#dc2626", flexShrink: 0 }} />
        <span className="tl-card-title" style={{ color: "#dc2626" }}>Anti-Forensics</span>
        <SevBadge sev={ev.severity} />
        <span className="tl-ts-inline">{ev.timestamp !== "unknown" ? ev.timestamp : ""}</span>
      </div>
      <div className="tl-card-label" style={{ color: "#7f1d1d" }}>{ev.detail}</div>
    </div>
  );
}

function GenericEventRow({ ev }) {
  const Icon = SRC_ICON[ev.source] || (ET_META[ev.event_type]?.Icon) || Activity;
  const c = SEV_COLOR[ev.severity] || "#6b7280";
  return (
    <div className="tl-row" style={{ borderLeft: `3px solid ${c}`, background: SEV_BG[ev.severity] || "#fff" }}>
      <div className="tl-ts">{ev.timestamp !== "unknown" ? ev.timestamp : ""}</div>
      <span className="tl-icon-wrap"><Icon size={13} style={{ color: c }} /></span>
      <div className="tl-body">
        <span className="tl-source">[{ev.source}]</span>
        <span className="tl-detail">{ev.detail}</span>
      </div>
      <SevBadge sev={ev.severity} />
    </div>
  );
}

function renderTimelineEvent(ev, i) {
  switch (ev.event_type) {
    case "attack_chain": return <AttackChainCard key={i} ev={ev} />;
    case "activity_profile": return <ActivityProfileCard key={i} ev={ev} />;
    case "suspicious_command": return <SuspiciousCommandCard key={i} ev={ev} />;
    case "frequency_analysis": return <FrequencyCard key={i} ev={ev} />;
    case "anti_forensics": return <AntiForensicsCard key={i} ev={ev} />;
    default: return <GenericEventRow key={i} ev={ev} />;
  }
}

// ── Collapsible section wrapper ────────────────────────────────────────────
function Section({ title, icon: Icon, count, severity, children, defaultOpen = true, empty }) {
  const [open, setOpen] = useState(defaultOpen);
  const c = severity ? SEV_COLOR[severity] || "#6b7280" : "#6b7280";
  return (
    <div className="tl-section">
      <button className="tl-section-hdr" onClick={() => setOpen(v => !v)}>
        {Icon && <Icon size={13} style={{ color: c, flexShrink: 0 }} />}
        <span className="tl-section-title">{title}</span>
        {count != null && <span className="tl-section-count" style={{ background: severity ? c : undefined, color: severity ? "#fff" : undefined }}>{count}</span>}
        <span style={{ marginLeft: "auto" }}>{open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}</span>
      </button>
      {open && (
        <div className="tl-section-body">
          {empty && count === 0 ? <div className="tl-empty-mini">{empty}</div> : children}
        </div>
      )}
    </div>
  );
}

// ── Bash History: Analysis view ─────────────────────────────────────────────
const BH_HIGH_RISK = new Set(["Reverse Shell", "Exploitation", "Credential Access", "Privilege Escalation", "Anti-Forensics", "Exfiltration", "Lateral Movement", "Persistence"]);

function BashAnalysisView({ events, dateRangeMs }) {
  const [section, setSection] = useState("suspicious");
  const [userFilter, setUserFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [navWidth, setNavWidth] = useState(180);
  const clampNav = (w) => Math.max(120, Math.min(320, w));

  const allUsers = [...new Set(events.map(e => e.data?.user).filter(Boolean))];
  const rawEvents = events.filter(e => e.event_type === "bash_history_raw");

  const visible = events.filter(e => {
    if (e.event_type === "bash_history_raw") return false;
    if (userFilter !== "all" && e.data?.user && e.data.user !== userFilter) return false;
    if (section !== "frequency" && search && !e.detail.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const by = (type) => visible.filter(e => e.event_type === type);
  const sev = (evs) => evs.some(e => e.severity === "critical") ? "critical"
    : evs.some(e => e.severity === "high") ? "high" : "medium";

  const chains = by("attack_chain");
  const suspCmds = by("suspicious_command");
  const af = by("anti_forensics");
  const profiles = by("activity_profile");
  const sessions = by("session_summary");
  const other = visible.filter(e =>
    !["attack_chain", "suspicious_command", "anti_forensics", "activity_profile",
      "frequency_analysis", "session_summary", "timestamp_reconstruction"].includes(e.event_type)
  );

  const navItems = [
    { id: "suspicious", label: "Suspicious Cmds", Icon: Terminal, count: suspCmds.length, sev: suspCmds.length ? sev(suspCmds) : null },
    { id: "chains", label: "Attack Chains", Icon: AlertTriangle, count: chains.length, sev: chains.length ? sev(chains) : null },
    { id: "af", label: "Anti-Forensics", Icon: Shield, count: af.length, sev: af.length ? "high" : null },
    { id: "frequency", label: "Frequency", Icon: BarChart2, count: null },
    { id: "profile", label: "Activity Profile", Icon: Activity, count: profiles.length },
    { id: "sessions", label: "Sessions", Icon: Clock, count: sessions.length },
    ...(other.length > 0 ? [{ id: "other", label: "Other Events", Icon: Info, count: other.length }] : []),
  ];

  return (
    <div className="bh-analysis">
      <div className="bh-toolbar">
        {allUsers.length > 1 && (
          <div className="bh-user-pills">
            {["all", ...allUsers].map(u => (
              <button key={u} className={`bh-user-pill ${userFilter === u ? "active" : ""}`}
                onClick={() => setUserFilter(u)}>
                <Users size={10} style={{ marginRight: 3, verticalAlign: "middle" }} />
                {u === "all" ? "All users" : u}
              </button>
            ))}
          </div>
        )}
        {section !== "frequency" && (
          <input className="tl-search" placeholder="Search events…" value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ marginLeft: "auto", maxWidth: 240 }} />
        )}
      </div>

      <div className="bh-sub-layout">
        {/* Left sub-sidebar — resizable */}
        <nav className="bh-sub-nav" style={{ width: navWidth }}>
          {navItems.map(({ id, label, Icon, count, sev: s }) => (
            <button key={id}
              className={`bh-sub-nav-btn ${section === id ? "active" : ""}`}
              onClick={() => { setSection(id); setSearch(""); }}>
              <Icon size={13} style={{ flexShrink: 0, color: s ? SEV_COLOR[s] : undefined }} />
              <span className="bh-sub-nav-label">{label}</span>
              {count != null && count > 0 && (
                <span className="bh-sub-nav-badge"
                  style={{ background: s ? SEV_COLOR[s] : undefined, color: s ? "#fff" : undefined }}>
                  {count}
                </span>
              )}
            </button>
          ))}
        </nav>

        <PaneDivider onDrag={(dx) => setNavWidth(w => clampNav(w + dx))} />

        {/* Right content */}
        <div className="bh-sub-content">
          {section === "suspicious" && (
            suspCmds.length > 0
              ? <SuspiciousCommandsPanel events={suspCmds} />
              : <EmptyState icon={Terminal} message="No suspicious commands detected." />
          )}
          {section === "chains" && (
            chains.length > 0
              ? <div className="tl-list">{chains.map((ev, i) => <AttackChainCard key={i} ev={ev} />)}</div>
              : <EmptyState icon={AlertTriangle} message="No attack chains detected." />
          )}
          {section === "af" && (
            af.length > 0
              ? <div className="tl-list">{af.map((ev, i) => <AntiForensicsCard key={i} ev={ev} />)}</div>
              : <EmptyState icon={Shield} message="No anti-forensics activity detected." />
          )}
          {section === "frequency" && <FrequencyAnalysisPanel rawEvents={rawEvents} dateRangeMs={dateRangeMs} />}
          {section === "profile" && (
            profiles.length > 0
              ? <div className="tl-list">{profiles.map((ev, i) => <ActivityProfileCard key={i} ev={ev} />)}</div>
              : <EmptyState icon={Activity} message="No profile data." />
          )}
          {section === "sessions" && (
            sessions.length > 0
              ? <div className="tl-list">{sessions.map((ev, i) => <GenericEventRow key={i} ev={ev} />)}</div>
              : <EmptyState icon={Clock} message="No sessions found." />
          )}
          {section === "other" && (
            <div className="tl-list">{other.map((ev, i) => <GenericEventRow key={i} ev={ev} />)}</div>
          )}
        </div>
      </div>
    </div>
  );
}


// ── Command category taxonomy for frequency analysis ─────────────────────────
const CMD_TAXONOMY = [
  { name: "File Operations", color: "#2563eb", risk: false, cmds: new Set(["ls", "cp", "mv", "rm", "mkdir", "rmdir", "touch", "find", "chmod", "chown", "chgrp", "ln", "rsync", "scp", "sftp", "install", "rename", "stat", "file"]) },
  { name: "Text Processing", color: "#7c3aed", risk: false, cmds: new Set(["cat", "grep", "awk", "sed", "sort", "uniq", "wc", "head", "tail", "less", "more", "cut", "tr", "diff", "patch", "echo", "printf", "tee", "xargs", "strings"]) },
  { name: "Compression", color: "#0891b2", risk: false, cmds: new Set(["tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "xz", "7z", "zstd", "ar", "cpio", "compress"]) },
  { name: "Network", color: "#059669", risk: false, cmds: new Set(["ping", "traceroute", "tracepath", "curl", "wget", "ssh", "ftp", "nc", "ncat", "dig", "host", "nslookup", "ip", "ifconfig", "netstat", "ss", "arp", "route", "mtr", "whois"]) },
  { name: "Process Mgmt", color: "#6366f1", risk: false, cmds: new Set(["ps", "top", "htop", "kill", "pkill", "killall", "nice", "renice", "jobs", "bg", "fg", "nohup", "watch", "timeout", "strace", "ltrace", "lsof"]) },
  { name: "System Info", color: "#8b5cf6", risk: false, cmds: new Set(["uname", "whoami", "id", "hostname", "uptime", "df", "du", "free", "lscpu", "lsblk", "lshw", "dmesg", "journalctl", "systemctl", "service", "mount", "umount", "env", "printenv"]) },
  { name: "Package Mgmt", color: "#d97706", risk: false, cmds: new Set(["apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pacman", "pip", "pip3", "npm", "gem", "cargo", "go", "snap", "flatpak"]) },
  { name: "Scripting", color: "#f59e0b", risk: false, cmds: new Set(["python", "python3", "perl", "ruby", "bash", "sh", "zsh", "fish", "node", "nodejs", "php", "lua"]) },
  { name: "Reconnaissance", color: "#dc2626", risk: true, cmds: new Set(["nmap", "masscan", "zmap", "nikto", "gobuster", "dirb", "dirbuster", "enum4linux", "smbclient", "rpcclient", "ldapsearch", "dnsenum", "fierce", "recon-ng", "theharvester"]) },
  { name: "Exploitation", color: "#b91c1c", risk: true, cmds: new Set(["msfconsole", "msfvenom", "sqlmap", "hydra", "medusa", "john", "hashcat", "aircrack-ng", "airmon-ng", "airodump-ng", "reaver", "wifite"]) },
  { name: "Privilege Esc.", color: "#ef4444", risk: true, cmds: new Set(["sudo", "su", "passwd", "chpasswd", "visudo", "usermod", "useradd", "newgrp", "pkexec"]) },
  { name: "Anti-Forensics", color: "#7f1d1d", risk: true, cmds: new Set(["shred", "wipe", "srm", "dd", "secure-delete", "bleachbit"]) },
  { name: "Tunneling", color: "#9f1239", risk: true, cmds: new Set(["socat", "chisel", "ngrok", "proxychains", "tor", "torsocks", "stunnel", "iodine", "ptunnel", "dns2tcp"]) },
];

function classifyCmd(cmdStr) {
  const base = (cmdStr || "").trim().split(/\s+/)[0].replace(/^(?:\.\/|\/\S+\/)/, "");
  for (const cat of CMD_TAXONOMY) {
    if (cat.cmds.has(base)) return cat;
  }
  return { name: "General", color: "#6b7280", risk: false };
}

// ── Frequency Analysis Panel ──────────────────────────────────────────────────
function FrequencyAnalysisPanel({ rawEvents, dateRangeMs }) {
  const [viewMode, setViewMode] = useState("command");
  const [topN, setTopN] = useState(20);

  const allLines = rawEvents.flatMap(e =>
    filterBashLinesByDateRange(e.data?.lines || [], dateRangeMs).map(l => ({ ...l, user: e.data?.user }))
  );

  if (!allLines.length)
    return <EmptyState icon={BarChart2} message="No command history available for frequency analysis." />;

  const totalCmds = allLines.length;

  // By-command frequency
  const cmdFreqMap = {};
  for (const line of allLines) {
    const base = (line.cmd || "").trim().split(/\s+/)[0].replace(/^(?:\.\/|\/\S+\/)/, "");
    if (!base) continue;
    if (!cmdFreqMap[base]) {
      const cat = classifyCmd(line.cmd);
      cmdFreqMap[base] = { count: 0, category: cat.name, risk: cat.risk, color: cat.color };
    }
    cmdFreqMap[base].count++;
  }
  const cmdRows = Object.entries(cmdFreqMap).sort((a, b) => b[1].count - a[1].count).slice(0, topN);
  const maxCmd = cmdRows[0]?.[1].count || 1;

  // By-category frequency
  const catFreqMap = {};
  for (const line of allLines) {
    const cat = classifyCmd(line.cmd);
    if (!catFreqMap[cat.name]) catFreqMap[cat.name] = { count: 0, color: cat.color, risk: cat.risk };
    catFreqMap[cat.name].count++;
  }
  const catRows = Object.entries(catFreqMap).sort((a, b) => b[1].count - a[1].count);
  const maxCat = catRows[0]?.[1].count || 1;

  return (
    <div className="freq-panel">
      <div className="freq-toolbar">
        <div className="freq-mode-switch">
          <button className={`freq-mode-btn ${viewMode === "command" ? "active" : ""}`}
            onClick={() => setViewMode("command")}>
            <Terminal size={12} style={{ marginRight: 5 }} />Raw Commands
          </button>
          <button className={`freq-mode-btn ${viewMode === "category" ? "active" : ""}`}
            onClick={() => setViewMode("category")}>
            <BarChart2 size={12} style={{ marginRight: 5 }} />By Category
          </button>
        </div>
        {viewMode === "command" && (
          <div className="freq-topn">
            <span>Top:</span>
            {[10, 20, 50].map(n => (
              <button key={n} className={`freq-topn-btn ${topN === n ? "active" : ""}`}
                onClick={() => setTopN(n)}>{n}</button>
            ))}
          </div>
        )}
        <span className="freq-total-stat">{totalCmds.toLocaleString()} commands total</span>
      </div>

      {viewMode === "command" && (
        <div className="freq-chart">
          <div className="freq-chart-header">
            <span className="fch-cmd">Command</span>
            <span className="fch-cat">Category</span>
            <span className="fch-count">Count</span>
            <span className="fch-pct">%</span>
            <span className="fch-bar">Frequency</span>
          </div>
          {cmdRows.map(([cmd, info]) => {
            const pct = ((info.count / totalCmds) * 100).toFixed(1);
            const barPct = Math.round((info.count / maxCmd) * 100);
            return (
              <div key={cmd} className={`freq-row ${info.risk ? "freq-row-risk" : ""}`}>
                <code className="fch-cmd freq-cmd-code">{cmd}</code>
                <span className="fch-cat freq-cat-tag" style={{ color: info.color }}>
                  {info.risk && <AlertTriangle size={9} style={{ marginRight: 3, verticalAlign: "middle" }} />}
                  {info.category}
                </span>
                <span className="fch-count freq-count-val" style={{ color: info.risk ? "#dc2626" : undefined }}>{info.count}</span>
                <span className="fch-pct freq-pct-val">{pct}%</span>
                <div className="fch-bar freq-bar-wrap">
                  <div className="freq-bar-track">
                    <div className="freq-bar-fill" style={{ width: `${barPct}%`, background: info.risk ? "#dc2626" : info.color }} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {viewMode === "category" && (
        <div className="freq-chart">
          <div className="freq-chart-header">
            <span className="fch-catname">Category</span>
            <span className="fch-risk">Risk</span>
            <span className="fch-count">Count</span>
            <span className="fch-pct">%</span>
            <span className="fch-bar">Frequency</span>
          </div>
          {catRows.map(([cat, info]) => {
            const pct = ((info.count / totalCmds) * 100).toFixed(1);
            const barPct = Math.round((info.count / maxCat) * 100);
            return (
              <div key={cat} className={`freq-row ${info.risk ? "freq-row-risk" : ""}`}>
                <span className="fch-catname freq-cat-name"
                  style={{ color: info.risk ? "#dc2626" : info.color, fontWeight: info.risk ? 700 : 500 }}>
                  {info.risk && <AlertTriangle size={11} style={{ marginRight: 5, verticalAlign: "middle" }} />}
                  {cat}
                </span>
                <span className="fch-risk">
                  <span className="freq-risk-pill"
                    style={{ background: info.risk ? "#fef2f2" : "#f0fdf4", color: info.risk ? "#dc2626" : "#16a34a", border: `1px solid ${info.risk ? "#fecaca" : "#86efac"}` }}>
                    {info.risk ? "High Risk" : "Normal"}
                  </span>
                </span>
                <span className="fch-count freq-count-val" style={{ color: info.risk ? "#dc2626" : undefined }}>{info.count}</span>
                <span className="fch-pct freq-pct-val">{pct}%</span>
                <div className="fch-bar freq-bar-wrap">
                  <div className="freq-bar-track">
                    <div className="freq-bar-fill" style={{ width: `${barPct}%`, background: info.risk ? "#dc2626" : info.color }} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Suspicious commands — category-split layout ───────────────────────────────
const SC_HIGH_RISK = BH_HIGH_RISK;

function SuspiciousCommandsPanel({ events: sevs }) {
  const allCats = [...new Set(sevs.map(ev => ev.data?.category || "General"))].sort();
  const [activeCat, setActiveCat] = useState(allCats[0] || "General");
  const [search, setSearch] = useState("");

  const catCounts = allCats.reduce((acc, cat) => {
    acc[cat] = sevs.filter(ev => (ev.data?.category || "General") === cat).length;
    return acc;
  }, {});

  const catItems = sevs
    .filter(ev => (ev.data?.category || "General") === activeCat)
    .filter(ev => !search ||
      (ev.data?.command || "").toLowerCase().includes(search.toLowerCase()) ||
      (ev.data?.label || "").toLowerCase().includes(search.toLowerCase()));

  const isHR = SC_HIGH_RISK.has(activeCat);

  return (
    <div className="sc-split">
      {/* Left: category nav */}
      <nav className="sc-cat-nav">
        <div className="sc-cat-nav-header">
          <Filter size={11} style={{ marginRight: 5 }} />Categories
        </div>
        {allCats.map(cat => {
          const hr = SC_HIGH_RISK.has(cat);
          const cnt = catCounts[cat];
          return (
            <button key={cat}
              className={`sc-cat-nav-btn ${activeCat === cat ? "active" : ""}`}
              onClick={() => { setActiveCat(cat); setSearch(""); }}>
              {hr && <AlertTriangle size={10} style={{ color: "#dc2626", flexShrink: 0 }} />}
              <span className="sc-cat-nav-label">{cat}</span>
              <span className="sc-cat-nav-count"
                style={{
                  background: hr ? "#fef2f2" : undefined, color: hr ? "#dc2626" : undefined,
                  border: `1px solid ${hr ? "#fecaca" : "#e5e7eb"}`
                }}>
                {cnt}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Right: command list */}
      <div className="sc-cmd-pane">
        <div className="sc-cmd-pane-header">
          {isHR && <AlertTriangle size={13} style={{ color: "#dc2626" }} />}
          <span style={{ color: isHR ? "#dc2626" : undefined, fontWeight: 600 }}>{activeCat}</span>
          <span className="del-count">{catItems.length} / {catCounts[activeCat]}</span>
          <input className="tl-search" placeholder="Filter commands…"
            value={search} onChange={e => setSearch(e.target.value)}
            style={{ marginLeft: "auto", maxWidth: 200 }} />
        </div>
        <div className="sc-cmd-list">
          {catItems.length === 0
            ? <div className="tl-empty-mini">No commands match filter.</div>
            : catItems.map((ev, i) => {
              const d = ev.data || {};
              const c = SEV_COLOR[ev.severity] || "#d97706";
              return (
                <div key={i} className="sc-cmd-item" style={{ borderLeft: `3px solid ${c}` }}>
                  <div className="sc-cmd-item-top">
                    <span className="sc-cmd-meta">
                      {d.user && <span className="sc-meta-chip sc-meta-user"><Users size={9} />{d.user}</span>}
                      {d.line_no != null && <span className="sc-meta-chip sc-meta-line">L{d.line_no}</span>}
                      {ev.timestamp !== "unknown" && <span className="sc-meta-chip sc-meta-ts">{ev.timestamp}</span>}
                    </span>
                    <span className="sc-cmd-label">{d.label || ""}</span>
                    <SevBadge sev={ev.severity} />
                  </div>
                  <code className="sc-cmd-code">{d.command || ""}</code>
                </div>
              );
            })
          }
        </div>
      </div>
    </div>
  );
}

// ── Bash History: Raw view ────────────────────────────────────────────────────
const RH_HIGH_RISK = BH_HIGH_RISK;

function BashRawView({ rawEvents, dateRangeMs }) {
  const [selectedUser, setSelectedUser] = useState("");
  const [catFilter, setCatFilter] = useState("all");
  const [showSuspOnly, setShowSuspOnly] = useState(false);
  const [histSearch, setHistSearch] = useState("");

  if (!rawEvents.length)
    return <div className="tl-empty-mini">No raw history data. The history file may be empty.</div>;

  const activeUser = selectedUser || rawEvents[0]?.data?.user || "";
  const ev = rawEvents.find(e => e.data?.user === activeUser) || rawEvents[0];
  const lines = ev?.data?.lines || [];
  const suspCount = lines.filter(l => l.suspicious).length;
  const linesInRange = filterBashLinesByDateRange(lines, dateRangeMs);
  const orderedLines = [...linesInRange].sort((a, b) => {
    const ta = getBashLineTimestampMs(a);
    const tb = getBashLineTimestampMs(b);
    if (ta != null && tb != null) return tb - ta;
    if (ta != null) return -1;
    if (tb != null) return 1;
    return (b.no || 0) - (a.no || 0);
  });

  const cats = ["all", ...new Set(orderedLines.map(l => l.category))];
  const visible = orderedLines.filter(l => {
    if (showSuspOnly && !l.suspicious) return false;
    if (catFilter !== "all" && l.category !== catFilter) return false;
    if (histSearch && !l.cmd.toLowerCase().includes(histSearch.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      {/* User selector */}
      {rawEvents.length > 1 && (
        <div className="rh-user-tabs">
          {rawEvents.map(e => {
            const u = e.data?.user || "unknown";
            return (
              <button key={u}
                className={`rh-user-tab ${activeUser === u ? "active" : ""}`}
                onClick={() => { setSelectedUser(u); setCatFilter("all"); setShowSuspOnly(false); setHistSearch(""); }}>
                <Users size={12} style={{ marginRight: 4 }} />{u}
              </button>
            );
          })}
        </div>
      )}
      <div className="rh-toolbar">
        <span className="rh-stat">{lines.length} commands</span>
        <span className="rh-stat rh-stat-danger">{suspCount} suspicious</span>
        {hasDateRange(dateRangeMs) && (
          <span className="rh-stat" style={{ color: "#2563eb" }}>
            {linesInRange.length} in date range
          </span>
        )}
        <span className="rh-stat rh-stat-muted">{ev?.data?.path}</span>
        <label className="rh-toggle">
          <input type="checkbox" checked={showSuspOnly} onChange={e => setShowSuspOnly(e.target.checked)} />
          Suspicious only
        </label>
        <select className="rh-select" value={catFilter} onChange={e => setCatFilter(e.target.value)}>
          {cats.map(c => <option key={c} value={c}>{c === "all" ? "All categories" : c}</option>)}
        </select>
        <input className="tl-search" placeholder="Search commands…" value={histSearch}
          onChange={e => setHistSearch(e.target.value)} />
      </div>
      <div className="rh-viewer">
        <table className="rh-table">
          <thead>
            <tr>
              <th className="rh-th-lineno">Line</th>
              <th className="rh-th-ts">Timestamp</th>
              <th className="rh-th-cat">Category</th>
              <th>Command</th>
            </tr>
          </thead>
          <tbody>
            {visible.length === 0
              ? <tr><td colSpan={4} style={{ textAlign: "center", padding: "24px", color: "#9ca3af" }}>No lines match filter.</td></tr>
              : visible.map(line => {
                const isHR = RH_HIGH_RISK.has(line.category);
                const catClr = isHR ? "#dc2626" : line.category !== "General" ? "#6366f1" : "#9ca3af";
                return (
                  <tr key={line.no} className={line.suspicious ? "rh-row-susp" : ""}>
                    <td className="rh-td-lineno">{line.no}</td>
                    <td className="rh-td-ts">{line.ts || "—"}</td>
                    <td className="rh-td-cat" style={{ color: catClr }}>
                      {isHR && <AlertTriangle size={10} style={{ marginRight: 3, verticalAlign: "middle" }} />}
                      {line.category !== "General" ? line.category : ""}
                    </td>
                    <td><code className="rh-cmd">{line.cmd}</code></td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Bash History section (Analysis + Raw sub-tabs) ────────────────────────────
function BashHistorySection({ events, dateRangeMs }) {
  const [view, setView] = useState("analysis");
  const bashEvs = events.filter(e => e.source === "bash_history");
  const rawEvents = bashEvs.filter(e => e.event_type === "bash_history_raw");
  const totalCmds = rawEvents.reduce((s, e) => s + (e.data?.lines?.length || 0), 0);

  if (!bashEvs.length)
    return (
      <div className="bh-empty-info">
        <Terminal size={36} strokeWidth={1.2} style={{ color: "#d1d5db", marginBottom: 12 }} />
        <p style={{ fontWeight: 600, marginBottom: 6, color: "#374151" }}>No bash history found</p>
        <p style={{ color: "#6b7280", fontSize: 12, maxWidth: 380, lineHeight: 1.6 }}>
          No <code>.bash_history</code> files were found in this image. This can mean:
        </p>
        <ul style={{ color: "#6b7280", fontSize: 12, textAlign: "left", marginTop: 8, lineHeight: 1.8, paddingLeft: 20 }}>
          <li>The image is a minimal or freshly created system</li>
          <li>History was deliberately wiped before capture</li>
          <li>The shell was configured with <code>HISTSIZE=0</code> or <code>HISTFILE=/dev/null</code></li>
          <li>The user never ran an interactive shell session</li>
        </ul>
      </div>
    );

  return (
    <div>
      <div className="bh-subtabs">
        <button className={`bh-subtab ${view === "analysis" ? "active" : ""}`}
          onClick={() => setView("analysis")}>
          <Activity size={12} style={{ marginRight: 5 }} />Analysis
        </button>
        <button className={`bh-subtab ${view === "raw" ? "active" : ""}`}
          onClick={() => setView("raw")}>
          <BookOpen size={12} style={{ marginRight: 5 }} />Raw History{totalCmds > 0 ? ` (${totalCmds})` : ""}
        </button>
      </div>
      {view === "analysis" && <BashAnalysisView events={bashEvs} dateRangeMs={dateRangeMs} />}
      {view === "raw" && <BashRawView rawEvents={rawEvents} dateRangeMs={dateRangeMs} />}
    </div>
  );
}

// ── Simple log events table ───────────────────────────────────────────────────
function LogSection({ title, sources, events }) {
  const [search, setSearch] = useState("");
  const logEvs = events.filter(e => sources.includes(e.source));
  const visible = search
    ? logEvs.filter(e => e.detail.toLowerCase().includes(search.toLowerCase()))
    : logEvs;
  const sevCounts = logEvs.reduce((a, e) => { a[e.severity] = (a[e.severity] || 0) + 1; return a; }, {});

  if (!logEvs.length)
    return (
      <div className="log-section-empty">
        <Server size={32} strokeWidth={1.2} style={{ color: "#d1d5db", marginBottom: 8 }} />
        <p style={{ color: "#9ca3af", fontSize: 13 }}>No {title} events in this image.</p>
      </div>
    );

  return (
    <div className="log-section">
      <div className="log-section-toolbar">
        <div className="log-stats">
          {Object.entries(sevCounts).filter(([, v]) => v > 0).map(([sev, cnt]) => (
            <span key={sev} className="log-stat-badge"
              style={{ background: SEV_BG[sev] || "#f3f4f6", color: SEV_COLOR[sev] || "#6b7280" }}>
              {cnt} {sev}
            </span>
          ))}
        </div>
        <input className="tl-search" placeholder={`Search ${title}…`} value={search}
          onChange={e => setSearch(e.target.value)} />
      </div>
      <div className="tl-list">
        {visible.map((ev, i) => <GenericEventRow key={i} ev={ev} />)}
        {visible.length === 0 && <div className="tl-empty">No events match search.</div>}
      </div>
    </div>
  );
}

// ── AI Timeline Analysis Component ───────────────────────────────────────────
function AITimelineAnalysis({ events }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const runAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiTimelineAI(events);
      if (res.error) setError(res.error);
      else setAnalysis(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ai-tl-container">
      {!analysis && !loading && (
        <div className="ai-tl-init">
          <Bot size={32} style={{ color: "#6366f1", marginBottom: 12 }} />
          <h3>AI Timeline Reconstruction</h3>
          <p>Analyze {events.length} events to reconstruct the attack sequence and predict goals.</p>
          <button className="ai-tl-btn" onClick={runAnalysis}>
            <Zap size={14} /> Generate AI Insights
          </button>
        </div>
      )}

      {loading && (
        <div className="ai-tl-loading">
          <Loader2 size={32} className="spin" style={{ color: "#6366f1", marginBottom: 12 }} />
          <p>Analyzing timeline patterns and TTPs...</p>
        </div>
      )}

      {error && (
        <div className="ai-tl-error">
          <AlertTriangle size={24} style={{ color: "#dc2626", marginBottom: 8 }} />
          <p>{error}</p>
          <button className="ai-tl-btn" onClick={runAnalysis}>Retry Analysis</button>
        </div>
      )}

      {analysis && (
        <div className="ai-tl-results">
          <div className="ai-tl-header">
            <Bot size={18} />
            <h2>AI Forensic Reconstruction</h2>
            <button className="ai-tl-btn-mini" onClick={runAnalysis} title="Re-analyze">
              <RefreshCw size={12} />
            </button>
          </div>

          <div className="ai-tl-grid">
            <div className="ai-tl-main">
              <section className="ai-tl-section">
                <h3><Activity size={14} /> Probable Attack Sequence</h3>
                <div className="ai-sequence">
                  {analysis.attack_sequence?.map((step, i) => (
                    <div key={i} className="ai-seq-step" style={{ borderLeftColor: SEV_COLOR[step.severity] || "#6b7280" }}>
                      <div className="ai-seq-phase">
                        <span className="ai-seq-pill" style={{ background: SEV_BG[step.severity], color: SEV_COLOR[step.severity] }}>
                          {step.phase}
                        </span>
                        <SevBadge sev={step.severity} />
                      </div>
                      <p className="ai-seq-desc">{step.description}</p>
                      <div className="ai-seq-events">
                        {step.event_indices?.slice(0, 5).map(idx => (
                          <span key={idx} className="ai-seq-ev-tag" title={events[idx]?.detail}>
                            Event #{idx}
                          </span>
                        ))}
                        {step.event_indices?.length > 5 && <span className="ai-seq-ev-more">+{step.event_indices.length - 5} more</span>}
                      </div>
                    </div>
                  ))}
                  {(!analysis.attack_sequence || analysis.attack_sequence.length === 0) && (
                    <div className="ai-empty-note">No discrete attack phases identified.</div>
                  )}
                </div>
              </section>

              <section className="ai-tl-section">
                <h3><Info size={14} /> Analyst Insights</h3>
                <div className="ai-insights-box">
                  {analysis.insights}
                </div>
              </section>

              {analysis.anti_forensics_report?.length > 0 && (
                <section className="ai-tl-section anti-forensics-section">
                  <div className="section-header danger">
                    <Shield size={14} />
                    <h3>Anti-Forensics Assessment</h3>
                    <span className="danger-badge">{analysis.anti_forensics_report.length} Findings</span>
                  </div>
                  <div className="ai-af-list">
                    {analysis.anti_forensics_report.map((af, i) => (
                      <div key={i} className={`ai-af-item sev-${af.severity}`}>
                        <div className="ai-af-meta">
                          <AlertTriangle size={14} className="af-icon" />
                          <span className="af-technique">{af.technique}</span>
                          <span className={`af-sev-pill ${af.severity}`}>{af.severity}</span>
                        </div>
                        <p className="ai-af-justification">{af.justification}</p>
                        <div className="ai-af-evidence">
                          <label>Evidence:</label>
                          {af.evidence_indices?.map(idx => (
                            <span key={idx} className="ai-seq-ev-tag" title={events[idx]?.detail}>
                              Ev #{idx}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              )}
            </div>

            <div className="ai-tl-side">
              <section className="ai-tl-section ai-prediction-card">
                <h3><Eye size={14} /> Attack Prediction</h3>
                <div className="ai-pred-item">
                  <label>Likely Goal</label>
                  <div className="ai-pred-goal">{analysis.attack_prediction?.likely_goal}</div>
                </div>
                <div className="ai-pred-item">
                  <label>Next Steps / Risks</label>
                  <ul className="ai-pred-list">
                    {analysis.attack_prediction?.next_steps?.map((s, i) => <li key={i}>{s}</li>)}
                  </ul>
                </div>
                <div className="ai-pred-footer">
                  <span className="ai-confidence">
                    Confidence: <strong className={`conf-${analysis.attack_prediction?.confidence}`}>{analysis.attack_prediction?.confidence}</strong>
                  </span>
                </div>
              </section>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Timeline Tab (source-nav + sections) ──────────────────────────────────────
function TimelineTab({ events = [], dateRangeMs }) {
  const [source, setSource] = useState("bash");

  if (!events.length) return <EmptyState icon={Clock} message="No timeline events found." />;

  // Count significant events per source for nav badges
  const bashHigh = events.filter(e => e.source === "bash_history" && (e.severity === "high" || e.severity === "critical")).length;
  const authEvs = events.filter(e => ["auth.log", "secure"].includes(e.source));
  const sysEvs = events.filter(e => ["syslog", "messages"].includes(e.source));
  const authHigh = authEvs.filter(e => e.severity === "high" || e.severity === "critical").length;
  const sysHigh = sysEvs.filter(e => e.severity === "high" || e.severity === "critical").length;

  const srcNav = [
    { id: "bash", label: "Bash History", Icon: Terminal, badge: bashHigh },
    { id: "auth", label: "Auth Log", Icon: Lock, badge: authHigh, count: authEvs.length },
    { id: "syslog", label: "System Log", Icon: Server, badge: sysHigh, count: sysEvs.length },
    { id: "ai", label: "AI Insights", Icon: Bot, badge: 0 },
  ];

  return (
    <div className="tab-content tl-main">
      {/* Source nav */}
      <div className="tl-src-nav">
        {srcNav.map(({ id, label, Icon, badge, count }) => (
          <button key={id}
            className={`tl-src-btn ${source === id ? "active" : ""}`}
            onClick={() => setSource(id)}>
            <Icon size={13} style={{ flexShrink: 0 }} />
            <span>{label}</span>
            {count != null && !badge && <span className="tl-src-count">{count}</span>}
            {badge > 0 && <span className="tl-src-badge">{badge}</span>}
          </button>
        ))}
      </div>

      {/* Content area */}
      <div className="tl-src-content">
        {source === "bash" && <BashHistorySection events={events} dateRangeMs={dateRangeMs} />}
        {source === "auth" && <LogSection title="Auth Log" sources={["auth.log", "secure"]} events={events} />}
        {source === "syslog" && <LogSection title="System Log" sources={["syslog", "messages"]} events={events} />}
        {source === "ai" && <AITimelineAnalysis events={events} />}
      </div>
    </div>
  );
}

// ── Global date-range helpers ────────────────────────────────────────────────
function parseDateToMs(value) {
  if (value == null) return null;

  if (typeof value === "number" && Number.isFinite(value)) {
    if (value > 1e15) return Math.floor(value / 1000); // ns -> ms
    if (value > 1e12) return Math.floor(value);         // ms epoch
    if (value > 1e9) return Math.floor(value * 1000);  // s epoch
    return null;
  }

  const text = String(value).trim();
  if (!text || text === "unknown" || text === "-") return null;
  if (/^\d+$/.test(text)) return parseDateToMs(Number(text));

  const parsed = Date.parse(text);
  return Number.isNaN(parsed) ? null : parsed;
}

function hasDateRange(range) {
  return range?.fromMs != null || range?.toMs != null;
}

function inDateRange(ts, range) {
  // Keep undated records visible; date-range filter only excludes dated rows outside range.
  if (ts == null) return true;
  if (range.fromMs != null && ts < range.fromMs) return false;
  if (range.toMs != null && ts > range.toMs) return false;
  return true;
}

function filterByDateRange(items, getTs, range) {
  if (!hasDateRange(range)) return items;
  return items.filter((item) => inDateRange(getTs(item), range));
}

function getBashLineTimestampMs(line) {
  return parseDateToMs(line?.ts)
    ?? parseDateToMs(line?.timestamp)
    ?? parseDateToMs(line?.datetime)
    ?? parseDateToMs(line?.date)
    ?? parseDateToMs(line?.unix_ts)
    ?? parseDateToMs(line?.epoch);
}

function filterBashLinesByDateRange(lines, range) {
  if (!hasDateRange(range)) return lines;
  return (lines || []).filter((line) => inDateRange(getBashLineTimestampMs(line), range));
}

function filterTimelineByDateRange(events, range) {
  if (!hasDateRange(range)) return events;

  return (events || []).filter((ev) => {
    const eventTs = parseDateToMs(ev?.timestamp);
    if (eventTs != null) return inDateRange(eventTs, range);

    if (ev?.source === "bash_history") {
      const lines = ev?.data?.lines || [];
      const datedLines = lines.map(getBashLineTimestampMs).filter((ts) => ts != null);
      if (datedLines.length === 0) return true;
      return datedLines.some((ts) => inDateRange(ts, range));
    }

    return true;
  });
}

function getDeletedTimestampMs(item) {
  return parseDateToMs(item?.deleted_at)
    ?? parseDateToMs(item?.mtime)
    ?? parseDateToMs(item?.ctime)
    ?? parseDateToMs(item?.atime);
}

function getMultimediaTimestampMs(item) {
  const meta = item?.metadata || {};
  return parseDateToMs(meta.datetime_original)
    ?? parseDateToMs(meta.date_time_original)
    ?? parseDateToMs(meta.create_date)
    ?? parseDateToMs(meta.modify_date)
    ?? parseDateToMs(meta.timestamp);
}

function getBrowserRowTimestampMs(row) {
  return parseDateToMs(row?.timestamp)
    ?? parseDateToMs(row?.last_visit)
    ?? parseDateToMs(row?.start_time)
    ?? parseDateToMs(row?.date_added)
    ?? parseDateToMs(row?.date_created)
    ?? parseDateToMs(row?.expires);
}

function filterBrowsersByDateRange(browsers, range) {
  if (!hasDateRange(range)) return browsers;

  return browsers
    .map((profile) => {
      const next = {
        ...profile,
        history: filterByDateRange(profile.history || [], getBrowserRowTimestampMs, range),
        downloads: filterByDateRange(profile.downloads || [], getBrowserRowTimestampMs, range),
        bookmarks: filterByDateRange(profile.bookmarks || [], getBrowserRowTimestampMs, range),
        cookies: filterByDateRange(profile.cookies || [], getBrowserRowTimestampMs, range),
        extensions: filterByDateRange(profile.extensions || [], getBrowserRowTimestampMs, range),
        logins: filterByDateRange(profile.logins || [], getBrowserRowTimestampMs, range),
        search_terms: filterByDateRange(profile.search_terms || [], getBrowserRowTimestampMs, range),
        autofill: filterByDateRange(profile.autofill || [], getBrowserRowTimestampMs, range),
      };

      const total =
        next.history.length + next.downloads.length + next.bookmarks.length + next.cookies.length +
        next.extensions.length + next.logins.length + next.search_terms.length + next.autofill.length;
      return total > 0 ? next : null;
    })
    .filter(Boolean);
}

function buildRecentActivities({ timeline, deleted, browsers, multimedia }) {
  const rows = [];

  for (const ev of timeline || []) {
    const ts = parseDateToMs(ev.timestamp);
    if (ts == null) continue;
    rows.push({
      timeMs: ts,
      timeText: ev.timestamp,
      section: "Timeline",
      severity: ev.severity || "info",
      detail: ev.detail,
      source: ev.source,
      path: ev.data?.path || "",
    });
  }

  for (const d of deleted || []) {
    const ts = getDeletedTimestampMs(d);
    if (ts == null) continue;
    rows.push({
      timeMs: ts,
      timeText: d.deleted_at || d.mtime || d.ctime || d.atime || "",
      section: "Deleted",
      severity: d.severity || "medium",
      detail: d.detail || d.path,
      source: d.type || "deleted",
      path: d.path || "",
    });
  }

  for (const profile of browsers || []) {
    const browser = profile.browser_label || profile.browser || "browser";
    for (const h of profile.history || []) {
      const ts = getBrowserRowTimestampMs(h);
      if (ts == null) continue;
      rows.push({
        timeMs: ts,
        timeText: h.last_visit || "",
        section: "Browser",
        severity: h.severity || "info",
        detail: h.title || h.url || "Visited URL",
        source: `${browser} history`,
        path: h.url || "",
      });
    }
    for (const dl of profile.downloads || []) {
      const ts = getBrowserRowTimestampMs(dl);
      if (ts == null) continue;
      rows.push({
        timeMs: ts,
        timeText: dl.start_time || "",
        section: "Browser",
        severity: dl.severity || "info",
        detail: dl.target_path || dl.url || "Download",
        source: `${browser} download`,
        path: dl.target_path || dl.url || "",
      });
    }
    for (const s of profile.search_terms || []) {
      const ts = getBrowserRowTimestampMs(s);
      if (ts == null) continue;
      rows.push({
        timeMs: ts,
        timeText: s.timestamp || "",
        section: "Browser",
        severity: s.severity || "info",
        detail: s.term ? `Search: ${s.term}` : "Search activity",
        source: `${browser} search`,
        path: "",
      });
    }
  }

  for (const m of multimedia || []) {
    const ts = getMultimediaTimestampMs(m);
    if (ts == null) continue;
    rows.push({
      timeMs: ts,
      timeText: m.metadata?.datetime_original || m.metadata?.create_date || "",
      section: "Multimedia",
      severity: m.severity || "info",
      detail: (m.findings && m.findings[0]) || m.name || m.path,
      source: m.media_type || "media",
      path: m.path || "",
    });
  }

  return rows.sort((a, b) => b.timeMs - a.timeMs).slice(0, 200);
}

function RecentActivitiesTab({ activities = [] }) {
  if (!activities.length) {
    return <EmptyState icon={Activity} message="No recent activities in the selected date range." />;
  }

  return (
    <div className="tab-content">
      <div className="ra-summary">Showing {activities.length} most recent timestamped activities.</div>
      <div className="ra-list">
        {activities.map((row, i) => (
          <div key={`${row.section}-${row.source}-${row.timeMs}-${i}`} className="ra-row" style={{ borderLeftColor: SEV_COLOR[row.severity] || "#6b7280" }}>
            <div className="ra-time">{row.timeText || new Date(row.timeMs).toLocaleString()}</div>
            <div className="ra-main">
              <div className="ra-head">
                <span className="ra-section">{row.section}</span>
                <span className="ra-source">{row.source}</span>
                <SevBadge sev={row.severity} />
              </div>
              <div className="ra-detail">{row.detail}</div>
              {row.path && <code className="ra-path">{row.path}</code>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function fmtBytes(n) {
  if (n == null || n <= 0) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(1)} GB`;
}

function RecoverButton({ finding, imgPath }) {
  const [status, setStatus] = useState("idle");   // idle | busy | ok | err
  const [result, setResult] = useState(null);

  const run = async () => {
    setStatus("busy");
    try {
      const r = await apiRecover(imgPath, finding.recovery_id);
      if (r.success) { setStatus("ok"); setResult(r); }
      else { setStatus("err"); setResult(r); }
    } catch (e) {
      setStatus("err");
      setResult({ error: e.message });
    }
  };

  if (status === "ok") return (
    <span className="del-rec-ok">
      <CheckCircle size={11} /> Saved to <code className="del-rec-path">{result.path}</code>
      {result.size > 0 && <span> ({fmtBytes(result.size)})</span>}
    </span>
  );
  if (status === "err") return (
    <span className="del-rec-err">
      <AlertTriangle size={11} /> {result?.error || "failed"}
      <button className="del-rec-btn" onClick={run}>Retry</button>
    </span>
  );
  return (
    <button className={`del-rec-btn${status === "busy" ? " busy" : ""}`} onClick={run} disabled={status === "busy"}>
      {status === "busy" ? <RefreshCw size={11} className="spin" /> : <FolderOpen size={11} />}
      {status === "busy" ? "Recovering…" : "Recover"}
    </button>
  );
}

function DelRow({ f, imgPath }) {
  const [open, setOpen] = useState(false);
  const { color } = DEL_TYPE_META[f.type] || { color: "#6b7280" };
  const sev = f.severity || "medium";
  return (
    <div className="del-row del-row2" style={{ borderLeft: `3px solid ${SEV_COLOR[sev] || "#6b7280"}` }}>
      <div className="del-row2-top" onClick={() => setOpen(x => !x)}>
        <span className="del-row2-toggle">{open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</span>
        <code className="del-path">{f.path}</code>
        <div className="del-row2-meta">
          {f.size != null && <span className="del-chip del-size">{fmtBytes(f.size)}</span>}
          {f.inode != null && <span className="del-chip del-inode">ino:{f.inode}</span>}
          {f.deleted_at && <span className="del-chip del-ts">{f.deleted_at}</span>}
          <SevBadge sev={sev} />
          {f.recoverable && imgPath
            ? <RecoverButton finding={f} imgPath={imgPath} />
            : f.recoverable
              ? <span className="del-chip del-recoverable"><CheckCircle size={10} /> Recoverable</span>
              : null
          }
        </div>
      </div>
      {open && (
        <div className="del-row2-body">
          <p className="del-detail">{f.detail}</p>
          {f.recovery_hint && (
            <p className="del-hint"><CheckCircle size={11} style={{ color: "#16a34a" }} /> {f.recovery_hint}</p>
          )}
          {f.command && <pre className="del-command">{f.command}</pre>}
          {(f.mtime || f.atime || f.ctime) && (
            <div className="del-times">
              {f.mtime && <span><strong>Modified:</strong> {f.mtime}</span>}
              {f.atime && <span><strong>Accessed:</strong> {f.atime}</span>}
              {f.ctime && <span><strong>Created:</strong> {f.ctime}</span>}
            </div>
          )}
          {f.user && <p className="del-user">User: <strong>{f.user}</strong></p>}
        </div>
      )}
    </div>
  );
}

// ── File Carving Panel ────────────────────────────────────────────────────────

const CARVE_GROUP_ICONS = {
  image: HardDrive,
  document: FileText,
  executable: Terminal,
  database: Database,
  archive: Package,
  email: BookOpen,
  video: Activity,
  audio: Activity,
  text: Code,
};

function CarvingPanel({ imgPath }) {
  const [groups, setGroups] = useState(null);    // {id: label} map from API
  const [selected, setSelected] = useState([]);       // group keys chosen by user
  const [maxFiles, setMaxFiles] = useState(200);
  const [maxScanGb, setMaxScanGb] = useState(2);
  const [outDir, setOutDir] = useState("");
  const [status, setStatus] = useState("idle");   // idle|loading-groups|carving|done|err
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  // Load group list once
  useEffect(() => {
    setStatus("loading-groups");
    apiCarveGroups()
      .then(r => { setGroups(r.groups); setSelected(Object.keys(r.groups)); setStatus("idle"); })
      .catch(() => { setGroups({}); setStatus("idle"); });
  }, []);

  const toggleGroup = (k) =>
    setSelected(s => s.includes(k) ? s.filter(x => x !== k) : [...s, k]);

  const startCarving = async () => {
    setStatus("carving");
    setResults(null);
    setError("");
    try {
      const r = await apiCarve(imgPath, {
        sig_groups: selected.length ? selected : null,
        max_files: Math.max(1, Math.min(500, maxFiles)),
        max_scan_gb: Math.max(0.1, Math.min(50, maxScanGb)),
        output_dir: outDir.trim() || undefined,
      });
      setResults(r);
      setStatus("done");
    } catch (e) {
      setError(e.message || "Carving failed");
      setStatus("err");
    }
  };

  const carved = results?.carved?.filter(f => f.type === "carved") ?? [];
  const info = results?.carved?.filter(f => f.type !== "carved") ?? [];

  return (
    <div className="carve-panel">
      <div className="carve-panel-header">
        <HardDrive size={14} style={{ color: "#7c3aed" }} />
        <span className="carve-title">File Carving</span>
        <span className="carve-subtitle">
          Scan raw disk sectors for file signatures — recovers deleted files even when
          all inode/directory metadata is wiped.
        </span>
        <span className="carve-badge">TSK image only</span>
      </div>

      {status !== "carving" && status !== "done" && (
        <div className="carve-config">
          {/* Signature group selector */}
          <div className="carve-section-label">File types to carve:</div>
          <div className="carve-groups">
            {groups === null && <span className="carve-loading">Loading signatures…</span>}
            {groups && Object.entries(groups).map(([k, label]) => {
              const Icon = CARVE_GROUP_ICONS[k] || File;
              const active = selected.includes(k);
              return (
                <button key={k} className={`carve-group-btn${active ? " active" : ""}`}
                  onClick={() => toggleGroup(k)}>
                  <Icon size={11} />{label}
                  {active && <CheckCircle size={10} className="carve-check" />}
                </button>
              );
            })}
          </div>

          {/* Numeric options */}
          <div className="carve-opts">
            <label className="carve-opt-lbl">
              Max carved files
              <input type="number" className="carve-num" value={maxFiles} min={1} max={500}
                onChange={e => setMaxFiles(Number(e.target.value))} />
            </label>
            <label className="carve-opt-lbl">
              Scan limit (GB)
              <input type="number" className="carve-num" value={maxScanGb} min={0.1} max={50} step={0.5}
                onChange={e => setMaxScanGb(Number(e.target.value))} />
            </label>
            <label className="carve-opt-lbl" style={{ flex: 2 }}>
              Output directory <span className="carve-opt-hint">(leave blank for default /tmp/osforensics_recovery/carved)</span>
              <input className="carve-path-inp" placeholder="/path/to/output/dir"
                value={outDir} onChange={e => setOutDir(e.target.value)} />
            </label>
          </div>

          <button className="carve-start-btn" disabled={!groups || selected.length === 0} onClick={startCarving}>
            <HardDrive size={13} /> Start Carving
          </button>
        </div>
      )}

      {status === "carving" && (
        <div className="carve-progress">
          <RefreshCw size={20} className="spin" style={{ color: "#7c3aed" }} />
          <span>Scanning image for file signatures…  This may take several minutes for large images.</span>
        </div>
      )}

      {status === "err" && (
        <div className="carve-err">
          <AlertTriangle size={14} /> {error}
          <button className="del-rec-btn" style={{ marginLeft: 10 }} onClick={() => setStatus("idle")}>Try again</button>
        </div>
      )}

      {status === "done" && (
        <div className="carve-results">
          <div className="carve-results-header">
            <CheckCircle size={13} style={{ color: "#16a34a" }} />
            <strong>{carved.length} file{carved.length !== 1 ? "s" : ""} carved</strong>
            {results?.output_dir && (
              <span className="carve-outdir">→ <code>{results.output_dir}</code></span>
            )}
            <button className="del-rec-btn" style={{ marginLeft: "auto" }}
              onClick={() => { setStatus("idle"); setResults(null); }}>
              Carve Again
            </button>
          </div>

          {/* Info / warning messages */}
          {info.map((f, i) => (
            <div key={i} className="carve-info-row">
              <Info size={11} style={{ flexShrink: 0 }} /> {f.detail}
            </div>
          ))}

          {/* Carved files table */}
          {carved.length > 0 && (
            <table className="carve-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Type / Offset</th>
                  <th>Size</th>
                  <th>Saved As</th>
                </tr>
              </thead>
              <tbody>
                {carved.map((f, i) => {
                  const offset = f.inode != null ? `0x${f.inode.toString(16).padStart(8, "0")}` : "—";
                  const fname = f.path.split("/").pop();
                  return (
                    <tr key={i}>
                      <td className="carve-td-num">{i + 1}</td>
                      <td>
                        <div className="carve-type-cell">
                          <span className="carve-type-badge">{fname.split("_")[1]?.toUpperCase() || "?"}</span>
                          <code className="carve-offset">{offset}</code>
                        </div>
                      </td>
                      <td className="carve-td-size">{fmtBytes(f.size) || "—"}</td>
                      <td><code className="del-path" style={{ fontSize: 10 }}>{f.path}</code></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

function DeletedTab({ findings = [], imgPath }) {
  const [search, setSearch] = useState("");
  const [filterSev, setFilterSev] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [recOnly, setRecOnly] = useState(false);

  // Determine if we have a disk image (not live root) — carving only makes sense then
  const isImage = imgPath && imgPath !== "/" && !imgPath.endsWith("/");

  const types = [...new Set(findings.map(f => f.type))];
  const filtered = findings.filter(f => {
    if (filterSev !== "all" && f.severity !== filterSev) return false;
    if (filterType !== "all" && f.type !== filterType) return false;
    if (recOnly && !f.recoverable) return false;
    if (search) {
      const q = search.toLowerCase();
      return (f.path?.toLowerCase().includes(q) ||
        f.detail?.toLowerCase().includes(q) ||
        f.command?.toLowerCase().includes(q));
    }
    return true;
  });

  const byType = filtered.reduce((acc, f) => {
    const k = f.type || "other";
    if (!acc[k]) acc[k] = [];
    acc[k].push(f);
    return acc;
  }, {});

  const nRecoverable = findings.filter(f => f.recoverable).length;
  const nHigh = findings.filter(f => f.severity === "high").length;

  return (
    <div className="tab-content">
      {findings.length === 0 ? (
        <EmptyState icon={Eye} message="No deleted files or anti-forensics indicators found." />
      ) : (
        <>
          {/* Summary bar */}
          <div className="del-summary-bar">
            <span className="del-sum-chip neutral"><Eye size={11} /> {findings.length} findings</span>
            <span className="del-sum-chip green"><CheckCircle size={11} /> {nRecoverable} recoverable</span>
            <span className="del-sum-chip red"><AlertTriangle size={11} /> {nHigh} high severity</span>
          </div>

          {/* Filter bar */}
          <div className="del-filter-bar">
            <div className="del-search-wrap">
              <Search size={12} className="del-search-icon" />
              <input className="del-search" placeholder="Search path, detail or command…"
                value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            <select className="del-select" value={filterSev} onChange={e => setFilterSev(e.target.value)}>
              <option value="all">All Severities</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="info">Info</option>
            </select>
            <select className="del-select" value={filterType} onChange={e => setFilterType(e.target.value)}>
              <option value="all">All Types</option>
              {types.map(t => <option key={t} value={t}>{DEL_TYPE_META[t]?.label || t}</option>)}
            </select>
            <label className="del-toggle-lbl">
              <input type="checkbox" checked={recOnly} onChange={e => setRecOnly(e.target.checked)} />
              Recoverable only
            </label>
          </div>

          {filtered.length === 0 && (
            <div className="empty-state" style={{ padding: "40px 20px" }}>
              <Search size={28} style={{ color: "var(--fg-muted)", marginBottom: 8 }} />
              <p>No results match the current filter.</p>
            </div>
          )}

          {Object.entries(byType).map(([type, items]) => {
            const m = DEL_TYPE_META[type] || { label: type, Icon: Eye, color: "#6b7280", desc: "" };
            const TypeIcon = m.Icon;
            return (
              <div key={type} className="del-group" style={{ borderTop: `3px solid ${m.color}` }}>
                <div className="del-group-header">
                  <TypeIcon size={13} style={{ color: m.color }} />
                  <span>{m.label}</span>
                  <span className="del-count">{items.length}</span>
                  {m.desc && <span className="del-group-desc">{m.desc}</span>}
                </div>
                <div className="del-list">
                  {items.map((f, i) => <DelRow key={i} f={f} imgPath={imgPath} />)}
                </div>
              </div>
            );
          })}
        </>
      )}

      {/* File Carving section — always shown when we have a disk image */}
      {isImage && <CarvingPanel imgPath={imgPath} />}
    </div>
  );
}

function PersistenceTab({ findings = [] }) {
  if (findings.length === 0) return <EmptyState icon={Shield} message="No persistence mechanisms detected." />;
  const byCategory = findings.reduce((acc, f) => { const k = f.category || "other"; if (!acc[k]) acc[k] = []; acc[k].push(f); return acc; }, {});
  return (
    <div className="tab-content">
      {Object.entries(byCategory).map(([cat, items]) => {
        const Icon = PERSIST_ICONS[cat] || Shield;
        return (
          <div key={cat} className="persist-group">
            <div className="persist-group-header"><Icon size={13} /><span>{PERSIST_LABELS[cat] || cat}</span><span className="del-count">{items.length}</span></div>
            <div className="persist-list">
              {items.map((f, i) => (
                <div key={i} className="persist-row" style={{ borderLeft: `3px solid ${SEV_COLOR[f.severity] || "#6b7280"}` }}>
                  <div className="persist-top">
                    <code className="del-path">{f.source}</code>
                    <SevBadge sev={f.severity} />
                  </div>
                  <div className="del-detail">{f.detail}</div>
                  <SnippetBlock snippet={f.snippet} />
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

const RISK_COLOR = { high: "#dc2626", medium: "#d97706", low: "#16a34a", "privacy-infrastructure": "#7c3aed", "dual-use": "#2563eb", infrastructure: "#0891b2" };
function EvidenceLocker({ report }) {
  const findings = [
    ...(report.persistence || []).map(f => ({ ...f, type: "Persistence", Icon: Shield })),
    ...(report.config || []).filter(f => f.severity !== "info").map(f => ({ ...f, type: "Config Audit", Icon: Settings })),
    ...(report.tails || []).map(f => ({ ...f, type: "TailsOS", Icon: Sailboat })),
    ...(report.findings || []).map(f => ({ ...f, type: "Notable Tool", Icon: Search, detail: f.tool })),
  ].sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4));

  if (findings.length === 0) return <EmptyState icon={Package} message="No high-priority evidence collected yet." />;

  return (
    <div className="tab-content">
      <div className="lsd-intro" style={{ marginBottom: 20 }}>
        <div className="tails-head-title" style={{ fontSize: 18, fontWeight: 700, color: "var(--fg)" }}><Package size={18} /> Central Evidence Repository</div>
      </div>
      <div className="sa-audit-card" style={{ padding: 0 }}>
        <div className="sc-table-wrap">
          <table className="sc-table">
            <thead>
              <tr>
                <th style={{ width: 120 }}>Category</th>
                <th style={{ width: 80 }}>Risk</th>
                <th>Preserved Finding / Artifact</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i}>
                  <td style={{ verticalAlign: "middle" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, fontWeight: 600 }}>
                      <f.Icon size={12} style={{ color: "var(--accent-purp)" }} /> {f.type}
                    </div>
                  </td>
                  <td style={{ verticalAlign: "middle" }}><SevBadge sev={f.severity} /></td>
                  <td>
                    <div style={{ fontWeight: 700, marginBottom: 2 }}>{f.detail || f.tool}</div>
                    <code className="del-path" style={{ fontSize: 10, opacity: 0.8 }}>{f.source || f.config || f.path || "System Level"}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Dashboard (Report panel) ─────────────────────────────────────────────────

// Config analyser labels and icons per config file / group
const CFG_FILE_META = {
  sshd_config: { label: "SSH Server (sshd_config)", Icon: Key },
  sudoers: { label: "sudo (sudoers)", Icon: Shield },
  iptables: { label: "IPTables / Firewall", Icon: Wifi },
  ufw: { label: "UFW Firewall", Icon: Wifi },
  "pam.d": { label: "PAM Configuration", Icon: Lock },
  "sysctl.conf": { label: "Kernel Parameters (sysctl)", Icon: Cpu },
  "login.defs": { label: "Password Policy", Icon: Users },
  "/etc/hosts": { label: "/etc/hosts", Icon: Globe },
  "resolv.conf": { label: "DNS (resolv.conf)", Icon: Globe },
  apparmor: { label: "AppArmor", Icon: Shield },
  selinux: { label: "SELinux", Icon: Shield },
  MAC: { label: "Mandatory Access Control", Icon: Shield },
  network: { label: "Network Interfaces", Icon: Wifi },
};

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function ConfigFindingRow({ f }) {
  const [open, setOpen] = useState(false);
  const borderColor = SEV_COLOR[f.severity] || "#6b7280";
  return (
    <div className="cfg-row" style={{ borderLeft: `3px solid ${borderColor}` }}>
      <div className="cfg-row-top">
        <span className="cfg-category">{f.category}</span>
        <SevBadge sev={f.severity} />
        {f.recommendation && (
          <button className="cfg-rec-toggle" onClick={() => setOpen(v => !v)} title="Show recommendation">
            {open ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
          </button>
        )}
      </div>
      <div className="cfg-detail">{f.detail}</div>
      {f.snippet && <pre className="cfg-snippet">{f.snippet}</pre>}
      {open && f.recommendation && (
        <div className="cfg-recommendation">
          <CheckCircle size={11} /> {f.recommendation}
        </div>
      )}
    </div>
  );
}

function ConfigGroup({ configKey, findings }) {
  const [collapsed, setCollapsed] = useState(false);
  const meta = CFG_FILE_META[configKey] || { label: configKey, Icon: FileText };
  const { Icon } = meta;
  const critCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const warnCount = findings.filter(f => f.severity === "medium").length;
  const topSev = critCount ? "critical" : highCount ? "high" : warnCount ? "medium" : "info";
  const alertCount = critCount + highCount;

  return (
    <div className="cfg-group">
      <button className="cfg-group-header" onClick={() => setCollapsed(v => !v)}>
        <Icon size={13} style={{ color: SEV_COLOR[topSev] || "#6b7280", flexShrink: 0 }} />
        <span className="cfg-group-title">{meta.label}</span>
        {alertCount > 0 && (
          <span className="cfg-alert-badge" style={{ background: SEV_COLOR[topSev] }}>{alertCount}</span>
        )}
        <span className="cfg-group-total">{findings.length} finding{findings.length !== 1 ? "s" : ""}</span>
        <span style={{ marginLeft: "auto" }}>
          {collapsed ? <ChevronRight size={13} /> : <ChevronDown size={13} />}
        </span>
      </button>
      {!collapsed && (
        <div className="cfg-group-body">
          {findings.map((f, i) => <ConfigFindingRow key={i} f={f} />)}
        </div>
      )}
    </div>
  );
}

function SecurityAuditDashboard({ findings }) {
  const total = findings.length;
  const critical = findings.filter(f => f.severity === "critical").length;
  const high = findings.filter(f => f.severity === "high").length;
  const score = Math.max(0, 100 - (critical * 20) - (high * 10));
  const statusLabel = score > 80 ? "Secure" : score > 50 ? "Risk" : "Critical";
  const scoreColor = score > 80 ? "var(--success)" : score > 50 ? "var(--warn)" : "var(--danger)";

  return (
    <div className="sa-dashboard">
      <div className="sa-risk-dial-wrap">
        <div className="sa-score-value" style={{ color: scoreColor }}>{score}</div>
        <div className="sa-score-label" style={{ color: scoreColor }}>{statusLabel} Safety Score</div>
        <div className="ws-sub" style={{ margin: 0, fontSize: 13 }}>System hardening analysis completed. {total} total findings.</div>
      </div>

      <div className="sa-audit-grid">
        <div className="sa-audit-card">
          <div className="sa-audit-header">
            <Lock size={16} style={{ color: "var(--accent-blu)" }} />
            <div className="sa-audit-title">Access Controls</div>
          </div>
          {findings.filter(f => f.category?.includes("Auth") || f.category?.includes("User") || f.category?.includes("sudo")).slice(0, 3).map((f, i) => (
            <div key={i} className="sa-finding-row">
              <div className="sa-finding-status"><SevBadge sev={f.severity} /></div>
              <div className="sa-finding-text">{f.detail}</div>
            </div>
          ))}
        </div>

        <div className="sa-audit-card">
          <div className="sa-audit-header">
            <Shield size={16} style={{ color: "var(--accent)" }} />
            <div className="sa-audit-title">Security Services</div>
          </div>
          {findings.filter(f => f.category?.includes("Firewall") || f.category?.includes("Kernel") || f.category?.includes("Network")).slice(0, 3).map((f, j) => (
            <div key={j} className="sa-finding-row">
              <div className="sa-finding-status"><SevBadge sev={f.severity} /></div>
              <div className="sa-finding-text">{f.detail}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ConfigTab({ findings = [] }) {
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [viewMode, setViewMode] = useState("dashboard"); // "dashboard" | "list"

  if (findings.length === 0)
    return <EmptyState icon={Settings} message="No configuration findings available." />;

  const filtered = findings.filter(f => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return f.detail.toLowerCase().includes(q)
        || (f.config || "").toLowerCase().includes(q)
        || (f.category || "").toLowerCase().includes(q);
    }
    return true;
  });

  const grouped = filtered.reduce((acc, f) => {
    const key = f.config || "system";
    if (!acc[key]) acc[key] = [];
    acc[key].push(f);
    return acc;
  }, {});

  const sortedKeys = Object.keys(grouped).sort((a, b) => {
    const sevA = Math.min(...grouped[a].map(f => SEV_ORDER[f.severity] ?? 4));
    const sevB = Math.min(...grouped[b].map(f => SEV_ORDER[f.severity] ?? 4));
    return sevA - sevB;
  });

  const SEV_FILTERS = [
    { id: "all", label: "All" },
    { id: "critical", label: "Critical", color: SEV_COLOR.critical },
    { id: "high", label: "High", color: SEV_COLOR.high },
    { id: "medium", label: "Medium", color: SEV_COLOR.medium },
    { id: "low", label: "Low", color: SEV_COLOR.low },
    { id: "info", label: "Info", color: "#6b7280" },
  ];

  return (
    <div className="tab-content">
      <div className="lsd-intro" style={{ marginBottom: 20, justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Settings size={18} />
          <div className="tails-head-title" style={{ fontSize: 18, fontWeight: 700, color: "var(--fg)" }}>Security Architecture Audit</div>
        </div>

        <div className="explorer-mode-toggle">
          <button className={`mode-toggle-btn ${viewMode === 'dashboard' ? 'active' : ''}`} onClick={() => setViewMode('dashboard')} title="Dashboard View"><LayoutPanelLeft size={11} /></button>
          <button className={`mode-toggle-btn ${viewMode === 'list' ? 'active' : ''}`} onClick={() => setViewMode('list')} title="Detailed List"><List size={11} /></button>
        </div>
      </div>

      {viewMode === "dashboard" ? (
        <SecurityAuditDashboard findings={findings} />
      ) : (
        <>
          <div className="cfg-summary-bar">
            <div className="cfg-sev-filters">
              {SEV_FILTERS.map(({ id, label, color }) => (
                <button key={id}
                  className={`cfg-sev-filter ${severityFilter === id ? "active" : ""}`}
                  style={severityFilter === id && color ? { background: color, color: "#fff", borderColor: color } : {}}
                  onClick={() => setSeverityFilter(id)}>
                  {label}
                </button>
              ))}
            </div>
            <div className="del-search-wrap" style={{ maxWidth: 300, marginLeft: "auto" }}>
              <Search size={12} className="del-search-icon" />
              <input className="del-search" placeholder="Search..." value={search}
                onChange={e => setSearch(e.target.value)} />
            </div>
          </div>
          <div className="cfg-list" style={{ marginTop: 20 }}>
            {filtered.length === 0 ? (
              <EmptyState icon={CheckCircle} message="No findings match the current filter." />
            ) : (
              sortedKeys.map(key => (
                <ConfigGroup key={key} configKey={key} findings={grouped[key]} />
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ─── Services Tab ─────────────────────────────────────────────────────────────

const SVC_CAT_META = {
  web_server: { label: "Web Server", Icon: Globe },
  ftp_server: { label: "FTP Server", Icon: FolderOpenIcon },
  database: { label: "Database", Icon: Database },
  mail: { label: "Mail", Icon: Package },
  dns: { label: "DNS", Icon: Wifi },
  dhcp: { label: "DHCP", Icon: Wifi },
  ssh: { label: "SSH", Icon: Terminal },
  remote_access: { label: "Remote Access", Icon: Cpu },
  file_sharing: { label: "File Sharing", Icon: FolderOpenIcon },
  vpn: { label: "VPN", Icon: Lock },
  container: { label: "Container", Icon: Box },
  proxy: { label: "Proxy", Icon: Server },
  monitoring: { label: "Monitoring", Icon: BarChart2 },
  security: { label: "Security", Icon: Shield },
  crypto_mining: { label: "Crypto Mining", Icon: AlertTriangle },
  system: { label: "System", Icon: Settings },
  other: { label: "Other", Icon: Package },
};

const SVC_STATE_COLOR = {
  enabled: { bg: "#dcfce7", color: "#166534", border: "#bbf7d0" },
  disabled: { bg: "#f1f5f9", color: "#64748b", border: "#e2e8f0" },
  masked: { bg: "#fef2f2", color: "#991b1b", border: "#fecaca" },
  static: { bg: "#eff6ff", color: "#1d4ed8", border: "#bfdbfe" },
  indirect: { bg: "#f0fdfa", color: "#0f766e", border: "#99f6e4" },
  detected: { bg: "#fff7ed", color: "#92400e", border: "#fed7aa" },
};

const SVC_FLAG_LABELS = {
  "unusual-exec-path": "Unusual exec path",
  "shell-exec": "Shell exec",
  "root-exec": "Runs as root",
  "unencrypted-protocol": "Unencrypted protocol",
  "deprecated-protocol": "Deprecated protocol",
  "crypto-miner": "Possible crypto miner",
  "potential-no-auth": "Potential no-auth",
  "config-only": "Config file only",
  "masked": "Masked",
};

function ServiceRow({ svc }) {
  const [open, setOpen] = useState(false);
  const meta = SVC_CAT_META[svc.category] || SVC_CAT_META.other;
  const CatIcon = meta.Icon;
  const stateSty = SVC_STATE_COLOR[svc.state] || SVC_STATE_COLOR.disabled;
  const sevColor = SEV_COLOR[svc.severity] || "#6b7280";
  const hasDetail = svc.description || svc.exec_start || svc.unit_path || svc.flags?.length > 0;

  return (
    <div className="svc-row" style={{ borderLeftColor: sevColor }}>
      <div className="svc-row-top">
        <span className="svc-cat-icon" style={{ color: sevColor }}>
          <CatIcon size={15} />
        </span>
        <div className="svc-name-group">
          <span className="svc-name">{svc.name}</span>
          {svc.display_name && svc.display_name !== svc.name && (
            <span className="svc-display-name">{svc.display_name}</span>
          )}
        </div>
        <div className="svc-badges">
          <span className="svc-state-badge" style={{ background: stateSty.bg, color: stateSty.color, border: `1px solid ${stateSty.border}` }}>
            {svc.state}
          </span>
          <span className="svc-cat-badge">{meta.label}</span>
          {svc.severity !== "info" && <SevBadge sev={svc.severity} />}
        </div>
        {hasDetail && (
          <button className="svc-detail-toggle" onClick={() => setOpen(v => !v)}>
            {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>
        )}
      </div>
      {open && (
        <div className="svc-row-body">
          {svc.description && (
            <div className="svc-desc">{svc.description}</div>
          )}
          {svc.exec_start && (
            <div className="svc-exec">
              <span className="svc-exec-label">Exec</span>
              <code>{svc.exec_start}</code>
            </div>
          )}
          {svc.run_user && svc.run_user !== "root" && svc.run_user !== "unknown" && (
            <div className="svc-exec">
              <span className="svc-exec-label">User</span>
              <code>{svc.run_user}</code>
            </div>
          )}
          {svc.unit_path && (
            <div className="svc-exec">
              <span className="svc-exec-label">Path</span>
              <code>{svc.unit_path}</code>
            </div>
          )}
          {svc.flags?.length > 0 && (
            <div className="svc-flags">
              {svc.flags.map((f, i) => (
                <span key={`${f}-${i}`} className="svc-flag"
                  style={f === "unusual-exec-path" || f === "deprecated-protocol" || f === "crypto-miner"
                    ? { background: "#fef2f2", color: "#991b1b", border: "1px solid #fecaca" }
                    : f === "unencrypted-protocol" || f === "shell-exec"
                      ? { background: "#fff7ed", color: "#92400e", border: "1px solid #fed7aa" }
                      : {}}>
                  {SVC_FLAG_LABELS[f] || f}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ServicesTab({ services = [] }) {
  const [stateFilter, setStateFilter] = useState("all");
  const [catFilter, setCatFilter] = useState("all");
  const [sevFilter, setSevFilter] = useState("all");
  const [search, setSearch] = useState("");

  if (services.length === 0)
    return <EmptyState icon={Server} message="No services detected." />;

  const filtered = services.filter(s => {
    if (stateFilter !== "all" && s.state !== stateFilter) return false;
    if (catFilter !== "all" && s.category !== catFilter) return false;
    if (sevFilter !== "all" && s.severity !== sevFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return s.name.toLowerCase().includes(q)
        || (s.display_name || "").toLowerCase().includes(q)
        || (s.description || "").toLowerCase().includes(q)
        || (s.exec_start || "").toLowerCase().includes(q);
    }
    return true;
  });

  const enabledCount = services.filter(s => s.state === "enabled").length;
  const critCount = services.filter(s => s.severity === "critical").length;
  const highCount = services.filter(s => s.severity === "high").length;

  const catCounts = services.reduce((acc, s) => {
    acc[s.category] = (acc[s.category] || 0) + 1;
    return acc;
  }, {});
  const presentCats = Object.keys(catCounts).sort();

  const STATE_FILTERS = [
    { id: "all", label: "All" },
    { id: "enabled", label: "Enabled" },
    { id: "disabled", label: "Disabled" },
    { id: "static", label: "Static" },
    { id: "masked", label: "Masked" },
    { id: "detected", label: "Detected" },
  ].filter(f => f.id === "all" || services.some(s => s.state === f.id));

  const SEV_FILTERS = [
    { id: "all", label: "All" },
    { id: "critical", label: "Critical" },
    { id: "high", label: "High" },
    { id: "medium", label: "Medium" },
    { id: "low", label: "Low" },
    { id: "info", label: "Info" },
  ].filter(f => f.id === "all" || services.some(s => s.severity === f.id));

  return (
    <div className="tab-content svc-tab">

      {/* Summary bar */}
      <div className="svc-summary-bar">
        <span className="svc-stat"><strong>{services.length}</strong> total</span>
        <span className="svc-stat" style={{ color: "#166534" }}>
          <strong>{enabledCount}</strong> enabled
        </span>
        {critCount > 0 && (
          <span className="svc-stat" style={{ color: SEV_COLOR.critical }}>
            <AlertTriangle size={11} /> <strong>{critCount}</strong> critical
          </span>
        )}
        {highCount > 0 && (
          <span className="svc-stat" style={{ color: SEV_COLOR.high }}>
            <AlertTriangle size={11} /> <strong>{highCount}</strong> high
          </span>
        )}
      </div>

      {/* Category chips */}
      <div className="svc-cat-bar">
        <button
          className={`svc-cat-chip ${catFilter === "all" ? "active" : ""}`}
          onClick={() => setCatFilter("all")}>
          All <span className="svc-chip-count">{services.length}</span>
        </button>
        {presentCats.map(cat => {
          const m = SVC_CAT_META[cat] || SVC_CAT_META.other;
          const Icon = m.Icon;
          return (
            <button key={cat}
              className={`svc-cat-chip ${catFilter === cat ? "active" : ""}`}
              onClick={() => setCatFilter(cat)}>
              <Icon size={11} /> {m.label} <span className="svc-chip-count">{catCounts[cat]}</span>
            </button>
          );
        })}
      </div>

      {/* State + Severity filters + Search */}
      <div className="svc-filter-bar">
        <div className="cfg-sev-filters">
          {STATE_FILTERS.map(({ id, label }) => (
            <button key={id}
              className={`cfg-sev-filter ${stateFilter === id ? "active" : ""}`}
              onClick={() => setStateFilter(id)}>{label}</button>
          ))}
        </div>
        <div className="cfg-sev-filters">
          {SEV_FILTERS.map(({ id, label }) => (
            <button key={id}
              className={`cfg-sev-filter ${sevFilter === id ? "active" : ""}`}
              style={sevFilter === id && id !== "all" ? { background: SEV_COLOR[id], color: "#fff" } : {}}
              onClick={() => setSevFilter(id)}>{label}</button>
          ))}
        </div>
        <input className="tl-search" placeholder="Search services…" value={search}
          onChange={e => setSearch(e.target.value)} style={{ maxWidth: 220 }} />
      </div>

      {filtered.length === 0 ? (
        <EmptyState icon={CheckCircle} message="No services match the current filter." />
      ) : (
        <div className="svc-list">
          {filtered.map((svc, i) => (
            <ServiceRow key={`${svc.source || "detected"}-${svc.name}-${i}`} svc={svc} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Browser Forensics Tab ────────────────────────────────────────────────────

const BROWSER_META = {
  chrome: { label: "Google Chrome", color: "#4285f4" },
  chromium: { label: "Chromium", color: "#2563eb" },
  brave: { label: "Brave", color: "#fb542b" },
  edge: { label: "Microsoft Edge", color: "#0078d4" },
  opera: { label: "Opera", color: "#ff1b2d" },
  vivaldi: { label: "Vivaldi", color: "#ef3939" },
  yandex: { label: "Yandex", color: "#ffcc00" },
  firefox: { label: "Firefox", color: "#ff9500" },
  waterfox: { label: "Waterfox", color: "#00acda" },
  librewolf: { label: "LibreWolf", color: "#00adef" },
  icecat: { label: "GNU IceCat", color: "#5b9bd5" },
  tor: { label: "Tor Browser", color: "#7d4698" },
};

function AntiForensicsTab({ findings = [], timelineAI }) {
  if (findings.length === 0 && !timelineAI?.anti_forensics_report)
    return <EmptyState icon={ShieldAlert} message="No anti-forensics artifacts detected." />;

  const afReport = timelineAI?.anti_forensics_report;

  return (
    <div className="tab-content af-tab animate-fade-in">
      {/* AI Enhanced Section */}
      {afReport && (
        <div className="af-ai-card">
          <div className="card-header af-ai-header">
            <h3><Zap size={16} /> AI Predictive Assessment</h3>
            <span className="ai-badge">AI INSIGHT</span>
          </div>
          <div className="af-ai-content">
            <div className="af-intent">
              <span className="intent-label">ESTIMATED INTENT:</span>
              <span className="intent-value">{afReport.predicted_intent}</span>
            </div>
            <div className="af-findings-grid">
              {(afReport.findings || []).map((f, i) => (
                <div key={i} className={`af-ai-finding sev-${f.severity || 'info'}`}>
                  <div className="af-ai-title">{f.technique}</div>
                  <p>{f.description}</p>
                  <div className="af-ai-evidence"><strong>Evidence:</strong> {f.evidence}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Deep Scanner Findings */}
      <h3 className="section-title"><Terminal size={16} /> Deep Scanner Detections</h3>
      <div className="af-grid">
        {findings.map((f, i) => (
          <div key={i} className={`af-card sev-${f.severity} animate-slide-up`} style={{ animationDelay: `${i * 0.05}s` }}>
            <div className="af-card-header">
              <span className="af-cat-tag">{f.category.toUpperCase()}</span>
              <span className={`af-sev-pill sev-${f.severity}`}>{f.severity.toUpperCase()}</span>
            </div>
            <div className="af-tech">{f.technique}</div>
            <div className="af-detail">{f.detail}</div>
            {f.path && <div className="af-path"><code>{f.path}</code></div>}
            {f.evidence && f.evidence.length > 0 && (
              <div className="af-evidence">
                <strong>Forensic Evidence:</strong>
                <ul>{f.evidence.map((exc, j) => <li key={j}>{exc}</li>)}</ul>
              </div>
            )}
          </div>
        ))}
        {findings.length === 0 && (
          <div className="af-empty-sub">No deep scanner detections found.</div>
        )}
      </div>
    </div>
  );
}

const BW_ARTIFACT_TABS = [
  { id: "history", label: "History", emptyMsg: "No history found." },
  { id: "downloads", label: "Downloads", emptyMsg: "No downloads found." },
  { id: "bookmarks", label: "Bookmarks", emptyMsg: "No bookmarks found." },
  { id: "cookies", label: "Cookies", emptyMsg: "No cookies found." },
  { id: "extensions", label: "Extensions", emptyMsg: "No extensions found." },
  { id: "logins", label: "Logins", emptyMsg: "No saved logins found." },
  { id: "search_terms", label: "Searches", emptyMsg: "No search terms found." },
  { id: "autofill", label: "Autofill", emptyMsg: "No autofill data found." },
];

const BW_FLAG_LABELS = {
  "saved-passwords": "Saved passwords",
  "suspicious-downloads": "Suspicious downloads",
  "suspicious-history": "Suspicious history",
  "suspicious-extensions": "Suspicious extensions",
  "suspicious-searches": "Suspicious searches",
  "wiped-history": "History wiped",
  "credential-store": "Credential store present",
  "saved-credentials": "Saved credentials",
  "executable": "Executable file",
  "suspicious-url": "Suspicious URL",
  "suspicious-search": "Suspicious search",
  "not-secure": "Non-secure flag",
  "not-httponly": "Missing HttpOnly",
  "unsigned": "Unsigned extension",
};

function BwFlagChip({ flag }) {
  const label = BW_FLAG_LABELS[flag] || flag.replace(/^perm:/, "perm: ");
  const isHigh = ["saved-passwords", "saved-credentials", "suspicious-searches", "suspicious-extensions", "wiped-history"].includes(flag)
    || flag.startsWith("perm:") && ["<all_urls>", "*://*/*", "webRequestBlocking", "proxy", "nativeMessaging", "debugger", "management"].some(p => flag.includes(p));
  const isMed = ["suspicious-downloads", "suspicious-history", "suspicious-url", "credential-store", "executable", "unsigned"].includes(flag)
    || flag.startsWith("perm:");
  const style = isHigh
    ? { background: "#fef2f2", color: "#991b1b", border: "1px solid #fecaca" }
    : isMed
      ? { background: "#fff7ed", color: "#92400e", border: "1px solid #fed7aa" }
      : { background: "var(--bg-hover)", color: "var(--fg-muted)", border: "1px solid var(--border-lt)" };
  return <span className="bw-flag-chip" style={style}>{label}</span>;
}

/* ── Artifact-type sub-tables ─────────────────────── */

function BwHistoryTable({ rows, search }) {
  const vis = rows.filter(r => !search || r.url?.toLowerCase().includes(search) || r.title?.toLowerCase().includes(search));
  if (!vis.length) return <div className="bw-empty">No entries match the filter.</div>;
  return (
    <div className="bw-table-wrap">
      <table className="bw-table">
        <thead><tr><th>URL / Title</th><th>Visits</th><th>Last Visit</th><th>Flags</th></tr></thead>
        <tbody>
          {vis.map((r, i) => (
            <tr key={i} className={r.severity !== "info" ? "bw-row-flagged" : ""}>
              <td className="bw-url-cell">
                <div className="bw-url">{r.url}</div>
                {r.title && <div className="bw-subtitle">{r.title}</div>}
              </td>
              <td className="bw-num">{r.visit_count || "—"}</td>
              <td className="bw-ts">{r.last_visit || "—"}</td>
              <td>{(r.flags || []).map(f => <BwFlagChip key={f} flag={f} />)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BwDownloadsTable({ rows, search }) {
  const vis = rows.filter(r => !search || r.url?.toLowerCase().includes(search) || r.target_path?.toLowerCase().includes(search));
  if (!vis.length) return <div className="bw-empty">No entries match the filter.</div>;
  return (
    <div className="bw-table-wrap">
      <table className="bw-table">
        <thead><tr><th>Source URL</th><th>Target Path</th><th>MIME / Size</th><th>Started</th><th>Flags</th></tr></thead>
        <tbody>
          {vis.map((r, i) => (
            <tr key={i} className={r.severity !== "info" ? "bw-row-flagged" : ""}>
              <td className="bw-url-cell"><div className="bw-url">{r.url || "—"}</div></td>
              <td className="bw-url-cell"><div className="bw-mono">{r.target_path || "—"}</div></td>
              <td className="bw-ts">{r.mime_type || "—"}{r.total_bytes > 0 && ` · ${(r.total_bytes / 1024).toFixed(0)} KB`}</td>
              <td className="bw-ts">{r.start_time || "—"}</td>
              <td>{(r.flags || []).map(f => <BwFlagChip key={f} flag={f} />)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BwBookmarksTable({ rows, search }) {
  const vis = rows.filter(r => !search || r.url?.toLowerCase().includes(search) || r.title?.toLowerCase().includes(search));
  if (!vis.length) return <div className="bw-empty">No entries match the filter.</div>;
  return (
    <div className="bw-table-wrap">
      <table className="bw-table">
        <thead><tr><th>Title</th><th>URL</th><th>Folder</th><th>Added</th></tr></thead>
        <tbody>
          {vis.map((r, i) => (
            <tr key={i}>
              <td>{r.title || "—"}</td>
              <td className="bw-url-cell"><div className="bw-url">{r.url}</div></td>
              <td className="bw-ts">{r.folder || "—"}</td>
              <td className="bw-ts">{r.date_added || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BwCookiesTable({ rows, search }) {
  const vis = rows.filter(r => !search || r.host?.toLowerCase().includes(search) || r.name?.toLowerCase().includes(search));
  if (!vis.length) return <div className="bw-empty">No entries match the filter.</div>;
  return (
    <div className="bw-table-wrap">
      <table className="bw-table">
        <thead><tr><th>Host</th><th>Name</th><th>Secure</th><th>HttpOnly</th><th>Expires</th><th>Flags</th></tr></thead>
        <tbody>
          {vis.map((r, i) => (
            <tr key={i} className={r.severity !== "info" ? "bw-row-flagged" : ""}>
              <td className="bw-mono">{r.host}</td>
              <td className="bw-mono">{r.name}</td>
              <td className="bw-center">{r.is_secure ? "✓" : <span style={{ color: "#dc2626" }}>✗</span>}</td>
              <td className="bw-center">{r.is_httponly ? "✓" : <span style={{ color: "#dc2626" }}>✗</span>}</td>
              <td className="bw-ts">{r.expires || "session"}</td>
              <td>{(r.flags || []).map(f => <BwFlagChip key={f} flag={f} />)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BwExtensionsTable({ rows, search }) {
  const vis = rows.filter(r => !search || r.name?.toLowerCase().includes(search) || r.id?.toLowerCase().includes(search));
  if (!vis.length) return <div className="bw-empty">No entries match the filter.</div>;
  return (
    <div className="bw-table-wrap">
      <table className="bw-table">
        <thead><tr><th>Name</th><th>ID</th><th>Version</th><th>Risk Permissions</th></tr></thead>
        <tbody>
          {vis.map((r, i) => (
            <tr key={i} className={r.severity !== "info" ? "bw-row-flagged" : ""}>
              <td>
                <div style={{ fontWeight: 600 }}>{r.name}</div>
                {r.description && <div className="bw-subtitle">{r.description}</div>}
                <SevBadge sev={r.severity} />
              </td>
              <td className="bw-mono" style={{ fontSize: 10 }}>{r.id}</td>
              <td className="bw-ts">{r.version || "—"}</td>
              <td>{(r.flags || []).map(f => <BwFlagChip key={f} flag={f} />)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BwLoginsTable({ rows, search }) {
  const vis = rows.filter(r => !search || r.origin?.toLowerCase().includes(search) || r.username?.toLowerCase().includes(search));
  if (!vis.length) return <div className="bw-empty">No entries match the filter.</div>;
  return (
    <div className="bw-table-wrap">
      <table className="bw-table">
        <thead><tr><th>Origin URL</th><th>Username</th><th>Created</th><th>Used</th></tr></thead>
        <tbody>
          {vis.map((r, i) => (
            <tr key={i} className="bw-row-flagged">
              <td className="bw-url-cell"><div className="bw-url">{r.origin || "—"}</div></td>
              <td className="bw-mono">{r.username || "—"}</td>
              <td className="bw-ts">{r.date_created || "—"}</td>
              <td className="bw-num">{r.times_used ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BwSearchesTable({ rows, search }) {
  const vis = rows.filter(r => !search || r.term?.toLowerCase().includes(search));
  if (!vis.length) return <div className="bw-empty">No entries match the filter.</div>;
  return (
    <div className="bw-table-wrap">
      <table className="bw-table">
        <thead><tr><th>Search Term</th><th>Source</th><th>Flags</th></tr></thead>
        <tbody>
          {vis.map((r, i) => (
            <tr key={i} className={r.severity === "high" ? "bw-row-flagged" : ""}>
              <td style={{ fontWeight: r.severity === "high" ? 700 : 400 }}>{r.term}</td>
              <td className="bw-ts">{r.engine || "—"}</td>
              <td>{(r.flags || []).map(f => <BwFlagChip key={f} flag={f} />)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BwAutofillTable({ rows, search }) {
  const vis = rows.filter(r => !search || r.field?.toLowerCase().includes(search) || r.value?.toLowerCase().includes(search));
  if (!vis.length) return <div className="bw-empty">No entries match the filter.</div>;
  return (
    <div className="bw-table-wrap">
      <table className="bw-table">
        <thead><tr><th>Field Name</th><th>Value</th><th>Count</th></tr></thead>
        <tbody>
          {vis.map((r, i) => (
            <tr key={i}>
              <td className="bw-mono">{r.field}</td>
              <td>{r.value}</td>
              <td className="bw-num">{r.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BrowserProfileView({ profile }) {
  const [artifactTab, setArtifactTab] = useState("history");
  const [search, setSearch] = useState("");

  const meta = BROWSER_META[profile.browser] || { label: profile.browser_label, color: "#6b7280" };
  const counts = {
    history: (profile.history || []).length,
    downloads: (profile.downloads || []).length,
    bookmarks: (profile.bookmarks || []).length,
    cookies: (profile.cookies || []).length,
    extensions: (profile.extensions || []).length,
    logins: (profile.logins || []).length,
    search_terms: (profile.search_terms || []).length,
    autofill: (profile.autofill || []).length,
  };
  const q = search.toLowerCase();

  return (
    <div className="bw-profile-view">
      {/* Profile header */}
      <div className="bw-profile-header">
        <span className="bw-browser-dot" style={{ background: meta.color }} />
        <span className="bw-profile-title">
          <strong>{meta.label}</strong>
          <span className="bw-profile-sub"> / {profile.user} / {profile.profile}</span>
        </span>
        <SevBadge sev={profile.severity} />
        {(profile.flags || []).map(f => <BwFlagChip key={f} flag={f} />)}
      </div>

      {/* Artifact sub-tabs */}
      <div className="bw-artifact-tabbar">
        {BW_ARTIFACT_TABS.map(({ id, label }) => (
          <button key={id}
            className={`bw-artifact-tab ${artifactTab === id ? "active" : ""}`}
            onClick={() => { setArtifactTab(id); setSearch(""); }}>
            {label}
            {counts[id] > 0 && <span className="bw-art-count">{counts[id]}</span>}
          </button>
        ))}
      </div>

      {/* Search */}
      <div className="bw-artifact-search">
        <input className="tl-search" placeholder="Filter…" value={search}
          onChange={e => setSearch(e.target.value)} style={{ maxWidth: 280 }} />
        <span className="bw-row-count">{counts[artifactTab]} item{counts[artifactTab] !== 1 ? "s" : ""}</span>
      </div>

      {/* Table */}
      <div className="bw-artifact-body">
        {artifactTab === "history" && (counts.history > 0 ? <BwHistoryTable rows={profile.history} search={q} /> : <div className="bw-empty">No history found.</div>)}
        {artifactTab === "downloads" && (counts.downloads > 0 ? <BwDownloadsTable rows={profile.downloads} search={q} /> : <div className="bw-empty">No downloads found.</div>)}
        {artifactTab === "bookmarks" && (counts.bookmarks > 0 ? <BwBookmarksTable rows={profile.bookmarks} search={q} /> : <div className="bw-empty">No bookmarks found.</div>)}
        {artifactTab === "cookies" && (counts.cookies > 0 ? <BwCookiesTable rows={profile.cookies} search={q} /> : <div className="bw-empty">No cookies found.</div>)}
        {artifactTab === "extensions" && (counts.extensions > 0 ? <BwExtensionsTable rows={profile.extensions} search={q} /> : <div className="bw-empty">No extensions found.</div>)}
        {artifactTab === "logins" && (counts.logins > 0 ? <BwLoginsTable rows={profile.logins} search={q} /> : <div className="bw-empty">No saved logins found.</div>)}
        {artifactTab === "search_terms" && (counts.search_terms > 0 ? <BwSearchesTable rows={profile.search_terms} search={q} /> : <div className="bw-empty">No search terms found.</div>)}
        {artifactTab === "autofill" && (counts.autofill > 0 ? <BwAutofillTable rows={profile.autofill} search={q} /> : <div className="bw-empty">No autofill data found.</div>)}
      </div>
    </div>
  );
}

function BrowserTab({ browsers = [] }) {
  const [selected, setSelected] = useState(0);

  if (!browsers || browsers.length === 0)
    return <EmptyState icon={Globe} message="No browser profiles detected." />;

  const cur = browsers[selected] || browsers[0];

  const totalHistory = browsers.reduce((n, b) => n + (b.history || []).length, 0);
  const totalDownloads = browsers.reduce((n, b) => n + (b.downloads || []).length, 0);
  const totalLogins = browsers.reduce((n, b) => n + (b.logins || []).length, 0);
  const totalExts = browsers.reduce((n, b) => n + (b.extensions || []).length, 0);

  return (
    <div className="bw-tab">
      {/* Stats bar */}
      <div className="bw-stats-bar">
        <span className="bw-stat"><strong>{browsers.length}</strong> profile{browsers.length !== 1 ? "s" : ""}</span>
        <span className="bw-stat"><strong>{totalHistory.toLocaleString()}</strong> history entries</span>
        <span className="bw-stat"><strong>{totalDownloads}</strong> downloads</span>
        {totalLogins > 0 && (
          <span className="bw-stat" style={{ color: SEV_COLOR.high }}>
            <Lock size={11} /><strong>{totalLogins}</strong> saved login{totalLogins !== 1 ? "s" : ""}
          </span>
        )}
        <span className="bw-stat"><strong>{totalExts}</strong> extension{totalExts !== 1 ? "s" : ""}</span>
      </div>

      <div className="bw-layout">
        {/* Sidebar: profile list */}
        <div className="bw-sidebar">
          {browsers.map((p, i) => {
            const m = BROWSER_META[p.browser] || { label: p.browser_label, color: "#6b7280" };
            return (
              <button key={i}
                className={`bw-profile-btn ${selected === i ? "active" : ""}`}
                onClick={() => setSelected(i)}>
                <span className="bw-browser-dot" style={{ background: m.color }} />
                <div className="bw-profile-btn-text">
                  <span className="bw-profile-btn-name">{m.label}</span>
                  <span className="bw-profile-btn-sub">{p.user} · {p.profile}</span>
                </div>
                {p.severity !== "info" && (
                  <span className="bw-sev-dot" style={{ background: SEV_COLOR[p.severity] || "#6b7280" }} />
                )}
              </button>
            );
          })}
        </div>

        {/* Main content */}
        <div className="bw-main">
          <BrowserProfileView profile={cur} />
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MULTIMEDIA TAB
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Bit-Plane / Visual Forensics Analyser ────────────────────────────────────
function BitPlaneAnalyzer({ findings = [], imgPath }) {
  const [selectedPath, setSelectedPath] = useState(null);
  const [channel, setChannel]           = useState("gray"); // "gray"|"r"|"g"|"b"
  const [loadStatus, setLoadStatus]     = useState("idle"); // "idle"|"loading"|"ready"|"error"
  const [loadErr, setLoadErr]           = useState(null);
  const [pixelCache, setPixelCache]     = useState(null);   // { data, w, h }
  const [renderedPlanes, setRenderedPlanes]   = useState([]); // [{bit, dataUrl, label}]
  const [channelCanvases, setChannelCanvases] = useState([]); // [{label, dataUrl}]
  const [imgDims, setImgDims]           = useState(null);
  const [zoomPlane, setZoomPlane]       = useState(null);   // bit number being zoomed

  const imageItems = (findings || []).filter(f => f.media_type === "image");

  // Auto-select first image when findings arrive
  useEffect(() => {
    if (imageItems.length > 0 && !selectedPath) {
      setSelectedPath(imageItems[0].path);
    }
  }, [findings]); // eslint-disable-line

  // Load image → cache raw pixels
  useEffect(() => {
    if (!selectedPath || !imgPath) return;
    setLoadStatus("loading");
    setLoadErr(null);
    setPixelCache(null);
    setRenderedPlanes([]);
    setChannelCanvases([]);
    setZoomPlane(null);

    const url = apiMediaUrl(imgPath, selectedPath);
    const img = new window.Image();
    img.crossOrigin = "anonymous";

    img.onload = () => {
      try {
        const w = img.naturalWidth;
        const h = img.naturalHeight;
        setImgDims({ w, h });

        const src = document.createElement("canvas");
        src.width = w; src.height = h;
        const ctx = src.getContext("2d");
        ctx.drawImage(img, 0, 0);
        // Copy pixel data out of the canvas before it goes out of scope
        const id = ctx.getImageData(0, 0, w, h);
        // Store as plain Uint8Array so React state serialisation is clean
        setPixelCache({ data: new Uint8Array(id.data.buffer), w, h });
        setLoadStatus("ready");
      } catch (e) {
        setLoadErr(`Canvas read failed: ${e.message}. The image may be blocked by CORS.`);
        setLoadStatus("error");
      }
    };
    img.onerror = () => {
      setLoadErr("Image failed to load – check the backend is running.");
      setLoadStatus("error");
    };
    img.src = url;
  }, [selectedPath, imgPath]);

  // Re-render bit-planes + channel separation whenever cache or channel changes
  useEffect(() => {
    if (!pixelCache) return;
    const { data: px, w, h } = pixelCache;

    // Helper: sample the chosen channel for pixel index i
    const sample = (i) => {
      const ri = i * 4;
      if (channel === "r") return px[ri];
      if (channel === "g") return px[ri + 1];
      if (channel === "b") return px[ri + 2];
      // gray = rec-601 luminance
      return Math.round(0.299 * px[ri] + 0.587 * px[ri + 1] + 0.114 * px[ri + 2]);
    };

    // Draw a single canvas from a per-pixel callback, return dataURL
    const makeCanvas = (perPixelRGBA) => {
      const c = document.createElement("canvas");
      c.width = w; c.height = h;
      const ctx = c.getContext("2d");
      const id  = ctx.createImageData(w, h);
      const d   = id.data;
      for (let i = 0; i < w * h; i++) {
        const ri = i * 4;
        perPixelRGBA(i, ri, d);
        d[ri + 3] = 255;
      }
      ctx.putImageData(id, 0, 0);
      return c.toDataURL();
    };

    // 8 bit planes: bit 7 (MSB) → bit 0 (LSB)
    const planes = [];
    for (let bit = 7; bit >= 0; bit--) {
      const dataUrl = makeCanvas((i, ri, d) => {
        const v = ((sample(i) >> bit) & 1) ? 255 : 0;
        d[ri] = v; d[ri + 1] = v; d[ri + 2] = v;
      });
      planes.push({
        bit,
        dataUrl,
        label: bit === 7 ? "Bit 7 — MSB" : bit === 0 ? "Bit 0 — LSB" : `Bit ${bit}`,
      });
    }
    setRenderedPlanes(planes);

    // Channel separation strip (always shows all 4 regardless of selector)
    const chDefs = [
      { key: "lum",  label: "Luminance" },
      { key: "r",    label: "Red"       },
      { key: "g",    label: "Green"     },
      { key: "b",    label: "Blue"      },
    ];
    const chCanvases = chDefs.map(({ key, label }) => {
      const dataUrl = makeCanvas((i, ri, d) => {
        if (key === "lum") {
          const v = Math.round(0.299 * px[ri] + 0.587 * px[ri+1] + 0.114 * px[ri+2]);
          d[ri] = v; d[ri+1] = v; d[ri+2] = v;
        } else if (key === "r") {
          d[ri] = px[ri]; d[ri+1] = 0; d[ri+2] = 0;
        } else if (key === "g") {
          d[ri] = 0; d[ri+1] = px[ri+1]; d[ri+2] = 0;
        } else {
          d[ri] = 0; d[ri+1] = 0; d[ri+2] = px[ri+2];
        }
      });
      return { label, dataUrl };
    });
    setChannelCanvases(chCanvases);
  }, [pixelCache, channel]);

  if (!imageItems.length) {
    return (
      <EmptyState
        icon={Image}
        message="No image files available. Run a multimedia scan to populate image files."
      />
    );
  }

  const CHANNEL_OPTS = [
    { id: "gray", label: "Grayscale" },
    { id: "r",    label: "Red"       },
    { id: "g",    label: "Green"     },
    { id: "b",    label: "Blue"      },
  ];

  return (
    <div className="bp-container">
      {/* ── Toolbar ─────────────────────────────────────────── */}
      <div className="bp-toolbar">
        <label className="bp-label">Image</label>
        <select
          className="input bp-select"
          value={selectedPath || ""}
          onChange={e => setSelectedPath(e.target.value)}
        >
          {imageItems.map(f => (
            <option key={f.path} value={f.path}>
              {f.name || f.path.split("/").pop()}
            </option>
          ))}
        </select>

        <span className="bp-divider" />

        <label className="bp-label">Channel</label>
        <div className="bp-channel-btns">
          {CHANNEL_OPTS.map(o => (
            <button
              key={o.id}
              className={"btn-pill btn-xs" + (channel === o.id ? " btn-pill-active" : "")}
              onClick={() => setChannel(o.id)}
            >
              {o.label}
            </button>
          ))}
        </div>

        {imgDims && (
          <span className="bp-dims">
            {imgDims.w} × {imgDims.h} px
          </span>
        )}
      </div>

      {/* ── States ──────────────────────────────────────────── */}
      {loadStatus === "loading" && (
        <div className="bp-loading">
          <Loader2 size={18} className="spin" style={{ marginRight: 8 }} />
          Loading image pixels…
        </div>
      )}
      {loadStatus === "error" && (
        <div className="dlg-error" style={{ margin: "12px 0" }}>{loadErr}</div>
      )}

      {/* ── Content ─────────────────────────────────────────── */}
      {loadStatus === "ready" && (
        <>
          {/* Channel Separation */}
          <div className="bp-section-hdr">
            <Layers size={13} /> Channel Separation
          </div>
          <div className="bp-ch-row">
            {channelCanvases.map(c => (
              <div key={c.label} className="bp-ch-card">
                <img src={c.dataUrl} alt={c.label} className="bp-ch-img" />
                <div className="bp-ch-label">{c.label}</div>
              </div>
            ))}
          </div>

          {/* Bit-Plane Grid */}
          <div className="bp-section-hdr" style={{ marginTop: 20 }}>
            <Eye size={13} />
            Bit-Plane Dissection — {CHANNEL_OPTS.find(o => o.id === channel)?.label} channel
            <span className="bp-hint">Bit 7 = MSB &nbsp;·&nbsp; Bit 0 = LSB (primary steganography plane)</span>
          </div>
          <div className="bp-planes-grid">
            {renderedPlanes.map(p => (
              <div
                key={p.bit}
                className={"bp-plane-card" + (p.bit === 0 ? " bp-lsb-card" : p.bit === 7 ? " bp-msb-card" : "")}
                onClick={() => setZoomPlane(p.bit === zoomPlane ? null : p.bit)}
                title="Click to zoom"
              >
                <img
                  src={p.dataUrl}
                  alt={p.label}
                  className={"bp-plane-img" + (zoomPlane === p.bit ? " bp-plane-zoomed" : "")}
                />
                <div className="bp-plane-label">
                  {p.label}
                  {p.bit === 0 && <span className="bp-badge bp-badge-lsb">LSB</span>}
                  {p.bit === 7 && <span className="bp-badge bp-badge-msb">MSB</span>}
                </div>
              </div>
            ))}
          </div>
          <p className="bp-info-note">
            <Info size={11} />
            In steganography detection the <strong>LSB (Bit 0)</strong> plane is studied first — hidden data
            injected into the least-significant bits produces a random, noisy pattern rather than the
            smooth gradients seen in natural images. Compare the LSB plane with Bit 1 and Bit 2 for
            anomalous uniformity or structure.
          </p>
        </>
      )}

      {/* Zoom overlay */}
      {zoomPlane !== null && renderedPlanes.length > 0 && (
        <div className="bp-zoom-overlay" onClick={() => setZoomPlane(null)}>
          <div className="bp-zoom-modal" onClick={e => e.stopPropagation()}>
            <div className="bp-zoom-hdr">
              <span>{renderedPlanes.find(p => p.bit === zoomPlane)?.label}</span>
              <button className="mv-close" onClick={() => setZoomPlane(null)}><X size={16} /></button>
            </div>
            <img
              src={renderedPlanes.find(p => p.bit === zoomPlane)?.dataUrl}
              alt={`bit ${zoomPlane}`}
              className="bp-zoom-img"
            />
          </div>
        </div>
      )}
    </div>
  );
}

const MM_TYPE_META = {
  image: { Icon: Image, label: "Image", color: "#7c3aed" },
  video: { Icon: Film, label: "Video", color: "#2563eb" },
  audio: { Icon: Music, label: "Audio", color: "#16a34a" },
  media: { Icon: Layers, label: "Media", color: "#6b7280" },
};

function GpsLink({ gps }) {
  if (!gps?.lat || !gps?.lon) return null;
  const url = gps.maps_url || `https://www.google.com/maps?q=${gps.lat},${gps.lon}`;
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" className="mm-gps-link">
      <MapPin size={11} /> {gps.lat.toFixed(5)}, {gps.lon.toFixed(5)}
      {gps.alt_m != null && <span style={{ marginLeft: 4, opacity: 0.7 }}>({gps.alt_m}m)</span>}
    </a>
  );
}

function MetaTable({ meta }) {
  const SKIP = new Set(["mime_detected", "has_embedded_thumbnail", "gps_lat", "gps_lon",
    "gps_maps_url", "gps_alt_m", "width_px", "height_px"]);
  const entries = Object.entries(meta || {}).filter(([k]) => !SKIP.has(k));
  if (!entries.length) return null;
  return (
    <table className="mm-meta-table">
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k}>
            <td className="mm-meta-key">{k.replace(/_/g, " ")}</td>
            <td className="mm-meta-val">{String(v)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function StreamsTable({ streams }) {
  if (!streams || !streams.length) return null;
  return (
    <div className="mm-streams">
      {streams.map((s, i) => (
        <span key={i} className="mm-stream-tag">
          {s.type === "video" ? <Film size={10} /> : <Music size={10} />}
          {" "}{s.codec || s.type}
          {s.width && ` ${s.width}×${s.height}`}
          {s.fps && ` @ ${s.fps}`}
          {s.sample_rate && ` ${s.sample_rate}Hz`}
          {s.channels && ` ${s.channels}ch`}
        </span>
      ))}
    </div>
  );
}

function EmbeddedThumbnail({ thumbnail }) {
  if (!thumbnail?.data_uri) return null;
  return (
    <div className="mm-thumb-wrap">
      <img src={thumbnail.data_uri} alt="EXIF thumbnail"
        className="mm-thumb"
        title={`${thumbnail.width}×${thumbnail.height}`} />
      <span className="mm-thumb-label">EXIF thumbnail {thumbnail.width}×{thumbnail.height}</span>
    </div>
  );
}

// ─── Media viewer modal ───────────────────────────────────────────────────────
function MediaViewerModal({ item, imgPath, onClose, onPrev, onNext, hasPrev, hasNext }) {
  const viewUrl = apiMediaUrl(imgPath, item.path);
  const isImage = item.media_type === "image";
  const isVideo = item.media_type === "video";
  const fname = item.path.split("/").pop();
  const [showMeta, setShowMeta] = useState(false);

  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape") onClose();
      if (e.key === "ArrowLeft" && hasPrev) onPrev();
      if (e.key === "ArrowRight" && hasNext) onNext();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [hasPrev, hasNext, onClose, onPrev, onNext]);

  const meta = item.metadata || {};
  const metaChips = [
    meta.make && `${meta.make}${meta.model ? " " + meta.model : ""}`,
    meta.datetime_original,
    meta.width_px && `${meta.width_px}×${meta.height_px}`,
    meta.duration_s && `${meta.duration_s}s`,
    meta.software && `Software: ${meta.software}`,
    item.gps?.lat && `GPS: ${item.gps.lat.toFixed(4)}, ${item.gps.lon.toFixed(4)}`,
  ].filter(Boolean);

  return (
    <div className="mv-overlay" onClick={onClose}>
      <div className="mv-modal" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="mv-header">
          <span className="mv-fname">{fname}</span>
          <span className="mv-path" title={item.path}>{item.path}</span>
          <div className="mv-header-actions">
            <a className="mv-download-btn" href={viewUrl} download={fname}>
              <Download size={13} /> Download
            </a>
            <button
              className="btn-secondary btn-sm"
              type="button"
              onClick={() => setShowMeta((v) => !v)}
            >
              EXIF / metadata
            </button>
            <button className="mv-close" onClick={onClose} title="Close (Esc)">
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Content area with side-nav arrows */}
        <div className="mv-content-wrap">
          <button className="mv-side-btn mv-side-prev" onClick={onPrev} disabled={!hasPrev} title="Previous (←)">
            ‹
          </button>

          <div className="mv-content">
            {isImage && <img src={viewUrl} alt={fname} className="mv-img" />}
            {isVideo && (
              <video controls autoPlay className="mv-video">
                <source src={viewUrl} />
              </video>
            )}
            {!isImage && !isVideo && (
              <div className="mv-audio-wrap">
                <Music size={64} className="mv-audio-icon" />
                <div className="mv-audio-fname">{fname}</div>
                <audio controls autoPlay className="mv-audio">
                  <source src={viewUrl} />
                </audio>
              </div>
            )}
          </div>

          <button className="mv-side-btn mv-side-next" onClick={onNext} disabled={!hasNext} title="Next (→)">
            ›
          </button>
        </div>

        {/* Metadata chips + detailed table */}
        {metaChips.length > 0 && (
          <div className="mv-meta-bar">
            {metaChips.map((c, i) => (
              <span key={i} className="mv-meta-chip">
                {c}
              </span>
            ))}
          </div>
        )}
        {showMeta && (
          <div style={{ marginTop: 8 }}>
            <table className="mm-meta-table">
              <tbody>
                {Object.entries(meta).map(([k, v]) => (
                  <tr key={k}>
                    <td className="mm-meta-key">{k}</td>
                    <td className="mm-meta-val">
                      {typeof v === "object" ? JSON.stringify(v) : String(v)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function MediaCard({ item, imgPath, onView }) {
  const mt = MM_TYPE_META[item.media_type] || MM_TYPE_META.media;
  const Icon = mt.Icon;
  const isFlagged = item.severity === "high" || item.severity === "critical";
  const fname = item.name || item.path.split("/").pop();
  const viewUrl = imgPath ? apiMediaUrl(imgPath, item.path) : null;

  const fmtSize = (n) => {
    if (!n) return "";
    if (n < 1024) return `${n}B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)}KB`;
    return `${(n / 1024 ** 2).toFixed(1)}MB`;
  };

  return (
    <div className="mm-card" onClick={() => onView(item)}>
      <div className="mm-card-preview">
        {viewUrl && item.media_type === "image" ? (
          <img src={viewUrl} alt={fname} className="mm-card-img" />
        ) : (
          <Icon size={48} className="mm-card-icon-overlay" />
        )}
        <div className="mm-card-type-badge">{item.media_type}</div>
        {isFlagged && <div className="mm-card-flag">FLAGGED</div>}
      </div>
      <div className="mm-card-info">
        <div className="mm-card-name" title={fname}>{fname}</div>
        <div className="mm-card-path" title={item.path}>{item.path}</div>
        <div className="mm-card-footer">
          <span className="mm-card-size">{fmtSize(item.size)}</span>
          <SevBadge sev={item.severity} />
        </div>
      </div>
    </div>
  );
}

function MultimediaTab({ findings = [], imgPath }) {
  const [filterType, setFilterType] = useState("all");
  const [filterSev, setFilterSev] = useState("all");
  const [search, setSearch] = useState("");
  const [subtab, setSubtab] = useState("gallery"); // "gallery" | "stego" | "bitplanes"
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState(null);
  const [localFindings, setLocalFindings] = useState(findings);
  const [viewItem, setViewItem] = useState(null);
  const [viewMode, setViewMode] = useState("grid"); // "grid" | "list"

  // Sync when parent report findings change
  useEffect(() => { setLocalFindings(findings); }, [findings]);

  const items = (localFindings || []).filter(item => {
    if (filterType !== "all" && item.media_type !== filterType) return false;
    if (filterSev !== "all" && item.severity !== filterSev) return false;
    if (search) {
      const q = search.toLowerCase();
      return item.path?.toLowerCase().includes(q) ||
        item.findings?.some(f => f.toLowerCase().includes(q));
    }
    return true;
  });

  const counts = {
    image: (localFindings || []).filter(i => i.media_type === "image").length,
    video: (localFindings || []).filter(i => i.media_type === "video").length,
    audio: (localFindings || []).filter(i => i.media_type === "audio").length,
  };
  const flagged = (localFindings || []).filter(i => i.severity !== "info").length;
  const withGps = (localFindings || []).filter(i => i.gps?.lat).length;

  const stegoItems = (localFindings || []).filter(i =>
    (i.flags || []).some(f =>
      ["high-entropy", "lsb-stego-suspected", "appended-data", "size-anomaly"].includes(f)
    )
  );

  const handleRescan = async () => {
    if (!imgPath) return;
    setRunning(true); setErr(null);
    try {
      const data = await apiMultimedia(imgPath);
      setLocalFindings(data.multimedia || []);
    } catch (e) {
      setErr(e.message);
    } finally {
      setRunning(false);
    }
  };

  if (!localFindings || localFindings.length === 0) {
    return (
      <div className="tab-content">
        <EmptyState icon={Image} message="No media files analysed." />
        {imgPath && (
          <div style={{ textAlign: "center", marginTop: 12 }}>
            <button className="btn-primary btn-sm" onClick={handleRescan} disabled={running}>
              {running ? "Scanning…" : "Scan for Media Files"}
            </button>
            {err && <div className="dlg-error" style={{ marginTop: 12 }}>{err}</div>}
          </div>
        )}
      </div>
    );
  }
  const hasItems = items.length > 0;
  const currentIndex = viewItem
    ? items.findIndex((i) => i.path === viewItem.path)
    : -1;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < items.length - 1;

  const handleView = (item) => setViewItem(item);
  const handlePrev = () => {
    if (!hasPrev) return;
    setViewItem(items[currentIndex - 1]);
  };
  const handleNext = () => {
    if (!hasNext) return;
    setViewItem(items[currentIndex + 1]);
  };

  return (
    <div className="tab-content">
      {/* Summary bar */}
      <div className="mm-summary-bar">
        <span className="del-sum-chip neutral">
          <Image size={11} /> {localFindings.length} media files
        </span>
        {counts.image > 0 && (
          <span className="del-sum-chip">
            Images: {counts.image}
          </span>
        )}
        {counts.video > 0 && (
          <span className="del-sum-chip">
            Videos: {counts.video}
          </span>
        )}
        {counts.audio > 0 && (
          <span className="del-sum-chip">
            Audio: {counts.audio}
          </span>
        )}
        {flagged > 0 && (
          <span className="del-sum-chip red">
            <AlertTriangle size={11} /> {flagged} flagged
          </span>
        )}
        {withGps > 0 && (
          <span className="del-sum-chip">
            <MapPin size={11} /> {withGps} with GPS
          </span>
        )}
        {imgPath && (
          <button
            className="btn-secondary btn-xs"
            onClick={handleRescan}
            disabled={running}
            style={{ marginLeft: "auto" }}
          >
            {running ? "Scanning…" : "Rescan"}
          </button>
        )}
      </div>

      {/* Subtabs inside multimedia */}
      <div className="mm-subtabs">
        {[
          { id: "gallery", label: "Gallery" },
          { id: "stego", label: "Stego / LSB" },
          { id: "bitplanes", label: "Visual Forensics" },
        ].map((t) => (
          <button
            key={t.id}
            className={
              "mm-subtab-btn" + (subtab === t.id ? " mm-subtab-btn-active" : "")
            }
            onClick={() => setSubtab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Gallery subtab: existing filters + cards */}
      {subtab === "gallery" && (
        <>
          <div className="mm-filters">
            <div className="mm-filter-group">
              <span className="mm-filter-label">Type:</span>
              {["all", "image", "video", "audio"].map((t) => (
                <button
                  key={t}
                  className={
                    "btn-pill btn-xs" +
                    (filterType === t ? " btn-pill-active" : "")
                  }
                  onClick={() => setFilterType(t)}
                >
                  {t[0].toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>
            <div className="mm-filter-group">
              <span className="mm-filter-label">Severity:</span>
              <select
                className="input"
                value={filterSev}
                onChange={(e) => setFilterSev(e.target.value)}
              >
                <option value="all">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <div className="mm-filter-group" style={{ flex: 1 }}>
              <input
                className="input"
                placeholder="Search path or findings…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <div className="mm-filter-group">
              <button
                className={
                  "btn-icon" + (viewMode === "grid" ? " btn-icon-active" : "")
                }
                onClick={() => setViewMode("grid")}
                title="Grid view"
              >
                ⬚
              </button>
              <button
                className={
                  "btn-icon" + (viewMode === "list" ? " btn-icon-active" : "")
                }
                onClick={() => setViewMode("list")}
                title="List view"
              >
                ☰
              </button>
            </div>
          </div>

          {!hasItems && (
            <EmptyState
              icon={Image}
              message="No media files match current filters."
            />
          )}
          {hasItems && viewMode === "grid" && (
            <div className="mm-grid">
              {items.map((m) => (
                <MediaCard
                  key={m.path}
                  item={m}
                  imgPath={imgPath}
                  onView={handleView}
                />
              ))}
            </div>
          )}
          {hasItems && viewMode === "list" && (
            <div className="mm-list">
              {items.map((m) => (
                <div
                  key={m.path}
                  className="mm-list-row"
                  onClick={() => handleView(m)}
                >
                  <span className="mm-list-name">
                    {m.name || m.path.split("/").pop()}
                  </span>
                  <span className="mm-list-path">{m.path}</span>
                  <span className="mm-list-type">{m.media_type}</span>
                  <SevBadge sev={m.severity} />
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* Stego / LSB subtab */}
      {subtab === "stego" && (
        <div style={{ marginTop: 8 }}>
          {stegoItems.length === 0 ? (
            <EmptyState
              icon={Image}
              message="No strong steganography indicators detected in analysed media."
            />
          ) : (
            <table className="mm-meta-table">
              <thead>
                <tr>
                  <th className="mm-meta-key">File</th>
                  <th className="mm-meta-key">Severity</th>
                  <th className="mm-meta-key">Flags</th>
                  <th className="mm-meta-key">Entropy</th>
                  <th className="mm-meta-key">LSB bits</th>
                </tr>
              </thead>
              <tbody>
                {stegoItems.map((m) => (
                  <tr key={m.path}>
                    <td className="mm-meta-val">
                      <div className="mm-list-name">
                        {m.name || m.path.split("/").pop()}
                      </div>
                      <div className="mm-list-path">{m.path}</div>
                    </td>
                    <td className="mm-meta-val">
                      <SevBadge sev={m.severity} />
                    </td>
                    <td className="mm-meta-val">
                      {(m.flags || []).join(", ") || "—"}
                    </td>
                    <td className="mm-meta-val">
                      entropy={m.metadata?.entropy ?? "?"}
                    </td>
                    <td className="mm-meta-val">
                      lsb_entropy={m.metadata?.lsb_entropy_bits ?? "?"},{" "}
                      p1={m.metadata?.lsb_p_one ?? "?"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Bit-plane / visual forensics subtab */}
      {subtab === "bitplanes" && (
        <BitPlaneAnalyzer findings={localFindings} imgPath={imgPath} />
      )}

      {viewItem && (
        <MediaViewerModal
          item={viewItem}
          imgPath={imgPath}
          onClose={() => setViewItem(null)}
          onPrev={handlePrev}
          onNext={handleNext}
          hasPrev={hasPrev}
          hasNext={hasNext}
        />
      )}
    </div>
  );
}
// ─── Tools Tab ────────────────────────────────────────────────────────────────

const RISK_LEVELS = {
  high: { label: "High Risk", color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  medium: { label: "Medium Risk", color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  low: { label: "Low Risk", color: "#16a34a", bg: "#f0fdf4", border: "#bbf7d0" },
  info: { label: "Info", color: "#2563eb", bg: "#eff6ff", border: "#bfdbfe" },
};

function ToolsTab({ findings = [] }) {
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("all");

  if (!findings || findings.length === 0)
    return <EmptyState icon={Search} message="No notable tools or binaries detected." />;

  const filtered = findings.filter(f => {
    if (sevFilter !== "all" && (f.severity || "info") !== sevFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        (f.tool || "").toLowerCase().includes(q) ||
        (f.detail || "").toLowerCase().includes(q) ||
        (f.path || "").toLowerCase().includes(q) ||
        (f.category || "").toLowerCase().includes(q)
      );
    }
    return true;
  });

  const highCount = findings.filter(f => f.severity === "high" || f.severity === "critical").length;
  const medCount = findings.filter(f => f.severity === "medium").length;

  const SEV_FILTERS = [
    { id: "all", label: "All" },
    { id: "critical", label: "Critical" },
    { id: "high", label: "High" },
    { id: "medium", label: "Medium" },
    { id: "low", label: "Low" },
    { id: "info", label: "Info" },
  ].filter(f => f.id === "all" || findings.some(t => (t.severity || "info") === f.id));

  return (
    <div className="tab-content">
      {/* Summary bar */}
      <div className="del-summary-bar">
        <span className="del-sum-chip neutral"><Search size={11} /> {findings.length} tools detected</span>
        {highCount > 0 && (
          <span className="del-sum-chip red"><AlertTriangle size={11} /> {highCount} high risk</span>
        )}
        {medCount > 0 && (
          <span className="del-sum-chip" style={{ background: "#fffbeb", color: "#92400e", border: "1px solid #fde68a" }}>
            <AlertTriangle size={11} /> {medCount} medium
          </span>
        )}
      </div>

      {/* Filters */}
      <div className="del-filter-bar">
        <div className="cfg-sev-filters">
          {SEV_FILTERS.map(({ id, label }) => (
            <button
              key={id}
              className={`cfg-sev-filter ${sevFilter === id ? "active" : ""}`}
              style={sevFilter === id && id !== "all" ? { background: SEV_COLOR[id] || "#6b7280", color: "#fff" } : {}}
              onClick={() => setSevFilter(id)}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="del-search-wrap" style={{ maxWidth: 300, marginLeft: "auto" }}>
          <Search size={12} className="del-search-icon" />
          <input
            className="del-search"
            placeholder="Search tools, paths, categories…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState icon={CheckCircle} message="No tools match the current filter." />
      ) : (
        <div className="cfg-list" style={{ marginTop: 16 }}>
          {filtered.map((f, i) => {
            const sev = f.severity || "info";
            const borderColor = SEV_COLOR[sev] || "#6b7280";
            const rl = RISK_LEVELS[sev] || RISK_LEVELS.info;
            return (
              <div
                key={i}
                className="cfg-row"
                style={{ borderLeft: `3px solid ${borderColor}` }}
              >
                <div className="cfg-row-top">
                  <span style={{ fontWeight: 700, fontFamily: "monospace", fontSize: 13 }}>
                    {f.tool || f.name || "Unknown"}
                  </span>
                  {f.category && (
                    <span
                      className="svc-cat-badge"
                      style={{ marginLeft: 8 }}
                    >
                      {f.category}
                    </span>
                  )}
                  <SevBadge sev={sev} />
                  <span
                    className="bw-flag-chip"
                    style={{
                      background: rl.bg,
                      color: rl.color,
                      border: `1px solid ${rl.border}`,
                      marginLeft: 4,
                    }}
                  >
                    {rl.label}
                  </span>
                </div>
                {f.detail && <div className="cfg-detail">{f.detail}</div>}
                {f.path && (
                  <code
                    className="del-path"
                    style={{ display: "block", marginTop: 4, fontSize: 11 }}
                  >
                    {f.path}
                  </code>
                )}
                {f.version && (
                  <div style={{ fontSize: 11, color: "var(--fg-muted)", marginTop: 2 }}>
                    Version: {f.version}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
const REPORT_TABS = [
  { id: "summary", label: "Summary", Icon: HardDrive },
  { id: "timeline", label: "Timeline", Icon: Clock },
  { id: "recent", label: "Recent", Icon: Activity },
  { id: "deleted", label: "Deleted", Icon: Eye },
  { id: "persistence", label: "Persistence", Icon: Shield },
  { id: "config", label: "Config", Icon: Settings },
  { id: "services", label: "Services", Icon: Server },
  { id: "browsers", label: "Browsers", Icon: Globe },
  { id: "multimedia", label: "Multimedia", Icon: Image },
  { id: "tails", label: "TailsOS", Icon: Sailboat },
  { id: "antiforensics", label: "Anti-Forensics", Icon: ShieldAlert },
  { id: "containers", label: "Containers", Icon: Box },
  { id: "tools", label: "Tools", Icon: Search },
  { id: "evidence", label: "Evidence", Icon: Package },
];

function isTailsFocusedReport(report) {
  const osName = String(report?.os_info?.name || "").toLowerCase();
  const osId = String(report?.os_info?.id || "").toLowerCase();
  const tags = (report?.os_info?.variant_tags || []).map((t) => String(t).toLowerCase());
  const analysisMode = String(report?.summary?.analysis_mode || "").toLowerCase();
  const tailsTag = tags.some((t) => t === "tails" || t.startsWith("tails_"));

  return (
    osName === "tails" ||
    osName.startsWith("tails ") ||
    osId === "tails" ||
    tailsTag ||
    analysisMode === "tails_os"
  );
}

const TAILS_HIGH_RISK_PATHS = [".gnupg", ".ssh", ".electrum", ".bitcoin", ".monero"];
const TAILS_SUSPICIOUS_CMD_RE = /\b(nmap|sqlmap|hydra|torsocks|proxychains|curl|wget|nc|netcat|ssh|scp|gpg|electrum)\b/i;

function safeLower(value) {
  return String(value || "").toLowerCase();
}

function hasTailsArtifactData(artifacts) {
  if (!artifacts || typeof artifacts !== "object") return false;
  return [
    artifacts?.persistence_modules?.total,
    artifacts?.crypto_wallets?.total,
    artifacts?.identity_keys?.total_identities,
    artifacts?.tor_browser_artifacts?.total,
    artifacts?.user_files?.stats?.total,
    artifacts?.dotfiles_and_activity?.history_entries,
    artifacts?.network_config?.bridges_count,
  ].some((value) => Number(value || 0) > 0);
}

function tailsModuleLabel(path) {
  const lower = safeLower(path);
  if (lower.includes(".gnupg")) return "GnuPG Keys";
  if (lower.includes(".ssh")) return "SSH Keys";
  if (lower.includes(".electrum")) return "Electrum Wallet";
  if (lower.includes(".thunderbird")) return "Thunderbird";
  if (lower.includes("persistent")) return "Persistent Files";
  if (lower.includes("tor-browser") || lower.includes(".mozilla")) return "Tor Browser Data";
  if (lower.includes("dotfiles")) return "Dotfiles";
  return "Persistent Module";
}

function tailsModuleRisk(path) {
  const lower = safeLower(path);
  if (TAILS_HIGH_RISK_PATHS.some((token) => lower.includes(token))) return "high";
  if (lower.includes("tor-browser") || lower.includes(".mozilla") || lower.includes(".thunderbird")) return "medium";
  return "low";
}

function parsePersistenceModulesText(content) {
  if (!content) return [];
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && line.startsWith("/"))
    .map((path) => ({
      source: path,
      destination: path,
      type: tailsModuleLabel(path),
      risk_level: tailsModuleRisk(path),
    }));
}

function parseKeyValueText(content) {
  const out = {};
  for (const line of String(content || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.includes("=")) continue;
    const [key, ...rest] = trimmed.split("=");
    out[key] = rest.join("=").replace(/^"|"$/g, "");
  }
  return out;
}

function classifyPersistentFile(name) {
  const ext = safeLower(name).split(".").pop();
  if (["txt", "md", "doc", "docx", "pdf"].includes(ext)) return "Documents";
  if (["jpg", "jpeg", "png", "gif", "bmp"].includes(ext)) return "Images";
  if (["zip", "7z", "rar", "tar", "gz"].includes(ext)) return "Archives";
  if (["sqlite", "db", "dat", "kdbx"].includes(ext)) return "Databases";
  if (["py", "sh", "js", "rb", "go"].includes(ext)) return "Scripts";
  return "Other";
}

function extractHistoryInsights(content) {
  const lines = String(content || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(-40);
  const suspicious = lines.filter((line) => TAILS_SUSPICIOUS_CMD_RE.test(line)).slice(-8);
  return { lines, suspicious };
}

function parseTorConfig(content) {
  const bridges = [];
  const custom = [];
  const hidden = [];
  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (/^bridge\s+/i.test(line)) bridges.push(line);
    if (/^hiddenservice(dir|port)\s+/i.test(line)) hidden.push(line);
    if (/^(entrynodes|exitnodes|socksport|dnsport|clientuseipv6|usebridges)\s+/i.test(line)) custom.push(line);
  }
  return { bridges, hidden, custom };
}

async function safeBrowseMount(imgPath, path) {
  try {
    return await apiBrowse(imgPath, path);
  } catch {
    return { path, children: [] };
  }
}

async function safeStatMount(imgPath, path) {
  try {
    return await apiStat(imgPath, path);
  } catch {
    return { path, exists: false };
  }
}

async function safeReadMount(imgPath, path) {
  try {
    return await apiRead(imgPath, path);
  } catch {
    return { path, exists: false, content: "" };
  }
}

function computeAnonymityScoreFromArtifacts(artifacts, mountInfo) {
  let score = 0;
  const leaks = [];
  if ((artifacts?.persistence_modules?.total || 0) > 0) {
    score += 20;
    leaks.push("Persistence modules enabled");
  }
  if ((artifacts?.crypto_wallets?.total || 0) > 0) {
    score += 18;
    leaks.push("Cryptocurrency wallet artifacts detected");
  }
  if ((artifacts?.identity_keys?.total_identities || 0) > 0) {
    score += 18;
    leaks.push("Cryptographic identity keys present");
  }
  if ((artifacts?.tor_browser_artifacts?.total || 0) > 0) {
    score += 10;
    leaks.push("Tor browser profile data persists");
  }
  if ((artifacts?.dotfiles_and_activity?.suspicious_count || 0) > 0) {
    score += 12;
    leaks.push("Command history exposes operator activity");
  }
  if ((artifacts?.network_config?.bridges_count || 0) > 0 || (artifacts?.network_config?.hidden_services?.length || 0) > 0) {
    score += 12;
    leaks.push("Tor network customization recovered");
  }
  if (mountInfo?.encryptedPersistence) {
    score += 6;
    leaks.push("Encrypted persistence volume unlocked during acquisition");
  }
  score = Math.min(score, 100);
  return {
    score,
    max: 100,
    risk_level: score >= 75 ? "critical" : score >= 55 ? "high" : score >= 30 ? "medium" : "low",
    primary_leaks: leaks.slice(0, 5),
    leak_count: leaks.length,
  };
}

function synthesizeTailsFindings(snapshot, fallbackFindings = []) {
  if (Array.isArray(fallbackFindings) && fallbackFindings.length > 0) return fallbackFindings;
  if (!snapshot) return [];
  const findings = [];
  const add = (category, detail, severity = "info", evidence = []) => findings.push({ source: "tails-mount", category, detail, severity, evidence });
  if ((snapshot?.artifacts?.persistence_modules?.total || 0) > 0) {
    add("persistence", `Recovered ${snapshot.artifacts.persistence_modules.total} persistence module definition(s).`, "high", snapshot.artifacts.persistence_modules.enabled.map((m) => m.destination));
  }
  if ((snapshot?.artifacts?.crypto_wallets?.total || 0) > 0) {
    add("crypto_wallets", `Detected ${snapshot.artifacts.crypto_wallets.total} cryptocurrency wallet artifact(s).`, "high", snapshot.artifacts.crypto_wallets.wallets.map((w) => w.path));
  }
  if ((snapshot?.artifacts?.identity_keys?.total_identities || 0) > 0) {
    add("identity_keys", `Recovered ${snapshot.artifacts.identity_keys.total_identities} SSH/GPG identity artifact(s).`, "high");
  }
  if ((snapshot?.artifacts?.dotfiles_and_activity?.history_entries || 0) > 0) {
    add("shell_activity", `Recovered ${snapshot.artifacts.dotfiles_and_activity.history_entries} shell history line(s).`, snapshot.artifacts.dotfiles_and_activity.suspicious_count > 0 ? "medium" : "info", snapshot.artifacts.dotfiles_and_activity.suspicious_commands || []);
  }
  if ((snapshot?.artifacts?.network_config?.bridges_count || 0) > 0) {
    add("tor", `Recovered ${snapshot.artifacts.network_config.bridges_count} Tor bridge configuration line(s).`, "medium", snapshot.artifacts.network_config.bridges || []);
  }
  if (snapshot?.mountInfo?.encryptedPersistence) {
    add("encryption", "Encrypted persistence appears mounted or unlocked in the acquired filesystem.", "medium", snapshot.mountInfo.encryptionHints || []);
  }
  return findings;
}

function useTailsMountSnapshot(imgPath) {
  const [state, setState] = useState({ loading: true, error: null, snapshot: null });

  useEffect(() => {
    if (!imgPath) {
      setState({ loading: false, error: null, snapshot: null });
      return;
    }
    let cancelled = false;

    async function load() {
      setState((prev) => ({ ...prev, loading: true, error: null }));
      try {
        const [osReleaseRaw, mountsRaw, torrcRaw, crypttabRaw, pconfRaw, rootBrowse, homeBrowse, persistenceStat, mapperStat] = await Promise.all([
          safeReadMount(imgPath, "/etc/os-release"),
          safeReadMount(imgPath, "/proc/mounts"),
          safeReadMount(imgPath, "/etc/tor/torrc"),
          safeReadMount(imgPath, "/etc/crypttab"),
          safeReadMount(imgPath, "/live/persistence/TailsData_unlocked/persistence.conf"),
          safeBrowseMount(imgPath, "/"),
          safeBrowseMount(imgPath, "/home"),
          safeStatMount(imgPath, "/live/persistence/TailsData_unlocked"),
          safeStatMount(imgPath, "/dev/mapper/TailsData"),
        ]);

        const homes = (homeBrowse?.children || [])
          .filter((entry) => entry?.is_dir)
          .map((entry) => `/home/${entry.name}`);
        if (homes.length === 0) homes.push("/home/amnesia");

        const modules = parsePersistenceModulesText(pconfRaw?.content || "");
        const osRelease = parseKeyValueText(osReleaseRaw?.content || "");
        const torConfig = parseTorConfig(torrcRaw?.content || "");
        const mountLines = String(mountsRaw?.content || "").split(/\r?\n/).filter(Boolean);
        const encryptionHints = [
          ...mountLines.filter((line) => /(dm-crypt|mapper|luks|tailsdata)/i.test(line)).slice(0, 6),
          ...String(crypttabRaw?.content || "").split(/\r?\n/).filter((line) => /(luks|crypt|tailsdata)/i.test(line)).slice(0, 4),
        ];

        const homeSnapshots = await Promise.all(homes.map(async (home) => {
          const [sshStat, gpgStat, electrumStat, persistentStat, bashStat, zshStat, torBrowserStat, torHiddenStat, mozillaStat] = await Promise.all([
            safeStatMount(imgPath, `${home}/.ssh`),
            safeStatMount(imgPath, `${home}/.gnupg`),
            safeStatMount(imgPath, `${home}/.electrum`),
            safeStatMount(imgPath, `${home}/Persistent`),
            safeStatMount(imgPath, `${home}/.bash_history`),
            safeStatMount(imgPath, `${home}/.zsh_history`),
            safeStatMount(imgPath, `${home}/Tor Browser`),
            safeStatMount(imgPath, `${home}/.tor-browser`),
            safeStatMount(imgPath, `${home}/.mozilla`),
          ]);

          const [sshBrowse, gpgBrowse, persistentBrowse, walletBrowse, bashRead, zshRead] = await Promise.all([
            sshStat?.exists && sshStat?.is_dir ? safeBrowseMount(imgPath, `${home}/.ssh`) : Promise.resolve({ children: [] }),
            gpgStat?.exists && gpgStat?.is_dir ? safeBrowseMount(imgPath, `${home}/.gnupg`) : Promise.resolve({ children: [] }),
            persistentStat?.exists && persistentStat?.is_dir ? safeBrowseMount(imgPath, `${home}/Persistent`) : Promise.resolve({ children: [] }),
            electrumStat?.exists ? safeBrowseMount(imgPath, `${home}/.electrum/wallets`) : Promise.resolve({ children: [] }),
            bashStat?.exists ? safeReadMount(imgPath, `${home}/.bash_history`) : Promise.resolve({ content: "" }),
            zshStat?.exists ? safeReadMount(imgPath, `${home}/.zsh_history`) : Promise.resolve({ content: "" }),
          ]);

          return {
            home,
            sshKeys: (sshBrowse?.children || []).filter((entry) => /^(id_|authorized_keys|known_hosts)/i.test(entry.name || "")),
            gpgKeys: (gpgBrowse?.children || []).filter((entry) => /(pubring|trustdb|private-keys|secring)/i.test(entry.name || "")),
            browserProfiles: [torBrowserStat, torHiddenStat, mozillaStat].filter((entry) => entry?.exists).map((entry) => entry.path),
            wallets: (walletBrowse?.children || []).filter((entry) => !entry?.is_dir).map((entry) => ({ type: "Electrum", name: entry.name, path: entry.path })),
            persistentFiles: (persistentBrowse?.children || []).filter((entry) => ![".", ".."].includes(entry.name)).map((entry) => ({ ...entry, type_label: classifyPersistentFile(entry.name) })),
            history: {
              bash: extractHistoryInsights(bashRead?.content || ""),
              zsh: extractHistoryInsights(zshRead?.content || ""),
            },
          };
        }));

        const sshKeys = homeSnapshots.flatMap((item) => item.sshKeys.map((entry) => ({ ...entry, home: item.home })));
        const gpgKeys = homeSnapshots.flatMap((item) => item.gpgKeys.map((entry) => ({ ...entry, home: item.home })));
        const browserProfiles = homeSnapshots.flatMap((item) => item.browserProfiles);
        const wallets = homeSnapshots.flatMap((item) => item.wallets);
        const persistentFiles = homeSnapshots.flatMap((item) => item.persistentFiles).slice(0, 60);
        const historyLines = homeSnapshots.flatMap((item) => [...item.history.bash.lines, ...item.history.zsh.lines]);
        const suspiciousCommands = homeSnapshots.flatMap((item) => [...item.history.bash.suspicious, ...item.history.zsh.suspicious]);
        const byType = {};
        for (const entry of persistentFiles) {
          byType[entry.type_label] = (byType[entry.type_label] || 0) + 1;
        }

        const mountInfo = {
          imgPath,
          homeDirs: homes,
          rootEntryCount: (rootBrowse?.children || []).length,
          encryptedPersistence: Boolean(persistenceStat?.exists || mapperStat?.exists || encryptionHints.length > 0),
          encryptionHints,
          osRelease,
          mountLines: mountLines.filter((line) => /(tails|persistence|mapper|dm-crypt|tor)/i.test(line)).slice(0, 8),
        };

        const artifacts = {
          persistence_modules: {
            enabled: modules,
            total: modules.length,
            high_risk_count: modules.filter((module) => module.risk_level === "high").length,
          },
          crypto_wallets: {
            wallets,
            total: wallets.length,
            types: new Set(wallets.map((wallet) => wallet.type)).size,
          },
          identity_keys: {
            ssh_keys: sshKeys,
            gpg_keys: gpgKeys,
            total_identities: sshKeys.length + gpgKeys.length,
          },
          tor_browser_artifacts: {
            profiles: browserProfiles,
            bookmarks: [],
            extensions: [],
            total: browserProfiles.length,
          },
          user_files: {
            files: persistentFiles,
            stats: { total: persistentFiles.length, by_type: byType },
          },
          dotfiles_and_activity: {
            history_entries: historyLines.length,
            suspicious_count: suspiciousCommands.length,
            bash_history: historyLines.slice(-12),
            suspicious_commands: suspiciousCommands.slice(-8),
          },
          network_config: {
            bridges: torConfig.bridges,
            bridges_count: torConfig.bridges.length,
            custom_config: torConfig.custom.length,
            hidden_services: torConfig.hidden,
          },
        };
        artifacts.anonymity_score = computeAnonymityScoreFromArtifacts(artifacts, mountInfo);

        const snapshot = {
          mountInfo,
          artifacts,
        };
        snapshot.findings = synthesizeTailsFindings(snapshot);

        if (!cancelled) {
          setState({ loading: false, error: null, snapshot });
        }
      } catch (error) {
        if (!cancelled) {
          setState({ loading: false, error: error?.message || String(error), snapshot: null });
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [imgPath]);

  return state;
}

function TailsLiteBrowser({ imgPath }) {
  const [path, setPath] = useState("/");
  const [entries, setEntries] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState(null);
  const [stats, setStats] = useState(null);
  const [splitPct, setSplitPct] = useState(58);
  const [isResizing, setIsResizing] = useState(false);
  const [preview, setPreview] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState(null);
  const containerRef = useRef(null);

  async function loadPath(p) {
    setLoading(true);
    try {
      const dir = await apiBrowse(imgPath, p);
      setEntries(dir.children || []);
      setPath(p);
    } catch (e) {
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }

  async function selectFile(entry) {
    setSelected(entry);
    setPreview(null);
    setPreviewError(null);
    if (entry.type === "directory") {
      loadPath(entry.path);
    } else {
      try {
        setPreviewLoading(true);
        const [meta, content] = await Promise.all([
          apiStat(imgPath, entry.path),
          apiRead(imgPath, entry.path),
        ]);
        setSelected({ ...entry, ...meta });
        setPreview(content || null);
      } catch (e) {
        setPreviewError(String(e?.message || e || "Failed to load content"));
      } finally {
        setPreviewLoading(false);
      }
    }
  }

  useEffect(() => {
    loadPath("/");
    setSelected(null);
    setPreview(null);
    setPreviewError(null);
  }, [imgPath]);

  useEffect(() => {
    if (!isResizing) return;

    function onMove(e) {
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect || rect.width <= 0) return;
      const pct = ((e.clientX - rect.left) / rect.width) * 100;
      setSplitPct(Math.max(26, Math.min(78, pct)));
    }

    function onUp() {
      setIsResizing(false);
    }

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [isResizing]);

  useEffect(() => {
    if (!entries || entries.length === 0) {
      setStats(null);
      return;
    }
    const totalSize = entries.reduce((sum, e) => sum + (e.size || 0), 0);
    const dirCount = entries.filter((e) => e.type === "directory").length;
    const fileCount = entries.filter((e) => e.type !== "directory").length;
    const extMap = new Map();
    for (const e of entries) {
      if (e.type !== "directory") {
        const ext = e.name?.split(".").pop()?.toLowerCase() || "no-ext";
        extMap.set(ext, (extMap.get(ext) || 0) + 1);
      }
    }
    const suidCount = entries.filter((e) => e.is_suid || e.is_sgid).length;
    const rootOwned = entries.filter((e) => e.uid === 0).length;
    const executable = entries.filter((e) => e.type === "file" && (parseInt(e.mode_octal || "0", 8) & 0o111) !== 0).length;

    setStats({
      totalSize,
      dirCount,
      fileCount,
      topExts: Array.from(extMap.entries()).slice(0, 5),
      suidCount,
      rootOwned,
      executable,
    });
  }, [entries]);

  const fmtSize = (bytes) => {
    if (!bytes) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(1) + " " + sizes[i];
  };

  return (
    <div className="tails-lite-browser">
      <div className="tlb-header">
        <span className="tlb-path" title={path}>{path}</span>
        {path !== "/" && (
          <button className="btn-secondary btn-xs" onClick={() => loadPath(path.replace(/\/[^/]*\/?$/, "") || "/")}>
            <ChevronUp size={10} /> Up
          </button>
        )}
      </div>

      <div
        className="tlb-container"
        ref={containerRef}
        style={{ gridTemplateColumns: `minmax(260px, ${splitPct}%) 8px minmax(300px, ${100 - splitPct}%)` }}
      >
        {/* File list */}
        <div className="tlb-list">
          {loading && <div className="tlb-empty"><RefreshCw size={14} className="spin" /> Loading…</div>}
          {!loading && (!entries || entries.length === 0) && <div className="tlb-empty">Empty directory</div>}
          {!loading && entries && entries.length > 0 && (
            <div className="tlb-files">
              {entries.map((e) => (
                <div
                  key={e.path}
                  className={`tlb-file-row ${selected?.path === e.path ? "selected" : ""}`}
                  onClick={() => selectFile(e)}
                  onDoubleClick={() => e.type === "directory" && loadPath(e.path)}
                >
                  <FileTypeIcon type={e.type} name={e.name} />
                  <span className="tlb-file-name">{e.name}</span>
                  <span className="tlb-file-size">{fmtSize(e.size)}</span>
                  {e.is_suid && <span className="sev-badge" style={{ fontSize: "9px", background: "#dc2626" }}>SUID</span>}
                </div>
              ))}
            </div>
          )}
        </div>

        <div
          className={`tlb-divider ${isResizing ? "active" : ""}`}
          onMouseDown={(e) => {
            e.preventDefault();
            setIsResizing(true);
          }}
          title="Drag to resize panes"
        />

        {/* Stats + details */}
        <div className="tlb-details">
          {stats && (
            <>
              <div className="tlb-stats-grid">
                <div className="tlb-stat"><strong>{stats.fileCount}</strong><span>Files</span></div>
                <div className="tlb-stat"><strong>{stats.dirCount}</strong><span>Dirs</span></div>
                <div className="tlb-stat"><strong>{fmtSize(stats.totalSize)}</strong><span>Total Size</span></div>
              </div>
              <div className="tlb-stats-grid">
                <div className="tlb-stat"><strong>{stats.executable}</strong><span>Executable</span></div>
                <div className="tlb-stat"><strong>{stats.rootOwned}</strong><span>Root Owned</span></div>
                <div className="tlb-stat"><strong>{stats.suidCount}</strong><span>SUID/SGID</span></div>
              </div>
              {stats.topExts.length > 0 && (
                <div className="tlb-exts">
                  <strong style={{ fontSize: "11px", display: "block", marginBottom: "4px" }}>Top Extensions</strong>\n                  {stats.topExts.map(([ext, count]) => (
                    <span key={ext} className="tlb-ext-tag">.{ext} ({count})</span>
                  ))}
                </div>
              )}
            </>
          )}
          {selected && (
            <div className="tlb-file-info">
              <strong style={{ fontSize: "11px", display: "block", marginBottom: "4px" }}>File Details</strong>
              <table className="rp-table" style={{ fontSize: "11px" }}>
                <tbody>
                  {selected.name && <tr><td>Name</td><td>{selected.name}</td></tr>}
                  {selected.path && <tr><td>Path</td><td><code className="tlb-path-code">{selected.path}</code></td></tr>}
                  {selected.size_human && <tr><td>Size</td><td>{selected.size_human}</td></tr>}
                  {selected.mtime && <tr><td>Modified</td><td>{selected.mtime}</td></tr>}
                  {selected.mode && <tr><td>Mode</td><td><code>{selected.mode}</code></td></tr>}
                  {selected.uid != null && <tr><td>UID</td><td>{selected.uid}</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {selected && selected.type !== "directory" && (
            <div className="tlb-file-content">
              <strong style={{ fontSize: "11px", display: "block", marginBottom: "6px" }}>
                Content Preview {preview?.encoding ? `(${preview.encoding})` : ""}
              </strong>
              {previewLoading && <div className="usb-empty">Loading content preview…</div>}
              {!previewLoading && previewError && <div className="dlg-error">{previewError}</div>}
              {!previewLoading && !previewError && !preview?.content && (
                <div className="usb-empty">No previewable content.</div>
              )}
              {!previewLoading && !previewError && preview?.content && (
                <pre className={`tlb-content-pre ${preview?.is_binary ? "is-binary" : ""}`}>{preview.content}</pre>
              )}
              {!previewLoading && !previewError && preview?.truncated && (
                <div className="usb-empty">Preview truncated to safe limit.</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function TailsAnalyticsPanel({ artifacts, report, mountInfo, loading, error }) {
  const artifacts_data = artifacts || {};
  const modules = artifacts_data.persistence_modules || {};
  const wallets = artifacts_data.crypto_wallets || {};
  const identities = artifacts_data.identity_keys || {};
  const browser_artifacts = artifacts_data.tor_browser_artifacts || {};
  const user_files = artifacts_data.user_files || {};
  const dotfiles = artifacts_data.dotfiles_and_activity || {};
  const network = artifacts_data.network_config || {};
  const anon_score = artifacts_data.anonymity_score || {};

  const score = anon_score.score || 0;
  const risk_level = anon_score.risk_level || "low";
  const artifactSnapshot = {
    modules: modules.total || 0,
    wallets: wallets.total || 0,
    identities: identities.total_identities || ((identities.ssh_keys?.length || 0) + (identities.gpg_keys?.length || 0)),
    browser: browser_artifacts.total || 0,
    files: user_files.stats?.total || 0,
    history: dotfiles.history_entries || 0,
    bridges: network.bridges_count || 0,
  };
  const hasStructuredArtifacts = Object.values(artifactSnapshot).some((v) => Number(v) > 0);

  return (
    <div className="tails-analytics">
      {(loading || error) && (
        <div className="ta-empty">
          <strong>{loading ? "Inspecting mounted filesystem…" : "Mount inspection failed"}</strong>
          <p>{loading ? "Gathering persistence, Tor, wallet, key, and command-history evidence from the mount point." : error}</p>
        </div>
      )}

      {/* Anonymity Leakage Score */}
      <div className="ta-section">
        <h3><AlertTriangle size={16} /> Anonymity Leakage Risk Score</h3>
        <div className="ta-score-card">
          <div className="ta-score-big" style={{
            color: risk_level === "critical" ? "#dc2626" : risk_level === "high" ? "#ea580c" : risk_level === "medium" ? "#f59e0b" : "#10b981"
          }}>
            {score} / 100
          </div>
          <div className="ta-score-label">{risk_level.toUpperCase()} RISK</div>
          {anon_score.primary_leaks && anon_score.primary_leaks.length > 0 && (
            <div className="ta-score-leaks">
              <strong>Privacy Leaks Detected:</strong>
              {anon_score.primary_leaks.map((leak, i) => (
                <div key={i} style={{ fontSize: "12px", color: "#666", marginTop: "4px" }}>• {leak}</div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="ta-section">
        <h3><BarChart3 size={16} /> Artifact Snapshot</h3>
        <div className="ta-grid ta-grid-compact">
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Persistence Modules</div><div className="ta-stat-value">{artifactSnapshot.modules}</div></div>
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Wallet Artifacts</div><div className="ta-stat-value">{artifactSnapshot.wallets}</div></div>
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Identity Keys</div><div className="ta-stat-value">{artifactSnapshot.identities}</div></div>
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Browser Artifacts</div><div className="ta-stat-value">{artifactSnapshot.browser}</div></div>
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Persistent Files</div><div className="ta-stat-value">{artifactSnapshot.files}</div></div>
          <div className="ta-card ta-stat-card"><div className="ta-card-type">History Entries</div><div className="ta-stat-value">{artifactSnapshot.history}</div></div>
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Bridge Configs</div><div className="ta-stat-value">{artifactSnapshot.bridges}</div></div>
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Tails Findings</div><div className="ta-stat-value">{report?.tails?.length || 0}</div></div>
        </div>
      </div>

      <div className="ta-section">
        <h3><Lock size={16} /> Mount and Encryption Evidence</h3>
        <div className="ta-grid ta-grid-compact">
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Encrypted Persistence</div><div className="ta-stat-value">{mountInfo?.encryptedPersistence ? "Yes" : "No"}</div></div>
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Home Directories</div><div className="ta-stat-value">{mountInfo?.homeDirs?.length || 0}</div></div>
          <div className="ta-card ta-stat-card"><div className="ta-card-type">Root Entries</div><div className="ta-stat-value">{mountInfo?.rootEntryCount || 0}</div></div>
        </div>
        {((mountInfo?.encryptionHints?.length || 0) > 0 || (mountInfo?.mountLines?.length || 0) > 0) && (
          <div className="ta-history">
            <strong style={{ fontSize: "11px" }}>Recovered Mount Evidence</strong>
            {[...(mountInfo?.encryptionHints || []), ...(mountInfo?.mountLines || [])].slice(0, 8).map((line, index) => (
              <div key={`${line}-${index}`} style={{ fontSize: "11px", fontFamily: "monospace", color: "#334155", marginTop: "4px", paddingLeft: "8px" }}>
                <code className="code-block">{line}</code>
              </div>
            ))}
          </div>
        )}
      </div>

      {!hasStructuredArtifacts && (
        <div className="ta-empty">
          <strong>No structured Tails artifacts are available in this report yet.</strong>
          <p>This can happen for older reports generated before artifact extraction was added. Re-run analysis on this source to populate Analytics.</p>
        </div>
      )}

      {/* Persistence Modules */}
      {modules.enabled && modules.enabled.length > 0 && (
        <div className="ta-section">
          <h3><Lock size={16} /> Persistence Modules ({modules.total})</h3>
          <div className="ta-grid">
            {modules.enabled.map((mod, i) => (
              <div key={i} className="ta-card">
                <div className="ta-card-type" style={{ color: mod.risk_level === "high" ? "#dc2626" : "#f59e0b" }}>
                  {mod.type}
                </div>
                <div className="ta-card-detail">{mod.destination}</div>
                <div className="ta-card-meta">Risk: <strong>{mod.risk_level}</strong></div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cryptocurrency Wallets */}
      {wallets.wallets && wallets.wallets.length > 0 && (
        <div className="ta-section">
          <h3><DollarSign size={16} /> Cryptocurrency Wallets ({wallets.total})</h3>
          <div className="ta-grid">
            {wallets.wallets.map((wallet, i) => (
              <div key={i} className="ta-card">
                <div className="ta-card-type">{wallet.type}</div>
                <div className="ta-card-detail">{wallet.name}</div>
                <div className="ta-card-meta">{wallet.path}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Identity Keys */}
      {(identities.ssh_keys?.length > 0 || identities.gpg_keys?.length > 0) && (
        <div className="ta-section">
          <h3><Key size={16} /> Cryptographic Identity Keys</h3>
          <div className="ta-grid">
            {identities.ssh_keys?.map((key, i) => (
              <div key={`ssh-${i}`} className="ta-card">
                <div className="ta-card-type">SSH Key</div>
                <div className="ta-card-detail">{key.name}</div>
                <div className="ta-card-meta">High Risk</div>
              </div>
            ))}
            {identities.gpg_keys?.map((key, i) => (
              <div key={`gpg-${i}`} className="ta-card">
                <div className="ta-card-type">GPG Key</div>
                <div className="ta-card-detail">{key.name}</div>
                <div className="ta-card-meta">High Risk</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tor Browser Artifacts */}
      {browser_artifacts.total > 0 && (
        <div className="ta-section">
          <h3><Globe size={16} /> Tor Browser Artifacts</h3>
          <p style={{ fontSize: "12px", color: "#666", marginBottom: "12px" }}>
            Profiles: {browser_artifacts.profiles?.length || 0} | 
            Artifacts: {browser_artifacts.bookmarks?.length || 0}
          </p>
        </div>
      )}

      {/* Dotfiles & Activity */}
      {dotfiles.history_entries > 0 && (
        <div className="ta-section">
          <h3><Terminal size={16} /> Command History & Activity</h3>
          <p style={{ fontSize: "12px", color: "#666", marginBottom: "8px" }}>
            <strong>Commands logged:</strong> {dotfiles.history_entries} | 
            <strong style={{ marginLeft: "12px" }}>Suspicious:</strong> {dotfiles.suspicious_count}
          </p>
          {dotfiles.suspicious_commands && dotfiles.suspicious_commands.length > 0 && (
            <div className="ta-history">
              <strong style={{ fontSize: "11px" }}>Notable Commands:</strong>
              {dotfiles.suspicious_commands.slice(0, 5).map((cmd, i) => (
                <div key={i} style={{ fontSize: "11px", fontFamily: "monospace", color: "#dc2626", marginTop: "4px", paddingLeft: "8px" }}>
                  <code className="code-block">{cmd.substring(0, 100)}</code>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Network Configuration */}
      {network.bridges_count > 0 && (
        <div className="ta-section">
          <h3><Network size={16} /> Tor Network Configuration</h3>
          <p style={{ fontSize: "12px", color: "#666" }}>
            Bridges: {network.bridges_count} | Custom Config: {network.custom_config}
          </p>
        </div>
      )}

      {/* User Files Summary */}
      {user_files.stats?.total > 0 && (
        <div className="ta-section">
          <h3><Files size={16} /> User Files in Persistent Storage</h3>
          <div className="ta-grid">
            {Object.entries(user_files.stats.by_type || {}).map(([type, count]) => (
              <div key={type} className="ta-card ta-stat-card">
                <div className="ta-card-type">{type}</div>
                <div style={{ fontSize: "20px", fontWeight: "bold", color: "#1f2937", textAlign: "center", marginTop: "8px" }}>
                  {count}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function TailsDeepIndicatorsTab({ deepScan }) {
  const artifacts = deepScan?.artifacts || {};
  const textScan = artifacts?.text_scan || {};
  const keyWalletBrowser = artifacts?.key_wallet_browser || {};
  const persistence = artifacts?.persistence || {};

  if (!deepScan || !artifacts || Object.keys(artifacts).length === 0) {
    return (
      <div className="tab-content">
        <div className="empty-state">
          <AlertTriangle size={24} />
          <p>Deep scan indicators are not available in this report. Re-run Tails Deep analysis.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="tab-content">
      <div className="tails-overview-panel" style={{ marginBottom: 12 }}>
        <h4>Deep Indicator Summary</h4>
        <table className="rp-table">
          <tbody>
            <tr><td>Onion Addresses</td><td>{(textScan?.onion_addresses || []).length}</td></tr>
            <tr><td>Suspicious Lines</td><td>{(textScan?.suspicious_lines || []).length}</td></tr>
            <tr><td>Bridge Lines</td><td>{(textScan?.bridge_related_lines || []).length}</td></tr>
            <tr><td>Hidden Service Lines</td><td>{(textScan?.hidden_service_lines || []).length}</td></tr>
            <tr><td>Wallet Files</td><td>{(keyWalletBrowser?.wallet_files || []).length}</td></tr>
            <tr><td>Identity/Key Files</td><td>{(keyWalletBrowser?.key_files || []).length}</td></tr>
            <tr><td>Browser Artifact Files</td><td>{(keyWalletBrowser?.browser_files || []).length}</td></tr>
          </tbody>
        </table>
      </div>

      <div className="tails-overview-panel" style={{ marginBottom: 12 }}>
        <h4>Onion Addresses</h4>
        {(textScan?.onion_addresses || []).length === 0 ? <p className="usb-empty">No onion indicators.</p> : (
          <ul className="evidence-list">
            {(textScan?.onion_addresses || []).map((v, i) => <li key={i}><code>{v}</code></li>)}
          </ul>
        )}
      </div>

      <div className="tails-overview-panel" style={{ marginBottom: 12 }}>
        <h4>Persistence Modules</h4>
        {(persistence?.modules || []).length === 0 ? <p className="usb-empty">No modules parsed.</p> : (
          <table className="rp-table">
            <thead><tr><th>Source</th><th>Destination</th></tr></thead>
            <tbody>
              {(persistence?.modules || []).map((m, i) => (
                <tr key={`${m.source}-${i}`}>
                  <td><code>{m.source}</code></td>
                  <td><code>{m.destination}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="tails-overview-panel" style={{ marginBottom: 12 }}>
        <h4>Suspicious Command Traces</h4>
        {(textScan?.suspicious_lines || []).length === 0 ? <p className="usb-empty">No suspicious lines recovered.</p> : (
          <table className="rp-table">
            <thead><tr><th>Path</th><th>Line</th></tr></thead>
            <tbody>
              {(textScan?.suspicious_lines || []).map((entry, i) => (
                <tr key={`${entry.path}-${i}`}>
                  <td><code>{entry.path}</code></td>
                  <td><code>{entry.line}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="tails-overview-panel">
        <h4>Wallet / Key / Browser Files</h4>
        <table className="rp-table">
          <thead><tr><th>Category</th><th>Path</th><th>Size</th></tr></thead>
          <tbody>
            {(keyWalletBrowser?.wallet_files || []).map((f, i) => (
              <tr key={`w-${i}`}><td>Wallet</td><td><code>{f.path}</code></td><td>{f.size ?? "-"}</td></tr>
            ))}
            {(keyWalletBrowser?.key_files || []).map((f, i) => (
              <tr key={`k-${i}`}><td>Identity Key</td><td><code>{f.path}</code></td><td>{f.size ?? "-"}</td></tr>
            ))}
            {(keyWalletBrowser?.browser_files || []).map((f, i) => (
              <tr key={`b-${i}`}><td>Browser</td><td><code>{f.path}</code></td><td>{f.size ?? "-"}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function TailsCollectedEvidenceTab({ deepScan }) {
  const artifacts = deepScan?.artifacts || {};
  const collection = artifacts?.evidence_collection || {};
  const hashes = artifacts?.largest_file_hash_samples || [];
  const fs = artifacts?.filesystem_inventory || {};

  if (!deepScan || !collection?.enabled) {
    return (
      <div className="tab-content">
        <div className="empty-state">
          <Archive size={24} />
          <p>Collected evidence bundle is not available for this report.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="tab-content">
      <div className="tails-overview-panel" style={{ marginBottom: 12 }}>
        <h4>Evidence Collection Metadata</h4>
        <table className="rp-table">
          <tbody>
            <tr><td>Collected Files</td><td>{collection.copied_count ?? 0}</td></tr>
            <tr><td>Skipped Files</td><td>{collection.skipped_count ?? 0}</td></tr>
            <tr><td>Copied Bytes</td><td>{collection.copied_bytes ?? 0}</td></tr>
            <tr><td>Collection Directory</td><td><code>{collection.collect_dir || "-"}</code></td></tr>
            <tr><td>Manifest Path</td><td><code>{collection.manifest_path || "-"}</code></td></tr>
            <tr><td>Collected Files Root</td><td><code>{collection.collected_files_root || "-"}</code></td></tr>
          </tbody>
        </table>
      </div>

      <div className="tails-overview-panel" style={{ marginBottom: 12 }}>
        <h4>Top Largest Files (Deep Inventory)</h4>
        <table className="rp-table">
          <thead><tr><th>Path</th><th>Size</th></tr></thead>
          <tbody>
            {(fs?.largest_files || []).slice(0, 30).map((f, i) => (
              <tr key={`${f.path}-${i}`}>
                <td><code>{f.path}</code></td>
                <td>{f.size ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="tails-overview-panel">
        <h4>Largest File Hash Samples</h4>
        <table className="rp-table">
          <thead><tr><th>Path</th><th>SHA-256</th></tr></thead>
          <tbody>
            {hashes.map((h, i) => (
              <tr key={`${h.path}-${i}`}>
                <td><code>{h.path}</code></td>
                <td><code>{h.sha256_first_bytes || "-"}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function TailsCaseWorkspace({ report, imgPath, caseName, onBackToCase, onExportJson, onExportHtml, onExportPdf, onReanalyze, reanalyzing }) {
  const [tab, setTab] = useState("overview");
  const findings = report?.tails || [];
  const summary = report?.summary || {};
  const tails_artifacts = report?.tails_artifacts || {};
  const { loading: mountLoading, error: mountError, snapshot: mountSnapshot } = useTailsMountSnapshot(imgPath);
  const effectiveArtifacts = useMemo(
    () => (hasTailsArtifactData(mountSnapshot?.artifacts) ? mountSnapshot.artifacts : tails_artifacts),
    [mountSnapshot, tails_artifacts]
  );
  const effectiveFindings = useMemo(
    () => synthesizeTailsFindings(mountSnapshot, findings),
    [mountSnapshot, findings]
  );
  const mountInfo = mountSnapshot?.mountInfo || {};
  const deepScan = tails_artifacts?.deep_scan || effectiveArtifacts?.deep_scan || null;
  const analyticsCount = useMemo(() => {
    const modules = effectiveArtifacts?.persistence_modules?.total || 0;
    const wallets = effectiveArtifacts?.crypto_wallets?.total || 0;
    const keys = effectiveArtifacts?.identity_keys?.total_identities || 0;
    const browser = effectiveArtifacts?.tor_browser_artifacts?.total || 0;
    const files = effectiveArtifacts?.user_files?.stats?.total || 0;
    const deepSignals = (deepScan?.artifacts?.text_scan?.onion_addresses?.length || 0)
      + (deepScan?.artifacts?.text_scan?.suspicious_lines?.length || 0);
    return modules + wallets + keys + browser + files + deepSignals;
  }, [effectiveArtifacts, deepScan]);
  const byCategory = useMemo(() => {
    const map = new Map();
    for (const f of effectiveFindings) {
      const key = f?.category || "other";
      map.set(key, (map.get(key) || 0) + 1);
    }
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [effectiveFindings]);

  return (
    <div className="tails-workspace">
      <div className="tails-workspace-head">
        <div className="tails-workspace-title-wrap">
          <div className="tails-workspace-kicker">CASE-SCOPED TAILS ANALYSIS</div>
          <div className="tails-workspace-title"><TailsLogo withText /> Mounted Source Investigation</div>
          <div className="tails-workspace-sub">
            {caseName ? `Case: ${caseName}` : "Case source"} · {imgPath || "-"}
          </div>
        </div>
        <div className="tails-workspace-actions">
          <button className="btn-secondary btn-sm" onClick={onBackToCase}><ChevronRight size={12} style={{ transform: "rotate(180deg)" }} /> Back to Case</button>
          <button className="btn-secondary btn-sm" onClick={onReanalyze} disabled={reanalyzing} title="Re-run analysis on the same source">
            {reanalyzing ? <><Loader2 size={12} className="spin" /> Reanalyzing...</> : <><RefreshCw size={12} /> Reanalyze</>}
          </button>
          <button className="btn-secondary btn-sm" onClick={onExportJson}><FolderOpen size={12} /> JSON</button>
          <button className="btn-secondary btn-sm" onClick={onExportHtml}><FileText size={12} /> HTML</button>
          <button className="btn-secondary btn-sm" onClick={onExportPdf}><Download size={12} /> PDF</button>
        </div>
      </div>

      <div className="tails-workspace-tabs">
        {[
          ["overview", Activity, "Overview", effectiveFindings.length],
          ["analytics", BarChart3, "Artifact Analytics", analyticsCount],
          ["deep", AlertTriangle, "Deep Indicators", deepScan?.artifacts?.text_scan?.suspicious_lines?.length || 0],
          ["evidence_pack", Archive, "Evidence Pack", deepScan?.artifacts?.evidence_collection?.copied_count || 0],
          ["browser", FolderOpenIcon, "File Browser", null],
          ["findings", Sailboat, "Tails Findings", effectiveFindings.length],
        ].map(([id, Icon, label, count]) => (
          <button key={id} className={`case-tab ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>
            <Icon size={13} /> {label}
            {count != null && <span className="tw-tab-count">{count}</span>}
          </button>
        ))}
      </div>

      <div className="tails-workspace-body">
        {tab === "overview" && (
          <div className="tails-overview-grid">
            <div className="tails-kpi-card"><strong>{effectiveFindings.length}</strong><span>Tails Findings</span></div>
            <div className="tails-kpi-card"><strong>{effectiveFindings.filter((item) => ["high", "critical"].includes(item?.severity)).length}</strong><span>High Severity</span></div>
            <div className="tails-kpi-card"><strong>{effectiveArtifacts?.persistence_modules?.total || 0}</strong><span>Persistence Modules</span></div>
            <div className="tails-kpi-card"><strong>{effectiveArtifacts?.crypto_wallets?.total || 0}</strong><span>Wallet Artifacts</span></div>
            <div className="tails-kpi-card"><strong>{effectiveArtifacts?.identity_keys?.total_identities || 0}</strong><span>Identity Keys</span></div>
            <div className="tails-kpi-card"><strong>{effectiveArtifacts?.anonymity_score?.score || 0}</strong><span>Leakage Score</span></div>

            <div className="tails-overview-panel">
              <h4>Source and Mount Context</h4>
              <table className="rp-table">
                <tbody>
                  <tr><td>Detected OS</td><td>{mountInfo?.osRelease?.PRETTY_NAME || report?.os_info?.name || "Unknown"}</td></tr>
                  <tr><td>OS ID</td><td>{mountInfo?.osRelease?.ID || report?.os_info?.id || "-"}</td></tr>
                  <tr><td>Mounted Path</td><td>{imgPath || "-"}</td></tr>
                  <tr><td>Home Directories</td><td>{mountInfo?.homeDirs?.join(", ") || "/home/amnesia"}</td></tr>
                  <tr><td>Encrypted Persistence</td><td>{mountInfo?.encryptedPersistence ? "Detected / Unlocked" : "No evidence recovered"}</td></tr>
                  <tr><td>Analysis Mode</td><td>{summary?.analysis_mode || "-"}</td></tr>
                  <tr><td>Extraction Method</td><td>{report?.evidence_provenance?.[0]?.extraction_method || "-"}</td></tr>
                </tbody>
              </table>
            </div>

            <div className="tails-overview-panel">
              <h4>Mount-Derived Highlights</h4>
              {mountLoading ? (
                <div className="cases-empty" style={{ minHeight: 120 }}><p>Inspecting mount point…</p></div>
              ) : mountError ? (
                <div className="cases-empty" style={{ minHeight: 120 }}><p>{mountError}</p></div>
              ) : (
                <table className="rp-table">
                  <tbody>
                    <tr><td>Browser Profiles</td><td>{effectiveArtifacts?.tor_browser_artifacts?.profiles?.length || 0}</td></tr>
                    <tr><td>Persistent Files</td><td>{effectiveArtifacts?.user_files?.stats?.total || 0}</td></tr>
                    <tr><td>History Entries</td><td>{effectiveArtifacts?.dotfiles_and_activity?.history_entries || 0}</td></tr>
                    <tr><td>Suspicious Commands</td><td>{effectiveArtifacts?.dotfiles_and_activity?.suspicious_count || 0}</td></tr>
                    <tr><td>Tor Bridges</td><td>{effectiveArtifacts?.network_config?.bridges_count || 0}</td></tr>
                    <tr><td>Hidden Service Lines</td><td>{effectiveArtifacts?.network_config?.hidden_services?.length || 0}</td></tr>
                  </tbody>
                </table>
              )}
            </div>

            <div className="tails-overview-panel">
              <h4>Persistence and Identity Evidence</h4>
              {(effectiveArtifacts?.persistence_modules?.enabled?.length || 0) === 0 && (effectiveArtifacts?.identity_keys?.total_identities || 0) === 0 ? (
                <div className="cases-empty" style={{ minHeight: 120 }}>
                  <p>No persistence modules or identity keys were recovered from the mounted source.</p>
                </div>
              ) : (
                <table className="rp-table">
                  <thead><tr><th>Artifact</th><th>Count / Detail</th></tr></thead>
                  <tbody>
                    {(effectiveArtifacts?.persistence_modules?.enabled || []).slice(0, 6).map((module) => (
                      <tr key={module.destination}><td>{module.type}</td><td>{module.destination}</td></tr>
                    ))}
                    <tr><td>SSH Keys</td><td>{effectiveArtifacts?.identity_keys?.ssh_keys?.length || 0}</td></tr>
                    <tr><td>GPG Keys</td><td>{effectiveArtifacts?.identity_keys?.gpg_keys?.length || 0}</td></tr>
                    <tr><td>Wallet Files</td><td>{effectiveArtifacts?.crypto_wallets?.total || 0}</td></tr>
                  </tbody>
                </table>
              )}
            </div>

            <div className="tails-overview-panel">
              <h4>Findings Distribution</h4>
              {byCategory.length === 0 ? (
                <div className="cases-empty" style={{ minHeight: 120 }}>
                  <p>No Tails-specific findings recorded for this source.</p>
                </div>
              ) : (
                <table className="rp-table">
                  <thead><tr><th>Category</th><th>Count</th></tr></thead>
                  <tbody>
                    {byCategory.map(([cat, count]) => (
                      <tr key={cat}><td>{TAILS_CATEGORY_LABELS[cat] || cat}</td><td>{count}</td></tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {tab === "browser" && <TailsLiteBrowser imgPath={imgPath} />}

        {tab === "analytics" && <TailsAnalyticsPanel artifacts={effectiveArtifacts} report={report} mountInfo={mountInfo} loading={mountLoading} error={mountError} />}

        {tab === "deep" && <TailsDeepIndicatorsTab deepScan={deepScan} />}

        {tab === "evidence_pack" && <TailsCollectedEvidenceTab deepScan={deepScan} />}

        {tab === "findings" && <TailsTab findings={effectiveFindings} summary={summary} />}
      </div>
    </div>
  );
}

function ReportPanel({ report, liveInfo, imgPath, onClear, onExportJson, onExportHtml, onExportPdf, onExportExecutivePdf, onReanalyze, reanalyzing }) {
  const [tab, setTab] = useState("summary");
  const [tabsMenuOpen, setTabsMenuOpen] = useState(false);
  const [visibleTabIds, setVisibleTabIds] = useState(REPORT_TABS.map((t) => t.id));
  const [dateRangeDraft, setDateRangeDraft] = useState({ from: "", to: "" });
  const [dateRangeApplied, setDateRangeApplied] = useState({ from: "", to: "" });
  const tabbarRef = useRef(null);
  const measureWrapRef = useRef(null);
  const moreMeasureRef = useRef(null);
  const { summary } = report;
  const isLive = !!liveInfo;
  const isTailsReport = useMemo(() => isTailsFocusedReport(report), [report]);

  const rangeMs = useMemo(() => {
    const fromMs = dateRangeApplied.from ? parseDateToMs(dateRangeApplied.from) : null;
    const toMs = dateRangeApplied.to ? parseDateToMs(dateRangeApplied.to) : null;
    return { fromMs, toMs };
  }, [dateRangeApplied]);

  const hasRange = hasDateRange(rangeMs);
  const draftHasRange = !!dateRangeDraft.from || !!dateRangeDraft.to;
  const hasPendingDateChanges =
    dateRangeDraft.from !== dateRangeApplied.from || dateRangeDraft.to !== dateRangeApplied.to;

  const filteredTimeline = useMemo(
    () => filterTimelineByDateRange(report.timeline || [], rangeMs),
    [report.timeline, rangeMs]
  );

  const filteredDeleted = useMemo(
    () => filterByDateRange(report.deleted || [], getDeletedTimestampMs, rangeMs),
    [report.deleted, rangeMs]
  );

  const filteredBrowsers = useMemo(
    () => filterBrowsersByDateRange(report.browsers || [], rangeMs),
    [report.browsers, rangeMs]
  );

  const filteredMultimedia = useMemo(
    () => filterByDateRange(report.multimedia || [], getMultimediaTimestampMs, rangeMs),
    [report.multimedia, rangeMs]
  );

  const recentActivities = useMemo(
    () => buildRecentActivities({
      timeline: filteredTimeline,
      deleted: filteredDeleted,
      browsers: filteredBrowsers,
      multimedia: filteredMultimedia,
    }),
    [filteredTimeline, filteredDeleted, filteredBrowsers, filteredMultimedia]
  );

  const highTimelineFiltered = filteredTimeline.filter((e) => e.severity === "high" || e.severity === "critical").length;
  const highDeletedFiltered = filteredDeleted.filter((e) => e.severity === "high" || e.severity === "critical").length;
  const highBrowserFiltered = filteredBrowsers.reduce(
    (acc, p) => acc + [
      ...(p.history || []), ...(p.downloads || []), ...(p.bookmarks || []), ...(p.cookies || []),
      ...(p.extensions || []), ...(p.logins || []), ...(p.search_terms || []), ...(p.autofill || []),
    ].filter((x) => x.severity === "high" || x.severity === "critical").length,
    0
  );
  const highMediaFiltered = filteredMultimedia.filter((m) => m.severity === "high" || m.severity === "critical").length;
  const highTailsFiltered = (report.tails || []).filter((t) => t.severity === "high" || t.severity === "critical").length;
  const containersDetected = !!(report.containers && report.containers.detected);
  const reportTabs = useMemo(
    () => REPORT_TABS.filter((t) => {
      if (t.id === "containers" && !containersDetected) return false;
      if (t.id === "tails" && !isTailsReport) return false;
      return true;
    }),
    [containersDetected, isTailsReport]
  );

  useEffect(() => {
    if (!reportTabs.some((t) => t.id === tab)) {
      setTab("summary");
    }
  }, [reportTabs, tab]);

  useEffect(() => {
    function recalcVisibleTabs() {
      const barW = tabbarRef.current?.clientWidth || 0;
      const measureWrap = measureWrapRef.current;
      if (!barW || !measureWrap) return;

      const widthById = new Map();
      for (const n of measureWrap.querySelectorAll("[data-tab-id]")) {
        widthById.set(n.getAttribute("data-tab-id"), n.getBoundingClientRect().width);
      }

      const gap = 2;
      const order = reportTabs.map((t) => t.id);
      const moreW = (moreMeasureRef.current?.getBoundingClientRect().width || 74) + gap;

      let used = 0;
      const ids = [];
      for (const id of order) {
        const w = (widthById.get(id) || 84) + (ids.length > 0 ? gap : 0);
        if (used + w <= barW) {
          ids.push(id);
          used += w;
        } else {
          break;
        }
      }

      const allFit = ids.length === order.length;
      if (!allFit) {
        while (ids.length > 1 && used + moreW > barW) {
          const removed = ids.pop();
          const rw = (widthById.get(removed) || 84) + (ids.length > 0 ? gap : 0);
          used -= rw;
        }
      }

      if (!ids.includes(tab)) {
        const base = [tab, ...order.filter((id) => id !== tab)];
        let u2 = 0;
        const keep = [];
        for (const id of base) {
          const w = (widthById.get(id) || 84) + (keep.length > 0 ? gap : 0);
          if (u2 + w <= barW) {
            keep.push(id);
            u2 += w;
          } else {
            break;
          }
        }
        const allFit2 = keep.length === order.length;
        if (!allFit2) {
          while (keep.length > 1 && u2 + moreW > barW) {
            const removed = keep.pop();
            const rw = (widthById.get(removed) || 84) + (keep.length > 0 ? gap : 0);
            u2 -= rw;
          }
        }
        setVisibleTabIds(keep);
      } else {
        setVisibleTabIds(ids);
      }
    }

    recalcVisibleTabs();
    const ro = new ResizeObserver(recalcVisibleTabs);
    if (tabbarRef.current) ro.observe(tabbarRef.current);
    window.addEventListener("resize", recalcVisibleTabs);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", recalcVisibleTabs);
    };
  }, [tab, highTimelineFiltered, highDeletedFiltered, highBrowserFiltered, highMediaFiltered, highTailsFiltered, reportTabs]);

  const visibleTabs = reportTabs.filter((t) => visibleTabIds.includes(t.id));
  const hiddenTabs = reportTabs.filter((t) => !visibleTabIds.includes(t.id));

  useEffect(() => {
    setTabsMenuOpen(false);
  }, [tab]);

  const badge = {
    timeline: highTimelineFiltered > 0 ? highTimelineFiltered : null,
    recent: recentActivities.length > 0 ? recentActivities.length : null,
    deleted: highDeletedFiltered > 0 ? highDeletedFiltered : null,
    persistence: summary?.high_persistence > 0 ? summary.high_persistence : null,
    config: summary?.high_config > 0 ? summary.high_config : null,
    services: summary?.high_services > 0 ? summary.high_services : null,
    browsers: highBrowserFiltered > 0 ? highBrowserFiltered : null,
    multimedia: highMediaFiltered > 0 ? highMediaFiltered : null,
    tails: highTailsFiltered > 0 ? highTailsFiltered : null,
    tools: summary?.high_risk_tools > 0 ? summary.high_risk_tools : null,
    antiforensics: summary?.high_antiforensics > 0 ? summary.high_antiforensics : null,
    containers:  summary?.high_containers > 0 ? summary.high_containers : null,
  };
  return (
    <div className="report-panel">
      <div className="report-panel-header">
        <div className="report-panel-header-left">
          <Microscope size={15} strokeWidth={1.6} style={{ color: "#2563eb" }} />
          <span className="report-panel-title">Analysis Report</span>
          {isLive && <span className="rp-live-badge"><Cpu size={11} /> LIVE SYSTEM</span>}
          <span className="dash-os">{report.os_info?.name || "Unknown OS"}</span>
          {(summary?.total_high ?? 0) > 0 && (
            <span className="dash-alert"><AlertTriangle size={11} />{summary.total_high} high</span>
          )}
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <button className="btn-secondary btn-sm" onClick={onReanalyze} disabled={reanalyzing} title="Re-run analysis on the same image">
            <RefreshCw size={12} className={reanalyzing ? "spin" : ""} /> {reanalyzing ? "Analyzing…" : "Reanalyze"}
          </button>
          <button className="btn-secondary btn-sm" onClick={onExportHtml} title="Generate a structured HTML forensic dossier"><FileText size={12} /> HTML</button>
          <button className="btn-secondary btn-sm" onClick={onExportPdf} title="Export comprehensive report as PDF"><Download size={12} /> PDF</button>
          <button className="btn-secondary btn-sm" onClick={onExportExecutivePdf} title="Export a concise executive summary PDF"><Download size={12} /> Exec PDF</button>
          <button className="btn-secondary btn-sm" onClick={onClear}><Trash2 size={12} /> Clear</button>
        </div>
      </div>
      <div className="report-tabbar" ref={tabbarRef}>
        {visibleTabs.map(({ id, label, Icon }) => (
          <button key={id} className={`dash-tab ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>
            <Icon size={12} />{label}
            {badge[id] != null && <span className="tab-badge">{badge[id]}</span>}
          </button>
        ))}
        {hiddenTabs.length > 0 && (
          <div className="tab-more-wrap">
            <button className={`dash-tab tab-more-btn ${tabsMenuOpen ? "active" : ""}`} onClick={() => setTabsMenuOpen((v) => !v)}>
              <List size={12} /> More <ChevronDown size={11} />
            </button>
            {tabsMenuOpen && (
              <div className="tab-more-menu">
                {hiddenTabs.map(({ id, label, Icon }) => (
                  <button
                    key={id}
                    className={`tab-more-item ${tab === id ? "active" : ""}`}
                    onClick={() => { setTab(id); setTabsMenuOpen(false); }}
                  >
                    <Icon size={12} /> {label}
                    {badge[id] != null && <span className="tab-badge">{badge[id]}</span>}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
        <div className="tab-measure-wrap" aria-hidden="true" ref={measureWrapRef}>
          {reportTabs.map(({ id, label, Icon }) => (
            <span key={`m-${id}`} data-tab-id={id} className="dash-tab tab-measure-item">
              <Icon size={12} />{label}
              {badge[id] != null && <span className="tab-badge">{badge[id]}</span>}
            </span>
          ))}
          <span ref={moreMeasureRef} className="dash-tab tab-measure-item"><List size={12} /> More <ChevronDown size={11} /></span>
        </div>
      </div>
      <div className="report-global-filter">
        <div className="rgf-left">
          <Filter size={12} />
          <span className="rgf-label">Global Date Range</span>
          <input
            className="rgf-input"
            type="datetime-local"
            value={dateRangeDraft.from}
            onChange={(e) => setDateRangeDraft((s) => ({ ...s, from: e.target.value }))}
          />
          <span className="rgf-sep">to</span>
          <input
            className="rgf-input"
            type="datetime-local"
            value={dateRangeDraft.to}
            onChange={(e) => setDateRangeDraft((s) => ({ ...s, to: e.target.value }))}
          />
          <button
            className="btn-primary btn-sm"
            onClick={() => setDateRangeApplied(dateRangeDraft)}
            disabled={!hasPendingDateChanges}
          >
            Apply
          </button>
          <button
            className="rgf-clear"
            onClick={() => {
              setDateRangeDraft({ from: "", to: "" });
              setDateRangeApplied({ from: "", to: "" });
            }}
            disabled={!draftHasRange && !hasRange}
          >
            Clear
          </button>
        </div>
        {hasRange && (
          <div className="rgf-right">
            {filteredTimeline.length + filteredDeleted.length + filteredMultimedia.length} records in range
          </div>
        )}
      </div>
      <div className="report-panel-body">
        {tab === "summary" && <SummaryTab report={report} liveInfo={liveInfo} />}
        {tab === "timeline" && <TimelineTab events={filteredTimeline} dateRangeMs={rangeMs} />}
        {tab === "recent" && <RecentActivitiesTab activities={recentActivities} />}
        {tab === "deleted" && <DeletedTab findings={filteredDeleted} imgPath={imgPath} />}
        {tab === "persistence" && <PersistenceTab findings={report.persistence} />}
        {tab === "config" && <ConfigTab findings={report.config} />}
        {tab === "services" && <ServicesTab services={report.services} />}
        {tab === "browsers" && <BrowserTab browsers={filteredBrowsers} />}
        {tab === "multimedia" && <MultimediaTab findings={filteredMultimedia} imgPath={imgPath} />}
        {tab === "tails" && <TailsTab findings={report.tails || []} summary={summary || {}} />}
        {tab === "antiforensics" && <AntiForensicsTab findings={report.antiforensics || []} timelineAI={report.timeline_ai} />}
        {tab === "containers" && <ContainerTab data={report.containers || {}} />}
        {tab === "tools" && <ToolsTab findings={report.findings} />}
        {tab === "evidence" && <EvidenceLocker report={report} />}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CASE MANAGEMENT COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

// ── NewCaseDialog ─────────────────────────────────────────────────────────────
function NewCaseDialog({ onClose, onCreate }) {
  const [fields, setFields] = useState({ name: "", number: "", examiner: "", description: "" });
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  const set = (k) => (e) => setFields((f) => ({ ...f, [k]: e.target.value }));

  async function submit(mode = "normal") {
    if (!fields.name.trim()) { setErr("Case name is required."); return; }
    setLoading(true); setErr(null);
    try {
      const c = await apiCaseCreate(fields);
      onCreate(c, { openAddSourceMode: mode === "tails" ? "tails" : "normal" });
      onClose();
    } catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  }

  return (
    <Modal title="New Forensic Case" onClose={onClose} width={520}>
      <div className="dlg-field">
        <label>Case Name *</label>
        <input autoFocus value={fields.name} onChange={set("name")} onKeyDown={(e) => e.key === "Enter" && submit("normal")} placeholder="e.g. Incident Response 2026-03" />
      </div>
      <div className="dlg-row2">
        <div className="dlg-field">
          <label>Case Number</label>
          <input value={fields.number} onChange={set("number")} placeholder="CASE-2026-001" />
        </div>
        <div className="dlg-field">
          <label>Examiner</label>
          <input value={fields.examiner} onChange={set("examiner")} placeholder="Jane Forensics" />
        </div>
      </div>
      <div className="dlg-field">
        <label>Description</label>
        <textarea rows={3} value={fields.description} onChange={set("description")} placeholder="Brief description of the investigation…" style={{ width: "100%", padding: "7px 10px", border: "1px solid var(--border)", borderRadius: "var(--radius)", font: "inherit", fontSize: 13, resize: "vertical", background: "#fafbfd", outline: "none" }} />
      </div>
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button className="btn-primary" onClick={() => submit("normal")} disabled={loading || !fields.name.trim()}>
          <Plus size={14} />{loading ? "Creating…" : "Create Case"}
        </button>
        <button className="btn-secondary tails-btn" onClick={() => submit("tails")} disabled={loading || !fields.name.trim()}>
          <TailsLogo size="sm" /> {loading ? "Creating…" : "Create + Analyze TailsOS"}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

// ── AddSourceDialog ───────────────────────────────────────────────────────────
function AddSourceDialog({ onClose, caseId, onSuccess, preferredMode = "normal", autoDetectUsb = false }) {
  const [picking, setPicking] = useState(false);
  const [path, setPath] = useState("");
  const [loadingMode, setLoadingMode] = useState(null);
  const [err, setErr] = useState(null);
  const [usbLoading, setUsbLoading] = useState(false);
  const [usbErr, setUsbErr] = useState(null);
  const [usbSources, setUsbSources] = useState([]);

  async function detectUsb() {
    setUsbLoading(true); setUsbErr(null);
    try {
      const r = await apiUsbSources();
      setUsbSources(r.sources || []);
      if (!path && (r.sources || []).length > 0) {
        setPath((r.sources || [])[0].use_path || "");
      }
    } catch (e) {
      setUsbErr(String(e));
    } finally {
      setUsbLoading(false);
    }
  }

  useEffect(() => {
    if (autoDetectUsb) detectUsb();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoDetectUsb]);

  async function run(mode = "normal") {
    if (!path) return;
    setLoadingMode(mode); setErr(null);
    try {
      const res = mode === "tails"
        ? await apiCaseAnalyzeTailsDeep(caseId, path)
        : await apiCaseAnalyze(caseId, path);
      onSuccess(res.source, res.report, mode);
      onClose();
    } catch (e) { setErr(String(e)); }
    finally { setLoadingMode(null); }
  }

  if (picking) {
    return (
      <FilePickerDialog
        onClose={() => setPicking(false)}
        onResult={(_, selectedPath) => { setPath(selectedPath); setPicking(false); }}
        analyzeOnPick={false}
      />
    );
  }

  return (
    <Modal title={preferredMode === "tails" ? "Add Data Source — Analyze TailsOS" : "Add Data Source to Case"} onClose={onClose} width={640}>
      <div className="usb-source-box">
        <div className="usb-source-head">
          <div className="usb-source-title"><Usb size={13} /> Add Tails USB as Source</div>
          <button className="btn-secondary btn-sm" onClick={detectUsb} disabled={usbLoading}>
            <RefreshCw size={12} className={usbLoading ? "spin" : ""} /> {usbLoading ? "Detecting…" : "Detect USB"}
          </button>
        </div>
        {usbErr && <div className="dlg-error" style={{ marginBottom: 8 }}>{usbErr}</div>}
        {usbSources.length === 0 && !usbLoading && (
          <div className="usb-empty">No USB sources found. Plug in a Tails USB and click Detect USB.</div>
        )}
        {usbSources.length > 0 && (
          <div className="usb-list">
            {usbSources.map((s, idx) => (
              <div key={`${s.device_path}-${idx}`} className="usb-row">
                <div className="usb-row-main">
                  <div className="usb-row-top">
                    <code>{s.device_path}</code>
                    {s.tails_likely && <span className="source-threat tl-high">TAILS LIKELY</span>}
                  </div>
                  <div className="usb-row-meta">
                    <span>{[s.vendor, s.model].filter(Boolean).join(" ") || "USB device"}</span>
                    <span>{s.size || ""}</span>
                    {s.mountpoint && <span>mounted: <code>{s.mountpoint}</code></span>}
                  </div>
                  {(s.tails_markers || []).length > 0 && (
                    <div className="usb-row-markers">markers: {(s.tails_markers || []).join(", ")}</div>
                  )}
                </div>
                <div className="usb-row-actions">
                  <button className="btn-secondary btn-sm" onClick={() => setPath(s.use_path || s.device_path)}>
                    Use Path
                  </button>
                  <button
                    className="btn-secondary btn-sm tails-btn"
                    onClick={() => { setPath(s.use_path || s.device_path); run("tails"); }}
                    disabled={!!loadingMode}
                  >
                    <TailsLogo size="sm" /> Add Tails USB
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="dlg-field">
        <label>Image / Mountpoint Path</label>
        <div style={{ display: "flex", gap: 8 }}>
          <input
            style={{ flex: 1 }}
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run(preferredMode === "tails" ? "tails" : "normal")}
            placeholder="/mnt/evidence  or  /path/to/disk.img"
          />
          <button className="btn-secondary" onClick={() => setPicking(true)} title="Browse filesystem">
            <FolderOpen size={15} />
          </button>
        </div>
        <div className="dlg-hint">The analysis result will be saved into this case automatically.</div>
      </div>
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button
          className={preferredMode === "tails" ? "btn-secondary" : "btn-primary"}
          onClick={() => run("normal")}
          disabled={!!loadingMode || !path}
        >
          <Search size={14} />{loadingMode === "normal" ? "Analyzing…" : "Analyze & Add"}
        </button>
        <button
          className={preferredMode === "tails" ? "btn-primary tails-btn" : "btn-secondary tails-btn"}
          onClick={() => run("tails")}
          disabled={!!loadingMode || !path}
          title="Run dedicated Tails OS artifact analysis under this case"
        >
          <TailsLogo size="sm" /> {loadingMode === "tails" ? "Analyzing TailsOS…" : "Analyze TailsOS"}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

// ── CasesView ─────────────────────────────────────────────────────────────────
function CasesView({ onOpen, onNewCase }) {
  const [cases, setCases] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [deleting, setDeleting] = useState(null);

  async function load() {
    setLoading(true); setErr(null);
    try { const r = await apiCasesList(); setCases(r.cases); }
    catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function handleDelete(e, id) {
    e.stopPropagation();
    if (!window.confirm("Permanently delete this case and all its data?")) return;
    setDeleting(id);
    try { await apiCaseDelete(id); setCases((cs) => cs.filter((c) => c.id !== id)); }
    catch (err2) { alert("Delete failed: " + String(err2)); }
    finally { setDeleting(null); }
  }

  return (
    <div className="cases-view">
      <div className="cases-header">
        <div className="cases-header-left">
          <BookOpen size={18} className="cases-hdr-icon" />
          <span className="cases-title">Cases</span>
          {cases && <span className="cases-count">{cases.length}</span>}
        </div>
        <div className="cases-header-right">
          <button className="btn-secondary btn-sm" onClick={load} title="Refresh">
            <RefreshCw size={13} />
          </button>
          <button className="btn-primary btn-sm" onClick={onNewCase}>
            <Plus size={13} /> New Case
          </button>
        </div>
      </div>

      <div className="cases-body">
        {loading && <div className="cases-loading"><RefreshCw size={20} className="spin" /> Loading cases…</div>}
        {err && <div className="dlg-error" style={{ margin: 24 }}>{err}</div>}
        {!loading && cases?.length === 0 && (
          <div className="cases-empty">
            <BookOpen size={48} strokeWidth={1.2} className="cases-empty-icon" />
            <p>No cases yet.</p>
            <button className="btn-primary" onClick={onNewCase}><Plus size={14} /> Create First Case</button>
          </div>
        )}
        {!loading && cases?.length > 0 && (
          <div className="cases-grid">
            {cases.map((c) => (
              <div key={c.id} className="case-card" onClick={() => onOpen(c.id)}>
                <div className="case-card-top">
                  <div className="case-card-icon"><BookOpen size={22} strokeWidth={1.4} /></div>
                  <div className="case-card-meta">
                    {c.number && <span className="case-number">{c.number}</span>}
                    <h3 className="case-name">{c.name}</h3>
                    {c.examiner && <span className="case-examiner"><Users size={11} /> {c.examiner}</span>}
                  </div>
                  <button
                    className="case-del-btn"
                    title="Delete case"
                    disabled={deleting === c.id}
                    onClick={(e) => handleDelete(e, c.id)}
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
                {c.description && <p className="case-desc">{c.description}</p>}
                <div className="case-card-footer">
                  <span><HardDrive size={11} /> {c.source_count} source{c.source_count !== 1 ? "s" : ""}</span>
                  <span><Clock size={11} /> {fmtDate(c.updated_at)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── CasePanel ─────────────────────────────────────────────────────────────────
function CasePanel({ caseData, activeSourceId, onSelectSource, onAddSource, onAddTailsSource, onAddTailsUsbSource, onScanLiveToCase, onDeleteSource, onBack, onExportCaseHtml, onExportCasePdf }) {
  const [activeTab, setActiveTab] = useState("sources");
  const { data_sources = [] } = caseData;
  const chainOfCustody = caseData.chain_of_custody || [];
  const auditLog = caseData.audit_log || [];

  const shortHash = (h) => {
    if (!h) return "-";
    return h.length > 20 ? `${h.slice(0, 12)}...${h.slice(-8)}` : h;
  };

  const evidenceRows = data_sources.map((src) => {
    const ev = src.evidence || {};
    const prov = src.provenance || {};
    return {
      sourceId: src.id,
      label: src.label || src.path,
      path: src.path,
      evidenceId: ev.evidence_id || "-",
      acquiredAt: ev.acquisition_time || src.added_at,
      sha256: ev.hashes?.sha256 || "",
      sha1: ev.hashes?.sha1 || "",
      extractionMethod: prov.extraction_method || "-",
      originalPath: prov.original_path || src.path,
      integrity: ev.hashes || {},
    };
  });

  const threatSummary = (src) => {
    const hi = src.report?.summary?.total_high ?? 0;
    if (hi === 0) return { label: "CLEAN", cls: "tl-low" };
    if (hi >= 10) return { label: "CRITICAL", cls: "tl-critical" };
    if (hi >= 5) return { label: "HIGH", cls: "tl-high" };
    return { label: "MEDIUM", cls: "tl-medium" };
  };

  return (
    <div className="case-panel">
      {/* Header */}
      <div className="case-panel-header">
        <button className="case-back-btn" onClick={onBack} title="Back to cases">
          <ChevronRight size={16} style={{ transform: "rotate(180deg)" }} />
        </button>
        <div className="case-panel-title-wrap">
          <BookOpen size={16} className="case-panel-icon" />
          <div>
            <div className="case-panel-name">{caseData.name}</div>
            <div className="case-panel-meta">
              {caseData.number && <span className="tag">{caseData.number}</span>}
              {caseData.examiner && <span className="tag"><Users size={10} /> {caseData.examiner}</span>}
              <span className="tag"><Clock size={10} /> Created {fmtDate(caseData.created_at)}</span>
            </div>
          </div>
        </div>
        <div style={{ marginLeft: "auto" }}>
          <button className="btn-secondary btn-sm" onClick={onScanLiveToCase} title="Scan current live machine and save findings under this case" style={{ marginRight: 8 }}>
            <Cpu size={12} /> Scan Live to Case
          </button>
          <button className="btn-secondary btn-sm" onClick={onAddTailsUsbSource} title="Detect connected USB drives and add Tails source" style={{ marginRight: 8 }}>
            <Usb size={12} /> Add Tails USB
          </button>
          <button className="btn-secondary btn-sm tails-btn" onClick={onAddTailsSource} title="Add source with dedicated TailsOS analysis" style={{ marginRight: 8 }}>
            <TailsLogo size="sm" /> Analyze TailsOS
          </button>
          <button className="btn-secondary btn-sm" onClick={onExportCaseHtml} title="Export full case-level report as HTML" style={{ marginRight: 8 }}>
            <FileText size={12} /> Case HTML
          </button>
          <button className="btn-secondary btn-sm" onClick={onExportCasePdf} title="Export full case-level report as PDF" style={{ marginRight: 8 }}>
            <Download size={12} /> Case PDF
          </button>
          <button className="btn-primary btn-sm" onClick={onAddSource}>
            <Plus size={13} /> Add Data Source
          </button>
        </div>
      </div>

      {/* Tab bar */}
      <div className="case-tabs">
        {[
          ["sources", HardDrive, "Data Sources"],
          ["integrity", Hash, "Integrity"],
          ["evidence", Hash, `Evidence (${evidenceRows.length})`],
          ["custody", Shield, `Chain of Custody (${chainOfCustody.length})`],
          ["audit", Activity, `Audit Log (${auditLog.length})`],
          ["info", Info, "Case Info"],
        ].map(([id, Icon, label]) => (
          <button key={id} className={`case-tab ${activeTab === id ? "active" : ""}`} onClick={() => setActiveTab(id)}>
            <Icon size={13} />{label}
          </button>
        ))}
      </div>

      {/* Sources tab */}
      {activeTab === "sources" && (
        <div className="case-sources">
          {data_sources.length === 0 ? (
            <div className="cases-empty" style={{ paddingTop: 40 }}>
              <HardDrive size={40} strokeWidth={1.2} className="cases-empty-icon" />
              <p>No data sources yet.</p>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn-secondary" onClick={onScanLiveToCase}><Cpu size={12} /> Scan Live to Case</button>
                <button className="btn-secondary" onClick={onAddTailsUsbSource}><Usb size={12} /> Add Tails USB</button>
                <button className="btn-secondary tails-btn" onClick={onAddTailsSource}><TailsLogo size="sm" /> Analyze TailsOS</button>
                <button className="btn-primary" onClick={onAddSource}><Plus size={14} /> Add Data Source</button>
              </div>
            </div>
          ) : (
            <div className="source-list">
              {data_sources.map((src) => {
                const threat = threatSummary(src);
                const isActive = activeSourceId === src.id;
                return (
                  <div
                    key={src.id}
                    className={`source-row ${isActive ? "source-row-active" : ""}`}
                    onClick={() => onSelectSource(src)}
                  >
                    <HardDrive size={18} strokeWidth={1.4} className="source-row-icon" />
                    <div className="source-row-body">
                      <div className="source-row-label">{src.label || src.path}</div>
                      <div className="source-row-path">{src.path}</div>
                      <div className="source-row-meta">
                        <span><Clock size={10} /> {fmtDate(src.added_at)}</span>
                        {src.report && (
                          <>
                            <span><FileText size={10} /> {src.report.findings?.length ?? 0} tools</span>
                            <span><Clock size={10} /> {src.report.summary?.timeline_events ?? 0} events</span>
                          </>
                        )}
                      </div>
                    </div>
                    <span className={`source-threat ${threat.cls}`}>{threat.label}</span>
                    <button
                      className="source-del-btn"
                      title="Remove source"
                      onClick={(e) => { e.stopPropagation(); onDeleteSource(src.id); }}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Integrity tab */}
      {activeTab === "integrity" && (
        <div className="case-info">
          {evidenceRows.length === 0 ? (
            <div className="cases-empty" style={{ paddingTop: 30 }}>
              <Hash size={36} strokeWidth={1.2} className="cases-empty-icon" />
              <p>No integrity records yet.</p>
            </div>
          ) : (
            <div style={{ display: "grid", gap: 14 }}>
              {evidenceRows.map((row) => {
                const extraHashes = Object.entries(row.integrity).filter(([key]) => key !== "sha256" && key !== "sha1");
                return (
                  <div key={row.sourceId} style={{ border: "1px solid var(--border-lt)", borderRadius: "var(--radius)", padding: "12px 14px", background: "#fff" }}>
                    <div style={{ marginBottom: 8 }}>
                      <strong style={{ fontSize: 13 }}>{row.label}</strong>
                    </div>
                    <table className="rp-table" style={{ maxWidth: "100%" }}>
                      <tbody>
                        <tr><td>SHA256</td><td><code style={{ fontSize: 11, wordBreak: "break-all" }}>{row.sha256 || "-"}</code></td></tr>
                        <tr><td>SHA1</td><td><code style={{ fontSize: 11, wordBreak: "break-all" }}>{row.sha1 || "-"}</code></td></tr>
                        {extraHashes.map(([key, value]) => (
                          <tr key={key}><td>{key.toUpperCase()}</td><td><code style={{ fontSize: 11, wordBreak: "break-all" }}>{value || "-"}</code></td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Evidence tab */}
      {activeTab === "evidence" && (
        <div className="case-info">
          {evidenceRows.length === 0 ? (
            <div className="cases-empty" style={{ paddingTop: 30 }}>
              <Hash size={36} strokeWidth={1.2} className="cases-empty-icon" />
              <p>No evidence records yet. Add a data source to generate integrity metadata.</p>
            </div>
          ) : (
            <div style={{ display: "grid", gap: 14 }}>
              {evidenceRows.map((row) => (
                <div key={row.sourceId} style={{ border: "1px solid var(--border-lt)", borderRadius: "var(--radius)", padding: "12px 14px", background: "#fff" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <strong style={{ fontSize: 13 }}>{row.label}</strong>
                    <span className="tag"><Hash size={10} /> {row.evidenceId}</span>
                  </div>
                  <table className="rp-table" style={{ maxWidth: "100%" }}>
                    <tbody>
                      <tr><td>Path</td><td style={{ wordBreak: "break-all" }}>{row.path}</td></tr>
                      <tr><td>Acquired</td><td>{fmtDate(row.acquiredAt)}</td></tr>
                      <tr><td>SHA256</td><td><code style={{ fontSize: 11 }}>{shortHash(row.sha256)}</code></td></tr>
                      <tr><td>SHA1</td><td><code style={{ fontSize: 11 }}>{shortHash(row.sha1)}</code></td></tr>
                      <tr><td>Extraction</td><td>{row.extractionMethod}</td></tr>
                      <tr><td>Original Path</td><td style={{ wordBreak: "break-all" }}>{row.originalPath}</td></tr>
                    </tbody>
                  </table>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Chain of custody tab */}
      {activeTab === "custody" && (
        <div className="case-info">
          {chainOfCustody.length === 0 ? (
            <div className="cases-empty" style={{ paddingTop: 30 }}>
              <Shield size={36} strokeWidth={1.2} className="cases-empty-icon" />
              <p>No chain-of-custody entries yet.</p>
            </div>
          ) : (
            <div style={{ display: "grid", gap: 10 }}>
              {chainOfCustody.map((ev, i) => (
                <div key={`${ev.timestamp || "t"}-${ev.evidence_id || "ev"}-${i}`} style={{ border: "1px solid var(--border-lt)", borderRadius: "var(--radius)", padding: "10px 12px", background: "#fff" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                    <strong style={{ fontSize: 13 }}>{ev.action || "event"}</strong>
                    <span className="tag"><Clock size={10} /> {fmtDate(ev.timestamp)}</span>
                  </div>
                  <div style={{ marginTop: 6, fontSize: 12, color: "var(--fg-muted)" }}>
                    Evidence: <code>{ev.evidence_id || "-"}</code> | Collected by: {ev.collected_by || "-"} | Verified by: {ev.verified_by || "-"}
                  </div>
                  {ev.notes && <div style={{ marginTop: 6, fontSize: 12 }}>{ev.notes}</div>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Audit tab */}
      {activeTab === "audit" && (
        <div className="case-info">
          {auditLog.length === 0 ? (
            <div className="cases-empty" style={{ paddingTop: 30 }}>
              <Activity size={36} strokeWidth={1.2} className="cases-empty-icon" />
              <p>No audit log entries yet.</p>
            </div>
          ) : (
            <table className="rp-table" style={{ maxWidth: "100%" }}>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {auditLog.map((ev, i) => (
                  <tr key={`${ev.timestamp || "a"}-${ev.action || "action"}-${i}`}>
                    <td>{fmtDate(ev.timestamp)}</td>
                    <td>{ev.actor || "-"}</td>
                    <td>{ev.action || "-"}</td>
                    <td><code style={{ fontSize: 11 }}>{JSON.stringify(ev.details || {})}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Info tab */}
      {activeTab === "info" && (
        <div className="case-info">
          <table className="rp-table" style={{ maxWidth: 600 }}>
            <tbody>
              {[
                ["Case Name", caseData.name],
                ["Case Number", caseData.number || "—"],
                ["Examiner", caseData.examiner || "—"],
                ["Created", fmtDate(caseData.created_at)],
                ["Last Updated", fmtDate(caseData.updated_at)],
                ["Sources", data_sources.length],
                ["Case ID", <code style={{ fontSize: 11 }}>{caseData.id}</code>],
              ].map(([k, v]) => (
                <tr key={k}><td>{k}</td><td>{v}</td></tr>
              ))}
            </tbody>
          </table>
          {caseData.description && (
            <div style={{ marginTop: 16, padding: "12px 14px", background: "#f8f9fc", border: "1px solid var(--border-lt)", borderRadius: "var(--radius)", fontSize: 13, color: "var(--fg-muted)", lineHeight: 1.6 }}>
              {caseData.description}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── WORKSPACE HOME ───────────────────────────────────────────────────────────
function WorkspaceHome({ onAction }) {
  return (
    <div className="ws-home">
      <div className="ws-logo"><Microscope size={64} strokeWidth={1.2} className="ws-logo-icon" /></div>
      <h1 className="ws-title">OS Forensics</h1>
      <p className="ws-sub">Advanced forensic detection &amp; artifact exploration for Linux-based environments</p>
      <div className="ws-feature-badges">
        <span className="feat-badge"><Clock size={12} /> Timeline Engine</span>
        <span className="feat-badge"><Eye size={12} /> Deleted Detection</span>
        <span className="feat-badge"><Shield size={12} /> Persistence Scanner</span>
        <span className="feat-badge"><FolderOpenIcon size={12} /> Artifact Explorer</span>
      </div>
      <div className="ws-quickactions">
        <button className="qa-btn" onClick={() => onAction("analyze")}>
          <span className="qa-icon"><Search size={28} strokeWidth={1.5} /></span>
          <span className="qa-label">Analyze Image</span>
          <span className="qa-hint">Ctrl+O</span>
        </button>
        <button className="qa-btn" onClick={() => onAction("filepick")}>
          <span className="qa-icon"><FolderSearch size={28} strokeWidth={1.5} /></span>
          <span className="qa-label">Browse & Open</span>
          <span className="qa-hint">Ctrl+B</span>
        </button>
        <button className="qa-btn qa-btn-live" onClick={() => onAction("live_scan")}>
          <span className="qa-icon"><Cpu size={28} strokeWidth={1.5} /></span>
          <span className="qa-label">Scan Live System</span>
          <span className="qa-hint">Ctrl+L</span>
        </button>
        <button className="qa-btn" onClick={() => onAction("remote_scan")}>
          <span className="qa-icon"><Wifi size={28} strokeWidth={1.5} /></span>
          <span className="qa-label">Remote Connect</span>
          <span className="qa-hint">Ctrl+Shift+L</span>
        </button>
      </div>
      <p className="ws-tip">Use the <kbd>File</kbd> menu or toolbar to begin. Press <kbd>F1</kbd> for help.</p>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROOT APP
// ═══════════════════════════════════════════════════════════════════════════════
// ─── ACTIVITY BAR ─────────────────────────────────────────────────────────────
// ─── AGENT PANEL ─────────────────────────────────────────────────────────────

function AgentMessage({ msg }) {
  const [expanded, setExpanded] = useState(false);

  if (msg.role === "user") {
    return (
      <div className="ag-msg user">
        <div className="ag-msg-bubble">{msg.text}</div>
      </div>
    );
  }

  const steps = msg.steps || [];
  return (
    <div className={`ag-msg agent${msg.error ? " err" : ""}${msg.inProgress ? " pending" : ""}`}>
      {steps.length > 0 && (
        <div className="ag-reasoning">
          <button className="ag-reasoning-toggle" onClick={() => setExpanded(e => !e)}>
            <Zap size={11} />
            {steps.length} investigation step{steps.length !== 1 ? "s" : ""}
            {msg.inProgress
              ? <Loader2 size={10} className="spin ag-spin-inline" />
              : <span>{expanded ? " ▲" : " ▼"}</span>}
          </button>
          {expanded && (
            <div className="ag-steps">
              {steps.map((s, i) => (
                <div key={i} className="ag-step">
                  <div className="ag-step-head">
                    <span className="ag-step-num">{s.step}</span>
                    <code className="ag-step-tool">{s.action}</code>
                    {s.args && Object.keys(s.args).length > 0 && (
                      <code className="ag-step-args">
                        {Object.entries(s.args).map(([k, v]) => `${k}="${v}"`).join(", ")}
                      </code>
                    )}
                  </div>
                  <div className="ag-step-thought">{s.thought}</div>
                  {s.observation && (
                    <div className={`ag-step-obs${s.observation.error ? " err" : ""}`}>
                      {s.observation.error
                        ? s.observation.error
                        : (() => {
                          const txt = JSON.stringify(s.observation);
                          return txt.length > 400 ? txt.slice(0, 400) + "…" : txt;
                        })()}
                    </div>
                  )}
                </div>
              ))}
              {msg.inProgress && (
                <div className="ag-step thinking-step">
                  <Loader2 size={11} className="spin" /> Investigating…
                </div>
              )}
            </div>
          )}
        </div>
      )}
      <div className="ag-msg-bubble">
        {msg.inProgress && !msg.text ? (
          <span className="ag-thinking-text">
            <Loader2 size={12} className="spin" /> Analysing evidence…
          </span>
        ) : (
          <SimpleMarkdown text={msg.text} />
        )}
      </div>
    </div>
  );
}

const AGENT_EXAMPLES = [
  "Analyse /mnt/evidence and identify all suspicious activity",
  "What persistence mechanisms are present on this system?",
  "Investigate browser history — look for malicious or unusual domains",
  "Check for deleted files and command history that indicate data exfiltration",
];

function AgentPanel() {
  const [messages, setMessages] = useState(() => {
    try { const saved = localStorage.getItem("osf_agent_messages"); return saved ? JSON.parse(saved) : []; }
    catch { return []; }
  });
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState(() => localStorage.getItem("osf_agent_session") || null);
  const [ollamaStatus, setOllamaStatus] = useState(null);
  const [model, setModel] = useState("qwen3.5");
  const bottomRef = useRef(null);
  const abortRef = useRef(null);

  useEffect(() => {
    localStorage.setItem("osf_agent_messages", JSON.stringify(messages));
  }, [messages]);

  useEffect(() => {
    if (sessionId) localStorage.setItem("osf_agent_session", sessionId);
    else localStorage.removeItem("osf_agent_session");
  }, [sessionId]);

  useEffect(() => {
    apiAgentStatus()
      .then(s => { setOllamaStatus(s); if (s.model) setModel(s.model); })
      .catch(() => setOllamaStatus({ available: false, message: "API server not running" }));
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function send() {
    const userMsg = input.trim();
    if (!userMsg || loading) return;
    setInput("");

    setMessages(m => [...m,
    { role: "user", text: userMsg },
    { role: "agent", text: "", steps: [], inProgress: true },
    ]);
    setLoading(true);

    const ctrl = new AbortController();
    abortRef.current = ctrl;
    let curSession = sessionId;
    let accSteps = [];
    let accText = "";

    try {
      const resp = await fetch(`${API}/agent/chat/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: userMsg, session_id: curSession, model }),
        signal: ctrl.signal,
      });
      if (!resp.ok) throw new Error((await resp.text()) || `HTTP ${resp.status}`);

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop();

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const payload = line.slice(6).trim();
          if (payload === "[DONE]") break;
          let ev;
          try { ev = JSON.parse(payload); } catch { continue; }

          if (ev.type === "session") {
            curSession = ev.session_id;
            setSessionId(ev.session_id);
          } else if (ev.type === "step") {
            accSteps = [...accSteps, ev];
            setMessages(m => {
              const c = [...m];
              c[c.length - 1] = { ...c[c.length - 1], steps: accSteps };
              return c;
            });
          } else if (ev.type === "answer") {
            accText = ev.text;
            setMessages(m => {
              const c = [...m];
              c[c.length - 1] = { role: "agent", text: ev.text, steps: accSteps, inProgress: false };
              return c;
            });
          } else if (ev.type === "error") {
            accText = ev.message;
            setMessages(m => {
              const c = [...m];
              c[c.length - 1] = { role: "agent", text: ev.message, steps: accSteps, inProgress: false, error: true };
              return c;
            });
          }
        }
      }

      // In case stream ended without an explicit answer/error event
      setMessages(m => {
        const last = m[m.length - 1];
        if (last?.role === "agent" && last?.inProgress) {
          const c = [...m];
          c[c.length - 1] = { ...last, inProgress: false, text: accText || "Investigation complete." };
          return c;
        }
        return m;
      });
    } catch (e) {
      if (e.name === "AbortError") {
        setMessages(m => {
          const c = [...m];
          if (c[c.length - 1]?.role === "agent")
            c[c.length - 1] = { ...c[c.length - 1], inProgress: false, text: "Investigation stopped by user." };
          return c;
        });
      } else {
        setMessages(m => {
          const c = [...m];
          if (c[c.length - 1]?.role === "agent")
            c[c.length - 1] = { role: "agent", text: String(e), steps: accSteps, inProgress: false, error: true };
          return c;
        });
      }
    } finally {
      setLoading(false);
      abortRef.current = null;
    }
  }

  function stopInvestigation() { abortRef.current?.abort(); }

  function clearSession() {
    if (sessionId) apiAgentReset(sessionId).catch(() => { });
    setMessages([]);
    setSessionId(null);
    localStorage.removeItem("osf_agent_messages");
    localStorage.removeItem("osf_agent_session");
  }

  return (
    <div className="ag-panel">
      {/* header */}
      <div className="ag-header">
        <Bot size={15} strokeWidth={1.8} />
        <span className="ag-header-title">Investigation Agent</span>
        {ollamaStatus && (
          <span
            className={`ag-status-badge${ollamaStatus.available ? " ok" : " err"}`}
            title={ollamaStatus.message}
          >
            {ollamaStatus.available ? ollamaStatus.model : "Ollama offline"}
          </span>
        )}
        <div className="ag-header-right">
          {sessionId && <span className="ag-session-id">#{sessionId}</span>}
          {messages.length > 0 && (
            <button className="ag-btn-icon" onClick={clearSession} disabled={loading} title="Clear session">
              <RefreshCw size={12} /> Clear
            </button>
          )}
        </div>
      </div>

      {/* message thread */}
      <div className="ag-messages">
        {messages.length === 0 && (
          <div className="ag-empty">
            <Bot size={38} strokeWidth={1.1} className="ag-empty-icon" />
            <p>State your investigation goal.<br />The agent gathers evidence using forensic tools, then reasons about it.</p>
            <div className="ag-examples">
              {AGENT_EXAMPLES.map((ex, i) => (
                <button key={i} className="ag-example" onClick={() => setInput(ex)}>{ex}</button>
              ))}
            </div>
          </div>
        )}
        {messages.map((msg, i) => <AgentMessage key={i} msg={msg} />)}
        <div ref={bottomRef} />
      </div>

      {/* input */}
      <div className="ag-input-area">
        <textarea
          className="ag-textarea"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
          placeholder="Describe the investigation goal… (Enter to send, Shift+Enter for newline)"
          rows={2}
          disabled={loading}
        />
        <div className="ag-input-btns">
          {loading ? (
            <button className="ag-btn-stop" onClick={stopInvestigation}>
              <X size={14} /> Stop
            </button>
          ) : (
            <button className="ag-btn-send" onClick={send} disabled={!input.trim()}>
              <Send size={14} />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

const SimpleMarkdown = ({ text }) => {
  if (!text) return null;
  return (
    <div className="markdown-report">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>
        {text}
      </ReactMarkdown>
    </div>
  );
};
function MemoryAnalyser() {
  const [data, setData] = useState(null);
  const [aiInsight, setAiInsight] = useState(null);
  const [loading, setLoading] = useState(true);
  const [aiLoading, setAiLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [activeSubTab, setActiveSubTab] = useState("monitor"); // monitor, processes, network, hidden, malfind, report
  const [analysisMode, setAnalysisMode] = useState("live"); // live, dump
  const [dumpReport, setDumpReport] = useState(null);
  const [uploading, setUploading] = useState(false);
  const timer = useRef(null);
  const [typedInsight, setTypedInsight] = useState("");

  const fetchData = useCallback(async () => {
    if (analysisMode === "dump") return;
    try {
      const res = await apiMemoryLive();
      setData(res);
      setErr(null);
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  }, [analysisMode]);

  useEffect(() => {
    if (analysisMode === "live") {
      fetchData();
      timer.current = setInterval(fetchData, 3000);
      return () => clearInterval(timer.current);
    }
  }, [fetchData, analysisMode]);

  async function getAI() {
    setAiLoading(true);
    setTypedInsight("");
    try {
      let res;
      if (analysisMode === "live") {
        res = await apiMemoryAI();
      } else {
        res = await apiMemoryDumpAI(dumpReport);
      }
      
      setAiInsight(res.insight);
      // Trigger typing animation
      let fullText = res.insight;
      let i = 0;
      const t = setInterval(() => {
        setTypedInsight(fullText.slice(0, i + 1));
        i++;
        if (i >= fullText.length) clearInterval(t);
      }, 10);
    } catch (e) {
      setAiInsight("Error: " + String(e));
      setTypedInsight("Error: " + String(e));
    } finally {
      setAiLoading(false);
    }
  }

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploading(true);
    setLoading(true);
    setErr(null);
    setAnalysisMode("dump");
    setAiInsight(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const report = await apiMemoryDumpUpload(formData);
      setDumpReport(report);
      setActiveSubTab("report"); // Switch to report after successful upload
    } catch (err) {
      setErr("Failed to analyze dump: " + err.message);
      setAnalysisMode("live");
    } finally {
      setUploading(false);
      setLoading(false);
    }
  };

  if (loading && analysisMode === "live" && !data) return <div className="pane-loading"><RefreshCw size={24} className="spin" /> Initializing Analyser…</div>;
  if (uploading) return <div className="pane-loading"><Loader2 size={24} className="spin" /> Uploading & Processing Memory Dump via Volatility 3…</div>;

  // Derive data based on mode
  const ram = analysisMode === "live" ? (data?.ram || {}) : { total_kb: 0, used_kb: 0, available_kb: 0, used_pct: 0 };
  const procs = analysisMode === "live" ? (data?.top_processes || []) : (dumpReport?.processes || []);
  const hiddenProcs = dumpReport?.hidden_processes || [];
  const malfind = dumpReport?.malfind || [];
  const connections = dumpReport?.connections || [];
  
  const usedPct = ram.used_pct || 0;

  // SVG Progress Ring constants
  const size = 180;
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circ = 2 * Math.PI * radius;
  const offset = circ - (usedPct / 100) * circ;

  const fmtSize = (bytes) => {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <div className="tab-content memory-analyser memory-white-theme animate-fade-in">
      <div className="ma-header">
        <div className="ma-title">
          <div className="title-icon-wrapper"><Cpu size={24} /></div>
          <div>
            <div className="ma-main-title">{analysisMode === "live" ? "Live Forensic Memory Analysis" : "Memory Dump Forensic Analysis"}</div>
            <div className="ma-sub-title">
              {analysisMode === "live" 
                ? "Real-time system artifacts & active execution monitoring" 
                : `Analyzing artifact: ${dumpReport?.dump_path?.split("/").pop() || "Memory Image"}`}
            </div>
          </div>
        </div>
        <div className="ma-header-actions" style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          {analysisMode === "dump" && (
            <button className="btn-secondary" onClick={() => setAnalysisMode("live")}>
              <RefreshCw size={14} className="mr-1" /> Switch to Live
            </button>
          )}
          <label className="btn-secondary" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Download size={16} />
            <span>Upload Dump</span>
            <input type="file" style={{ display: 'none' }} onChange={handleFileUpload} accept=".raw,.mem,.lime,.dmp,.vmem" />
          </label>
          <button className="btn-ai-premium" onClick={getAI} disabled={aiLoading || (analysisMode === "dump" && !dumpReport)}>
            {aiLoading ? <Loader2 size={16} className="spin" /> : <Bot size={16} />}
            <span>{aiLoading ? "Analysing Artifacts…" : "Generate AI Forensic Report"}</span>
            <Zap size={12} className="btn-zap-icon" />
          </button>
        </div>
      </div>

      <div className="ma-tabs-nav">
        {analysisMode === "live" && (
          <button className={`ma-tab-btn ${activeSubTab === "monitor" ? "active" : ""}`} onClick={() => setActiveSubTab("monitor")}>
            <Activity size={14} className="mr-1" /> System Monitor
          </button>
        )}
        <button className={`ma-tab-btn ${activeSubTab === "processes" ? "active" : ""}`} onClick={() => setActiveSubTab("processes")}>
          <List size={14} className="mr-1" /> Process List
        </button>
        {analysisMode === "dump" && (
          <>
            <button className={`ma-tab-btn ${activeSubTab === "hidden" ? "active" : ""}`} onClick={() => setActiveSubTab("hidden")}>
              <Eye size={14} className="mr-1" /> Hidden Tasks
            </button>
            <button className={`ma-tab-btn ${activeSubTab === "bash" ? "active" : ""}`} onClick={() => setActiveSubTab("bash")}>
              <Terminal size={14} className="mr-1" /> Bash History
            </button>
            <button className={`ma-tab-btn ${activeSubTab === "malfind" ? "active" : ""}`} onClick={() => setActiveSubTab("malfind")}>
              <Shield size={14} className="mr-1" /> Malfind
            </button>
            <button className={`ma-tab-btn ${activeSubTab === "modules" ? "active" : ""}`} onClick={() => setActiveSubTab("modules")}>
              <Archive size={14} className="mr-1" /> Kernel Modules
            </button>
            <button className={`ma-tab-btn ${activeSubTab === "files" ? "active" : ""}`} onClick={() => setActiveSubTab("files")}>
              <Paperclip size={14} className="mr-1" /> Open Files
            </button>
            <button className={`ma-tab-btn ${activeSubTab === "maps" ? "active" : ""}`} onClick={() => setActiveSubTab("maps")}>
              <Link size={14} className="mr-1" /> Shared Libraries
            </button>
            <button className={`ma-tab-btn ${activeSubTab === "network" ? "active" : ""}`} onClick={() => setActiveSubTab("network")}>
              <Wifi size={14} className="mr-1" /> Connections
            </button>
          </>
        )}
        <button className={`ma-tab-btn ${activeSubTab === "report" ? "active" : ""}`} onClick={() => setActiveSubTab("report")}>
          <FileText size={14} className="mr-1" /> AI Forensic Report
        </button>
      </div>

      <div className="ma-content-area">
        {activeSubTab === "monitor" && analysisMode === "live" && (
          <div className="ma-grid animate-fade-in">
            <div className="ma-card ram-card">
              <div className="card-header">
                <h3><Activity size={16} /> Live RAM Utilization</h3>
                <span className={`status-pill ${usedPct > 80 ? "danger" : (usedPct > 60 ? "warning" : "safe")}`}>
                  {usedPct > 80 ? "Critical" : (usedPct > 60 ? "Moderate" : "Healthy")}
                </span>
              </div>
              
              <div className="usage-visual-container">
                <svg width={size} height={size} className="progress-ring">
                  <circle className="progress-ring-bg" stroke="#f1f5f9" strokeWidth={stroke} fill="transparent" r={radius} cx={size / 2} cy={size / 2} />
                  <circle className={`progress-ring-fill ${usedPct > 85 ? "pulse-danger" : ""}`} stroke={usedPct > 80 ? "#ef4444" : (usedPct > 60 ? "#f59e0b" : "#2563eb")} strokeWidth={stroke} strokeDasharray={`${circ} ${circ}`} style={{ strokeDashoffset: offset }} strokeLinecap="round" fill="transparent" r={radius} cx={size / 2} cy={size / 2} />
                </svg>
                <div className="usage-overlay">
                  <span className="usage-number" style={{ color: "var(--wf-text)" }}>{Math.round(usedPct)}%</span>
                  <span className="usage-label">Used</span>
                </div>
              </div>

              <div className="ma-stats-grid">
                <div className="stat-box"><span className="label">Physical Total</span><strong className="value">{fmtSize(ram.total_kb * 1024)}</strong></div>
                <div className="stat-box"><span className="label">Active Memory</span><strong className="value">{fmtSize(ram.used_kb * 1024)}</strong></div>
                <div className="stat-box"><span className="label">Remaining</span><strong className="value">{fmtSize(ram.available_kb * 1024)}</strong></div>
                <div className="stat-box"><span className="label">Cache Buffer</span><strong className="value">{fmtSize(ram.cached_kb * 1024)}</strong></div>
              </div>
            </div>

            <div className="ma-card">
              <div className="card-header"><h3><Shield size={16} /> Security Overview</h3></div>
              <div className="usage-details">
                <p style={{ fontSize: "12px", color: "var(--wf-text-muted)" }}>Live memory analysis detects patterns of unauthorized execution and resource exhaustion.</p>
                <div style={{ marginTop: "20px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}><span style={{ fontSize: "11px", fontWeight: "600" }}>System Integrity</span><span style={{ color: "#16a34a", fontSize: "11px", fontWeight: "700" }}>VERIFIED</span></div>
                  <div style={{ width: "100%", height: "4px", background: "#f1f5f9", borderRadius: "2px" }}><div style={{ width: "100%", height: "100%", background: "#16a34a", borderRadius: "2px" }}></div></div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeSubTab === "processes" && (
          <div className="ma-card proc-panel animate-fade-in" style={{ gridColumn: "auto" }}>
            <div className="card-header">
              <h3><List size={16} /> {analysisMode === "live" ? "High-Impact Processes" : "All Processes from Dump"}</h3>
              <div className="proc-count-badge">{procs.length} total</div>
            </div>
            <div className="table-wrapper">
              <table className="forensic-table">
                <thead><tr><th width="80">PID</th><th width="180">Entity Name</th><th width="120">Memory Lift</th><th>Execution Path / Parameters</th></tr></thead>
                <tbody>
                  {procs.map((p, i) => (
                    <tr key={p.pid} style={{ animationDelay: `${i * 0.05}s` }}>
                      <td><code className="pid-badge">{p.pid}</code></td>
                      <td><span className="proc-name-highlight">{p.name}</span></td>
                      <td><span className="mem-value">{p.memory_kb ? fmtSize(p.memory_kb * 1024) : 'N/A'}</span></td>
                      <td><code className="cmdline-forensic" title={p.cmdline}>{p.cmdline || 'N/A'}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeSubTab === "hidden" && analysisMode === "dump" && (
          <div className="ma-card proc-panel animate-fade-in">
            <div className="card-header">
              <h3><Eye size={16} /> Hidden Processes (psscan)</h3>
              <div className="proc-count-badge" style={{ background: '#ef4444' }}>{hiddenProcs.length} anomalies</div>
            </div>
            <div className="table-wrapper">
              <table className="forensic-table">
                <thead><tr><th width="80">PID</th><th width="180">Name</th><th>Offset (P)</th><th>Result</th></tr></thead>
                <tbody>
                  {hiddenProcs.map((p, i) => (
                    <tr key={i} className="danger-row">
                      <td><code className="pid-badge" style={{ background: '#fecaca', color: '#b91c1c' }}>{p.pid}</code></td>
                      <td><strong style={{ color: '#b91c1c' }}>{p.name}</strong></td>
                      <td style={{ fontFamily: 'monospace' }}>{p.offset}</td>
                      <td><span className="status-pill danger">HIDDEN</span></td>
                    </tr>
                  ))}
                  {hiddenProcs.length === 0 && <tr><td colSpan="4" style={{ textAlign: 'center', padding: '40px', color: 'var(--wf-text-muted)' }}>No hidden processes detected in this dump.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeSubTab === "malfind" && analysisMode === "dump" && (
          <div className="ma-card proc-panel animate-fade-in">
            <div className="card-header">
              <h3><Shield size={16} /> Suspicious Memory Permissions (Malfind)</h3>
              <div className="proc-count-badge" style={{ background: '#ef4444' }}>{malfind.length} findings</div>
            </div>
            <div className="table-wrapper">
              <table className="forensic-table">
                <thead><tr><th width="80">PID</th><th width="150">Process</th><th width="150">Address</th><th width="120">Protection</th><th>Assembly Preview</th></tr></thead>
                <tbody>
                  {malfind.map((m, i) => (
                    <tr key={i}>
                      <td><code className="pid-badge">{m.pid}</code></td>
                      <td>{m.process}</td>
                      <td style={{ fontFamily: 'monospace' }}>{m.address}</td>
                      <td><code style={{ color: '#dc2626' }}>{m.protection}</code></td>
                      <td><code style={{ fontSize: '10px', display: 'block', maxHeight: '60px', overflow: 'hidden' }}>{m.disassembly}</code></td>
                    </tr>
                  ))}
                  {malfind.length === 0 && <tr><td colSpan="5" style={{ textAlign: 'center', padding: '40px', color: 'var(--wf-text-muted)' }}>No suspicious memory mappings found.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeSubTab === "network" && analysisMode === "dump" && (
          <div className="ma-card proc-panel animate-fade-in">
            <div className="card-header">
              <h3><Wifi size={16} /> Recovered Network Artifacts</h3>
              <div className="proc-count-badge">{(connections.length || 0) + (dumpReport?.interfaces?.length || 0)} sessions/ifaces</div>
            </div>
            <div className="table-wrapper">
              <h4 style={{ margin: '15px 15px 5px', fontSize: '12px', opacity: 0.7 }}>Network Connections (Netstat)</h4>
              <table className="forensic-table">
                <thead><tr><th width="80">Proto</th><th width="200">Local Address</th><th width="200">Remote Address</th><th>State</th></tr></thead>
                <tbody>
                  {connections.map((c, i) => (
                    <tr key={i}>
                      <td><span className="status-pill info">{c.proto}</span></td>
                      <td>{c.laddr}:{c.lport}</td>
                      <td><strong>{c.raddr}:{c.rport}</strong></td>
                      <td>{c.state}</td>
                    </tr>
                  ))}
                  {connections.length === 0 && <tr><td colSpan="4" style={{ textAlign: 'center', padding: '10px', color: 'var(--wf-text-muted)' }}>No network history found.</td></tr>}
                </tbody>
              </table>

              <h4 style={{ margin: '15px 15px 5px', fontSize: '12px', opacity: 0.7 }}>Network Interfaces (Ifconfig)</h4>
              <table className="forensic-table" style={{ marginTop: '5px' }}>
                <thead><tr><th width="150">Interface</th><th width="150">IP Address</th><th width="200">MAC Address</th><th>Flags</th></tr></thead>
                <tbody>
                  {(dumpReport?.interfaces || []).map((iface, i) => (
                    <tr key={i}>
                      <td><strong style={{ color: 'var(--wf-primary)' }}>{iface.name}</strong></td>
                      <td style={{ fontFamily: 'monospace' }}>{iface.ip}</td>
                      <td style={{ fontFamily: 'monospace' }}>{iface.mac}</td>
                      <td><code style={{ fontSize: '11px' }}>{iface.flags}</code></td>
                    </tr>
                  ))}
                  {(dumpReport?.interfaces || []).length === 0 && <tr><td colSpan="4" style={{ textAlign: 'center', padding: '10px', color: 'var(--wf-text-muted)' }}>No active interfaces recovered.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeSubTab === "bash" && analysisMode === "dump" && (
          <div className="ma-card proc-panel animate-fade-in">
            <div className="card-header">
              <h3><Terminal size={16} /> Recovered Bash History</h3>
              <div className="proc-count-badge">{(dumpReport?.bash_history || []).length} commands</div>
            </div>
            <div className="table-wrapper">
              <table className="forensic-table">
                <thead><tr><th width="80">PID</th><th width="150">Process</th><th>Command Line Artifact</th></tr></thead>
                <tbody>
                  {(dumpReport?.bash_history || []).map((b, i) => (
                    <tr key={i}>
                      <td><code className="pid-badge">{b.pid || "-"}</code></td>
                      <td>
                        <strong>{b.process}</strong>
                        {b.is_carved && <div style={{ fontSize: '10px', color: '#f97316', fontWeight: 600 }}>Deep Recovery</div>}
                      </td>
                      <td>
                        <code className="cmdline-forensic" style={{ 
                          background: b.is_carved ? '#fff7ed' : '#f8fafc', 
                          padding: '4px 8px',
                          borderLeft: b.is_carved ? '3px solid #f97316' : 'none',
                          display: 'inline-block',
                          width: '100%'
                        }}>
                          {b.command}
                        </code>
                      </td>
                    </tr>
                  ))}
                  {(dumpReport?.bash_history || []).length === 0 && <tr><td colSpan="3" style={{ textAlign: 'center', padding: '40px', color: 'var(--wf-text-muted)' }}>No shell history recovered from memory.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeSubTab === "modules" && analysisMode === "dump" && (
          <div className="ma-card proc-panel animate-fade-in">
            <div className="card-header">
              <h3><Archive size={16} /> Loaded Kernel Modules (Lsmod)</h3>
              <div className="proc-count-badge">{(dumpReport?.modules || []).length} LKMs</div>
            </div>
            <div className="table-wrapper">
              <table className="forensic-table">
                <thead><tr><th>Module Name</th><th width="120">Size</th><th width="180">Memory Offset</th></tr></thead>
                <tbody>
                  {(dumpReport?.modules || []).map((m, i) => (
                    <tr key={i}>
                      <td><strong style={{ color: 'var(--wf-primary)' }}>{m.name}</strong></td>
                      <td>{fmtSize(m.size)}</td>
                      <td style={{ fontFamily: 'monospace' }}>{m.offset}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeSubTab === "files" && analysisMode === "dump" && (
          <div className="ma-card proc-panel animate-fade-in">
            <div className="card-header">
              <h3><Paperclip size={16} /> Open Forensic File Handles (LSOF)</h3>
              <div className="proc-count-badge">{(dumpReport?.open_files || []).length} handles</div>
            </div>
            <div className="table-wrapper">
              <table className="forensic-table">
                <thead><tr><th width="80">PID</th><th width="150">Process</th><th width="80">FD</th><th>Object Path</th></tr></thead>
                <tbody>
                  {(dumpReport?.open_files || []).map((f, i) => (
                    <tr key={i}>
                      <td><code className="pid-badge">{f.pid}</code></td>
                      <td>{f.process}</td>
                      <td><code>{f.fd}</code></td>
                      <td style={{ wordBreak: 'break-all' }}>{f.path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeSubTab === "maps" && analysisMode === "dump" && (
          <div className="ma-card proc-panel animate-fade-in">
            <div className="card-header">
              <h3><Link size={16} /> Shared Libraries & Mappings (Maps)</h3>
              <div className="proc-count-badge">{(dumpReport?.shared_libraries || []).length} mappings</div>
            </div>
            <div className="table-wrapper">
              <table className="forensic-table">
                <thead><tr><th width="80">PID</th><th width="150">Process</th><th width="250">Memory Range</th><th>Mapped Object</th></tr></thead>
                <tbody>
                  {(dumpReport?.shared_libraries || []).map((m, i) => (
                    <tr key={i}>
                      <td><code className="pid-badge">{m.pid}</code></td>
                      <td>{m.process}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: '11px' }}>{m.start} - {m.end}</td>
                      <td style={{ wordBreak: 'break-all' }}>{m.path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeSubTab === "report" && (
          <div className="ma-card ai-insight-card animate-fade-in">
            <div className="card-header">
              <h3><FileText size={16} /> {analysisMode === "live" ? "AI Live Forensic Investigation" : "AI Dump Forensic Evidence"}</h3>
              {aiInsight && !aiLoading && <button className="btn-secondary btn-sm" onClick={() => window.print()}>Export JSON/PDF</button>}
            </div>
            <div className="ai-container">
              {aiLoading ? (
                <div className="ai-loading-state">
                  <div className="ai-scanner-line"></div>
                  <Loader2 size={40} className="spin-slow ai-bot-icon" />
                  <p style={{ color: "var(--wf-text)" }}>Decrypting and Categorizing Operational Artifacts history...</p>
                  <div className="loading-dots"><span></span><span></span><span></span></div>
                </div>
              ) : typedInsight ? (
                <div className="ai-insight-content">
                  <SimpleMarkdown text={typedInsight} />
                  <span className="terminal-cursor">_</span>
                </div>
              ) : (
                <div className="ai-empty-state">
                  <FileText size={48} className="empty-bot" style={{ opacity: 0.1 }} />
                  <p style={{ color: "var(--wf-text-muted)" }}>{analysisMode === "dump" && !dumpReport ? "Please upload a memory dump first." : "No forensic report generated yet."}</p>
                  <button className="btn-primary" style={{ marginTop: "12px" }} onClick={getAI} disabled={analysisMode === "dump" && !dumpReport}>
                    Start AI Investigation
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ActivityBar({ view, onView, hasExplorer, hasReport }) {
  const items = [
    { id: "home", Icon: Home, label: "Home", always: true },
    { id: "cases", Icon: BookOpen, label: "Cases", always: true },
    { id: "agent", Icon: Bot, label: "Agent", always: true },
    { id: "memory", Icon: Cpu, label: "Memory", always: true },
    { id: "explorer", Icon: LayoutPanelLeft, label: "Explorer", disabled: !hasExplorer },
    { id: "report", Icon: BarChart2, label: "Report", disabled: !hasReport },
  ];
  const caseActive = view === "cases" || view === "case";
  return (
    <div className="activity-bar">
      {items.map(({ id, Icon, label, always, disabled }) => (
        <button
          key={id}
          className={`act-btn ${(id === "cases" && caseActive) || (id !== "cases" && view === id) ? "active" : ""
            }`}
          title={label}
          disabled={!always && disabled}
          onClick={() => !disabled && onView(id)}
        >
          <Icon size={20} strokeWidth={1.6} />
          <span className="act-label">{label}</span>
        </button>
      ))}
    </div>
  );
}

export default function App() {
  const [dialog, setDialog] = useState(null);
  const [report, setReport] = useState(null);
  const [imgPath, setImgPath] = useState(null);
  const [liveInfo, setLiveInfo] = useState(null);
  const [status, setStatus] = useState("Ready");
  const [toolbar, setToolbar] = useState(true);
  const [statbar, setStatbar] = useState(true);
  const [reanalyzing, setReanalyzing] = useState(false);
  const [liveScanning, setLiveScanning] = useState(false);
  // "home" | "cases" | "case" | "explorer" | "report"
  const [view, setView] = useState("home");
  const [activeCase, setActiveCase] = useState(null);
  const [activeSrcId, setActiveSrcId] = useState(null);

  function closeDialog() { setDialog(null); }

  function handleResult(r, path) {
    setReport(r);
    setImgPath(path || imgPath);
    setView("report");
    const hi = r.summary?.total_high ?? 0;
    setStatus(
      `Analysis complete — ${r.findings?.length ?? 0} tool(s), ` +
      `${r.summary?.timeline_events ?? 0} timeline event(s), ` +
      `${hi} high-severity indicator${hi !== 1 ? "s" : ""}`
    );
  }

  async function handleReanalyze() {
    if (!imgPath || reanalyzing) return;
    setReanalyzing(true);
    setStatus("Reanalyzing…");
    try {
      const tailsMode = isTailsFocusedReport(report);
      const r = imgPath === "/"
        ? await apiAnalyzeLive()
        : tailsMode
          ? (activeCase ? (await apiCaseAnalyzeTailsDeep(activeCase.id, imgPath)).report : await apiAnalyzeTailsDeep(imgPath))
          : await apiAnalyze(imgPath);
      handleResult(r, imgPath);
      setStatus(`Reanalysis complete — ${r.summary?.total_high ?? 0} high-severity indicator(s)`);
    } catch (e) {
      setStatus(`Reanalyze failed: ${e.message}`);
    } finally {
      setReanalyzing(false);
    }
  }

  async function handleLiveScan(scanTypes, info) {
    setLiveInfo(info || null);
    setLiveScanning(true);
    setStatus("Scanning live system…");
    try {
      const [info2, r] = liveInfo
        ? [liveInfo, await apiAnalyzeLive()]
        : await Promise.all([apiLiveInfo(), apiAnalyzeLive()]);
      setLiveInfo(info2);
      handleResult(r, "/");
      const hi = r.summary?.total_high ?? 0;
      setStatus(`Live scan complete (${info2.hostname}) — ${hi} high-severity indicator${hi !== 1 ? "s" : ""}`);
    } catch (e) {
      setStatus(`Live scan failed: ${e.message}`);
    } finally {
      setLiveScanning(false);
    }
  }

  function handleSourceAdded(updatedCase, source, rpt, mode = "normal") {
    setActiveCase(updatedCase);
    setReport(rpt);
    setImgPath(source.path);
    setActiveSrcId(source.id);
    setView("report");
    const hi = rpt.summary?.total_high ?? 0;
    const modeText = mode === "tails" ? "TailsOS analysis" : mode === "live" ? "live scan" : "analysis";
    setStatus(`Source added to "${updatedCase.name}" (${modeText}) — ${hi} high-severity indicator${hi !== 1 ? "s" : ""}`);
  }

  function selectSource(src) {
    setActiveSrcId(src.id);
    setReport(src.report);
    setImgPath(src.path);
    setView("report");
  }

  function downloadJSON(r) {
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "forensic_report.json"; a.click();
  }

  function triggerBlobDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  async function exportComprehensive(format, variantOverride = null) {
    if (!report) {
      setStatus("No report to export");
      return;
    }

    const variant = variantOverride || (activeCase ? "legal" : "comprehensive");
    const intro = activeCase
      ? `This report presents a case-level forensic narrative for ${activeCase.name || "the selected investigation"}. It consolidates findings from all attached evidence sources, highlights high-risk indicators, and documents chain-of-custody context for evidentiary review.`
      : "This report presents a structured forensic narrative for the selected evidence source and highlights key indicators requiring analyst attention.";

    const payload = {
      report,
      report_title: "OS Forensics Comprehensive Report",
      case_name: activeCase?.name || "",
      source_path: imgPath || "",
      generated_by: "OSForensics UI",
      case_data: activeCase || null,
      intro_text: intro,
      report_variant: variant,
      include_raw_json: format === "html",
    };

    try {
      const res = format === "pdf" ? await apiExportReportPdf(payload) : await apiExportReportHtml(payload);
      const ext = format === "pdf" ? "pdf" : "html";
      const fallback = `${(activeCase?.name || "forensics_report").replace(/[^a-z0-9_-]+/gi, "_")}.${ext}`;
      triggerBlobDownload(res.blob, res.filename || fallback);
      setStatus(`Comprehensive ${format.toUpperCase()} report exported`);
    } catch (e) {
      setStatus(`Failed to export ${format.toUpperCase()} report: ${String(e)}`);
    }
  }

  async function exportCaseLevel(format, variantOverride = null) {
    if (!activeCase) {
      setStatus("No case selected");
      return;
    }

    const sourceReports = (activeCase.data_sources || []).map((src) => src?.report).filter((r) => r && typeof r === "object");
    const seedReport = sourceReports[0] || report || { os_info: {}, summary: {} };
    const sourceCount = activeCase.data_sources?.length || 0;
    const variant = variantOverride || "legal";
    const intro = `Case-level forensic dossier for ${activeCase.name || "selected case"}. ` +
      `This export aggregates outputs across ${sourceCount} source${sourceCount === 1 ? "" : "s"}, ` +
      `including per-source indicators, integrity context, and case-level chain-of-custody/audit records.`;

    const payload = {
      report: seedReport,
      report_title: `${activeCase.name || "Case"} - Case-Level Forensic Report`,
      case_name: activeCase.name || "",
      source_path: "",
      generated_by: "OSForensics UI",
      case_data: activeCase,
      intro_text: intro,
      report_variant: variant,
      include_raw_json: format === "html",
    };

    try {
      const res = format === "pdf" ? await apiExportReportPdf(payload) : await apiExportReportHtml(payload);
      const ext = format === "pdf" ? "pdf" : "html";
      const fallback = `${(activeCase.name || "case_report").replace(/[^a-z0-9_-]+/gi, "_")}_case_level.${ext}`;
      triggerBlobDownload(res.blob, res.filename || fallback);
      setStatus(`Case-level ${format.toUpperCase()} report exported`);
    } catch (e) {
      setStatus(`Failed to export case-level ${format.toUpperCase()} report: ${String(e)}`);
    }
  }

  function handleAction(key) {
    switch (key) {
      case "analyze":       return setDialog("analyze");
      case "filepick":      return setDialog("filepick");
      case "live_scan":     return setDialog("live_scan");
      case "remote_scan":   return setDialog("remote_scan");
      case "new_case":      return setDialog("new_case");
      case "view_cases":    return setView("cases");
      case "export":        return report ? downloadJSON(report) : setStatus("No report to export");
      case "clear":         setReport(null); setImgPath(null); setLiveInfo(null); setActiveCase(null); setActiveSrcId(null); setView("home"); return setStatus("Analysis cleared");
      case "settings":      return setDialog("settings");
      case "shortcuts":     return setDialog("shortcuts");
      case "about":         return setDialog("about");
      case "statusbar":     return setStatbar(v => !v);
      case "toolbar":       return setToolbar(v => !v);
      case "view_explorer": return imgPath ? setView("explorer") : setStatus("Open an image first");
      case "view_report": return report ? setView("report") : setStatus("Run analysis first");
      case "explorer": return imgPath ? setView("explorer") : setStatus("Open an image first");
      case "report_panel": return report ? setView("report") : setStatus("Run analysis first");
      default: return;
    }
  }

  useEffect(() => {
    function onKey(e) {
      if (e.ctrlKey && e.key === "o") { e.preventDefault(); handleAction("analyze"); }
      if (e.ctrlKey && e.key === "b") { e.preventDefault(); handleAction("filepick"); }
      if (e.ctrlKey && e.shiftKey && (e.key === "L" || e.key === "l")) { e.preventDefault(); handleAction("remote_scan"); return; }
      if (e.ctrlKey && !e.shiftKey && (e.key === "L" || e.key === "l")) { e.preventDefault(); handleAction("live_scan"); }
      if (e.ctrlKey && e.key === ",") { e.preventDefault(); handleAction("settings"); }
      if (e.key === "F1") { e.preventDefault(); handleAction("about"); }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  return (
    <div className="app-shell">
      <div className="titlebar">
        <Microscope size={16} strokeWidth={1.8} className="title-icon" />
        <span className="title-name">OS Forensics</span>
        <span className="title-build">Advanced Forensic Analysis</span>
        {activeCase && (
          <span className="title-case-badge">
            <BookOpen size={11} /> {activeCase.name}{activeCase.number ? ` · ${activeCase.number}` : ""}
          </span>
        )}
        {!activeCase && imgPath && imgPath !== "/" && <span className="title-path">{imgPath}</span>}
        {!activeCase && imgPath === "/" && (
          <span className="title-live-badge"><Cpu size={11} /> LIVE SYSTEM</span>
        )}
        {!activeCase && String(imgPath || "").startsWith("ssh://") && (
          <span className="title-live-badge"><Wifi size={11} /> REMOTE LIVE</span>
        )}
        {liveScanning && <span className="title-live-scanning"><RefreshCw size={11} className="spin" /> Scanning live system…</span>}
      </div>
      <MenuBar onAction={handleAction} />
      <Toolbar visible={toolbar} onAction={handleAction} />

      <div className="workspace">
        <ActivityBar
          view={view}
          onView={setView}
          hasExplorer={!!imgPath}
          hasReport={!!report}
        />

        <div className="main-content">
          {view === "home" && <WorkspaceHome onAction={handleAction} />}

          <div style={{ display: view === "agent" ? "flex" : "none", height: "100%", flexDirection: "column", flex: 1, minHeight: 0 }}>
            <AgentPanel />
          </div>

          {view === "cases" && (
            <CasesView
              onOpen={async (id) => {
                try { const c = await apiCaseGet(id); setActiveCase(c); setView("case"); }
                catch (e) { setStatus("Failed to open case: " + String(e)); }
              }}
              onNewCase={() => handleAction("new_case")}
            />
          )}

          {view === "case" && activeCase && (
            <CasePanel
              caseData={activeCase}
              activeSourceId={activeSrcId}
              onSelectSource={selectSource}
              onAddSource={() => setDialog("add_source")}
              onAddTailsSource={() => setDialog("add_source_tails")}
              onAddTailsUsbSource={() => setDialog("add_source_tails_usb")}
              onScanLiveToCase={() => setDialog("live_scan_case")}
              onDeleteSource={async (srcId) => {
                try {
                  await apiCaseDelSrc(activeCase.id, srcId);
                  const updated = await apiCaseGet(activeCase.id);
                  setActiveCase(updated);
                  if (activeSrcId === srcId) { setActiveSrcId(null); setReport(null); setImgPath(null); }
                } catch (e) { setStatus("Failed to remove source: " + String(e)); }
              }}
              onExportCaseHtml={() => exportCaseLevel("html")}
              onExportCasePdf={() => exportCaseLevel("pdf")}
              onBack={() => setView("cases")}
            />
          )}

          {view === "explorer" && imgPath && <Explorer imgPath={imgPath} />}

          {view === "memory" && <MemoryAnalyser />}

          {view === "report" && report && (
            activeCase && isTailsFocusedReport(report) ? (
              <TailsCaseWorkspace
                report={report}
                imgPath={imgPath}
                caseName={activeCase?.name}
                onBackToCase={() => setView("case")}
                onExportJson={() => downloadJSON(report)}
                onExportHtml={() => exportComprehensive("html")}
                onExportPdf={() => exportComprehensive("pdf")}
                onReanalyze={handleReanalyze}
                reanalyzing={reanalyzing}
              />
            ) : (
              <ReportPanel
                report={report}
                liveInfo={imgPath === "/" || report?.summary?.analysis_mode === "remote_ssh_live" ? liveInfo : null}
                imgPath={imgPath}
                onClear={() => handleAction("clear")}
                onExportJson={() => downloadJSON(report)}
                onExportHtml={() => exportComprehensive("html")}
                onExportPdf={() => exportComprehensive("pdf")}
                onExportExecutivePdf={() => exportComprehensive("pdf", "executive")}
                onReanalyze={handleReanalyze}
                reanalyzing={reanalyzing}
              />
            )
          )}
        </div>
      </div>

      <StatusBar visible={statbar} status={status} report={report} />

      {dialog === "analyze" && <AnalyzeDialog onClose={closeDialog} onResult={handleResult} />}
      {dialog === "filepick" && <FilePickerDialog onClose={closeDialog} onResult={handleResult} />}
      {dialog === "live_scan" && (
        <LiveScanDialog
          onClose={closeDialog}
          onResult={(r, path, info) => { handleResult(r, path); setLiveInfo(info); closeDialog(); }}
        />
      )}
      {dialog === "remote_scan" && (
        <RemoteScanDialog
          onClose={closeDialog}
          onResult={(r, path, info) => {
            handleResult(r, path);
            setLiveInfo(info || null);
            closeDialog();
          }}
        />
      )}
      {dialog === "live_scan_case" && activeCase && (
        <LiveScanDialog
          title={`Scan Live System to Case: ${activeCase.name}`}
          onClose={closeDialog}
          runScan={async (types) => {
            const [info, saved] = await Promise.all([
              apiLiveInfo(),
              apiCaseAnalyzeLive(activeCase.id, types),
            ]);
            return {
              info,
              report: saved.report,
              path: "/",
              source: saved.source,
            };
          }}
          onResult={async (r, path, info, source) => {
            try {
              const updated = await apiCaseGet(activeCase.id);
              setLiveInfo(info || null);
              if (source) handleSourceAdded(updated, source, r, "live");
              else handleResult(r, path || "/");
            } catch (e) {
              setStatus("Case update failed: " + String(e));
            }
          }}
        />
      )}
      {dialog === "new_case" && (
        <NewCaseDialog
          onClose={closeDialog}
          onCreate={(c, options) => {
            setActiveCase(c);
            setView("case");
            if (options?.openAddSourceMode === "tails") setDialog("add_source_tails");
          }}
        />
      )}
      {dialog === "add_source" && activeCase && (
        <AddSourceDialog
          onClose={closeDialog}
          caseId={activeCase.id}
          onSuccess={async (source, rpt, mode) => {
            try { const updated = await apiCaseGet(activeCase.id); handleSourceAdded(updated, source, rpt, mode); }
            catch (e) { setStatus("Case update failed: " + String(e)); }
          }}
        />
      )}
      {dialog === "add_source_tails" && activeCase && (
        <AddSourceDialog
          onClose={closeDialog}
          caseId={activeCase.id}
          preferredMode="tails"
          onSuccess={async (source, rpt, mode) => {
            try { const updated = await apiCaseGet(activeCase.id); handleSourceAdded(updated, source, rpt, mode); }
            catch (e) { setStatus("Case update failed: " + String(e)); }
          }}
        />
      )}
      {dialog === "add_source_tails_usb" && activeCase && (
        <AddSourceDialog
          onClose={closeDialog}
          caseId={activeCase.id}
          preferredMode="tails"
          autoDetectUsb={true}
          onSuccess={async (source, rpt, mode) => {
            try { const updated = await apiCaseGet(activeCase.id); handleSourceAdded(updated, source, rpt, mode); }
            catch (e) { setStatus("Case update failed: " + String(e)); }
          }}
        />
      )}
      {dialog === "settings" && <SettingsDialog onClose={closeDialog} />}
      {dialog === "shortcuts" && <ShortcutsDialog onClose={closeDialog} />}
      {dialog === "about" && <AboutDialog onClose={closeDialog} />}
    </div>
  );
}
