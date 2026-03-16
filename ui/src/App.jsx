import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import {
  Search, FolderSearch, Trash2, Settings, Microscope,
  X, FolderOpen, AlertTriangle, CheckCircle, HardDrive, Activity,
  Clock, Shield, Eye, ChevronDown, ChevronRight, Hash, Terminal,
  Lock, Server, Key, Folder, FolderOpen as FolderOpenIcon, FileText,
  Wifi, Package, List, Database, Cpu, Box, Globe, Users, ChevronUp,
  File, Code, RefreshCw, Info, LayoutPanelLeft, BarChart2, Home,
  BookOpen, Plus, Filter, Bot, Send, Loader2, Zap,
  Image, Film, Music, MapPin, Camera, Layers, Download, Play,
  Sailboat,
  Usb,
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

const get = async (url) => {
  const res = await fetch(`${API}${url}`);
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  return res.json();
};

const apiAnalyze     = (path)       => post("/analyze",        { image_path: path });
const apiMemory      = (path)       => post("/memory",         { image_path: path });
const apiAnalyzeLive = (scanTypes)   => post("/analyze/live",  scanTypes || {});
const apiLiveInfo    = ()            => get("/live/info");
const apiFsBrowse    = (path)        => post("/fs/browse",      { path });
const apiUsbSources  = ()            => get("/fs/usb/sources");
const apiBrowse      = (img, path)   => post("/explore/browse", { image_path: img, path });
const apiStat        = (img, path)   => post("/explore/stat",   { image_path: img, path });
const apiRead        = (img, path)   => post("/explore/read",   { image_path: img, path });
const apiTree        = ()            => get("/explore/tree");

// ── Case management API ───────────────────────────────────────────────────────
const apiCasesList   = ()                => get("/cases");
const apiCaseCreate  = (body)            => post("/cases", body);
const apiCaseGet     = (id)              => get(`/cases/${id}`);
const apiCaseDelete  = (id)              => fetch(`${API}/cases/${id}`, { method: "DELETE" }).then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); });
const apiCaseAnalyze = (caseId, imgPath) => post(`/cases/${caseId}/analyze`, { image_path: imgPath });
const apiCaseAnalyzeTails = (caseId, imgPath) => post(`/cases/${caseId}/analyze/tails`, { image_path: imgPath });
const apiCaseAnalyzeLive = (caseId, scanTypes) => post(`/cases/${caseId}/analyze/live`, scanTypes || {});
const apiCaseAnalyzeMemory = (caseId, imgPath) => post(`/cases/${caseId}/analyze/memory`, { image_path: imgPath });
const apiCaseDelSrc  = (caseId, srcId)   => fetch(`${API}/cases/${caseId}/sources/${srcId}`, { method: "DELETE" }).then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); });
const apiRecover     = (img, recoveryId) => post("/deleted/recover", { image_path: img, recovery_id: recoveryId });
const apiCarveGroups = ()                => get("/deleted/carve/groups");
const apiCarve       = (img, opts)       => post("/deleted/carve", { image_path: img, ...opts });
const apiMultimedia  = (path)            => post("/multimedia", { image_path: path });
const apiMediaUrl    = (imgPath, filePath) =>
  `${API}/multimedia/view?image_path=${encodeURIComponent(imgPath)}&file_path=${encodeURIComponent(filePath)}`;

// ── Agent API ─────────────────────────────────────────────────────────────────
const apiAgentStatus  = ()    => get("/agent/status");
const apiAgentReset   = (sid) => fetch(`${API}/agent/reset/${sid}`, { method: "POST" }).then(r => r.json());

// ─── Severity / icon helpers ──────────────────────────────────────────────────
const SEV_COLOR = { critical: "#7f1d1d", high: "#dc2626", medium: "#d97706", low: "#16a34a", info: "#2563eb" };
const SEV_BG    = { critical: "#fef2f2", high: "#fff1f0", medium: "#fffbeb", low: "#f0fdf4", info: "#eff6ff" };

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

function MemoryDialog({ onClose, onResult }) {
  const [path, setPath] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  async function run() {
    if (!path.trim()) return;
    setLoading(true); setErr(null);
    try { onResult(await apiMemory(path.trim()), path.trim()); onClose(); }
    catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  }
  return (
    <Modal title="Analyze — Open Memory Dump" onClose={onClose} width={600}>
      <div className="dlg-field">
        <label>Path to memory dump</label>
        <input autoFocus value={path} onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder="/path/to/memory.dump  or  /path/to/mem.raw" />
        <div className="dlg-hint">Supported formats: .raw, .mem, .lime, .dmp, .vmem</div>
      </div>
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button className="btn-primary" onClick={run} disabled={loading || !path.trim()}>
          <Cpu size={14} />{loading ? "Analyzing…" : "Analyze"}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

// ─── LIVE SCAN DIALOG ───────────────────────────────────────────────────────
const SCAN_TYPES = [
  { key: "timeline",    label: "Timeline",         hint: "File access / modification events",           default: true  },
  { key: "deleted",     label: "Deleted Files",     hint: "Recoverable deleted file detection",           default: true  },
  { key: "persistence", label: "Persistence",       hint: "Cron, systemd, rc files, SUID, keys",          default: true  },
  { key: "services",    label: "Services",          hint: "Installed daemons and service units",          default: true  },
  { key: "config",      label: "Config Audit",      hint: "Security-relevant config file analysis",       default: false },
  { key: "browsers",    label: "Browser Artifacts", hint: "History, cookies, extensions",                 default: false },
  { key: "multimedia",  label: "Multimedia",        hint: "Image / video / audio metadata (slow)",        default: false },
];

function LiveScanDialog({ onClose, onResult, runScan, title = "Scan Live System" }) {
  const defaults = Object.fromEntries(SCAN_TYPES.map(t => [t.key, t.default]));
  const [types,   setTypes]   = useState(defaults);
  const [loading, setLoading] = useState(false);
  const [err,     setErr]     = useState(null);

  const toggle = (key) => setTypes(prev => ({ ...prev, [key]: !prev[key] }));
  const anyOn  = Object.values(types).some(Boolean);

  async function run() {
    setLoading(true); setErr(null);
    try {
      const result = runScan
        ? await runScan(types)
        : (() => Promise.all([apiLiveInfo(), apiAnalyzeLive(types)]).then(([info, report]) => ({ info, report, path: "/" })))();
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

// ─── FILE PICKER DIALOG ──────────────────────────────────────────────────────
function FilePickerDialog({ onClose, onResult, analyzeOnPick = true }) {
  const [cwd,      setCwd]      = useState("/");
  const [children, setChildren] = useState([]);
  const [crumbs,   setCrumbs]   = useState([{ label: "/", path: "/" }]);
  const [selected, setSelected] = useState(null);   // { path, is_dir }
  const [loading,  setLoading]  = useState(false);
  const [analyzing,setAnalyzing]= useState(false);
  const [err,      setErr]      = useState(null);

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
  const FILE_CLR   = "#4b5563";

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
                  : <File          size={15} style={{ color: FILE_CLR   }} />}
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
  if (n < 1024)          return `${n} B`;
  if (n < 1024 * 1024)   return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3)     return `${(n / 1024 / 1024).toFixed(1)} MB`;
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
    ["Ctrl + M", "Analyze Memory Dump"],
    ["Ctrl + B", "Browse & Open file picker"],
    ["Ctrl + ,", "Preferences"],
    ["F1",       "Help / About"],
    ["Escape",   "Close current dialog"],
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
      { label: "Analyze Memory Dump…",        key: "memory",   shortcut: "Ctrl+M" },
      { label: "Browse & Open…",               key: "filepick", shortcut: "Ctrl+B" },
      { type: "sep" },
      { label: "Export Report JSON…",         key: "export" },
      { type: "sep" },
      { label: "Clear Analysis",              key: "clear" },
    ],
    Cases: [
      { label: "New Case…",       key: "new_case"   },
      { label: "Open Cases View", key: "view_cases" },
    ],
    View: [
      { label: "Show Explorer",   key: "view_explorer" },
      { label: "Show Report",     key: "view_report" },
      { type: "sep" },
      { label: "Toggle Toolbar",  key: "toolbar" },
      { label: "Toggle Status Bar", key: "statusbar" },
    ],
    Tools: [
      { label: "Analyze Image / Mountpoint…", key: "analyze" },
      { label: "Analyze Memory Dump…",        key: "memory" },
      { label: "Browse & Open…",               key: "filepick" },
      { type: "sep" },
      { label: "Keyboard Shortcuts…",         key: "shortcuts" },
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
    { Icon: Search,         label: "Analyze",  key: "analyze",        title: "Analyze path (Ctrl+O)" },
    { Icon: FolderSearch,   label: "Browse",   key: "filepick",       title: "Browse & Open (Ctrl+B)" },
    { type: "sep" },
    { Icon: LayoutPanelLeft,label: "Explorer", key: "view_explorer",  title: "Explorer view" },
    { Icon: BarChart2,      label: "Report",   key: "view_report",    title: "Report view" },
    { type: "sep" },
    { Icon: Trash2,         label: "Clear",    key: "clear",          title: "Clear analysis" },
    { type: "sep" },
    { Icon: Settings,       label: "Prefs",    key: "settings",       title: "Preferences" },
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
function StatusBar({ visible, status, report, memoryReport }) {
  if (!visible) return null;
  const totalHigh = (report?.summary?.total_high ?? 0) + (memoryReport?.summary?.total_high ?? 0);
  const currentReport = report || memoryReport;
  return (
    <div className="statusbar">
      <Activity size={11} className="sb-icon" />
      <span className="sb-status">{status}</span>
      {currentReport && (
        <>
          <span className="sb-sep" />
          {report ? <HardDrive size={11} className="sb-icon" /> : <Cpu size={11} className="sb-icon" />}
          <span>OS: <strong>{report?.os_info?.name || memoryReport?.kernel_version || "Unknown"}</strong></span>
          {report && (
            <>
              <span className="sb-sep" />
              <span>Tools: <strong>{report.summary?.total_tools ?? 0}</strong></span>
              <span className="sb-sep" />
              <span>Timeline: <strong>{report.summary?.timeline_events ?? 0}</strong></span>
            </>
          )}
          {memoryReport && (
            <>
              <span className="sb-sep" />
              <span>Processes: <strong>{memoryReport.summary?.process_count ?? 0}</strong></span>
            </>
          )}
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
  if (["sh", "bash", "py", "rb", "pl"].includes(ext))            return <Code     size={13} style={{ color: "#10b981" }} />;
  if (["service", "socket", "timer"].includes(ext))              return <Server   size={13} style={{ color: "#8b5cf6" }} />;
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
  if (item.is_suid)   suid_flags.push("SUID");
  if (item.is_sgid)   suid_flags.push("SGID");
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
              <MetaRow label="Path"        value={item.path} mono />
              <MetaRow label="Type"        value={item.type} />
              <MetaRow label="Size"        value={item.size_human ? `${item.size_human} (${item.size?.toLocaleString()} bytes)` : item.size} />
              <MetaRow label="Permissions" value={item.mode} mono />
              <MetaRow label="Mode (octal)"value={item.mode_octal} mono />
              <MetaRow label="Owner (UID)" value={item.uid} />
              <MetaRow label="Group (GID)" value={item.gid} />
              <MetaRow label="Inode"       value={item.inode} />
              <MetaRow label="Hard Links"  value={item.nlinks} />
              <MetaRow label="Modified"    value={item.mtime} />
              <MetaRow label="Accessed"    value={item.atime} />
              <MetaRow label="Changed"     value={item.ctime} />
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
  const lastX    = useRef(0);

  const onMouseDown = useCallback((e) => {
    e.preventDefault();
    dragging.current = true;
    lastX.current    = e.clientX;
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
      window.removeEventListener("mouseup",   onUp);
    }
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup",   onUp);
  }, [onDrag]);

  return <div className="pane-divider" onMouseDown={onMouseDown} />;
}


// ─── Plain File-System Directory Tree ───────────────────────────────────────
// Lazily loads subdirectories on expand. Works with apiBrowse.
function FsDirTreeNode({ imgPath, path, name, depth, selectedPath, onSelect }) {
  const [expanded, setExpanded] = useState(depth === 0);
  const [children, setChildren] = useState(null);  // null = not yet loaded
  const [loading, setLoading]   = useState(false);

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
  const [tree, setTree]             = useState(null);
  const [treeErr, setTreeErr]       = useState(null);
  const [expandedIds, setExpanded]  = useState(new Set(["os", "logs", "shell_history"]));
  const [selectedNode, setSelNode]  = useState(null);

  // ── Shared state (both modes use these) ──
  const [browseEntries, setBrowse]  = useState(null);
  const [browseLoading, setBrowseL] = useState(false);
  const [browsePath, setBrowsePath] = useState(null);
  const [selectedFile, setSelFile]  = useState(null);
  const [navStack, setNavStack]     = useState([]);
  const [treeWidth, setTreeWidth]   = useState(230);
  const [metaWidth, setMetaWidth]   = useState(300);

  // ── Files mode state ──
  const [fsTreeSel, setFsTreeSel]   = useState(null);  // currently selected dir in fs tree

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
const PERSIST_ICONS  = { crontab: Clock, systemd_service: Server, shell_startup: Terminal, ssh_authorized_keys: Key };
const PERSIST_LABELS = { crontab: "Suspicious Crontab Entries", systemd_service: "Unknown Systemd Services", shell_startup: "Shell Startup Modifications", ssh_authorized_keys: "SSH Authorized Keys" };
const DEL_TYPE_META = {
  deleted_inode:  { label: "Deleted Inodes (TSK)",         Icon: Trash2,        color: "#dc2626", desc: "Files whose directory entry survives in the inode table but are flagged as unallocated." },
  trash:          { label: "Trash / Recycle Bin",          Icon: FolderOpenIcon, color: "#d97706", desc: "Files moved to the freedesktop Trash. Immediately recoverable." },
  open_deleted:   { label: "Deleted-but-Open",             Icon: Eye,           color: "#7c3aed", desc: "Files unlinked from disk but still held open by a running process." },
  anti_forensics: { label: "Anti-Forensics Indicators",    Icon: AlertTriangle, color: "#b45309", desc: "Evidence of intentional evidence destruction (rm, shred, wipe, etc.)." },
  scan_error:     { label: "Scan Errors",                  Icon: Info,          color: "#6b7280", desc: "" },
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
      <div className="live-banner-badge"><Cpu size={12} /> LIVE SYSTEM</div>
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
    : totalHigh >= 5  ? { label: "HIGH",     cls: "tl-high"     }
    : totalHigh >= 1  ? { label: "MEDIUM",   cls: "tl-medium"   }
    :                   { label: "CLEAN",    cls: "tl-low"      };
  const stats = [
    { label: "Tool Findings",       value: summary?.total_tools ?? 0,          danger: false },
    { label: "High-Risk Tools",     value: summary?.high_risk_tools ?? 0,      danger: true  },
    { label: "Timeline Events",     value: summary?.timeline_events ?? 0,      danger: false },
    { label: "High Timeline",       value: summary?.high_timeline ?? 0,        danger: true  },
    { label: "Deleted / Missing",   value: summary?.deleted_findings ?? 0,     danger: false },
    { label: "High Deleted",        value: summary?.high_deleted ?? 0,         danger: true  },
    { label: "Persistence Hits",    value: summary?.persistence_findings ?? 0, danger: false },
    { label: "High Persistence",    value: summary?.high_persistence ?? 0,     danger: true  },
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
  attack_chain:             { label: "Attack Chains",     Icon: AlertTriangle },
  suspicious_command:       { label: "Suspicious Cmds",   Icon: Terminal      },
  anti_forensics:           { label: "Anti-Forensics",    Icon: Shield        },
  activity_profile:         { label: "Activity Profile",  Icon: BarChart2     },
  session_summary:          { label: "Sessions",          Icon: Clock         },
  frequency_analysis:       { label: "Frequency",         Icon: Activity      },
  timestamp_reconstruction: { label: "Timestamps",        Icon: Info          },
  file_modified:            { label: "File Changes",      Icon: FileText      },
  log_event:                { label: "Log Events",        Icon: Server        },
};

// ── Per-type card renderers ───────────────────────────────────────────────────
function AttackChainCard({ ev }) {
  const [expanded, setExpanded] = useState(false);
  const d = ev.data || {};
  const steps = d.steps || [];
  const lineNos = d.step_line_nos || [];
  const c = SEV_COLOR[ev.severity] || "#7f1d1d";
  const bg = SEV_BG[ev.severity]   || "#fef2f2";
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
  const bg = SEV_BG[ev.severity]   || "#fffbeb";
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
    case "attack_chain":       return <AttackChainCard      key={i} ev={ev} />;
    case "activity_profile":   return <ActivityProfileCard  key={i} ev={ev} />;
    case "suspicious_command": return <SuspiciousCommandCard key={i} ev={ev} />;
    case "frequency_analysis": return <FrequencyCard        key={i} ev={ev} />;
    case "anti_forensics":     return <AntiForensicsCard    key={i} ev={ev} />;
    default:                   return <GenericEventRow      key={i} ev={ev} />;
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
const BH_HIGH_RISK = new Set(["Reverse Shell","Exploitation","Credential Access","Privilege Escalation","Anti-Forensics","Exfiltration","Lateral Movement","Persistence"]);

function BashAnalysisView({ events, dateRangeMs }) {
  const [section,    setSection]    = useState("suspicious");
  const [userFilter, setUserFilter] = useState("all");
  const [search,     setSearch]     = useState("");
  const [navWidth,   setNavWidth]   = useState(180);
  const clampNav = (w) => Math.max(120, Math.min(320, w));

  const allUsers  = [...new Set(events.map(e => e.data?.user).filter(Boolean))];
  const rawEvents = events.filter(e => e.event_type === "bash_history_raw");

  const visible = events.filter(e => {
    if (e.event_type === "bash_history_raw") return false;
    if (userFilter !== "all" && e.data?.user && e.data.user !== userFilter) return false;
    if (section !== "frequency" && search && !e.detail.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const by  = (type) => visible.filter(e => e.event_type === type);
  const sev = (evs)  => evs.some(e => e.severity === "critical") ? "critical"
                      : evs.some(e => e.severity === "high")     ? "high" : "medium";

  const chains   = by("attack_chain");
  const suspCmds = by("suspicious_command");
  const af       = by("anti_forensics");
  const profiles = by("activity_profile");
  const sessions = by("session_summary");
  const other    = visible.filter(e =>
    !["attack_chain","suspicious_command","anti_forensics","activity_profile",
      "frequency_analysis","session_summary","timestamp_reconstruction"].includes(e.event_type)
  );

  const navItems = [
    { id: "suspicious", label: "Suspicious Cmds",  Icon: Terminal,      count: suspCmds.length, sev: suspCmds.length ? sev(suspCmds) : null },
    { id: "chains",     label: "Attack Chains",    Icon: AlertTriangle, count: chains.length,   sev: chains.length   ? sev(chains)   : null },
    { id: "af",         label: "Anti-Forensics",   Icon: Shield,        count: af.length,       sev: af.length       ? "high"        : null },
    { id: "frequency",  label: "Frequency",        Icon: BarChart2,     count: null },
    { id: "profile",    label: "Activity Profile", Icon: Activity,      count: profiles.length },
    { id: "sessions",   label: "Sessions",         Icon: Clock,         count: sessions.length },
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
  { name: "File Operations", color: "#2563eb", risk: false, cmds: new Set(["ls","cp","mv","rm","mkdir","rmdir","touch","find","chmod","chown","chgrp","ln","rsync","scp","sftp","install","rename","stat","file"]) },
  { name: "Text Processing", color: "#7c3aed", risk: false, cmds: new Set(["cat","grep","awk","sed","sort","uniq","wc","head","tail","less","more","cut","tr","diff","patch","echo","printf","tee","xargs","strings"]) },
  { name: "Compression",     color: "#0891b2", risk: false, cmds: new Set(["tar","zip","unzip","gzip","gunzip","bzip2","xz","7z","zstd","ar","cpio","compress"]) },
  { name: "Network",         color: "#059669", risk: false, cmds: new Set(["ping","traceroute","tracepath","curl","wget","ssh","ftp","nc","ncat","dig","host","nslookup","ip","ifconfig","netstat","ss","arp","route","mtr","whois"]) },
  { name: "Process Mgmt",    color: "#6366f1", risk: false, cmds: new Set(["ps","top","htop","kill","pkill","killall","nice","renice","jobs","bg","fg","nohup","watch","timeout","strace","ltrace","lsof"]) },
  { name: "System Info",     color: "#8b5cf6", risk: false, cmds: new Set(["uname","whoami","id","hostname","uptime","df","du","free","lscpu","lsblk","lshw","dmesg","journalctl","systemctl","service","mount","umount","env","printenv"]) },
  { name: "Package Mgmt",    color: "#d97706", risk: false, cmds: new Set(["apt","apt-get","dpkg","yum","dnf","rpm","pacman","pip","pip3","npm","gem","cargo","go","snap","flatpak"]) },
  { name: "Scripting",       color: "#f59e0b", risk: false, cmds: new Set(["python","python3","perl","ruby","bash","sh","zsh","fish","node","nodejs","php","lua"]) },
  { name: "Reconnaissance",  color: "#dc2626", risk: true,  cmds: new Set(["nmap","masscan","zmap","nikto","gobuster","dirb","dirbuster","enum4linux","smbclient","rpcclient","ldapsearch","dnsenum","fierce","recon-ng","theharvester"]) },
  { name: "Exploitation",    color: "#b91c1c", risk: true,  cmds: new Set(["msfconsole","msfvenom","sqlmap","hydra","medusa","john","hashcat","aircrack-ng","airmon-ng","airodump-ng","reaver","wifite"]) },
  { name: "Privilege Esc.",  color: "#ef4444", risk: true,  cmds: new Set(["sudo","su","passwd","chpasswd","visudo","usermod","useradd","newgrp","pkexec"]) },
  { name: "Anti-Forensics",  color: "#7f1d1d", risk: true,  cmds: new Set(["shred","wipe","srm","dd","secure-delete","bleachbit"]) },
  { name: "Tunneling",       color: "#9f1239", risk: true,  cmds: new Set(["socat","chisel","ngrok","proxychains","tor","torsocks","stunnel","iodine","ptunnel","dns2tcp"]) },
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
  const [topN,     setTopN]     = useState(20);

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
  const maxCmd  = cmdRows[0]?.[1].count || 1;

  // By-category frequency
  const catFreqMap = {};
  for (const line of allLines) {
    const cat  = classifyCmd(line.cmd);
    if (!catFreqMap[cat.name]) catFreqMap[cat.name] = { count: 0, color: cat.color, risk: cat.risk };
    catFreqMap[cat.name].count++;
  }
  const catRows = Object.entries(catFreqMap).sort((a, b) => b[1].count - a[1].count);
  const maxCat  = catRows[0]?.[1].count || 1;

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
            const pct    = ((info.count / totalCmds) * 100).toFixed(1);
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
            const pct    = ((info.count / totalCmds) * 100).toFixed(1);
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
  const [search,    setSearch]    = useState("");

  const catCounts = allCats.reduce((acc, cat) => {
    acc[cat] = sevs.filter(ev => (ev.data?.category || "General") === cat).length;
    return acc;
  }, {});

  const catItems = sevs
    .filter(ev => (ev.data?.category || "General") === activeCat)
    .filter(ev => !search ||
      (ev.data?.command || "").toLowerCase().includes(search.toLowerCase()) ||
      (ev.data?.label   || "").toLowerCase().includes(search.toLowerCase()));

  const isHR = SC_HIGH_RISK.has(activeCat);

  return (
    <div className="sc-split">
      {/* Left: category nav */}
      <nav className="sc-cat-nav">
        <div className="sc-cat-nav-header">
          <Filter size={11} style={{ marginRight: 5 }} />Categories
        </div>
        {allCats.map(cat => {
          const hr  = SC_HIGH_RISK.has(cat);
          const cnt = catCounts[cat];
          return (
            <button key={cat}
              className={`sc-cat-nav-btn ${activeCat === cat ? "active" : ""}`}
              onClick={() => { setActiveCat(cat); setSearch(""); }}>
              {hr && <AlertTriangle size={10} style={{ color: "#dc2626", flexShrink: 0 }} />}
              <span className="sc-cat-nav-label">{cat}</span>
              <span className="sc-cat-nav-count"
                style={{ background: hr ? "#fef2f2" : undefined, color: hr ? "#dc2626" : undefined,
                         border: `1px solid ${hr ? "#fecaca" : "#e5e7eb"}` }}>
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
                        {d.user     && <span className="sc-meta-chip sc-meta-user"><Users size={9} />{d.user}</span>}
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
  const [catFilter,    setCatFilter]    = useState("all");
  const [showSuspOnly, setShowSuspOnly] = useState(false);
  const [histSearch,   setHistSearch]   = useState("");
  const [sortBy,       setSortBy]       = useState("timestamp");
  const [sortOrder,    setSortOrder]    = useState("desc");

  if (!rawEvents.length)
    return <div className="tl-empty-mini">No raw history data. The history file may be empty.</div>;

  const activeUser = selectedUser || rawEvents[0]?.data?.user || "";
  const ev         = rawEvents.find(e => e.data?.user === activeUser) || rawEvents[0];
  const lines      = ev?.data?.lines || [];
  const suspCount  = lines.filter(l => l.suspicious).length;
  const linesInRange = filterBashLinesByDateRange(lines, dateRangeMs);
  const orderedLines = [...linesInRange].sort((a, b) => {
    let aVal, bVal;
    if (sortBy === "timestamp") {
      aVal = getBashLineTimestampMs(a);
      bVal = getBashLineTimestampMs(b);
      if (aVal == null) aVal = 0;
      if (bVal == null) bVal = 0;
    } else if (sortBy === "lineno") {
      aVal = a.no || 0;
      bVal = b.no || 0;
    } else if (sortBy === "category") {
      aVal = a.category || "";
      bVal = b.category || "";
    } else {
      aVal = a.cmd || "";
      bVal = b.cmd || "";
    }
    if (sortOrder === "asc") return aVal > bVal ? 1 : -1;
    return aVal < bVal ? 1 : -1;
  });

  const cats = ["all", ...new Set(orderedLines.map(l => l.category))];
  const visible = orderedLines.filter(l => {
    if (showSuspOnly && !l.suspicious) return false;
    if (catFilter !== "all" && l.category !== catFilter) return false;
    if (histSearch && !l.cmd.toLowerCase().includes(histSearch.toLowerCase())) return false;
    return true;
  });

  const toggleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("desc");
    }
  };

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
        <div className="rh-sort-controls">
          <label>Sort by:</label>
          <select value={sortBy} onChange={e => setSortBy(e.target.value)}>
            <option value="timestamp">Timestamp</option>
            <option value="lineno">Line</option>
            <option value="category">Category</option>
            <option value="command">Command</option>
          </select>
          <button className="btn-secondary btn-sm" onClick={() => setSortOrder(sortOrder === "asc" ? "desc" : "asc")}>
            {sortOrder === "asc" ? "↑ Asc" : "↓ Desc"}
          </button>
        </div>
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
              ? <tr><td colSpan={4} style={{ textAlign:"center", padding:"24px", color:"#9ca3af" }}>No lines match filter.</td></tr>
              : visible.map(line => {
                  const isHR   = RH_HIGH_RISK.has(line.category);
                  const catClr = isHR ? "#dc2626" : line.category !== "General" ? "#6366f1" : "#9ca3af";
                  return (
                    <tr key={line.no} className={line.suspicious ? "rh-row-susp" : ""}>
                      <td className="rh-td-lineno">{line.no}</td>
                      <td className="rh-td-ts">{line.ts || "—"}</td>
                      <td className="rh-td-cat" style={{ color: catClr }}>
                        {isHR && <AlertTriangle size={10} style={{ marginRight: 3, verticalAlign:"middle" }} />}
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
  const bashEvs   = events.filter(e => e.source === "bash_history");
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
      {view === "raw"      && <BashRawView rawEvents={rawEvents} dateRangeMs={dateRangeMs} />}
    </div>
  );
}

// ── Simple log events table ───────────────────────────────────────────────────
function LogSection({ title, sources, events }) {
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("timestamp");
  const [sortOrder, setSortOrder] = useState("desc");
  const logEvs = events.filter(e => sources.includes(e.source));
  const visible = search
    ? logEvs.filter(e => e.detail.toLowerCase().includes(search.toLowerCase()))
    : logEvs;

  const sortedVisible = [...visible].sort((a, b) => {
    let aVal, bVal;
    if (sortBy === "timestamp") {
      aVal = parseDateToMs(a.timestamp);
      bVal = parseDateToMs(b.timestamp);
      if (aVal == null) aVal = 0;
      if (bVal == null) bVal = 0;
    } else if (sortBy === "severity") {
      const sevOrder = { critical: 3, high: 2, medium: 1, low: 0 };
      aVal = sevOrder[a.severity] || 0;
      bVal = sevOrder[b.severity] || 0;
    } else if (sortBy === "source") {
      aVal = a.source || "";
      bVal = b.source || "";
    } else {
      aVal = a.detail || "";
      bVal = b.detail || "";
    }
    if (sortOrder === "asc") return aVal > bVal ? 1 : -1;
    return aVal < bVal ? 1 : -1;
  });

  const sevCounts = logEvs.reduce((a, e) => { a[e.severity] = (a[e.severity] || 0) + 1; return a; }, {});

  if (!logEvs.length)
    return (
      <div className="log-section-empty">
        <Server size={32} strokeWidth={1.2} style={{ color:"#d1d5db", marginBottom:8 }} />
        <p style={{ color:"#9ca3af", fontSize:13 }}>No {title} events in this image.</p>
      </div>
    );

  const toggleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("desc");
    }
  };

  return (
    <div className="log-section">
      <div className="log-section-toolbar">
        <div className="log-stats">
          {Object.entries(sevCounts).filter(([,v]) => v > 0).map(([sev, cnt]) => (
            <span key={sev} className="log-stat-badge"
              style={{ background: SEV_BG[sev] || "#f3f4f6", color: SEV_COLOR[sev] || "#6b7280" }}>
              {cnt} {sev}
            </span>
          ))}
        </div>
        <div className="log-sort-controls">
          <label>Sort by:</label>
          <select value={sortBy} onChange={e => setSortBy(e.target.value)}>
            <option value="timestamp">Time</option>
            <option value="severity">Severity</option>
            <option value="source">Source</option>
            <option value="detail">Detail</option>
          </select>
          <button className="btn-secondary btn-sm" onClick={() => setSortOrder(sortOrder === "asc" ? "desc" : "asc")}>
            {sortOrder === "asc" ? "↑ Asc" : "↓ Desc"}
          </button>
        </div>
        <input className="tl-search" placeholder={`Search ${title}…`} value={search}
          onChange={e => setSearch(e.target.value)} />
      </div>
      <div className="tl-list">
        {sortedVisible.map((ev, i) => <GenericEventRow key={i} ev={ev} />)}
        {sortedVisible.length === 0 && <div className="tl-empty">No events match search.</div>}
      </div>
    </div>
  );
}

// ── Timeline Tab (source-nav + sections) ──────────────────────────────────────
function TimelineTab({ events = [], dateRangeMs }) {
  const [source, setSource] = useState("bash");

  if (!events.length) return <EmptyState icon={Clock} message="No timeline events found." />;

  // Count significant events per source for nav badges
  const bashHigh = events.filter(e => e.source === "bash_history" && (e.severity === "high" || e.severity === "critical")).length;
  const authEvs  = events.filter(e => ["auth.log","secure"].includes(e.source));
  const sysEvs   = events.filter(e => ["syslog","messages"].includes(e.source));
  const authHigh = authEvs.filter(e => e.severity === "high" || e.severity === "critical").length;
  const sysHigh  = sysEvs.filter(e => e.severity === "high" || e.severity === "critical").length;

  const srcNav = [
    { id: "bash",  label: "Bash History", Icon: Terminal, badge: bashHigh },
    { id: "auth",  label: "Auth Log",     Icon: Lock,     badge: authHigh, count: authEvs.length },
    { id: "syslog",label: "System Log",   Icon: Server,   badge: sysHigh,  count: sysEvs.length },
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
        {source === "bash"   && <BashHistorySection events={events} dateRangeMs={dateRangeMs} />}
        {source === "auth"   && <LogSection title="Auth Log"    sources={["auth.log","secure"]}   events={events} />}
        {source === "syslog" && <LogSection title="System Log"  sources={["syslog","messages"]}   events={events} />}
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
    if (value > 1e9)  return Math.floor(value * 1000);  // s epoch
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
        history:      filterByDateRange(profile.history || [], getBrowserRowTimestampMs, range),
        downloads:    filterByDateRange(profile.downloads || [], getBrowserRowTimestampMs, range),
        bookmarks:    filterByDateRange(profile.bookmarks || [], getBrowserRowTimestampMs, range),
        cookies:      filterByDateRange(profile.cookies || [], getBrowserRowTimestampMs, range),
        extensions:   filterByDateRange(profile.extensions || [], getBrowserRowTimestampMs, range),
        logins:       filterByDateRange(profile.logins || [], getBrowserRowTimestampMs, range),
        search_terms: filterByDateRange(profile.search_terms || [], getBrowserRowTimestampMs, range),
        autofill:     filterByDateRange(profile.autofill || [], getBrowserRowTimestampMs, range),
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
  if (n < 1024)        return `${n} B`;
  if (n < 1048576)     return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824)  return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(1)} GB`;
}

function RecoverButton({ finding, imgPath }) {
  const [status, setStatus] = useState("idle");   // idle | busy | ok | err
  const [result, setResult] = useState(null);

  const run = async () => {
    setStatus("busy");
    try {
      const r = await apiRecover(imgPath, finding.recovery_id);
      if (r.success) { setStatus("ok");  setResult(r); }
      else           { setStatus("err"); setResult(r); }
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
          {f.inode   != null && <span className="del-chip del-inode">ino:{f.inode}</span>}
          {f.deleted_at      && <span className="del-chip del-ts">{f.deleted_at}</span>}
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
  image:      HardDrive,
  document:   FileText,
  executable: Terminal,
  database:   Database,
  archive:    Package,
  email:      BookOpen,
  video:      Activity,
  audio:      Activity,
  text:       Code,
};

function CarvingPanel({ imgPath }) {
  const [groups,     setGroups]     = useState(null);    // {id: label} map from API
  const [selected,   setSelected]   = useState([]);       // group keys chosen by user
  const [maxFiles,   setMaxFiles]   = useState(200);
  const [maxScanGb,  setMaxScanGb]  = useState(2);
  const [outDir,     setOutDir]     = useState("");
  const [status,     setStatus]     = useState("idle");   // idle|loading-groups|carving|done|err
  const [results,    setResults]    = useState(null);
  const [error,      setError]      = useState("");

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
  const info   = results?.carved?.filter(f => f.type !== "carved") ?? [];

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
                  const offset = f.inode != null ? `0x${f.inode.toString(16).padStart(8,"0")}` : "—";
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
  const [search,      setSearch]      = useState("");
  const [filterSev,   setFilterSev]   = useState("all");
  const [filterType,  setFilterType]  = useState("all");
  const [recOnly,     setRecOnly]     = useState(false);

  // Determine if we have a disk image (not live root) — carving only makes sense then
  const isImage = imgPath && imgPath !== "/" && !imgPath.endsWith("/");

  const types = [...new Set(findings.map(f => f.type))];
  const filtered = findings.filter(f => {
    if (filterSev  !== "all" && f.severity !== filterSev)  return false;
    if (filterType !== "all" && f.type     !== filterType)  return false;
    if (recOnly && !f.recoverable)                          return false;
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
  const nHigh        = findings.filter(f => f.severity === "high").length;

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
function ToolsTab({ findings = [] }) {
  if (findings.length === 0) return <EmptyState icon={Search} message="No notable tools detected." />;
  return (
    <div className="tab-content">
      <table className="rp-table findings">
        <thead><tr><th>Tool</th><th>Risk</th><th>Evidence</th></tr></thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i}>
              <td><strong>{f.tool}</strong></td>
              <td><span className="sev-badge" style={{ background: RISK_COLOR[f.risk] || "#6b7280" }}>{f.risk}</span></td>
              <td><ul className="evidence-list">{f.evidence?.map((ev, j) => <li key={j}><code>{ev}</code></li>)}</ul></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Dashboard (Report panel) ─────────────────────────────────────────────────

// Config analyser labels and icons per config file / group
const CFG_FILE_META = {
  sshd_config:  { label: "SSH Server (sshd_config)", Icon: Key },
  sudoers:      { label: "sudo (sudoers)",            Icon: Shield },
  iptables:     { label: "IPTables / Firewall",       Icon: Wifi },
  ufw:          { label: "UFW Firewall",              Icon: Wifi },
  "pam.d":      { label: "PAM Configuration",         Icon: Lock },
  "sysctl.conf":{ label: "Kernel Parameters (sysctl)",Icon: Cpu  },
  "login.defs": { label: "Password Policy",           Icon: Users },
  "/etc/hosts": { label: "/etc/hosts",                Icon: Globe },
  "resolv.conf":{ label: "DNS (resolv.conf)",         Icon: Globe },
  apparmor:     { label: "AppArmor",                  Icon: Shield },
  selinux:      { label: "SELinux",                   Icon: Shield },
  MAC:          { label: "Mandatory Access Control",  Icon: Shield },
  network:      { label: "Network Interfaces",        Icon: Wifi },
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
  const critCount  = findings.filter(f => f.severity === "critical").length;
  const highCount  = findings.filter(f => f.severity === "high").length;
  const warnCount  = findings.filter(f => f.severity === "medium").length;
  const topSev     = critCount ? "critical" : highCount ? "high" : warnCount ? "medium" : "info";
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

function ConfigTab({ findings = [] }) {
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");

  if (findings.length === 0)
    return <EmptyState icon={Settings} message="No configuration findings available." />;

  const filtered = findings.filter(f => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return f.detail.toLowerCase().includes(q)
          || f.config.toLowerCase().includes(q)
          || f.category.toLowerCase().includes(q)
          || (f.recommendation || "").toLowerCase().includes(q);
    }
    return true;
  });

  // Group by config file, sorted so highest-severity groups come first
  const grouped = filtered.reduce((acc, f) => {
    const key = f.config;
    if (!acc[key]) acc[key] = [];
    acc[key].push(f);
    return acc;
  }, {});

  const sortedKeys = Object.keys(grouped).sort((a, b) => {
    const sevA = Math.min(...grouped[a].map(f => SEV_ORDER[f.severity] ?? 4));
    const sevB = Math.min(...grouped[b].map(f => SEV_ORDER[f.severity] ?? 4));
    return sevA - sevB;
  });

  const critCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const medCount  = findings.filter(f => f.severity === "medium").length;

  const SEV_FILTERS = [
    { id: "all",      label: "All" },
    { id: "critical", label: "Critical", color: SEV_COLOR.critical },
    { id: "high",     label: "High",     color: SEV_COLOR.high     },
    { id: "medium",   label: "Medium",   color: SEV_COLOR.medium   },
    { id: "low",      label: "Low",      color: SEV_COLOR.low      },
    { id: "info",     label: "Info",     color: "#6b7280"          },
  ];

  return (
    <div className="tab-content cfg-tab">
      {/* Summary bar */}
      <div className="cfg-summary-bar">
        {critCount > 0 && (
          <span className="cfg-sev-pill" style={{ background: "#fef2f2", color: SEV_COLOR.critical, border: "1px solid #fecaca" }}>
            <AlertTriangle size={11} /> {critCount} Critical
          </span>
        )}
        {highCount > 0 && (
          <span className="cfg-sev-pill" style={{ background: "#fff7ed", color: SEV_COLOR.high, border: "1px solid #fed7aa" }}>
            <AlertTriangle size={11} /> {highCount} High
          </span>
        )}
        {medCount > 0 && (
          <span className="cfg-sev-pill" style={{ background: "#fffbeb", color: SEV_COLOR.medium, border: "1px solid #fde68a" }}>
            <AlertTriangle size={11} /> {medCount} Medium
          </span>
        )}
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
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
          <input className="tl-search" placeholder="Search…" value={search}
            onChange={e => setSearch(e.target.value)} style={{ maxWidth: 200 }} />
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState icon={CheckCircle} message="No findings match the current filter." />
      ) : (
        sortedKeys.map(key => (
          <ConfigGroup key={key} configKey={key} findings={grouped[key]} />
        ))
      )}
    </div>
  );
}

// ─── Services Tab ─────────────────────────────────────────────────────────────

const SVC_CAT_META = {
  web_server:    { label: "Web Server",    Icon: Globe          },
  ftp_server:    { label: "FTP Server",    Icon: FolderOpenIcon },
  database:      { label: "Database",      Icon: Database       },
  mail:          { label: "Mail",          Icon: Package        },
  dns:           { label: "DNS",           Icon: Wifi           },
  dhcp:          { label: "DHCP",          Icon: Wifi           },
  ssh:           { label: "SSH",           Icon: Terminal       },
  remote_access: { label: "Remote Access", Icon: Cpu            },
  file_sharing:  { label: "File Sharing",  Icon: FolderOpenIcon },
  vpn:           { label: "VPN",           Icon: Lock           },
  container:     { label: "Container",     Icon: Box            },
  proxy:         { label: "Proxy",         Icon: Server         },
  monitoring:    { label: "Monitoring",    Icon: BarChart2      },
  security:      { label: "Security",      Icon: Shield         },
  crypto_mining: { label: "Crypto Mining", Icon: AlertTriangle  },
  system:        { label: "System",        Icon: Settings       },
  other:         { label: "Other",         Icon: Package        },
};

const SVC_STATE_COLOR = {
  enabled:  { bg: "#dcfce7", color: "#166534", border: "#bbf7d0" },
  disabled: { bg: "#f1f5f9", color: "#64748b", border: "#e2e8f0" },
  masked:   { bg: "#fef2f2", color: "#991b1b", border: "#fecaca" },
  static:   { bg: "#eff6ff", color: "#1d4ed8", border: "#bfdbfe" },
  indirect: { bg: "#f0fdfa", color: "#0f766e", border: "#99f6e4" },
  detected: { bg: "#fff7ed", color: "#92400e", border: "#fed7aa" },
};

const SVC_FLAG_LABELS = {
  "unusual-exec-path":    "Unusual exec path",
  "shell-exec":           "Shell exec",
  "root-exec":            "Runs as root",
  "unencrypted-protocol": "Unencrypted protocol",
  "deprecated-protocol":  "Deprecated protocol",
  "crypto-miner":         "Possible crypto miner",
  "potential-no-auth":    "Potential no-auth",
  "config-only":          "Config file only",
  "masked":               "Masked",
};

function ServiceRow({ svc }) {
  const [open, setOpen] = useState(false);
  const meta     = SVC_CAT_META[svc.category] || SVC_CAT_META.other;
  const CatIcon  = meta.Icon;
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
              {svc.flags.map(f => (
                <span key={f} className="svc-flag"
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
  const [catFilter,   setCatFilter]   = useState("all");
  const [sevFilter,   setSevFilter]   = useState("all");
  const [search,      setSearch]      = useState("");

  if (services.length === 0)
    return <EmptyState icon={Server} message="No services detected." />;

  const filtered = services.filter(s => {
    if (stateFilter !== "all" && s.state   !== stateFilter) return false;
    if (catFilter   !== "all" && s.category !== catFilter)  return false;
    if (sevFilter   !== "all" && s.severity !== sevFilter)  return false;
    if (search) {
      const q = search.toLowerCase();
      return s.name.toLowerCase().includes(q)
          || (s.display_name || "").toLowerCase().includes(q)
          || (s.description  || "").toLowerCase().includes(q)
          || (s.exec_start   || "").toLowerCase().includes(q);
    }
    return true;
  });

  const enabledCount = services.filter(s => s.state    === "enabled").length;
  const critCount    = services.filter(s => s.severity === "critical").length;
  const highCount    = services.filter(s => s.severity === "high").length;

  const catCounts = services.reduce((acc, s) => {
    acc[s.category] = (acc[s.category] || 0) + 1;
    return acc;
  }, {});
  const presentCats = Object.keys(catCounts).sort();

  const STATE_FILTERS = [
    { id: "all",      label: "All"      },
    { id: "enabled",  label: "Enabled"  },
    { id: "disabled", label: "Disabled" },
    { id: "static",   label: "Static"   },
    { id: "masked",   label: "Masked"   },
    { id: "detected", label: "Detected" },
  ].filter(f => f.id === "all" || services.some(s => s.state === f.id));

  const SEV_FILTERS = [
    { id: "all",      label: "All"      },
    { id: "critical", label: "Critical" },
    { id: "high",     label: "High"     },
    { id: "medium",   label: "Medium"   },
    { id: "low",      label: "Low"      },
    { id: "info",     label: "Info"     },
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
          {filtered.map(svc => (
            <ServiceRow key={`${svc.source}-${svc.name}`} svc={svc} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Browser Forensics Tab ────────────────────────────────────────────────────

const BROWSER_META = {
  chrome:    { label: "Google Chrome",  color: "#4285f4" },
  chromium:  { label: "Chromium",       color: "#2563eb" },
  brave:     { label: "Brave",          color: "#fb542b" },
  edge:      { label: "Microsoft Edge", color: "#0078d4" },
  opera:     { label: "Opera",          color: "#ff1b2d" },
  vivaldi:   { label: "Vivaldi",        color: "#ef3939" },
  yandex:    { label: "Yandex",         color: "#ffcc00" },
  firefox:   { label: "Firefox",        color: "#ff9500" },
  waterfox:  { label: "Waterfox",       color: "#00acda" },
  librewolf: { label: "LibreWolf",      color: "#00adef" },
  icecat:    { label: "GNU IceCat",     color: "#5b9bd5" },
  tor:       { label: "Tor Browser",    color: "#7d4698" },
};

const BW_ARTIFACT_TABS = [
  { id: "history",      label: "History",     emptyMsg: "No history found."      },
  { id: "downloads",    label: "Downloads",   emptyMsg: "No downloads found."    },
  { id: "bookmarks",    label: "Bookmarks",   emptyMsg: "No bookmarks found."    },
  { id: "cookies",      label: "Cookies",     emptyMsg: "No cookies found."      },
  { id: "extensions",   label: "Extensions",  emptyMsg: "No extensions found."   },
  { id: "logins",       label: "Logins",      emptyMsg: "No saved logins found." },
  { id: "search_terms", label: "Searches",    emptyMsg: "No search terms found." },
  { id: "autofill",     label: "Autofill",    emptyMsg: "No autofill data found."},
];

const BW_FLAG_LABELS = {
  "saved-passwords":      "Saved passwords",
  "suspicious-downloads": "Suspicious downloads",
  "suspicious-history":   "Suspicious history",
  "suspicious-extensions":"Suspicious extensions",
  "suspicious-searches":  "Suspicious searches",
  "wiped-history":        "History wiped",
  "credential-store":     "Credential store present",
  "saved-credentials":    "Saved credentials",
  "executable":           "Executable file",
  "suspicious-url":       "Suspicious URL",
  "suspicious-search":    "Suspicious search",
  "not-secure":           "Non-secure flag",
  "not-httponly":         "Missing HttpOnly",
  "unsigned":             "Unsigned extension",
};

function BwFlagChip({ flag }) {
  const label = BW_FLAG_LABELS[flag] || flag.replace(/^perm:/, "perm: ");
  const isHigh = ["saved-passwords","saved-credentials","suspicious-searches","suspicious-extensions","wiped-history"].includes(flag)
    || flag.startsWith("perm:") && ["<all_urls>","*://*/*","webRequestBlocking","proxy","nativeMessaging","debugger","management"].some(p => flag.includes(p));
  const isMed = ["suspicious-downloads","suspicious-history","suspicious-url","credential-store","executable","unsigned"].includes(flag)
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
              <td>{(r.flags||[]).map(f => <BwFlagChip key={f} flag={f} />)}</td>
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
              <td className="bw-ts">{r.mime_type || "—"}{r.total_bytes > 0 && ` · ${(r.total_bytes/1024).toFixed(0)} KB`}</td>
              <td className="bw-ts">{r.start_time || "—"}</td>
              <td>{(r.flags||[]).map(f => <BwFlagChip key={f} flag={f} />)}</td>
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
              <td className="bw-center">{r.is_secure ? "✓" : <span style={{color:"#dc2626"}}>✗</span>}</td>
              <td className="bw-center">{r.is_httponly ? "✓" : <span style={{color:"#dc2626"}}>✗</span>}</td>
              <td className="bw-ts">{r.expires || "session"}</td>
              <td>{(r.flags||[]).map(f => <BwFlagChip key={f} flag={f} />)}</td>
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
                <div style={{fontWeight: 600}}>{r.name}</div>
                {r.description && <div className="bw-subtitle">{r.description}</div>}
                <SevBadge sev={r.severity} />
              </td>
              <td className="bw-mono" style={{fontSize:10}}>{r.id}</td>
              <td className="bw-ts">{r.version || "—"}</td>
              <td>{(r.flags||[]).map(f => <BwFlagChip key={f} flag={f} />)}</td>
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
              <td style={{fontWeight: r.severity === "high" ? 700 : 400}}>{r.term}</td>
              <td className="bw-ts">{r.engine || "—"}</td>
              <td>{(r.flags||[]).map(f => <BwFlagChip key={f} flag={f} />)}</td>
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
    history:      (profile.history      || []).length,
    downloads:    (profile.downloads    || []).length,
    bookmarks:    (profile.bookmarks    || []).length,
    cookies:      (profile.cookies      || []).length,
    extensions:   (profile.extensions   || []).length,
    logins:       (profile.logins       || []).length,
    search_terms: (profile.search_terms || []).length,
    autofill:     (profile.autofill     || []).length,
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
        {artifactTab === "history"      && (counts.history      > 0 ? <BwHistoryTable    rows={profile.history}      search={q} /> : <div className="bw-empty">No history found.</div>     )}
        {artifactTab === "downloads"    && (counts.downloads    > 0 ? <BwDownloadsTable  rows={profile.downloads}    search={q} /> : <div className="bw-empty">No downloads found.</div>   )}
        {artifactTab === "bookmarks"    && (counts.bookmarks    > 0 ? <BwBookmarksTable  rows={profile.bookmarks}    search={q} /> : <div className="bw-empty">No bookmarks found.</div>   )}
        {artifactTab === "cookies"      && (counts.cookies      > 0 ? <BwCookiesTable    rows={profile.cookies}      search={q} /> : <div className="bw-empty">No cookies found.</div>     )}
        {artifactTab === "extensions"   && (counts.extensions   > 0 ? <BwExtensionsTable rows={profile.extensions}   search={q} /> : <div className="bw-empty">No extensions found.</div>  )}
        {artifactTab === "logins"       && (counts.logins       > 0 ? <BwLoginsTable     rows={profile.logins}       search={q} /> : <div className="bw-empty">No saved logins found.</div>)}
        {artifactTab === "search_terms" && (counts.search_terms > 0 ? <BwSearchesTable   rows={profile.search_terms} search={q} /> : <div className="bw-empty">No search terms found.</div>)}
        {artifactTab === "autofill"     && (counts.autofill     > 0 ? <BwAutofillTable   rows={profile.autofill}     search={q} /> : <div className="bw-empty">No autofill data found.</div>)}
      </div>
    </div>
  );
}

function BrowserTab({ browsers = [] }) {
  const [selected, setSelected] = useState(0);

  if (!browsers || browsers.length === 0)
    return <EmptyState icon={Globe} message="No browser profiles detected." />;

  const cur = browsers[selected] || browsers[0];

  const totalHistory   = browsers.reduce((n, b) => n + (b.history      || []).length, 0);
  const totalDownloads = browsers.reduce((n, b) => n + (b.downloads    || []).length, 0);
  const totalLogins    = browsers.reduce((n, b) => n + (b.logins       || []).length, 0);
  const totalExts      = browsers.reduce((n, b) => n + (b.extensions   || []).length, 0);

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

const MM_TYPE_META = {
  image: { Icon: Image,  label: "Image",  color: "#7c3aed" },
  video: { Icon: Film,   label: "Video",  color: "#2563eb" },
  audio: { Icon: Music,  label: "Audio",  color: "#16a34a" },
  media: { Icon: Layers, label: "Media",  color: "#6b7280" },
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
          {s.fps &&   ` @ ${s.fps}`}
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
  const fname   = item.path.split("/").pop();

  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape")     onClose();
      if (e.key === "ArrowLeft"  && hasPrev) onPrev();
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

        {/* Metadata chips */}
        {metaChips.length > 0 && (
          <div className="mv-meta-bar">
            {metaChips.map((c, i) => <span key={i} className="mv-meta-chip">{c}</span>)}
          </div>
        )}
      </div>
    </div>
  );
}

function MediaRow({ item, imgPath, onView }) {
  const [open, setOpen] = useState(false);
  const mt = MM_TYPE_META[item.media_type] || MM_TYPE_META.media;
  const Icon = mt.Icon;
  const hasBadFlags = item.severity === "high" || item.severity === "critical";
  const hasMedFlags = item.severity === "medium";

  const fmtSize = (n) => {
    if (!n) return "";
    if (n < 1024) return `${n}B`;
    if (n < 1024**2) return `${(n/1024).toFixed(1)}KB`;
    return `${(n/1024**2).toFixed(1)}MB`;
  };

  return (
    <div className={`mm-row ${hasBadFlags ? "mm-row-high" : hasMedFlags ? "mm-row-med" : ""}`}>
      <div className="mm-row-header" onClick={() => setOpen(o => !o)}>
        <span className="mm-row-chevron">
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </span>
        <Icon size={13} style={{ color: mt.color, flexShrink: 0 }} />
        <span className="mm-row-path" title={item.path}>{item.name || item.path.split("/").pop()}</span>
        {item.size > 0 && <span className="mm-row-size">{fmtSize(item.size)}</span>}
        {item.metadata?.resolution && (
          <span className="mm-row-dim">{item.metadata.resolution}</span>
        )}
        {item.metadata?.width_px && (
          <span className="mm-row-dim">{item.metadata.width_px}×{item.metadata.height_px}</span>
        )}
        <GpsLink gps={item.gps} />
        <div style={{ flex: 1 }} />
        {item.flags?.map(f => (
          <span key={f} className="mm-flag-tag">{f}</span>
        ))}
        {imgPath && (
          <button
            className="mm-view-btn"
            title="View file"
            onClick={e => { e.stopPropagation(); onView(item); }}
          >
            <Play size={11} /> View
          </button>
        )}
        <SevBadge sev={item.severity} />
      </div>
      {open && (
        <div className="mm-row-body">
          <div className="mm-row-path-full"><FileText size={10} /> {item.path}</div>
          {item.findings?.length > 0 && (
            <ul className="mm-findings-list">
              {item.findings.map((f, i) => (
                <li key={i} className="mm-finding-item"><AlertTriangle size={10} /> {f}</li>
              ))}
            </ul>
          )}
          <EmbeddedThumbnail thumbnail={item.thumbnail} />
          <StreamsTable streams={item.streams} />
          <MetaTable meta={item.metadata} />
        </div>
      )}
    </div>
  );
}

function MultimediaTab({ findings = [], imgPath }) {
  const [filterType, setFilterType] = useState("all");
  const [filterSev,  setFilterSev]  = useState("all");
  const [search,     setSearch]     = useState("");
  const [running,    setRunning]    = useState(false);
  const [err,        setErr]        = useState(null);
  const [localFindings, setLocalFindings] = useState(findings);
  const [viewItem,   setViewItem]   = useState(null);

  // Sync when parent report findings change
  useEffect(() => { setLocalFindings(findings); }, [findings]);

  const items = (localFindings || []).filter(item => {
    if (filterType !== "all" && item.media_type !== filterType) return false;
    if (filterSev  !== "all" && item.severity    !== filterSev)  return false;
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
      <div className="mm-tab">
        <EmptyState icon={Image} message="No media files analysed." />
        {imgPath && (
          <div style={{ textAlign: "center", marginTop: 12 }}>
            <button className="btn-primary btn-sm" onClick={handleRescan} disabled={running}>
              {running ? "Scanning…" : "Scan for Media Files"}
            </button>
            {err && <div className="mm-err">{err}</div>}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="mm-tab">
      {/* Stats bar */}
      <div className="mm-stats-bar">
        <span className="mm-stat"><Image size={11} /><strong>{counts.image}</strong> image{counts.image !== 1 ? "s" : ""}</span>
        <span className="mm-stat"><Film  size={11} /><strong>{counts.video}</strong> video{counts.video !== 1 ? "s" : ""}</span>
        <span className="mm-stat"><Music size={11} /><strong>{counts.audio}</strong> audio</span>
        {withGps > 0 && (
          <span className="mm-stat mm-stat-warn"><MapPin size={11} /><strong>{withGps}</strong> with GPS</span>
        )}
        {flagged > 0 && (
          <span className="mm-stat mm-stat-warn"><AlertTriangle size={11} /><strong>{flagged}</strong> flagged</span>
        )}
        <div style={{ flex: 1 }} />
        {imgPath && (
          <button className="btn-secondary btn-sm" onClick={handleRescan} disabled={running}>
            <RefreshCw size={11} className={running ? "spin" : ""} />
            {running ? "Scanning…" : "Re-scan"}
          </button>
        )}
      </div>

      {/* Filters */}
      <div className="mm-filters">
        <Filter size={11} />
        <select value={filterType} onChange={e => setFilterType(e.target.value)} className="mm-select">
          <option value="all">All types</option>
          <option value="image">Images</option>
          <option value="video">Videos</option>
          <option value="audio">Audio</option>
        </select>
        <select value={filterSev} onChange={e => setFilterSev(e.target.value)} className="mm-select">
          <option value="all">All severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="info">Info</option>
        </select>
        <input
          type="text"
          placeholder="Search path or finding…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="mm-search"
        />
      </div>
      {err && <div className="mm-err">{err}</div>}

      {/* File list */}
      <div className="mm-list">
        {items.length === 0 ? (
          <div className="mm-empty">No items match current filters.</div>
        ) : (
          items.map((item, i) => (
            <MediaRow key={i} item={item} imgPath={imgPath} onView={setViewItem} />
          ))
        )}
      </div>

      {/* Viewer modal */}
      {viewItem && imgPath && (() => {
        const idx    = items.findIndex(i => i.path === viewItem.path);
        const safeIdx = idx === -1 ? 0 : idx;
        return (
          <MediaViewerModal
            item={viewItem}
            imgPath={imgPath}
            onClose={() => setViewItem(null)}
            onPrev={() => setViewItem(items[safeIdx - 1])}
            onNext={() => setViewItem(items[safeIdx + 1])}
            hasPrev={safeIdx > 0}
            hasNext={safeIdx < items.length - 1}
          />
        );
      })()}
    </div>
  );
}

function MemoryTab({ report }) {
  if (!report) return <EmptyState icon={Cpu} message="No memory analysis available." />;

  const { processes = [], connections = [], bash_history = [], malfind = [], modules = [], summary = {} } = report;

  return (
    <div className="tab-content">
      {/* Summary */}
      <div className="mem-summary">
        <div className="mem-stat"><strong>{summary.process_count || 0}</strong> processes</div>
        <div className="mem-stat"><strong>{summary.hidden_count || 0}</strong> hidden</div>
        <div className="mem-stat"><strong>{summary.connection_count || 0}</strong> connections</div>
        <div className="mem-stat"><strong>{summary.bash_entries || 0}</strong> bash entries</div>
        <div className="mem-stat"><strong>{summary.malfind_count || 0}</strong> malfind</div>
        {summary.total_high > 0 && (
          <div className="mem-stat mem-high"><AlertTriangle size={11} /> <strong>{summary.total_high}</strong> high</div>
        )}
      </div>

      {/* Processes */}
      <Section title="Processes" icon={Server} count={processes.length}>
        <table className="rp-table">
          <thead><tr><th>PID</th><th>Name</th><th>Command</th><th>Hidden</th></tr></thead>
          <tbody>
            {processes.map((p, i) => (
              <tr key={i}>
                <td>{p.pid}</td>
                <td>{p.name}</td>
                <td><code>{p.command || ""}</code></td>
                <td>{p.hidden ? <AlertTriangle size={11} style={{ color: "#dc2626" }} /> : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      {/* Connections */}
      <Section title="Network Connections" icon={Wifi} count={connections.length}>
        <table className="rp-table">
          <thead><tr><th>PID</th><th>Local</th><th>Remote</th><th>State</th></tr></thead>
          <tbody>
            {connections.map((c, i) => (
              <tr key={i}>
                <td>{c.pid}</td>
                <td><code>{c.laddr}:{c.lport}</code></td>
                <td><code>{c.raddr}:{c.rport}</code></td>
                <td>{c.state}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      {/* Bash History */}
      <Section title="Bash History" icon={Terminal} count={bash_history.length}>
        <table className="rp-table">
          <thead><tr><th>PID</th><th>Command</th><th>Timestamp</th></tr></thead>
          <tbody>
            {bash_history.map((b, i) => (
              <tr key={i}>
                <td>{b.pid}</td>
                <td><code>{b.command}</code></td>
                <td>{b.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      {/* Malfind */}
      <Section title="Malfind" icon={AlertTriangle} count={malfind.length}>
        <table className="rp-table">
          <thead><tr><th>PID</th><th>Address</th><th>Protection</th><th>Tag</th></tr></thead>
          <tbody>
            {malfind.map((m, i) => (
              <tr key={i}>
                <td>{m.pid}</td>
                <td><code>{m.address}</code></td>
                <td><code>{m.protection}</code></td>
                <td>{m.tag}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      {/* Modules */}
      <Section title="Loaded Modules" icon={Box} count={modules.length}>
        <table className="rp-table">
          <thead><tr><th>Name</th><th>Address</th><th>Size</th></tr></thead>
          <tbody>
            {modules.map((m, i) => (
              <tr key={i}>
                <td>{m.name}</td>
                <td><code>{m.address}</code></td>
                <td>{m.size}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </div>
  );
}

const REPORT_TABS = [
  { id: "summary",     label: "Summary",     Icon: HardDrive },
  { id: "timeline",    label: "Timeline",    Icon: Clock     },
  { id: "recent",      label: "Recent",      Icon: Activity  },
  { id: "deleted",     label: "Deleted",     Icon: Eye       },
  { id: "persistence", label: "Persistence", Icon: Shield    },
  { id: "config",      label: "Config",      Icon: Settings  },
  { id: "services",    label: "Services",    Icon: Server    },
  { id: "browsers",    label: "Browsers",    Icon: Globe     },
  { id: "multimedia",  label: "Multimedia",  Icon: Image     },
  { id: "tails",       label: "TailsOS",     Icon: Sailboat  },
  { id: "tools",       label: "Tools",       Icon: Search    },
  { id: "memory",      label: "Memory",      Icon: Cpu       },
];

function ReportPanel({ report, memoryReport, liveInfo, imgPath, onClear, onExport, onReanalyze, reanalyzing }) {
  const [tab, setTab] = useState("summary");
  const [dateRangeDraft, setDateRangeDraft] = useState({ from: "", to: "" });
  const [dateRangeApplied, setDateRangeApplied] = useState({ from: "", to: "" });
  const { summary } = report;
  const isLive = !!liveInfo;

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

  const badge = {
    timeline:    highTimelineFiltered > 0 ? highTimelineFiltered : null,
    recent:      recentActivities.length > 0 ? recentActivities.length : null,
    deleted:     highDeletedFiltered > 0 ? highDeletedFiltered : null,
    persistence: summary?.high_persistence > 0 ? summary.high_persistence : null,
    config:      summary?.high_config      > 0 ? summary.high_config      : null,
    services:    summary?.high_services    > 0 ? summary.high_services    : null,
    browsers:    highBrowserFiltered > 0 ? highBrowserFiltered : null,
    multimedia:  highMediaFiltered > 0 ? highMediaFiltered : null,
    tails:       highTailsFiltered > 0 ? highTailsFiltered : null,
    tools:       summary?.high_risk_tools  > 0 ? summary.high_risk_tools  : null,
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
          <button className="btn-secondary btn-sm" onClick={onExport}><FolderOpen size={12} /> Export</button>
          <button className="btn-secondary btn-sm" onClick={onClear}><Trash2 size={12} /> Clear</button>
        </div>
      </div>
      <div className="report-tabbar">
        {REPORT_TABS.map(({ id, label, Icon }) => (
          <button key={id} className={`dash-tab ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>
            <Icon size={12} />{label}
            {badge[id] != null && <span className="tab-badge">{badge[id]}</span>}
          </button>
        ))}
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
        {tab === "summary"     && <SummaryTab     report={report} liveInfo={liveInfo} />}
        {tab === "timeline"    && <TimelineTab    events={filteredTimeline} dateRangeMs={rangeMs} />}
        {tab === "recent"      && <RecentActivitiesTab activities={recentActivities} />}
        {tab === "deleted"     && <DeletedTab     findings={filteredDeleted} imgPath={imgPath} />}
        {tab === "persistence" && <PersistenceTab findings={report.persistence} />}
        {tab === "config"      && <ConfigTab      findings={report.config} />}
        {tab === "services"    && <ServicesTab    services={report.services} />}
        {tab === "browsers"    && <BrowserTab     browsers={filteredBrowsers} />}
        {tab === "multimedia"  && <MultimediaTab  findings={filteredMultimedia} imgPath={imgPath} />}
        {tab === "tails"       && <TailsTab       findings={report.tails || []} summary={summary || {}} />}
        {tab === "tools"       && <ToolsTab       findings={report.findings} />}
        {tab === "memory"      && <MemoryTab      report={memoryReport} />}
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
  const [analysisType, setAnalysisType] = useState("disk"); // "disk" or "memory"

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
      let res;
      if (analysisType === "memory") {
        res = await apiCaseAnalyzeMemory(caseId, path);
      } else {
        res = mode === "tails"
          ? await apiCaseAnalyzeTails(caseId, path)
          : await apiCaseAnalyze(caseId, path);
      }
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
      <div className="dlg-field">
        <label>Analysis Type</label>
        <div style={{ display: "flex", gap: 16 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <input
              type="radio"
              name="analysisType"
              value="disk"
              checked={analysisType === "disk"}
              onChange={(e) => setAnalysisType(e.target.value)}
            />
            Disk Image / Mountpoint
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <input
              type="radio"
              name="analysisType"
              value="memory"
              checked={analysisType === "memory"}
              onChange={(e) => setAnalysisType(e.target.value)}
            />
            Memory Dump
          </label>
        </div>
      </div>

      {analysisType === "disk" && (
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
      )}

      <div className="dlg-field">
        <label>{analysisType === "memory" ? "Memory Dump Path" : "Image / Mountpoint Path"}</label>
        <div style={{ display: "flex", gap: 8 }}>
          <input
            style={{ flex: 1 }}
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run(analysisType === "memory" ? "memory" : (preferredMode === "tails" ? "tails" : "normal"))}
            placeholder={analysisType === "memory" ? "/path/to/memory.dump" : "/mnt/evidence  or  /path/to/disk.img"}
          />
          <button className="btn-secondary" onClick={() => setPicking(true)} title="Browse filesystem">
            <FolderOpen size={15} />
          </button>
        </div>
        <div className="dlg-hint">The analysis result will be saved into this case automatically.</div>
      </div>
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        {analysisType === "memory" ? (
          <button
            className="btn-primary"
            onClick={() => run("memory")}
            disabled={!!loadingMode || !path}
          >
            <Search size={14} />{loadingMode === "memory" ? "Analyzing…" : "Analyze Memory Dump"}
          </button>
        ) : (
          <>
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
          </>
        )}
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
function CasePanel({ caseData, activeSourceId, onSelectSource, onAddSource, onAddTailsSource, onAddTailsUsbSource, onScanLiveToCase, onDeleteSource, onBack }) {
  const [activeTab, setActiveTab] = useState("sources");
  const { data_sources = [] } = caseData;

  const threatSummary = (src) => {
    const hi = src.report?.summary?.total_high ?? 0;
    if (hi === 0) return { label: "CLEAN", cls: "tl-low" };
    if (hi >= 10) return { label: "CRITICAL", cls: "tl-critical" };
    if (hi >= 5)  return { label: "HIGH",     cls: "tl-high" };
    return             { label: "MEDIUM",   cls: "tl-medium" };
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
          <button className="btn-primary btn-sm" onClick={onAddSource}>
            <Plus size={13} /> Add Data Source
          </button>
        </div>
      </div>

      {/* Tab bar */}
      <div className="case-tabs">
        {[["sources", HardDrive, "Data Sources"], ["info", Info, "Case Info"]].map(([id, Icon, label]) => (
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

      {/* Info tab */}
      {activeTab === "info" && (
        <div className="case-info">
          <table className="rp-table" style={{ maxWidth: 600 }}>
            <tbody>
              {[
                ["Case Name",    caseData.name],
                ["Case Number",  caseData.number  || "—"],
                ["Examiner",     caseData.examiner || "—"],
                ["Created",      fmtDate(caseData.created_at)],
                ["Last Updated", fmtDate(caseData.updated_at)],
                ["Sources",      data_sources.length],
                ["Case ID",      <code style={{ fontSize: 11 }}>{caseData.id}</code>],
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
          <span style={{ whiteSpace: "pre-wrap" }}>{msg.text}</span>
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
  const [messages,     setMessages]     = useState([]);
  const [input,        setInput]        = useState("");
  const [loading,      setLoading]      = useState(false);
  const [sessionId,    setSessionId]    = useState(null);
  const [ollamaStatus, setOllamaStatus] = useState(null);
  const [model,        setModel]        = useState("qwen2.5:7b");
  const bottomRef = useRef(null);
  const abortRef  = useRef(null);

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
      { role: "user",  text: userMsg },
      { role: "agent", text: "", steps: [], inProgress: true },
    ]);
    setLoading(true);

    const ctrl = new AbortController();
    abortRef.current = ctrl;
    let curSession = sessionId;
    let accSteps   = [];
    let accText    = "";

    try {
      const resp = await fetch(`${API}/agent/chat/stream`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ message: userMsg, session_id: curSession, model }),
        signal:  ctrl.signal,
      });
      if (!resp.ok) throw new Error((await resp.text()) || `HTTP ${resp.status}`);

      const reader  = resp.body.getReader();
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
    if (sessionId) apiAgentReset(sessionId).catch(() => {});
    setMessages([]);
    setSessionId(null);
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

      {/* Ollama setup notice */}
      {ollamaStatus && !ollamaStatus.available && (
        <div className="ag-notice">
          <div className="ag-notice-title">
            <AlertTriangle size={13} /> {ollamaStatus.message}
          </div>
          <div className="ag-notice-steps">
            <code>curl -fsSL https://ollama.ai/install.sh | sh</code>
            <code>ollama serve</code>
            <code>ollama pull qwen2.5:7b</code>
          </div>
        </div>
      )}

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

function ActivityBar({ view, onView, hasExplorer, hasReport }) {
  const items = [
    { id: "home",     Icon: Home,           label: "Home",     always: true },
    { id: "cases",    Icon: BookOpen,        label: "Cases",    always: true },
    { id: "agent",    Icon: Bot,             label: "Agent",    always: true },
    { id: "explorer", Icon: LayoutPanelLeft, label: "Explorer", disabled: !hasExplorer },
    { id: "report",   Icon: BarChart2,       label: "Report",   disabled: !hasReport },
  ];
  const caseActive = view === "cases" || view === "case";
  return (
    <div className="activity-bar">
      {items.map(({ id, Icon, label, always, disabled }) => (
        <button
          key={id}
          className={`act-btn ${
            (id === "cases" && caseActive) || (id !== "cases" && view === id) ? "active" : ""
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
  const [dialog,      setDialog]      = useState(null);
  const [report,      setReport]      = useState(null);
  const [memoryReport,setMemoryReport]= useState(null);
  const [imgPath,     setImgPath]     = useState(null);
  const [liveInfo,    setLiveInfo]    = useState(null);
  const [status,      setStatus]      = useState("Ready");
  const [toolbar,     setToolbar]     = useState(true);
  const [statbar,     setStatbar]     = useState(true);
  const [reanalyzing, setReanalyzing] = useState(false);
  const [liveScanning,setLiveScanning]= useState(false);
  // "home" | "cases" | "case" | "explorer" | "report"
  const [view,        setView]        = useState("home");
  const [activeCase,  setActiveCase]  = useState(null);
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

  function handleMemoryResult(r, path) {
    setMemoryReport(r);
    setImgPath(path);
    setView("report");
    const hi = r.summary?.total_high ?? 0;
    setStatus(`Memory analysis complete — ${hi} high-severity indicator${hi !== 1 ? "s" : ""}`);
  }

  async function handleReanalyze() {
    if (!imgPath || reanalyzing) return;
    setReanalyzing(true);
    setStatus("Reanalyzing…");
    try {
      const r = imgPath === "/" ? await apiAnalyzeLive() : await apiAnalyze(imgPath);
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
    if (mode === "memory") {
      setMemoryReport(rpt);
      setReport(null);
    } else {
      setReport(rpt);
      setMemoryReport(null);
    }
    setImgPath(source.path);
    setActiveSrcId(source.id);
    setView("report");
    const hi = rpt.summary?.total_high ?? 0;
    const modeText = mode === "tails" ? "TailsOS analysis" : mode === "live" ? "live scan" : mode === "memory" ? "memory analysis" : "analysis";
    setStatus(`Source added to "${updatedCase.name}" (${modeText}) — ${hi} high-severity indicator${hi !== 1 ? "s" : ""}`);
  }

  function selectSource(src) {
    setActiveSrcId(src.id);
    if (src.report && 'processes' in src.report) {
      setMemoryReport(src.report);
      setReport(null);
    } else {
      setReport(src.report);
      setMemoryReport(null);
    }
    setImgPath(src.path);
    setView("report");
  }

  function downloadJSON(r) {
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "forensic_report.json"; a.click();
  }

  function handleAction(key) {
    switch (key) {
      case "analyze":       return setDialog("analyze");
      case "memory":        return setDialog("memory");
      case "filepick":      return setDialog("filepick");
      case "live_scan":     return setDialog("live_scan");
      case "new_case":      return setDialog("new_case");
      case "view_cases":    return setView("cases");
      case "export":        return report ? downloadJSON(report) : setStatus("No report to export");
      case "clear":         setReport(null); setMemoryReport(null); setImgPath(null); setLiveInfo(null); setActiveCase(null); setActiveSrcId(null); setView("home"); return setStatus("Analysis cleared");
      case "settings":      return setDialog("settings");
      case "shortcuts":     return setDialog("shortcuts");
      case "about":         return setDialog("about");
      case "statusbar":     return setStatbar(v => !v);
      case "toolbar":       return setToolbar(v => !v);
      case "view_explorer": return imgPath ? setView("explorer") : setStatus("Open an image first");
      case "view_report":   return report  ? setView("report")   : setStatus("Run analysis first");
      case "explorer":      return imgPath ? setView("explorer") : setStatus("Open an image first");
      case "report_panel":  return report  ? setView("report")   : setStatus("Run analysis first");
      default:              return;
    }
  }

  useEffect(() => {
    function onKey(e) {
      if (e.ctrlKey && e.key === "o") { e.preventDefault(); handleAction("analyze"); }
      if (e.ctrlKey && e.key === "m") { e.preventDefault(); handleAction("memory"); }
      if (e.ctrlKey && e.key === "b") { e.preventDefault(); handleAction("filepick"); }
      if (e.ctrlKey && e.key === "l") { e.preventDefault(); handleAction("live_scan"); }
      if (e.ctrlKey && e.key === ",") { e.preventDefault(); handleAction("settings"); }
      if (e.key === "F1")             { e.preventDefault(); handleAction("about"); }
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

          {view === "agent" && <AgentPanel />}

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
              onBack={() => setView("cases")}
            />
          )}

          {view === "explorer" && imgPath && <Explorer imgPath={imgPath} />}

          {view === "report" && (report || memoryReport) && (
            <ReportPanel
              report={report}
              memoryReport={memoryReport}
              liveInfo={imgPath === "/" ? liveInfo : null}
              imgPath={imgPath}
              onClear={() => handleAction("clear")}
              onExport={() => downloadJSON(report || memoryReport)}
              onReanalyze={handleReanalyze}
              reanalyzing={reanalyzing}
            />
          )}
        </div>
      </div>

      <StatusBar visible={statbar} status={status} report={report} memoryReport={memoryReport} />

      {dialog === "analyze"    && <AnalyzeDialog    onClose={closeDialog} onResult={handleResult} />}
      {dialog === "memory"     && <MemoryDialog     onClose={closeDialog} onResult={handleMemoryResult} />}
      {dialog === "filepick"   && <FilePickerDialog  onClose={closeDialog} onResult={handleResult} />}
      {dialog === "live_scan"  && (
        <LiveScanDialog
          onClose={closeDialog}
          onResult={(r, path, info) => { handleResult(r, path); setLiveInfo(info); closeDialog(); }}
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
      {dialog === "new_case"   && (
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
      {dialog === "settings"   && <SettingsDialog   onClose={closeDialog} />}
      {dialog === "shortcuts"  && <ShortcutsDialog  onClose={closeDialog} />}
      {dialog === "about"      && <AboutDialog      onClose={closeDialog} />}
    </div>
  );
}
