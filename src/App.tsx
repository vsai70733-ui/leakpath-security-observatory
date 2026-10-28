import { useEffect, useMemo, useState } from "react";
import LoginPage from "./LoginPage";

type Severity = "low" | "medium" | "high" | "critical";
type Finding = {
  id: string;
  file: string;
  type: string;
  severity: Severity;
  confidence: number;
  evidence: string;
  rationale: string;
  gitState: string;
  gitDetail: string;
  missingIgnore: boolean;
  remediation: string;
  path: string[];
};
type EventItem = {
  id: string;
  time: string;
  activity: string;
  file: string;
  severity: Severity;
  message: string;
  category: string;
};
type State = {
  monitoring: boolean;
  simulationRunning: boolean;
  workspace: string;
  lastScan: string;
  riskScore: number;
  riskLevel: string;
  findings: Finding[];
  events: EventItem[];
  factors: { label: string; value: number; detail: string }[];
  gitRisks: number;
  sensitiveFiles: number;
  affectedFiles: number;
  openAlerts: number;
  eventCount: number;
  scanCount: number;
};
type AuthUser = { openId: string; name: string; email: string };

const emptyState: State = {
  monitoring: true,
  simulationRunning: false,
  workspace: "demo-workspace/",
  lastScan: new Date().toISOString(),
  riskScore: 0,
  riskLevel: "LOW",
  findings: [],
  events: [],
  factors: [],
  gitRisks: 0,
  sensitiveFiles: 0,
  affectedFiles: 0,
  openAlerts: 0,
  eventCount: 0,
  scanCount: 0
};

const severityOrder: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const staticDemo = import.meta.env.VITE_STATIC_DEMO === "true";

function demoState(): State {
  const now = new Date().toISOString();
  const findings: Finding[] = [
    { id: "finding_demo_1", file: "config/dev.env", type: "API key", severity: "high", confidence: 0.96, evidence: "API_K••••2d", rationale: "API key pattern found; not ignored — likely to be added by accident.", gitState: "untracked", gitDetail: "Not ignored — likely to be added by accident", missingIgnore: true, remediation: "Move the key to a runtime secret store and keep the file ignored.", path: ["File created", "Signal detected", "Git untracked", "Review before sharing"] },
    { id: "finding_demo_2", file: "src/api.ts", type: "Password", severity: "high", confidence: 0.96, evidence: "demo-••••ord", rationale: "Password pattern found; staged in the educational fixture.", gitState: "staged", gitDetail: "Staged in the educational fixture", missingIgnore: false, remediation: "Replace the inline password with an environment variable reference.", path: ["File created", "Signal detected", "Git staged", "Review before sharing"] },
    { id: "finding_demo_3", file: "demo-workspace/.env.example", type: "API key", severity: "medium", confidence: 0.96, evidence: "[redacted demo value]", rationale: "Template value safely marked for runtime replacement.", gitState: "working tree", gitDetail: "Local-only demo file", missingIgnore: false, remediation: "Keep templates free of real credentials.", path: ["File created", "Signal detected", "Local review", "Review before sharing"] },
  ];
  return { monitoring: true, simulationRunning: false, workspace: "demo-workspace/", lastScan: now, riskScore: 72, riskLevel: "HIGH", findings, events: [{ id: "evt_demo", time: now, activity: "Scan complete", file: "demo-workspace/", severity: "high", message: "Synthetic signals mapped across the safe fixture workspace.", category: "monitor" }], factors: [{ label: "Sensitive patterns", value: 3, detail: "3 redacted signals found" }, { label: "Git exposure paths", value: 2, detail: "2 findings have a Git state" }, { label: "Ignore protection gaps", value: 1, detail: "1 file needs ignore protection" }], gitRisks: 2, sensitiveFiles: 3, affectedFiles: 3, openAlerts: 2, eventCount: 1, scanCount: 1 };
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(value));
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}

function riskClass(level: string) {
  return level.toLowerCase();
}

function Icon({ name }: { name: string }) {
  const paths: Record<string, string> = {
    grid: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
    radar: "M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l6-5",
    pulse: "M3 12h4l2-7 4 14 2-7h6",
    lock: "M6 10V8a6 6 0 0 1 12 0v2M5 10h14v10H5zM12 14v2",
    file: "M6 3h8l4 4v14H6zM14 3v5h5M9 13h6M9 17h6",
    download: "M12 3v12m0 0 4-4m-4 4-4-4M5 20h14",
    play: "m9 6 9 6-9 6z",
    refresh: "M20 11a8 8 0 1 0 1 4M20 5v6h-6",
    arrow: "M4 12h15m-6-6 6 6-6 6",
    shield: "M12 3 20 6v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-5",
    chevron: "m9 6 6 6-6 6"
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d={paths[name] || paths.grid} /></svg>;
}

function App() {
  const [authStatus, setAuthStatus] = useState<"checking" | "guest" | "authenticated">("checking");
  const [user, setUser] = useState<AuthUser | null>(null);
  const [authError, setAuthError] = useState("");
  const [state, setState] = useState<State>(staticDemo ? demoState() : emptyState);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [busy, setBusy] = useState<"scan" | "simulate" | "reset" | null>(null);
  const [toast, setToast] = useState("Monitor online · safe boundary locked");
  const [activeView, setActiveView] = useState("Overview");

  const loadState = async () => {
    if (staticDemo) return;
    const response = await fetch("/api/state");
    if (response.status === 401) {
      setUser(null);
      setAuthStatus("guest");
      return;
    }
    if (response.ok) setState(await response.json());
  };

  useEffect(() => {
    if (staticDemo) {
      setUser({ openId: "static-demo", name: "LeakPath Demo Operator", email: "public-demo@leakpath.local" });
      setAuthStatus("authenticated");
      return;
    }
    const params = new URLSearchParams(window.location.search);
    if (params.get("auth") === "error") setAuthError("The secure sign-in could not be completed. Please try again.");
    fetch("/api/auth/me")
      .then(async (response) => {
        if (!response.ok) {
          setAuthStatus("guest");
          return;
        }
        const payload = await response.json();
        setUser(payload.user);
        setAuthStatus("authenticated");
      })
      .catch(() => {
        setAuthError("The authentication service is waking up. Please try again.");
        setAuthStatus("guest");
      });
  }, []);

  useEffect(() => {
    if (authStatus !== "authenticated") return;
    loadState().catch(() => setToast("Preview is waking up — retrying connection"));
    const source = new EventSource("/api/events");
    source.onmessage = (event) => setState(JSON.parse(event.data));
    source.onerror = () => source.close();
    const interval = window.setInterval(() => loadState().catch(() => {}), 6000);
    return () => { source.close(); window.clearInterval(interval); };
  }, [authStatus]);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(""), 4200);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const topFindings = useMemo(() => [...state.findings].sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity]).slice(0, 4), [state.findings]);
  const scoreDash = 2 * Math.PI * 49;
  const scoreOffset = scoreDash - (state.riskScore / 100) * scoreDash;
  const chartBars = useMemo(() => {
    const seed = [22, 30, 18, 38, 34, 58, 45, 72, 63, 86, 78, Math.max(40, state.riskScore)];
    return seed;
  }, [state.riskScore]);

  const action = async (kind: "scan" | "simulate" | "reset") => {
    setBusy(kind);
    setToast(kind === "simulate" ? "Safe simulation armed · synthetic files only" : kind === "reset" ? "Restoring app-owned fixture…" : "Scanning redacted signals…");
    try {
      if (staticDemo) {
        setState((previous) => ({ ...previous, lastScan: new Date().toISOString(), scanCount: previous.scanCount + (kind === "scan" ? 1 : 0), eventCount: previous.eventCount + 1, events: [{ id: `evt_static_${Date.now()}`, time: new Date().toISOString(), activity: kind === "simulate" ? "Safe simulation" : kind === "reset" ? "Demo reset" : "Scan complete", file: "demo-workspace/", severity: kind === "reset" ? "low" : "medium", message: kind === "simulate" ? "Synthetic files created inside the locked demo boundary." : kind === "reset" ? "The app-owned fixture workspace was restored." : "Synthetic signals mapped across the safe fixture workspace.", category: "monitor" }, ...previous.events].slice(0, 20) }));
        return;
      }
      const response = await fetch(`/api/${kind === "simulate" ? "simulate" : kind}`, { method: "POST" });
      if (response.status === 401) {
        setUser(null);
        setAuthStatus("guest");
        return;
      }
      if (!response.ok) throw new Error("Action failed");
      const next = await response.json();
      setState(next);
      setToast(kind === "simulate" ? "Simulation complete · nothing encrypted or deleted" : kind === "reset" ? "Demo reset · boundary still locked" : "Scan complete · path mapped");
    } catch {
      setToast("Action could not complete — try again");
    } finally {
      setBusy(null);
    }
  };

  const downloadReport = async () => {
    if (staticDemo) {
      const blob = new Blob([JSON.stringify({ generatedAt: new Date().toISOString(), workspace: state.workspace, riskScore: state.riskScore, findings: state.findings }, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `leakpath-report-${new Date().toISOString().slice(0, 10)}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      setToast("Report downloaded · evidence remains redacted");
      return;
    }
    const response = await fetch("/api/report");
    if (response.status === 401) {
      setUser(null);
      setAuthStatus("guest");
      return;
    }
    if (!response.ok) {
      setToast("Report could not be generated — try again");
      return;
    }
    const report = await response.json();
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `leakpath-report-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    setToast("Report downloaded · evidence remains redacted");
  };

  const navigateTo = (label: string, target: string) => {
    setActiveView(label);
    window.requestAnimationFrame(() => document.getElementById(target)?.scrollIntoView({ behavior: "smooth", block: "start" }));
  };

  const startLogin = () => { window.location.assign("/api/auth/login"); };
  const logout = async () => {
    if (staticDemo) {
      setToast("Public demo mode stays available for review");
      return;
    }
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.assign("/");
  };

  if (authStatus === "checking") {
    return <main className="auth-loading"><div className="loading-mark"><span></span><span></span><span></span><span></span></div><span>VERIFYING OBSERVATORY ACCESS</span></main>;
  }

  if (authStatus === "guest") {
    return <LoginPage error={authError} onLogin={startLogin} />;
  }

  return (
    <div className="app-shell">
      <aside className="side-rail">
        <div className="brand-lockup">
          <div className="brand-mark"><span></span><span></span><span></span><span></span></div>
          <div><div className="brand-name">LeakPath</div><div className="brand-kicker">SECURITY OBSERVATORY</div></div>
        </div>
        <div className="rail-label">Workspace</div>
        <div className="workspace-pill"><span className="status-dot"></span><span>demo-workspace/</span><span className="tiny-caret">⌄</span></div>
        <nav className="nav-list" aria-label="Primary navigation">
          {[{ label: "Overview", icon: "grid", target: "overview" }, { label: "Exposure map", icon: "radar", target: "exposure" }, { label: "Live events", icon: "pulse", target: "events" }, { label: "Safe controls", icon: "lock", target: "controls" }].map((item) => (
            <button className={`nav-item ${activeView === item.label ? "active" : ""}`} key={item.label} onClick={() => navigateTo(item.label, item.target)}><Icon name={item.icon} /><span>{item.label}</span>{item.label === "Live events" && <span className="nav-count">{state.eventCount}</span>}</button>
          ))}
        </nav>
        <div className="rail-footer">
          <div className="boundary-card"><Icon name="shield" /><div><strong>Boundary locked</strong><span>simulation only</span></div></div>
          <div className="rail-meta"><span>v1.0.0 / local preview</span><span>© 2026 LeakPath</span></div>
        </div>
      </aside>

      <main className="main-canvas">
        <header className="topbar">
          <div className="breadcrumb"><span>OBSERVATORY</span><Icon name="chevron" /><strong>{activeView.toUpperCase()}</strong></div>
          <div className="topbar-actions"><div className="monitoring-chip"><span className="pulse-ring"></span> MONITORING <b>ON</b></div><span className="topbar-date">{formatDate(state.lastScan)}</span><div className="operator-chip"><span>{(user?.name || "O").slice(0, 1).toUpperCase()}</span><div><strong>{user?.name || "Operator"}</strong><small>{user?.email || "Manus account"}</small></div></div><button className="icon-button" aria-label="Download report" onClick={downloadReport}><Icon name="download" /></button><button className="logout-button" onClick={logout}>LOG OUT</button></div>
        </header>

        <div className="content-wrap">
          <section className="hero-row">
            <div>
              <div className="eyebrow"><span className="eyebrow-line"></span> LIVE WORKSPACE TELEMETRY</div>
              <h1>Find the leak<br /><em>before it travels.</em></h1>
              <p className="hero-copy">LeakPath maps sensitive-data signals from file creation to Git exposure — with a safe simulator built for learning, not damage.</p>
            </div>
            <div className="hero-actions"><button className="button primary" onClick={() => action("scan")} disabled={busy !== null}><span className="button-signal"></span>{busy === "scan" ? "Scanning…" : "Scan workspace"}</button><button className="button ghost" onClick={() => action("simulate")} disabled={busy !== null}><Icon name="play" />{busy === "simulate" ? "Simulating…" : "Run safe simulation"}</button></div>
          </section>

          <section className="score-band" id="overview">
            <div className="score-card">
              <div className="card-label"><span className="live-marker"></span> AGGREGATE RISK <span className="info-dot">i</span></div>
              <div className="score-body">
                <div className="score-orbit">
                  <svg viewBox="0 0 120 120" aria-label={`Risk score ${state.riskScore} out of 100`}><circle className="orbit-track" cx="60" cy="60" r="49" /><circle className={`orbit-progress ${riskClass(state.riskLevel)}`} cx="60" cy="60" r="49" strokeDasharray={scoreDash} strokeDashoffset={scoreOffset} /><circle className="orbit-core" cx="60" cy="60" r="37" /></svg>
                  <div className="score-value"><strong>{state.riskScore}</strong><span>/100</span></div>
                </div>
                <div className="score-copy"><div className={`risk-tag ${riskClass(state.riskLevel)}`}>{state.riskLevel} SIGNAL</div><h2>{state.riskLevel === "CRITICAL" ? "Exposure needs attention" : "Signals are mapped"}</h2><p>{state.findings.length ? `${state.findings.length} sensitive pattern${state.findings.length === 1 ? "" : "s"} detected across ${state.affectedFiles} file${state.affectedFiles === 1 ? "" : "s"}.` : "Run a scan to map your workspace signals."}</p><div className="score-meta"><span>LAST SCAN <b>{formatTime(state.lastScan)}</b></span><span>CONFIDENCE <b>96%</b></span></div></div>
              </div>
            </div>
            <div className="factor-card">
              <div className="card-heading"><div><div className="card-label">WHY THIS SCORE</div><h3>Contributing signals</h3></div><span className="factor-total">{state.factors.length} <small>factors</small></span></div>
              <div className="factor-list">{state.factors.map((factor, index) => <div className="factor-row" key={factor.label}><span className={`factor-index f-${index + 1}`}>0{index + 1}</span><div className="factor-main"><div><strong>{factor.label}</strong><span>{factor.detail}</span></div><span className="factor-value">{factor.value}</span></div><div className="factor-bar"><span style={{ width: `${Math.min(100, factor.value * 10 + 8)}%` }}></span></div></div>)}</div>
            </div>
          </section>

          <section className="path-section" id="exposure">
            <div className="section-heading"><div><div className="eyebrow"><span className="eyebrow-line"></span> EXPOSURE PATH</div><h2>How a signal can travel</h2></div><button className="text-button" onClick={() => setActiveView("Exposure map")}>View full map <Icon name="arrow" /></button></div>
            <div className="path-ribbon"><div className="path-start"><span className="path-icon"><Icon name="file" /></span><div><small>01 / ORIGIN</small><strong>File created</strong><span>inside the locked workspace</span></div></div><div className="path-connector"><span></span><i></i><i></i><i></i></div><div className="path-node active"><span className="path-icon"><Icon name="radar" /></span><div><small>02 / SIGNAL</small><strong>Pattern detected</strong><span>evidence safely redacted</span></div></div><div className="path-connector"><span></span><i></i><i></i><i></i></div><div className="path-node warning"><span className="path-icon"><Icon name="grid" /></span><div><small>03 / STATE</small><strong>Git exposure</strong><span>{state.gitRisks} path{state.gitRisks === 1 ? "" : "s"} to review</span></div></div><div className="path-connector"><span></span><i></i><i></i><i></i></div><div className="path-end"><span className="path-icon"><Icon name="shield" /></span><div><small>04 / OUTCOME</small><strong>Review before share</strong><span>no automatic fixes applied</span></div></div></div>
          </section>

          <section className="lower-grid">
            <div className="findings-panel panel">
              <div className="panel-header"><div><div className="card-label">SENSITIVE FILES <span className="count-badge">{state.sensitiveFiles}</span></div><h3>Signals worth reviewing</h3></div><button className="text-button" onClick={() => action("scan")}>Rescan <Icon name="refresh" /></button></div>
              <div className="finding-list">{topFindings.length ? topFindings.map((finding) => <button className="finding-row" key={finding.id} onClick={() => setSelectedFinding(finding)}><span className={`severity-mark ${finding.severity}`}></span><span className="finding-file">{finding.file}<small>{finding.type} · {Math.round(finding.confidence * 100)}% confidence</small></span><span className={`severity-text ${finding.severity}`}>{finding.severity}</span><Icon name="chevron" /></button>) : <div className="empty-state">No signals yet. Run the scanner to inspect the synthetic workspace.</div>}</div>
            </div>
            <div className="events-panel panel" id="events">
              <div className="panel-header"><div><div className="card-label"><span className="live-marker"></span> STREAMING NOW</div><h3>Activity pulse</h3></div><span className="event-count">{state.events.length} recent</span></div>
              <div className="event-list">{state.events.slice(0, 5).map((event) => <div className="event-row" key={event.id}><div className={`event-dot ${event.severity}`}></div><div className="event-detail"><div><strong>{event.activity}</strong><span>{formatTime(event.time)}</span></div><p>{event.message}</p><code>{event.file}</code></div></div>)}</div>
              <div className="panel-foot"><span className="stream-line"></span> SSE live stream <span className="foot-muted">· polling fallback active</span></div>
            </div>
          </section>

          <section className="bottom-grid">
            <div className="chart-panel panel"><div className="panel-header"><div><div className="card-label">SIGNAL VOLUME</div><h3>Activity over the last scan window</h3></div><span className="chart-legend"><i></i> events</span></div><div className="chart-area"><div className="y-axis"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div><div className="bars">{chartBars.map((height, index) => <div className="bar-wrap" key={index}><div className={`bar ${index > 8 ? "hot" : ""}`} style={{ height: `${height}%` }}><span>{height}</span></div><small>{index === 11 ? "now" : `-${11 - index}m`}</small></div>)}</div></div></div>
            <div className="control-panel panel" id="controls"><div className="panel-header"><div><div className="card-label">SAFE CONTROLS</div><h3>Operate with intent</h3></div><Icon name="lock" /></div><div className="control-list"><button onClick={() => action("reset")} disabled={busy !== null}><span><Icon name="refresh" /><b>Reset demo</b></span><small>restore fake fixtures</small></button><button onClick={downloadReport}><span><Icon name="download" /><b>Export report</b></span><small>redacted JSON snapshot</small></button></div><div className="safe-note"><Icon name="shield" /><p><strong>Simulation boundary</strong><br />LeakPath never encrypts, deletes, or reaches outside the app-owned workspace.</p></div></div>
          </section>
        </div>
        <footer className="main-footer"><span>LEAKPATH / DEFENSIVE DEVSECOPS</span><span>SAFE SIMULATION ONLY <b>•</b> SYNTHETIC CREDENTIALS</span></footer>
      </main>

      {toast && <div className="toast"><span className="toast-pulse"></span>{toast}</div>}
      {selectedFinding && <div className="modal-backdrop" onClick={() => setSelectedFinding(null)}><div className="finding-modal" onClick={(event) => event.stopPropagation()}><button className="modal-close" onClick={() => setSelectedFinding(null)}>×</button><div className="eyebrow"><span className="eyebrow-line"></span> FINDING DETAIL</div><div className="modal-top"><div><h2>{selectedFinding.file}</h2><p>{selectedFinding.type} · {selectedFinding.gitState}</p></div><span className={`severity-text ${selectedFinding.severity}`}>{selectedFinding.severity}</span></div><div className="evidence-box"><span>REDACTED EVIDENCE</span><code>{selectedFinding.evidence}</code></div><p className="modal-rationale">{selectedFinding.rationale}</p><div className="modal-path">{selectedFinding.path.map((step, index) => <div key={step}><span>{String(index + 1).padStart(2, "0")}</span>{step}{index < selectedFinding.path.length - 1 && <Icon name="arrow" />}</div>)}</div><div className="remediation"><Icon name="shield" /><div><strong>Safe remediation</strong><p>{selectedFinding.remediation}</p></div></div></div></div>}
    </div>
  );
}

export default App;
