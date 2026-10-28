import express from "express";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const workspaceRoot = path.resolve(projectRoot, "demo-workspace");
const port = Number(process.env.PORT || 3000);
const sessionCookieName = "webdev_app_session";
const oauthStateCookieName = "leakpath_oauth_state";
const sessionLifetimeSeconds = 8 * 60 * 60;
const app = express();
const clients = new Set();
const oauthNonces = new Map();
let pool = null;
let simulationRunning = false;
let watcher = null;

const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
const patterns = [
  {
    type: "API key",
    regex: /(?:API_KEY|API_TOKEN|ACCESS_KEY)\s*[:=]\s*["']?([A-Za-z0-9_-]{8,})/i,
    remediation: "Move the key to a runtime secret store and keep the file ignored."
  },
  {
    type: "Password",
    regex: /(?:PASSWORD|DB_PASSWORD|PASSWD)\s*[:=]\s*["']?([^\s"']{6,})/i,
    remediation: "Replace the inline password with an environment variable reference."
  },
  {
    type: "Database URL",
    regex: /(?:mysql|postgres(?:ql)?:\/\/)[^\s"']+/i,
    remediation: "Use a managed connection secret and redact the URL from logs and commits."
  },
  {
    type: "Private key marker",
    regex: /-----BEGIN [A-Z ]+ PRIVATE KEY-----/i,
    remediation: "Remove the private key from the workspace and rotate it if it was real."
  },
  {
    type: "Personal data",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
    remediation: "Minimize personal data in fixtures and redact it before sharing logs."
  }
];

const safeFixtures = {
  "config/dev.env": "API_KEY=demo_leakpath_key_9f7b2d\nDB_PASSWORD=demo-only-password\n",
  "src/api.ts": "API_TOKEN=demo_public_token_abc123\n// educational fixture: this file is marked as staged\n",
  "docs/README.md": "# Demo project\nThis file contains no credentials.\n",
  ".env.example": "API_KEY=replace-me-at-runtime\nDB_PASSWORD=replace-me-at-runtime\n",
  ".gitignore": "node_modules/\n# TODO: add environment files before a real commit\n"
};

const baseState = () => ({
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
});
let state = baseState();

function insideWorkspace(relativePath) {
  const resolved = path.resolve(workspaceRoot, relativePath);
  return resolved === workspaceRoot || resolved.startsWith(`${workspaceRoot}${path.sep}`);
}

function absoluteWorkspacePath(relativePath) {
  if (!insideWorkspace(relativePath)) {
    throw new Error("Workspace boundary rejected the requested path.");
  }
  return path.resolve(workspaceRoot, relativePath);
}

function redactedEvidence(value) {
  const compact = String(value).replace(/\s+/g, " ").trim();
  if (compact.length <= 12) return "[redacted demo value]";
  return `${compact.slice(0, 5)}••••${compact.slice(-3)}`;
}

function normalizeSeverity(value) {
  return value in severityRank ? value : "low";
}

function severityFor(type, gitState, missingIgnore) {
  if (type === "Private key marker") return "critical";
  if (missingIgnore || gitState === "committed") return "high";
  if (type === "Password" || type === "Database URL") return "high";
  return "medium";
}

function gitProfile(relativePath) {
  if (relativePath === "config/dev.env") {
    return { state: "untracked", detail: "Not ignored — likely to be added by accident", missingIgnore: true };
  }
  if (relativePath === "src/api.ts") {
    return { state: "staged", detail: "Staged in the educational fixture", missingIgnore: false };
  }
  if (relativePath.includes("exports/") || relativePath.includes("staging/")) {
    return { state: "committed", detail: "Appears in a simulated handoff or commit preview", missingIgnore: true };
  }
  return { state: "working tree", detail: "Local-only demo file", missingIgnore: false };
}

function addEvent({ activity, file, severity = "low", message, category = "monitor" }) {
  const event = {
    id: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    time: new Date().toISOString(),
    activity,
    file: file || "workspace",
    severity: normalizeSeverity(severity),
    message,
    category
  };
  state.events = [event, ...state.events].slice(0, 80);
  state.eventCount += 1;
  broadcast();
  persistEvent(event).catch(() => {});
}

function broadcast() {
  const payload = `data: ${JSON.stringify(state)}\n\n`;
  for (const response of clients) response.write(payload);
}

async function persistEvent(event) {
  if (!pool) return;
  await pool.execute(
    "INSERT INTO leakpath_events (event_id, activity, file_path, severity, message, category, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [event.id, event.activity, event.file, event.severity, event.message, event.category, new Date(event.time)]
  );
}

async function initializePersistence() {
  if (!process.env.DATABASE_URL) return;
  try {
    pool = mysql.createPool(process.env.DATABASE_URL);
    await pool.query(`CREATE TABLE IF NOT EXISTS leakpath_events (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      event_id VARCHAR(100) NOT NULL,
      activity VARCHAR(80) NOT NULL,
      file_path VARCHAR(255) NOT NULL,
      severity VARCHAR(20) NOT NULL,
      message VARCHAR(500) NOT NULL,
      category VARCHAR(60) NOT NULL,
      created_at DATETIME NOT NULL
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS leakpath_users (
      open_id VARCHAR(191) PRIMARY KEY,
      email VARCHAR(255) NULL,
      display_name VARCHAR(255) NULL,
      last_seen DATETIME NOT NULL
    )`);
    console.log("LeakPath event store connected.");
  } catch (error) {
    pool = null;
    console.log("LeakPath is using the in-memory event store for this preview.");
  }
}

function parseCookies(header = "") {
  const cookies = {};
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    try {
      cookies[name] = decodeURIComponent(value);
    } catch {
      continue;
    }
  }
  return cookies;
}

function serializeCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=None; Secure`;
}

function requestOrigin(req) {
  const configuredOrigin = process.env.PUBLIC_ORIGIN || process.env.MANUS_ADDON_PREVIEW_PUBLIC_ORIGIN || process.env.MANUS_ADDON_RUNTIME_PUBLIC_ORIGIN;
  if (configuredOrigin) return configuredOrigin.replace(/\/$/, "");
  const forwardedHost = String(req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
  const forwardedProto = String(req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  if (!forwardedHost) throw new Error("Cannot determine the browser callback origin.");
  const trustedHost = forwardedHost.endsWith(".manus.computer") || forwardedHost === "localhost" || forwardedHost.startsWith("127.0.0.1:");
  if (!trustedHost) throw new Error("Untrusted browser callback origin.");
  return `${forwardedProto}://${forwardedHost}`;
}

function callbackUri(req) {
  return `${requestOrigin(req)}/manus-oauth/callback`;
}

function encodeState(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decodeState(value) {
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
}

function randomNonce() {
  return randomBytes(32).toString("base64url");
}

function normalizeUser(identity) {
  const openId = identity?.openId || identity?.open_id || identity?.sub;
  if (!openId) throw new Error("Manus identity did not include an openId.");
  return {
    openId: String(openId),
    name: String(identity.name || identity.displayName || identity.email || "LeakPath operator"),
    email: identity.email ? String(identity.email) : ""
  };
}

function userFromClaims(claims) {
  const appId = claims.appId || claims.app_id;
  if (!process.env.MANUS_PROJECT_ID || appId !== process.env.MANUS_PROJECT_ID) return null;
  try {
    return normalizeUser({ openId: claims.openId || claims.open_id || claims.sub, name: claims.name, email: claims.email });
  } catch {
    return null;
  }
}

function authenticateRequest(req) {
  const secret = process.env.MANUS_JWT_SECRET;
  if (!secret || !process.env.MANUS_PROJECT_ID) return null;
  const token = parseCookies(req.headers.cookie)[sessionCookieName];
  if (!token) return null;
  try {
    const claims = jwt.verify(token, secret, { algorithms: ["HS256"] });
    return userFromClaims(claims);
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const user = authenticateRequest(req);
  if (!user) return res.status(401).json({ authenticated: false, error: "AUTH_REQUIRED" });
  req.user = user;
  recordUser(user).catch(() => {});
  next();
}

async function recordUser(user) {
  if (!pool) return;
  await pool.execute(
    "INSERT INTO leakpath_users (open_id, email, display_name, last_seen) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE email = VALUES(email), display_name = VALUES(display_name), last_seen = NOW()",
    [user.openId, user.email, user.name]
  );
}

async function exchangeOAuthCode(code, redirectUri) {
  const response = await fetch(`${process.env.MANUS_OAUTH_API_URL}/webdev.v1.WebDevAuthPublicService/ExchangeToken`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ clientId: process.env.MANUS_PROJECT_ID, grantType: "authorization_code", code, redirectUri })
  });
  if (!response.ok) throw new Error("Manus OAuth code exchange failed.");
  return response.json();
}

async function fetchManusIdentity(accessToken) {
  const response = await fetch(`${process.env.MANUS_OAUTH_API_URL}/webdev.v1.WebDevAuthPublicService/GetUserInfo`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ accessToken })
  });
  if (!response.ok) throw new Error("Manus identity lookup failed.");
  return response.json();
}

function issueSession(user) {
  return jwt.sign(
    { appId: process.env.MANUS_PROJECT_ID, openId: user.openId, name: user.name, email: user.email },
    process.env.MANUS_JWT_SECRET,
    { algorithm: "HS256", expiresIn: sessionLifetimeSeconds }
  );
}

async function seedWorkspace() {
  await fsp.mkdir(workspaceRoot, { recursive: true });
  for (const [relativePath, content] of Object.entries(safeFixtures)) {
    const target = absoluteWorkspacePath(relativePath);
    await fsp.mkdir(path.dirname(target), { recursive: true });
    try {
      if ((await fsp.lstat(target)).isSymbolicLink()) await fsp.unlink(target);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await fsp.writeFile(target, content, "utf8");
  }
}

async function listFiles(directory, prefix = "") {
  const entries = await fsp.readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.name === ".git") continue;
    const relative = path.join(prefix, entry.name).replaceAll(path.sep, "/");
    const absolute = path.join(directory, entry.name);
    const stats = await fsp.lstat(absolute);
    if (stats.isSymbolicLink()) continue;
    if (stats.isDirectory()) files.push(...await listFiles(absolute, relative));
    else if (stats.isFile()) files.push({ relative, absolute });
  }
  return files;
}

async function scanWorkspace({ announce = true } = {}) {
  const findings = [];
  let files = [];
  try {
    files = await listFiles(workspaceRoot);
  } catch {
    await seedWorkspace();
    files = await listFiles(workspaceRoot);
  }

  for (const file of files) {
    const content = await fsp.readFile(file.absolute, "utf8");
    const isTemplateFile = path.basename(file.relative) === ".env.example";
    for (const pattern of patterns) {
      const match = content.match(pattern.regex);
      if (!match) continue;
      if (isTemplateFile || /replace-me-at-runtime/i.test(match[0])) continue;
      const git = gitProfile(file.relative);
      const severity = severityFor(pattern.type, git.state, git.missingIgnore);
      findings.push({
        id: `finding_${findings.length + 1}_${file.relative.replaceAll("/", "-")}`,
        file: file.relative,
        type: pattern.type,
        severity,
        confidence: pattern.type === "Personal data" ? 0.82 : 0.96,
        evidence: redactedEvidence(match[1] || match[0]),
        rationale: `${pattern.type} pattern found; ${git.detail.toLowerCase()}.`,
        gitState: git.state,
        gitDetail: git.detail,
        missingIgnore: git.missingIgnore,
        remediation: pattern.remediation,
        path: ["File created", "Signal detected", git.state === "working tree" ? "Local review" : `Git ${git.state}`, git.state === "committed" ? "Public exposure risk" : "Review before sharing"]
      });
    }
  }

  const uniqueGitRisks = findings.filter((finding) => finding.gitState !== "working tree").length;
  const missingIgnoreCount = findings.filter((finding) => finding.missingIgnore).length;
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const highCount = findings.filter((finding) => finding.severity === "high").length;
  const activityPressure = Math.min(20, Math.round(state.events.slice(0, 10).length * 1.5));
  const score = Math.min(100, 18 + findings.length * 8 + uniqueGitRisks * 10 + missingIgnoreCount * 9 + criticalCount * 8 + highCount * 4 + activityPressure);
  const riskLevel = score >= 75 ? "CRITICAL" : score >= 55 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW";

  state = {
    ...state,
    lastScan: new Date().toISOString(),
    findings,
    riskScore: score,
    riskLevel,
    gitRisks: uniqueGitRisks,
    sensitiveFiles: findings.length,
    affectedFiles: new Set(findings.map((finding) => finding.file)).size,
    openAlerts: findings.filter((finding) => severityRank[finding.severity] >= 3).length,
    factors: [
      { label: "Sensitive patterns", value: findings.length, detail: `${findings.length} redacted signal${findings.length === 1 ? "" : "s"} found` },
      { label: "Git exposure paths", value: uniqueGitRisks, detail: `${uniqueGitRisks} finding${uniqueGitRisks === 1 ? "" : "s"} have a Git state` },
      { label: "Ignore protection gaps", value: missingIgnoreCount, detail: missingIgnoreCount ? "Sensitive files need ignore rules" : "Ignore coverage is healthy" },
      { label: "Recent activity pressure", value: activityPressure, detail: "Weighted from the live event stream" }
    ],
    scanCount: state.scanCount + 1
  };
  if (announce) addEvent({ activity: "Workspace scan", file: "demo-workspace/", severity: riskLevel.toLowerCase(), message: `${findings.length} signal${findings.length === 1 ? "" : "s"} mapped with redacted evidence.`, category: "scan" });
  broadcast();
  return state;
}

function resetState() {
  state = baseState();
  state.events = [
    {
      id: "evt_boot",
      time: new Date().toISOString(),
      activity: "Monitor online",
      file: "demo-workspace/",
      severity: "low",
      message: "Safe boundary locked. Watching the app-owned fixture.",
      category: "system"
    }
  ];
  state.eventCount = 1;
}

async function resetWorkspace() {
  await fsp.rm(workspaceRoot, { recursive: true, force: true });
  await seedWorkspace();
  resetState();
  await scanWorkspace({ announce: false });
  addEvent({ activity: "Demo reset", file: "demo-workspace/", severity: "low", message: "Fixture restored. No files outside the workspace were touched.", category: "system" });
  return state;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function runSafeSimulation() {
  if (simulationRunning) return state;
  simulationRunning = true;
  state.simulationRunning = true;
  broadcast();
  const steps = [
    {
      wait: 250,
      relative: "exports/debug.log",
      content: "debug_session=demo\nAPI_TOKEN=demo_simulation_token_77ab\n",
      activity: "New file",
      severity: "high",
      message: "A fake token entered an export log."
    },
    {
      wait: 380,
      relative: "staging/commit-preview.json",
      content: "{\"DB_PASSWORD\":\"demo-staged-password\",\"source\":\"safe-simulator\"}\n",
      activity: "Commit preview",
      severity: "critical",
      message: "A fake password appeared in a simulated staging handoff."
    },
    {
      wait: 460,
      relative: "config/production.env.review",
      content: "API_KEY=demo_review_key_8a12\nOWNER_EMAIL=demo@example.test\n",
      activity: "Review copy",
      severity: "high",
      message: "A review copy carries synthetic credentials into a tracked-looking path."
    }
  ];

  try {
    for (const step of steps) {
      await sleep(step.wait);
      const target = absoluteWorkspacePath(step.relative);
      await fsp.mkdir(path.dirname(target), { recursive: true });
      await fsp.writeFile(target, step.content, "utf8");
      addEvent({ activity: step.activity, file: step.relative, severity: step.severity, message: step.message, category: "simulation" });
    }
    await scanWorkspace({ announce: true });
    addEvent({ activity: "Simulation complete", file: "safe-simulator", severity: "low", message: "Signals mapped. Nothing was encrypted or deleted.", category: "simulation" });
  } finally {
    simulationRunning = false;
    state.simulationRunning = false;
    broadcast();
  }
  return state;
}

async function startWorkspaceWatcher() {
  const { watch } = await import("chokidar");
  watcher = watch(workspaceRoot, { ignoreInitial: true, followSymlinks: false, awaitWriteFinish: { stabilityThreshold: 120, pollInterval: 40 } });
  watcher.on("add", (absolute) => {
    const relative = path.relative(workspaceRoot, absolute).replaceAll(path.sep, "/");
    if (relative) addEvent({ activity: "File created", file: relative, severity: "low", message: "Workspace monitor observed a new file.", category: "filesystem" });
  });
  watcher.on("change", (absolute) => {
    const relative = path.relative(workspaceRoot, absolute).replaceAll(path.sep, "/");
    if (relative) addEvent({ activity: "File changed", file: relative, severity: "medium", message: "Workspace monitor observed a content change.", category: "filesystem" });
  });
  watcher.on("unlink", (absolute) => {
    const relative = path.relative(workspaceRoot, absolute).replaceAll(path.sep, "/");
    if (relative) addEvent({ activity: "File removed", file: relative, severity: "low", message: "A demo fixture file left the workspace.", category: "filesystem" });
  });
}

app.use(express.json({ limit: "64kb" }));

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "leakpath", monitoring: state.monitoring }));
app.get("/api/auth/me", (req, res) => {
  const user = authenticateRequest(req);
  if (!user) return res.status(401).json({ authenticated: false, error: "AUTH_REQUIRED" });
  recordUser(user).catch(() => {});
  res.json({ authenticated: true, user });
});
app.get("/api/auth/login", (req, res) => {
  if (!process.env.MANUS_PROJECT_ID || !process.env.MANUS_OAUTH_PORTAL_URL || !process.env.MANUS_JWT_SECRET) {
    return res.status(503).json({ error: "OAuth is not configured for this project." });
  }
  const nonce = randomNonce();
  const redirectUri = callbackUri(req);
  const encodedState = encodeState({ redirectUri, nonce });
  oauthNonces.set(nonce, Date.now() + 600_000);
  for (const [knownNonce, expiresAt] of oauthNonces) if (expiresAt < Date.now()) oauthNonces.delete(knownNonce);
  const authorizeUrl = new URL(`${process.env.MANUS_OAUTH_PORTAL_URL}/app-auth`);
  authorizeUrl.searchParams.set("appId", process.env.MANUS_PROJECT_ID);
  authorizeUrl.searchParams.set("redirectUri", redirectUri);
  authorizeUrl.searchParams.set("state", encodedState);
  authorizeUrl.searchParams.set("responseType", "code");
  res.setHeader("Set-Cookie", serializeCookie(oauthStateCookieName, nonce, 600));
  res.redirect(authorizeUrl.toString());
});
app.get("/manus-oauth/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    const returnedState = String(req.query.state || "");
    const storedNonce = parseCookies(req.headers.cookie)[oauthStateCookieName];
    const state = decodeState(returnedState);
    const expectedRedirectUri = callbackUri(req);
    const nonceExpiry = storedNonce ? oauthNonces.get(storedNonce) : undefined;
    if (!code || !storedNonce || !nonceExpiry || nonceExpiry < Date.now() || state.nonce !== storedNonce || state.redirectUri !== expectedRedirectUri) throw new Error("OAuth state validation failed.");
    oauthNonces.delete(storedNonce);
    const exchange = await exchangeOAuthCode(code, expectedRedirectUri);
    const user = normalizeUser(await fetchManusIdentity(exchange.accessToken));
    await recordUser(user);
    const session = issueSession(user);
    res.setHeader("Set-Cookie", [serializeCookie(oauthStateCookieName, "", 0), serializeCookie(sessionCookieName, session, sessionLifetimeSeconds)]);
    res.redirect("/");
  } catch (error) {
    console.error("LeakPath OAuth callback failed:", error.message);
    res.setHeader("Set-Cookie", serializeCookie(oauthStateCookieName, "", 0));
    res.redirect("/?auth=error");
  }
});
app.post("/api/auth/logout", (_req, res) => {
  res.setHeader("Set-Cookie", serializeCookie(sessionCookieName, "", 0));
  res.redirect("/");
});
app.get("/api/state", requireAuth, (_req, res) => res.json(state));
app.get("/api/events", requireAuth, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();
  res.write(`data: ${JSON.stringify(state)}\n\n`);
  clients.add(res);
  req.on("close", () => clients.delete(res));
});
app.post("/api/scan", requireAuth, async (_req, res) => res.json(await scanWorkspace()));
app.post("/api/simulate", requireAuth, async (_req, res) => res.json(await runSafeSimulation()));
app.post("/api/reset", requireAuth, async (_req, res) => res.json(await resetWorkspace()));
app.get("/api/report", requireAuth, (_req, res) => {
  res.json({
    product: "LeakPath",
    generatedAt: new Date().toISOString(),
    boundary: "Synthetic demo workspace only",
    score: state.riskScore,
    level: state.riskLevel,
    factors: state.factors,
    findings: state.findings.map(({ id, file, type, severity, evidence, rationale, gitState, remediation }) => ({ id, file, type, severity, evidence, rationale, gitState, remediation })),
    events: state.events.slice(0, 20)
  });
});

async function serve() {
  await initializePersistence();
  await seedWorkspace();
  resetState();
  await scanWorkspace({ announce: false });
  await startWorkspaceWatcher();

  if (process.env.NODE_ENV === "production") {
    const dist = path.resolve(projectRoot, "dist");
    app.use(express.static(dist));
    app.get(/.*/, (_req, res) => res.sendFile(path.join(dist, "index.html")));
  } else {
    const { createServer } = await import("vite");
    const vite = await createServer({ server: { middlewareMode: true, host: "0.0.0.0" }, appType: "spa" });
    app.use(vite.middlewares);
    app.use(async (req, res, next) => {
      if (req.path.startsWith("/api/")) return next();
      try {
        const template = await fsp.readFile(path.resolve(projectRoot, "index.html"), "utf8");
        const html = await vite.transformIndexHtml(req.originalUrl, template);
        res.status(200).set({ "Content-Type": "text/html" }).end(html);
      } catch (error) {
        vite.ssrFixStacktrace(error);
        next(error);
      }
    });
  }

  app.listen(port, "0.0.0.0", () => console.log(`LeakPath listening on http://0.0.0.0:${port}`));
}

serve().catch((error) => {
  console.error(error);
  process.exit(1);
});
