import jwt from "jsonwebtoken";

const base = process.env.LEAKPATH_URL || "http://127.0.0.1:3000";
const hasManagedAuth = Boolean(process.env.MANUS_JWT_SECRET && process.env.MANUS_PROJECT_ID);
const sessionCookie = hasManagedAuth
  ? `webdev_app_session=${jwt.sign({ appId: process.env.MANUS_PROJECT_ID, openId: "smoke-user", name: "Smoke Operator", email: "smoke@example.test" }, process.env.MANUS_JWT_SECRET, { algorithm: "HS256", expiresIn: "10m" })}`
  : "";

async function request(path, options = {}, authenticated = true) {
  const headers = new Headers(options.headers || {});
  if (authenticated && sessionCookie) headers.set("cookie", sessionCookie);
  const response = await fetch(`${base}${path}`, { ...options, headers });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

const health = await request("/api/health", {}, false);
if (!health.ok) throw new Error("health contract failed");

const unauthenticated = await fetch(`${base}/api/auth/me`);
if (unauthenticated.status !== 401) throw new Error("unauthenticated state contract failed");

for (const [path, method] of [["/api/state", "GET"], ["/api/events", "GET"], ["/api/report", "GET"], ["/api/scan", "POST"], ["/api/simulate", "POST"], ["/api/reset", "POST"]]) {
  const response = await fetch(`${base}${path}`, { method });
  if (response.status !== 401) throw new Error(`protected route contract failed for ${path}`);
}

if (!hasManagedAuth) {
  console.log("LeakPath public contracts passed; managed auth variables are unavailable, so authenticated smoke steps were skipped.");
  process.exit(0);
}

const loginRedirect = await fetch(`${base}/api/auth/login`, { redirect: "manual" });
if (loginRedirect.status !== 302 || !loginRedirect.headers.get("location")?.includes("/app-auth")) throw new Error("OAuth redirect contract failed");

const me = await request("/api/auth/me");
if (!me.authenticated || me.user?.openId !== "smoke-user") throw new Error("authenticated identity contract failed");

const initial = await request("/api/state");
if (initial.workspace !== "demo-workspace/") throw new Error("workspace boundary contract failed");

const sse = await fetch(`${base}/api/events`, { headers: { cookie: sessionCookie } });
if (sse.headers.get("content-type")?.split(";")[0] !== "text/event-stream") throw new Error("SSE content-type contract failed");
const reader = sse.body.getReader();
const firstChunk = await reader.read();
await reader.cancel();
if (!new TextDecoder().decode(firstChunk.value).includes('"workspace":"demo-workspace/"')) throw new Error("SSE initial state contract failed");

const simulated = await request("/api/simulate", { method: "POST" });
if (simulated.riskLevel !== "CRITICAL" || simulated.sensitiveFiles < 6) throw new Error("simulation contract failed");
const types = new Set(simulated.findings.map((finding) => finding.type));
for (const required of ["API key", "Password", "Personal data"]) {
  if (!types.has(required)) throw new Error(`multi-signal scan missed ${required}`);
}
if (simulated.findings.some((finding) => finding.file.endsWith(".env.example"))) throw new Error("template exclusion contract failed");

const report = await request("/api/report");
const rawDemoSecrets = ["demo_leakpath_key_9f7b2d", "demo_public_token_abc123", "demo_simulation_token_77ab", "demo-staged-password", "demo_review_key_8a12"];
if (!Array.isArray(report.findings) || report.findings.some((finding) => rawDemoSecrets.some((secret) => String(finding.evidence).includes(secret)))) {
  throw new Error("redacted report contract failed");
}

await request("/api/reset", { method: "POST" });
const logout = await fetch(`${base}/api/auth/logout`, { method: "POST", redirect: "manual", headers: { cookie: sessionCookie } });
if (logout.status !== 302 || !logout.headers.get("set-cookie")?.includes("webdev_app_session=")) throw new Error("logout contract failed");
console.log("LeakPath authenticated smoke flow passed");
