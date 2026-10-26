const base = process.env.LEAKPATH_URL || "http://127.0.0.1:3000";

async function request(path, options) {
  const response = await fetch(`${base}${path}`, options);
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

const health = await request("/api/health");
if (!health.ok) throw new Error("health contract failed");

const initial = await request("/api/state");
if (initial.workspace !== "demo-workspace/") throw new Error("workspace boundary contract failed");

const sse = await fetch(`${base}/api/events`);
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
console.log("LeakPath smoke flow passed");
