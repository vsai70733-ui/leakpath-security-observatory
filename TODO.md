# LeakPath Delivery Outcomes

- [x] **Safe demo workspace and simulator**
  - The application creates and manages an isolated `demo-workspace/` fixture area.
  - Simulation operates only inside that workspace, rejects arbitrary system paths, uses synthetic credentials, never encrypts files, never deletes real files, and exposes clear simulation boundaries.
  - A reset action restores the demo fixture without touching files outside the workspace.

- [x] **Live monitoring and event timeline**
  - The dashboard shows monitoring status and a live event timeline.
  - File-system activity and scans appear as visible events through server-sent updates with polling resilience.
  - Events carry time, file, activity, severity, and evidence-oriented copy.

- [x] **Sensitive-data findings**
  - Scanning identifies synthetic API keys, passwords, tokens, private-key markers, database URLs, and personal-data-like patterns.
  - Findings are grouped by affected file and show redacted evidence rather than raw secret values.
  - Each finding includes type, severity, rationale, and a safe remediation suggestion.

- [x] **Git exposure analysis**
  - Findings explain untracked, staged, and committed exposure states.
  - The analyzer identifies missing or insufficient `.gitignore` protection.
  - The UI visualizes each finding's path from file creation through Git toward potential public exposure.

- [x] **Explainable score and dashboard**
  - An aggregate score from 0–100 is visible with severity, contributing factors, and per-finding rationale.
  - The dashboard covers sensitive files, Git risks, alerts, affected files, timeline, and summary charts.
  - Primary actions include scan, safe simulation, and reset.

- [x] **Non-destructive remediation and reporting**
  - The product proposes `.gitignore` entries, `.env.example` practices, redaction guidance, and safe next steps.
  - Users can download a report without exposing arbitrary local paths or raw credentials.
  - No automatic destructive fix is applied.

- [x] **Repository-ready delivery**
  - Setup instructions, architecture notes, threat-model boundaries, package scripts, route manifest, and a security policy are included.
  - The app has a working managed preview, health endpoint, and automated checks for the server scanner and build.
  - The dashboard is visually polished with responsive layout, motion, reduced-motion support, and a clear responsible-use notice.

## Verification evidence

`npm run build`, `npx tsc --noEmit`, and `npm run test:smoke` pass against the live preview. The smoke flow covers health, workspace boundary, safe simulation, redacted report output, and reset.
