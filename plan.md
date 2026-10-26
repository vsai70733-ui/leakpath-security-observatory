# LeakPath Implementation Plan

## Product scope

LeakPath is a live defensive DevSecOps observatory for a locked-down, application-created demo workspace. It detects synthetic secret patterns, explains Git exposure risk, calculates an explainable aggregate score, visualizes exposure paths, and offers non-destructive remediation guidance. The simulator is deliberately harmless: it only writes and renames fake files inside `demo-workspace/`, never encrypts, deletes, or accepts arbitrary paths.

## Implementation approach

- Use a single Node/Express runtime on port 3000 with Vite middleware in development and compiled static assets in production.
- Keep the server-side demo workspace as the only filesystem boundary. The server owns workspace initialization, safe simulation, scanning, Git-risk fixtures, event aggregation, and SSE live updates.
- Use a lightweight persistent-ready event store abstraction. When the managed MySQL `DATABASE_URL` is available, initialize an additive `leakpath_events` table and persist alert/event records. If the preview is running without a DSN, use an in-memory fallback so the demo still works visibly.
- Use React + TypeScript for the dashboard, with a custom CSS system rather than a component library. The interface favors an asymmetric observatory canvas: left navigation rail, a telemetry header, a wide score surface, and stacked evidence panels.
- Use Server-Sent Events for live event updates and short polling as a resilience fallback. The UI has explicit scan, simulation, and reset controls.
- Generate reports client-side from the explainable state so the download remains safe and contains no real credentials.

## Main project structure

```text
leakpath/
├── server/index.js             # Express runtime, safe workspace, scanner, SSE, persistence hook
├── src/main.tsx                # React entry point
├── src/App.tsx                 # Dashboard composition and interactions
├── src/styles.css              # Visual system, responsive layout, motion, charts
├── public/manus-routes.json    # Managed route manifest
├── demo-workspace/             # App-owned synthetic fixture files only
├── app.config.ts               # Project logo metadata
├── package.json                # Vite/React/Express toolchain
├── README.md                   # Setup, demo flow, architecture
├── SECURITY.md                 # Threat model and safe-use boundaries
└── TODO.md                     # Outcome-based delivery record
```

## Data and behavior

The server exposes `/api/state`, `/api/scan`, `/api/simulate`, `/api/reset`, `/api/report`, `/api/health`, and `/api/events`. Scanning uses redacted evidence and only returns metadata. Findings carry severity, file, type, rationale, Git state, and remediation. The risk engine weights secret type, Git exposure, missing ignore protection, and recent activity. The simulator creates safe fake files, then runs a scan; it does not perform cryptography or destructive cleanup.

## Design direction

Three possible directions considered:

- **Obsidian Observatory** (0.06): a dark editorial security console with luminous telemetry and quiet, precise motion.
- **Terminal Brutalist** (0.08): monochrome panels, oversized labels, and raw command-line energy.
- **Infrared Command** (0.04): warm alert colors, dense signal maps, and incident-room urgency.

### Chosen movement: Obsidian Observatory

- **Core principles:** evidence before decoration; tension through contrast; progressive disclosure; calm during incidents.
- **Color philosophy:** graphite and midnight blue create a quiet instrument panel; acid chartreuse marks healthy telemetry and active controls; cyan identifies data flow; amber and coral are reserved for exposure severity.
- **Layout paradigm:** a fixed left rail anchors the product; the main content is an asymmetric vertical scanline with an oversized score card, offset evidence cards, and a live activity column rather than a centered tile grid.
- **Signature elements:** a pulsing “live” beacon, thin scanline borders that animate on state changes, and an exposure-path ribbon connecting file → detection → Git → public risk.
- **Interaction philosophy:** every control should communicate safety boundaries. Simulation actions are explicit, reversible, and labeled. Motion reinforces causality: an event appears in the stream, then the score and path update.
- **Animation:** use 180–420ms ease-out transitions, slow 6–9s ambient gradients, subtle data pulses, and a one-time sweep when a scan completes. Never make core content depend on motion; respect reduced-motion preferences.
- **Typography system:** Space Grotesk for headings and UI labels, IBM Plex Mono for evidence, timestamps, scores, and code-like content. Headings are compact and slightly tracked; body copy is high-contrast and readable.
- **Brand essence:** a calm, explainable radar for sensitive-data exposure inside real developer workflows; precise, protective, transparent.
- **Brand voice:** concise, evidence-led, never alarmist. Example lines: “Signal found. Here’s the path.” and “Safe simulation only — no encryption, no destructive actions.”
- **Wordmark & logo:** a compact “L” glyph formed from a vertical scanline and four connected nodes, paired with the `LeakPath` wordmark.
- **Signature brand color:** `#d7ff55`, an acid-lime signal color used for healthy monitoring and primary actions.

## Material constraints

No real secrets, arbitrary file paths, malware behavior, encryption, or destructive auto-fixes are included. Demo fixtures use clearly fake credential values. The project should remain usable when the managed database is unavailable in local preview through an in-memory fallback.
