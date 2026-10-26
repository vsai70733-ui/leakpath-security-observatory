# LeakPath

LeakPath is a live defensive DevSecOps observatory that watches an application-owned demo workspace, detects synthetic sensitive-data patterns, explains Git exposure risk, and visualizes the path from file creation to public-exposure risk.

## What is included

- Safe synthetic-secret scanner with redacted evidence
- Git-risk fixture analysis for untracked, staged, committed, and missing ignore protection
- Explainable 0–100 risk score
- Live dashboard with SSE events and polling fallback
- Safe simulator that only writes fake files inside `demo-workspace/`
- Non-destructive remediation guidance and report download
- Responsive observatory UI with accessible motion and reduced-motion support

## Run locally

```bash
npm install
npm run dev
```

Open the managed Preview or `http://localhost:3000`. The project uses `DATABASE_URL` when available to persist event records. If it is absent, the preview uses an in-memory fallback so the safety demo remains usable.

## Demo flow

1. Review the current score and the exposure-path ribbon.
2. Press **Scan workspace** to run the synthetic scanner.
3. Press **Run safe simulation** to create harmless fake files and watch the stream update.
4. Open a finding to see redacted evidence and Git rationale.
5. Download the generated report.
6. Press **Reset demo** to restore only the app-owned fixture workspace.

## Architecture

- `server/index.js` owns the safe workspace boundary, scanner, risk engine, SSE stream, report payload, and persistence hook.
- `src/App.tsx` renders the observatory surface and handles actions.
- `src/styles.css` contains the visual language, charts, motion, and responsive states.
- `demo-workspace/` is the only directory the simulator may modify.

## Safe-use boundary

This project is an educational defensive simulator. It does not contain ransomware, encryption, credential theft, arbitrary path selection, automatic cleanup, or attack automation. Use synthetic credentials only. See [SECURITY.md](./SECURITY.md) for the threat model and limits.
