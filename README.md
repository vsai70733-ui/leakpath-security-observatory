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
- Manus OAuth login page with secure `webdev_app_session` application sessions

## Run locally

```bash
npm install
npm run dev
```

Open the managed Preview. LeakPath starts on a protected login page and uses the managed Manus account OAuth flow; it does not create or store a separate password database. The project uses `DATABASE_URL` when available to persist event records and recognized operators. If it is absent, the preview uses an in-memory fallback so the safety demo remains usable.

## Demo flow

1. Select **Continue with Manus** and complete the managed OAuth sign-in.
2. Review the current score and the exposure-path ribbon.
3. Press **Scan workspace** to run the synthetic scanner.
4. Press **Run safe simulation** to create harmless fake files and watch the stream update.
5. Open a finding to see redacted evidence and Git rationale.
6. Download the generated report, then use **Log out** when finished.
7. Press **Reset demo** to restore only the app-owned fixture workspace.

## Architecture

- `server/index.js` owns Manus OAuth, JWT session validation, the safe workspace boundary, scanner, risk engine, SSE stream, report payload, and persistence hook.
- `src/App.tsx` renders the authenticated observatory surface and handles actions.
- `src/LoginPage.tsx` renders the logged-out access experience and starts the OAuth redirect.
- `src/styles.css` contains the visual language, charts, motion, and responsive states.
- `demo-workspace/` is the only directory the simulator may modify.

## Safe-use boundary

This project is an educational defensive simulator. It does not contain ransomware, encryption, credential theft, arbitrary path selection, automatic cleanup, or attack automation. Use synthetic credentials only. See [SECURITY.md](./SECURITY.md) for the threat model and limits.
