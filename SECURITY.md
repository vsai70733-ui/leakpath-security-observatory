# Security boundaries

LeakPath is intentionally constrained for safe education and portfolio demonstrations.

## In scope

- Synthetic files under the application-created `demo-workspace/` directory
- Pattern matching for fake credentials and sensitive-data-like strings
- Read-only metadata analysis of the demo Git-risk fixtures
- Safe event simulation through writes and renames inside the workspace
- Redacted evidence and non-destructive suggestions
- Manus OAuth authentication with HS256-validated `webdev_app_session` cookies

## Authentication boundary

LeakPath delegates identity to Manus OAuth. It never collects, stores, or validates a separate email/password credential. OAuth state is bound to a single-use nonce cookie, callback URLs are fixed to the current application origin, and dashboard APIs require a verified session whose `appId` matches the managed project. Health and login endpoints remain public; workspace state, simulation, reports, and live events require authentication.

## Out of scope

- Real credential collection or validation
- Arbitrary filesystem paths
- Encryption, destructive deletion, persistence, privilege escalation, or malware behavior
- Network scanning or attacks against external systems
- Automatic credential rotation or automatic repository rewriting
- Reusing the application session cookie for unrelated applications or projects

## Reporting issues

If you find a way for the simulator to access a path outside `demo-workspace/`, stop using the demo and open a security issue with a minimal reproduction. Do not include real credentials or private data in issues.
