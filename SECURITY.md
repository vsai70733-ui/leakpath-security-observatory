# Security boundaries

LeakPath is intentionally constrained for safe education and portfolio demonstrations.

## In scope

- Synthetic files under the application-created `demo-workspace/` directory
- Pattern matching for fake credentials and sensitive-data-like strings
- Read-only metadata analysis of the demo Git-risk fixtures
- Safe event simulation through writes and renames inside the workspace
- Redacted evidence and non-destructive suggestions

## Out of scope

- Real credential collection or validation
- Arbitrary filesystem paths
- Encryption, destructive deletion, persistence, privilege escalation, or malware behavior
- Network scanning or attacks against external systems
- Automatic credential rotation or automatic repository rewriting

## Reporting issues

If you find a way for the simulator to access a path outside `demo-workspace/`, stop using the demo and open a security issue with a minimal reproduction. Do not include real credentials or private data in issues.
