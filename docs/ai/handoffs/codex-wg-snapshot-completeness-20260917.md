# WireGuard snapshot completeness

Owned branch: codex/wg-snapshot-completeness-20260917, based on UniqueOS's pinned 4ddc268.

- WireGuard list methods now require an explicit list section, successful response, and distinct nonempty policy/peer identities before returning typed models.
- Server peer sections must be present; missing/malformed responses raise sanitized errors instead of returning an empty list.
- Explicit empty lists remain successful observations, enabling safe application-side reconciliation.
- No transport, mutation, authentication or retry changes; no live vendor calls.

Validation: 106 tests passed (snapshot completeness, WireGuard manager, gateway client); Ruff check/format and diff whitespace passed.
SDK boundary and stability reviewers: OK across the application + SDK integration.

Dependency: UniqueOS branch codex/vpn-sync-reconciliation-20260917 pins this commit. Publish this SDK branch/commit before publishing a parent gitlink update. Both changes are local; no release or deployment.
