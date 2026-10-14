# Preserve WireGuard server fields during peer edits

The full-policy serializer discarded existing firmware configuration fields and the optional peerPrikey field on gateway-generated peers. Adding a peer replaces the full server policy, so unrelated peer export material and firmware settings must survive that operation. A live gateway rejected an old-serializer add-peer request; this patch addresses confirmed serialization loss, but live validation is still required to establish whether it resolves the rejection.

Changed src/pyruijie/models.py and added tests/test_wireguard_config_preservation.py. Known firmware configuration fields are preserved explicitly; arbitrary raw fields and runtime counters are not forwarded. Existing typed edits retain precedence. New externally keyed peers do not gain invented private keys. Tests use synthetic keys only.

Validation: 447 tests passed; Ruff check passed; Ruff format check passed (39 files).

Risk: preservation is limited to observed configuration fields. No protocol mutation, live deployment, or credential changes are part of this commit. Owner approval and downstream pin update are required before runtime adoption. Read back a live full-policy update and verify unrelated peers after approval.
