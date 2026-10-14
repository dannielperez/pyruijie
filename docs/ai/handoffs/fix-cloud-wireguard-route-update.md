# Existing cloud client route correction

Adds a route-only SDK operation for the UniqueOS technician provisioning retry. It verifies gateway identity and the caller's expected client snapshot, rereads immediately before the write, and preserves the complete cloud payload except allowIps. Missing/masked private key material and stale snapshots prevent writes. The caller must verify queued updates through readback; no automatic write retries.

Validation: 18 focused cloud policy/model tests passed. Changed-file Ruff checks and format pass. No live mutation performed. There is no vendor compare-and-swap API, so a concurrent external write remains possible between read and write.
