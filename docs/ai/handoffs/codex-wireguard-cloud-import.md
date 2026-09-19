# WireGuard cloud configuration import

- Changed `models.py`: normalize existing cloud clients into the same typed DTO/canonical snapshot as direct gateway reads, preserving UUIDs, keys, enabled state and all routes. Reject incomplete/malformed required data.
- Changed `client.py`: verify exactly one EGW and its serial in a bounded project inventory read before reading typed client configuration; reject duplicate policy identities. Read-only API calls only.
- Added `tests/test_cloud_wireguard_models.py`: identity rejection, route preservation, duplicate rejection and malformed configuration coverage. New DTO tests failed before implementation.
- Validation: full SDK suite 410 passed; Ruff check passed. SDK-boundary specialist OK. Application integration and safety tests in companion UniqueOS PR.
- No schema/API removals, gateway writes, credential changes or deployment. Existing untyped APIs remain compatible.
- Human next step: review this SDK PR before the companion UniqueOS gitlink update. No merge performed.
