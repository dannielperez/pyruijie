# intercom-path-evidence

Added bounded read-only endpoint/registrar path evidence with secret-free field allowlists. Run `pytest tests/test_intercom_diagnostics.py --import-mode=importlib`; 2 tests pass. No live gateway call performed. Route evidence is explicitly configuration-only; kernel interface, selected peer and reverse path remain unproven. Unsupported sections stay unknown.
