# Contributing

1. Create a branch from `main`.
2. Add or change one control at a time.
3. Include authoritative source metadata, audit logic, remediation, verification,
   rollback behavior, risk flags, and tests.
4. Run `python -m pytest`, `python -m ruff check .`, and `shellcheck` against a
   generated bundle.
5. Never allow model-generated shell text to enter a bundle.

Rule changes require security review. A source URL alone is insufficient:
record the document title, applicable version, control reference, and the date
on which the implementation was reviewed.

