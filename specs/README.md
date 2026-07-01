# Clack Specs

This directory is the canonical spec shelf for Clack v0 planning.

- `product/` — product scope and runtime model.
- `architecture/` — build plans and implementation decisions.
- `protocol/` — envelope, receipt, CNS identity/route/grant/heartbeat docs.
- `fixtures/` — JSON fixtures used by validation tools.

Start with:

- `product/clack-product-scope-v0.md` — product boundary.
- `architecture/clack-build-plan-v0.md` — build gates and source-of-truth model.
- `architecture/clack-artifact-index-v0.md` — artifact classification / salvage catalog.

Run validation from repo root:

```bash
python tools/validation/validate_clack_docs.py
```
