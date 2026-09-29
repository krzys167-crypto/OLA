# Evidence Graph v0.1 — Implementation Record

Source contract: Evidence Graph v0.1 Design Specification, dated 2026-09-09.

Implementation slice:
- `evidence_graph.py`: SQLite projection, node/edge/discovery contracts, provenance fields, epistemic state enforcement, tenant isolation, path/subgraph/lineage queries, deterministic reconstruction, and read-only FastAPI endpoints.
- `tests/test_evidence_graph.py`: schema/invariant, provenance/epistemic, rejected-state, forensic-path, reconstruction, lineage, tenant isolation, API read-only, and canonical OLA-chain tests.
- `.github/workflows/evidence-graph.yml`: reproducible compile + pytest verification.

Boundary notes:
- Canonical records remain external source of truth; this module only projects them.
- Discovery creates candidate hypotheses with status OPEN and never exposes an execution-authorization route.
- `create_app()` takes an authorization callable so OLA's existing RBAC boundary can be injected rather than replaced.
- Numeric QP, graph-derived authorization, cross-tenant federation, and dedicated graph DB are outside this slice.

Status:
- Repository implementation was NOT STARTED per the submitted specification.
- This branch contains the v0.1 executable slice and its contract tests.
