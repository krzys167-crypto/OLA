# ADR-001 stage 2 — local semantic binding

Scope: /nina-run and result review. Production NO-GO, execution assurance UNKNOWN.
This supersedes the stage-1 null policy binding and legacy CLI description.

Before execution, a source observer reads Git HEAD and compares every tracked
app/ and policies/ blob with on-disk bytes. Missing Git data, mismatched environment
SHA, dirty bytes, symlinks and extra files in this boundary block /nina-run.
The observer compares the same source again after execution; disagreement blocks
the result (it cannot undo actions already performed). Deployment without Git is
currently BLOCKED; a trusted immutable build-manifest adapter is still required.

This is LOCAL disk consistency, not proof of loaded process memory, authentic
publisher, dependencies, runtime configuration, external model, or uncompromised
host. It cannot defeat a privileged attacker or a change-and-restore race. No
ATTESTED/VERIFIED claim is made. Run from a clean committed checkout.

The byte digest of policies/nina-review-v1.json is recorded with tenant, requester,
operation, parameter digest and ALLOW before invoking NINA. Policy permits the
registered bounded runtime capabilities; it does not authorize deployment,
payments, arbitrary tools or production promotion. Other API routes are outside
this change. The result report embeds this context and binds the source SHA,
policy digest and the input evidence-chain root.

Approval is a post-execution result review, never pre-execution human permission.
POST /nina-run/{run_id}/approve requires bearer credentials from a different key
in the same tenant plus tip_hash, report_sha256 and scope="review-result". The
server loads the persisted report, validates its checksum and context, compares
current source and policy, and enforces the 900-second server-clock review window.
Legacy candidates without binding are rejected; rerun is required. Responses say
APPROVED with assurance UNKNOWN and production_eligible=false, never VERIFIED.
An atomic transaction preserves single-use review under concurrent approvers.

The original report stays immutable to avoid an approval/report hash cycle.
A separate human.approval record binds its digest, exact report digest, parameters,
source, policy, actor, scope and expiry. The original report's approval digest stays
null because it predates review; the approval response supplies the receipt digest.
There is no cryptographic signature yet.

GET /nina-run/{run_id}/approval revalidates chain, report, current source, policy and
time. New evidence after approval yields STALE; expiry or changed bindings yields
BLOCKED. POST /nina-run/{run_id}/approval/revoke accepts human_approval_digest and
is restricted to the original approver. Revocation is append-only. A revoked review
cannot become valid again. These endpoints do not grant execution permission.
Time uses the local server clock; a trusted time source remains future work.

Legacy report CLI now returns DECISION_REPORT=LOCAL and EXECUTION_ASSURANCE=UNKNOWN
for a checksum match. Exit 0 means local integrity only. CI and the Aurora approval
client were migrated to the new contracts. v1 report payload semantics otherwise
remain legacy; do not treat any legacy VERIFIED field as external attestation.

Validation distinguishes mocked source observations in API unit tests from actual
Git mutation tests and a real HTTP smoke test from a clean committed checkout.
Remaining: signed canonical Evidence-Stream, separately administered trust roots,
independent IGOR, external checkpoints, signed release, exact-SHA remote CI,
real Ollama/ZBook proof, and owner production gates. None is implied by local PASS.
