# Stage 3 — registered tool dispatch enforcement

NINA passes the exact approved tool list into the shared six-agent runtime.
The runtime defaults to no permissions. Its fixed pipeline requires both
safe_expression and local_mcp_tool_registry.sha256; incomplete/unknown scopes
produce TOOL_SCOPE_DENIED before model calls and tool execution. Dispatch checks
scope again immediately before each of these tools, including tenant and task.
The scope is copied into a frozen set and recorded with each agent result.

This changes /agent-run and /nina-run clients: explicitly request both tools for
the current fixed pipeline. It does not automatically expand a narrower request.
Existing CI consumers and Aurora request both. The authenticated Stripe fulfillment
handler explicitly selects the same server-owned profile after its existing
payment checks. No payment behavior or permission to initiate payments is added.

Scope: the two registered tools of the existing fixed pipeline. Internal reasoning,
retrieval, aggregation and provider network calls are not independently delegated
capabilities here. Python helper functions are not a process sandbox; malicious
in-process code can bypass them. Other runtimes are not claimed protected.

This is NOT a signed single-use execution permit. Durable consumption, actor roles,
identity separation, external-effect authorization and independent signatures are
still open. Execution assurance stays UNKNOWN; production NO-GO.
