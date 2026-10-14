# ADR-001 integration boundary

This change binds NINA's local source/policy/parameters to the report and subsequent
review. Review approval does not authorize production execution. The separate
SQLite execution-permit pilot only computes a local SHA256 result, with injected
test identities; it is not a live owner identity or a NINA execution authorization.
Legacy report hash verification now says LOCAL, with execution assurance UNKNOWN.

## Container builds

From a committed checkout, run `python3 scripts/build_source_manifest.py` before
`docker build`. CI build steps do this explicitly. Dirty or missing application or
policy files block inventory generation. The image copies policies and the generated
inventory, validates its bytes during build, and explicitly selects
`OLA_SOURCE_MODE=build-inventory`. A failed Git check never silently falls back.

Runtime checks cover exact app/policies bytes, missing/extra files and symlinks.
The inventory is unsigned, locally generated evidence; its claimed source SHA is
NOT authenticated at runtime. Replacing both inventory and application can pass
this local check. This does not prove process memory, dependencies, builder or host
integrity. Assurance remains LOCAL / UNKNOWN; independent signed provenance and
trusted owner identity remain required for production. OLA_RUNTIME_COMMIT, if
provided, must agree with the inventory. Git checkouts retain Git byte comparison.

## Validation and release gates

Before this container correction, the complete local suite had 366 passed and
four GPG setup errors. The environment denies gpg-agent UNIX socket creation
(`Operation not permitted`). No owner private signing key is available here.
No tests were disabled to convert these errors into a green full-suite result.

The reviewed candidate requires fresh CI at the published SHA, independent review,
owner signature and verification of branch protection before production merge.
This document does not substitute for any of those gates. Production: NO-GO.
