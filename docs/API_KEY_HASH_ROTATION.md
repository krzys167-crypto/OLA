# OLA API-key fingerprint rotation — production blocking procedure

API keys now use scrypt with a server-side `OLA_API_KEY_PEPPER` of at least 32 bytes. Secret must be random, provided by a secret manager, never committed, and identical across all backend replicas. No insecure fallback is enabled.

**Production migration is not automatic:** hashes of legacy bearer keys cannot be upgraded to keyed fingerprints without the raw keys. Inventory existing tenants, back up the key table, generate new high-entropy bearer keys, and store only `api_key_fingerprint(raw_key)`. Deliver the raw keys once through a secure channel, revoke legacy key hashes, and verify both rotation success and old-key denial. Expect service disruption until the owner provisions the pepper and rotates keys.

CI uses a test-only value (not a production secret). Historical workstation scripts also require secret provisioning. Do not deploy this candidate, merge it, or call it VERIFIED until credential migration, signed source, independent Human Gate, protected main, health/rollback and FULL CI are independently proven.

Derived fingerprint parameters: scrypt N=16384, r=8, p=1, dkLen=32; stable across replicas. Offline rotation still required. A provider-backed secret is mandatory; the CI value is not a production key.
