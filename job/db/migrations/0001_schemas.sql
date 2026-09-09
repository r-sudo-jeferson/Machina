BEGIN;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA iam AUTHORIZATION CURRENT_USER;
CREATE SCHEMA authz AUTHORIZATION CURRENT_USER;
CREATE SCHEMA audit AUTHORIZATION CURRENT_USER;
CREATE SCHEMA ops AUTHORIZATION CURRENT_USER;
CREATE SCHEMA ai AUTHORIZATION CURRENT_USER;

COMMENT ON SCHEMA iam IS 'Identity, tenant, workspace, membership, invitation, session, and preference records.';
COMMENT ON SCHEMA authz IS 'Versioned authorization policy snapshots and related authorization state.';
COMMENT ON SCHEMA audit IS 'Append-only tenant-correlated audit records.';
COMMENT ON SCHEMA ops IS 'Operational outbox, idempotency, and transaction-context primitives.';
COMMENT ON SCHEMA ai IS 'Safe AI interaction metadata; raw sensitive prompts are not stored here.';

COMMIT;
