BEGIN;

REVOKE CREATE ON SCHEMA iam, authz, audit, ops, ai FROM PUBLIC;
REVOKE CREATE ON SCHEMA iam, authz, audit, ops, ai FROM machina_runtime;
GRANT USAGE ON SCHEMA iam, authz, audit, ops, ai TO machina_runtime;

REVOKE ALL ON TABLE iam.subjects, iam.sessions FROM machina_runtime;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    iam.tenants,
    iam.workspaces,
    iam.memberships,
    iam.invitations,
    iam.preferences,
    authz.policy_snapshots,
    audit.events,
    ops.outbox,
    ops.idempotency_keys,
    ai.interactions
TO machina_runtime;

REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE
    iam.tenants,
    iam.workspaces,
    iam.memberships,
    iam.invitations,
    iam.preferences,
    authz.policy_snapshots,
    audit.events,
    ops.outbox,
    ops.idempotency_keys,
    ai.interactions
FROM machina_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA iam REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA authz REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA audit REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA ops REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA ai REVOKE ALL ON TABLES FROM PUBLIC;

COMMENT ON FUNCTION ops.current_tenant_id() IS 'Returns only the transaction-local app.tenant_id; missing/empty context resolves to NULL so tenant RLS denies by default.';

COMMIT;
