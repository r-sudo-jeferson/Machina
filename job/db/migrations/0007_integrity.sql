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

CREATE FUNCTION iam.enforce_recoverable_owner()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    another_active_owner_exists boolean;
BEGIN
    IF OLD.starter_role <> 'owner' OR OLD.status <> 'active' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' AND NEW.starter_role = 'owner' AND NEW.status = 'active' THEN
        RETURN NEW;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM iam.memberships AS candidate
        WHERE candidate.tenant_id = OLD.tenant_id
          AND candidate.subject_id <> OLD.subject_id
          AND candidate.starter_role = 'owner'
          AND candidate.status = 'active'
    )
    INTO another_active_owner_exists;

    IF NOT another_active_owner_exists THEN
        RAISE EXCEPTION 'tenant % must retain at least one active owner', OLD.tenant_id
            USING ERRCODE = '23514',
                  CONSTRAINT = 'memberships_recoverable_owner';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER memberships_recoverable_owner_on_delete
    BEFORE DELETE ON iam.memberships
    FOR EACH ROW
    EXECUTE FUNCTION iam.enforce_recoverable_owner();

CREATE TRIGGER memberships_recoverable_owner_on_update
    BEFORE UPDATE OF starter_role, status ON iam.memberships
    FOR EACH ROW
    EXECUTE FUNCTION iam.enforce_recoverable_owner();

REVOKE ALL ON FUNCTION iam.enforce_recoverable_owner() FROM PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA iam REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA authz REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA audit REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA ops REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA ai REVOKE ALL ON TABLES FROM PUBLIC;

COMMENT ON FUNCTION ops.current_tenant_id() IS 'Returns only the transaction-local app.tenant_id; missing/empty context resolves to NULL so tenant RLS denies by default.';
COMMENT ON FUNCTION iam.enforce_recoverable_owner() IS 'Rejects deletion, revocation, or demotion of the final active tenant owner. Concurrency serialization is verified separately.';

COMMIT;
