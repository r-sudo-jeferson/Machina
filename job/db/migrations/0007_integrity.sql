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

REVOKE UPDATE, DELETE ON TABLE iam.memberships FROM machina_runtime;

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

-- SECURITY DEFINER membership mutations execute as machina_migrator. FORCE RLS
-- still applies to the table owner, so the definer is admitted only for the
-- same transaction-local tenant as the runtime caller.
ALTER POLICY tenant_isolation ON iam.tenants TO machina_runtime, machina_migrator;
ALTER POLICY tenant_isolation ON iam.memberships TO machina_runtime, machina_migrator;

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

CREATE FUNCTION iam.set_membership_access(
    p_subject_id uuid,
    p_starter_role text,
    p_status text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    tenant_context uuid;
    current_starter_role text;
    current_status text;
    another_active_owner_exists boolean;
BEGIN
    tenant_context := ops.current_tenant_id();
    IF tenant_context IS NULL THEN
        RAISE EXCEPTION 'tenant context is required'
            USING ERRCODE = '42501';
    END IF;

    -- Acquire the canonical per-tenant lock before the membership UPDATE
    -- statement starts. A concurrent caller therefore waits here and its
    -- subsequent statements observe the previously committed owner change.
    PERFORM 1
    FROM iam.tenants AS tenant
    WHERE tenant.id = tenant_context
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'active tenant context is not visible'
            USING ERRCODE = '42501';
    END IF;

    SELECT membership.starter_role, membership.status
    INTO current_starter_role, current_status
    FROM iam.memberships AS membership
    WHERE membership.tenant_id = tenant_context
      AND membership.subject_id = p_subject_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership not found in active tenant'
            USING ERRCODE = 'P0002';
    END IF;

    IF current_starter_role = 'owner'
       AND current_status = 'active'
       AND NOT (p_starter_role = 'owner' AND p_status = 'active') THEN
        SELECT EXISTS (
            SELECT 1
            FROM iam.memberships AS candidate
            WHERE candidate.tenant_id = tenant_context
              AND candidate.subject_id <> p_subject_id
              AND candidate.starter_role = 'owner'
              AND candidate.status = 'active'
        )
        INTO another_active_owner_exists;

        IF NOT another_active_owner_exists THEN
            RAISE EXCEPTION 'tenant % must retain at least one active owner', tenant_context
                USING ERRCODE = '23514',
                      CONSTRAINT = 'memberships_recoverable_owner';
        END IF;
    END IF;

    UPDATE iam.memberships
    SET starter_role = p_starter_role,
        status = p_status,
        updated_at = now()
    WHERE tenant_id = tenant_context
      AND subject_id = p_subject_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership disappeared during mutation'
            USING ERRCODE = '40001';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION iam.enforce_recoverable_owner() FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.set_membership_access(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.set_membership_access(uuid, text, text) TO machina_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA iam REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA authz REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA audit REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA ops REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA ai REVOKE ALL ON TABLES FROM PUBLIC;

COMMENT ON FUNCTION ops.current_tenant_id() IS 'Returns only the transaction-local app.tenant_id; missing/empty context resolves to NULL so tenant RLS denies by default.';
COMMENT ON FUNCTION iam.enforce_recoverable_owner() IS 'Defense-in-depth guard rejecting deletion, revocation, or demotion of the final active tenant owner.';
COMMENT ON FUNCTION iam.set_membership_access(uuid, text, text) IS 'Serialized tenant-scoped mutation boundary for protected membership role/status changes; direct runtime UPDATE/DELETE on memberships is revoked.';

COMMIT;
