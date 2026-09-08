BEGIN;

CREATE POLICY session_context_migrator_read
ON iam.memberships
FOR SELECT
TO machina_migrator
USING (
    current_user = 'machina_migrator'
    AND current_setting('app.session_context_lookup', true) = 'on'
);

CREATE POLICY session_context_migrator_read
ON iam.tenants
FOR SELECT
TO machina_migrator
USING (
    current_user = 'machina_migrator'
    AND current_setting('app.session_context_lookup', true) = 'on'
);

CREATE FUNCTION iam.get_session_identity(p_session_token_hash bytea)
RETURNS TABLE (
    id uuid,
    display_name text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
    SELECT
        subject.id,
        subject.display_name
    FROM iam.sessions AS session
    JOIN iam.subjects AS subject
      ON subject.id = session.subject_id
    WHERE octet_length(p_session_token_hash) = 32
      AND session.session_token_hash = p_session_token_hash
      AND session.revoked_at IS NULL
      AND session.expires_at > now()
$$;

CREATE FUNCTION iam.list_session_tenants(p_session_token_hash bytea)
RETURNS TABLE (
    tenant_id uuid,
    slug text,
    display_name text,
    status text,
    starter_role text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
SET app.session_context_lookup = 'on'
AS $$
    SELECT
        tenant.id,
        tenant.slug,
        tenant.display_name,
        tenant.status,
        membership.starter_role
    FROM iam.sessions AS session
    JOIN iam.memberships AS membership
      ON membership.subject_id = session.subject_id
     AND membership.status = 'active'
    JOIN iam.tenants AS tenant
      ON tenant.id = membership.tenant_id
     AND tenant.status = 'active'
    WHERE octet_length(p_session_token_hash) = 32
      AND session.session_token_hash = p_session_token_hash
      AND session.revoked_at IS NULL
      AND session.expires_at > now()
    ORDER BY tenant.id
$$;

REVOKE ALL ON FUNCTION iam.get_session_identity(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.list_session_tenants(bytea) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION iam.get_session_identity(bytea) TO machina_runtime;
GRANT EXECUTE ON FUNCTION iam.list_session_tenants(bytea) TO machina_runtime;

COMMENT ON POLICY session_context_migrator_read ON iam.memberships IS 'Allows only the migration-role security definer to read cross-tenant membership rows while the function-local session-context capability is active; runtime callers remain governed by tenant RLS.';
COMMENT ON POLICY session_context_migrator_read ON iam.tenants IS 'Allows only the migration-role security definer to read cross-tenant tenant rows while the function-local session-context capability is active; runtime callers remain governed by tenant RLS.';
COMMENT ON FUNCTION iam.get_session_identity(bytea) IS 'Returns the minimal public identity projection for a currently active server-side session without exposing subjects or session rows directly.';
COMMENT ON FUNCTION iam.list_session_tenants(bytea) IS 'Returns only active tenants and active memberships reachable from a currently active server-side session through a function-local cross-tenant read capability.';

COMMIT;
