BEGIN;

CREATE POLICY session_context_switch_migrator_read
ON iam.memberships
FOR SELECT
TO machina_migrator
USING (
    current_user = 'machina_migrator'
    AND current_setting('app.session_context_switch', true) = 'on'
);

CREATE POLICY session_context_switch_migrator_read
ON iam.tenants
FOR SELECT
TO machina_migrator
USING (
    current_user = 'machina_migrator'
    AND current_setting('app.session_context_switch', true) = 'on'
);

CREATE POLICY session_context_switch_migrator_read
ON iam.workspaces
FOR SELECT
TO machina_migrator
USING (
    current_user = 'machina_migrator'
    AND current_setting('app.session_context_switch', true) = 'on'
);

CREATE FUNCTION iam.switch_session_context(
    p_current_session_token_hash bytea,
    p_replacement_session_token_hash bytea,
    p_replacement_csrf_token_hash bytea,
    p_target_tenant_id uuid,
    p_target_workspace_id uuid
)
RETURNS TABLE (
    session_id uuid,
    active_tenant_id uuid,
    active_workspace_id uuid,
    expires_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    selected_session_id uuid;
    selected_subject_id uuid;
    selected_expires_at timestamptz;
    current_csrf_token_hash bytea;
    previous_switch_capability text;
BEGIN
    IF p_current_session_token_hash IS NULL OR octet_length(p_current_session_token_hash) <> 32 THEN
        RAISE EXCEPTION 'active session unavailable' USING ERRCODE = '42501';
    END IF;
    IF p_replacement_session_token_hash IS NULL OR octet_length(p_replacement_session_token_hash) <> 32 THEN
        RAISE EXCEPTION 'replacement session token hash must contain exactly 32 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_replacement_csrf_token_hash IS NULL OR octet_length(p_replacement_csrf_token_hash) <> 32 THEN
        RAISE EXCEPTION 'replacement csrf token hash must contain exactly 32 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_target_tenant_id IS NULL OR p_target_workspace_id IS NULL THEN
        RAISE EXCEPTION 'requested context is unavailable' USING ERRCODE = '42501';
    END IF;
    IF p_current_session_token_hash = p_replacement_session_token_hash
       OR p_replacement_session_token_hash = p_replacement_csrf_token_hash THEN
        RAISE EXCEPTION 'replacement session secrets must be independent' USING ERRCODE = '22023';
    END IF;

    SELECT session.id, session.subject_id, session.expires_at, session.csrf_token_hash
    INTO selected_session_id, selected_subject_id, selected_expires_at, current_csrf_token_hash
    FROM iam.sessions AS session
    WHERE session.session_token_hash = p_current_session_token_hash
      AND session.revoked_at IS NULL
      AND session.expires_at > now()
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'active session unavailable' USING ERRCODE = '42501';
    END IF;

    IF current_csrf_token_hash = p_replacement_csrf_token_hash THEN
        RAISE EXCEPTION 'replacement csrf token must rotate' USING ERRCODE = '22023';
    END IF;

    previous_switch_capability := current_setting('app.session_context_switch', true);
    PERFORM set_config('app.session_context_switch', 'on', true);

    PERFORM 1
    FROM iam.memberships AS membership
    JOIN iam.tenants AS tenant
      ON tenant.id = membership.tenant_id
     AND tenant.status = 'active'
    WHERE membership.tenant_id = p_target_tenant_id
      AND membership.subject_id = selected_subject_id
      AND membership.status = 'active';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'requested context is unavailable' USING ERRCODE = '42501';
    END IF;

    PERFORM 1
    FROM iam.workspaces AS workspace
    WHERE workspace.tenant_id = p_target_tenant_id
      AND workspace.id = p_target_workspace_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'requested context is unavailable' USING ERRCODE = '42501';
    END IF;

    UPDATE iam.sessions AS session
    SET session_token_hash = p_replacement_session_token_hash,
        csrf_token_hash = p_replacement_csrf_token_hash,
        active_tenant_id = p_target_tenant_id,
        active_workspace_id = p_target_workspace_id,
        rotated_at = now()
    WHERE session.id = selected_session_id;

    PERFORM set_config(
        'app.session_context_switch',
        COALESCE(previous_switch_capability, ''),
        true
    );

    RETURN QUERY
    SELECT selected_session_id, p_target_tenant_id, p_target_workspace_id, selected_expires_at;
END;
$$;

REVOKE ALL ON FUNCTION iam.switch_session_context(bytea, bytea, bytea, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.switch_session_context(bytea, bytea, bytea, uuid, uuid) TO machina_runtime;

COMMENT ON POLICY session_context_switch_migrator_read ON iam.memberships IS 'Allows only the migration-role security definer to verify a requested tenant membership while the transaction-local session-context-switch capability is active.';
COMMENT ON POLICY session_context_switch_migrator_read ON iam.tenants IS 'Allows only the migration-role security definer to verify requested tenant availability while the transaction-local session-context-switch capability is active.';
COMMENT ON POLICY session_context_switch_migrator_read ON iam.workspaces IS 'Allows only the migration-role security definer to verify that the requested workspace belongs to the validated target tenant while the transaction-local session-context-switch capability is active.';
COMMENT ON FUNCTION iam.switch_session_context(bytea, bytea, bytea, uuid, uuid) IS 'Atomically validates an active session, active membership, active tenant, and tenant-owned workspace before rotating session secrets and setting the server-owned active context while preserving and returning the absolute session expiry.';

COMMIT;
