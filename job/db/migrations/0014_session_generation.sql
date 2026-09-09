BEGIN;

ALTER TABLE iam.sessions ADD COLUMN generation bigint NOT NULL DEFAULT 1
    CHECK (generation > 0);

CREATE FUNCTION iam.advance_session_generation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.generation <> OLD.generation THEN
        RAISE EXCEPTION 'session generation is server managed' USING ERRCODE = '22023';
    END IF;
    IF ROW(NEW.session_token_hash, NEW.csrf_token_hash, NEW.active_tenant_id, NEW.active_workspace_id)
       IS DISTINCT FROM
       ROW(OLD.session_token_hash, OLD.csrf_token_hash, OLD.active_tenant_id, OLD.active_workspace_id) THEN
        NEW.generation := OLD.generation + 1;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sessions_advance_generation
BEFORE UPDATE ON iam.sessions
FOR EACH ROW EXECUTE FUNCTION iam.advance_session_generation();
REVOKE ALL ON FUNCTION iam.advance_session_generation() FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam.rotate_session(
    p_session_token_hash bytea,
    p_new_session_token_hash bytea,
    p_new_csrf_token_hash bytea
)
RETURNS TABLE (id uuid, subject_id uuid, expires_at timestamptz, rotated_at timestamptz)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    locked_session iam.sessions%ROWTYPE;
BEGIN
    IF p_session_token_hash IS NULL OR octet_length(p_session_token_hash) <> 32 THEN
        RAISE EXCEPTION 'session token hash must contain exactly 32 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_new_session_token_hash IS NULL OR octet_length(p_new_session_token_hash) <> 32 THEN
        RAISE EXCEPTION 'new session token hash must contain exactly 32 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_new_csrf_token_hash IS NULL OR octet_length(p_new_csrf_token_hash) <> 32 THEN
        RAISE EXCEPTION 'new CSRF token hash must contain exactly 32 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_session_token_hash = p_new_session_token_hash THEN
        RAISE EXCEPTION 'session rotation requires a new session token hash' USING ERRCODE = '22023';
    END IF;

    SELECT session.* INTO locked_session
    FROM iam.sessions AS session
    WHERE session.session_token_hash = p_session_token_hash
    FOR UPDATE;

    IF NOT FOUND OR locked_session.revoked_at IS NOT NULL
       OR NOT isfinite(locked_session.expires_at)
       OR locked_session.expires_at <= clock_timestamp()
       OR locked_session.csrf_token_hash = p_new_csrf_token_hash THEN
        RETURN;
    END IF;

    RETURN QUERY
    UPDATE iam.sessions AS session
    SET session_token_hash = p_new_session_token_hash,
        csrf_token_hash = p_new_csrf_token_hash,
        rotated_at = clock_timestamp()
    WHERE session.id = locked_session.id
    RETURNING session.id, session.subject_id, session.expires_at, session.rotated_at;
END;
$$;

-- Row locks requested by SELECT require an UPDATE visibility policy too. These
-- policies admit only the owner running this narrow capability. WITH CHECK false
-- prevents this capability from authorizing writes to another tenant's rows.
CREATE POLICY session_context_switch_migrator_lock ON iam.tenants
FOR UPDATE TO machina_migrator
USING (current_user = 'machina_migrator' AND current_setting('app.session_context_switch', true) = 'on')
WITH CHECK (false);
CREATE POLICY session_context_switch_migrator_lock ON iam.memberships
FOR UPDATE TO machina_migrator
USING (current_user = 'machina_migrator' AND current_setting('app.session_context_switch', true) = 'on')
WITH CHECK (false);
CREATE POLICY session_context_switch_migrator_lock ON iam.workspaces
FOR UPDATE TO machina_migrator
USING (current_user = 'machina_migrator' AND current_setting('app.session_context_switch', true) = 'on')
WITH CHECK (false);

CREATE OR REPLACE FUNCTION iam.switch_session_context(
    p_current_session_token_hash bytea,
    p_replacement_session_token_hash bytea,
    p_replacement_csrf_token_hash bytea,
    p_target_tenant_id uuid
)
RETURNS TABLE (session_id uuid, active_tenant_id uuid, active_workspace_id uuid, expires_at timestamptz)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    locked_session iam.sessions%ROWTYPE;
    selected_workspace_id uuid;
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
    IF p_target_tenant_id IS NULL THEN
        RAISE EXCEPTION 'requested context is unavailable' USING ERRCODE = '42501';
    END IF;
    IF p_current_session_token_hash = p_replacement_session_token_hash
       OR p_current_session_token_hash = p_replacement_csrf_token_hash
       OR p_replacement_session_token_hash = p_replacement_csrf_token_hash THEN
        RAISE EXCEPTION 'replacement session secrets must be independent' USING ERRCODE = '22023';
    END IF;

    SELECT session.* INTO locked_session
    FROM iam.sessions AS session
    WHERE session.session_token_hash = p_current_session_token_hash
    FOR UPDATE;
    IF NOT FOUND OR locked_session.revoked_at IS NOT NULL
       OR NOT isfinite(locked_session.expires_at)
       OR locked_session.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'active session unavailable' USING ERRCODE = '42501';
    END IF;
    IF locked_session.csrf_token_hash = p_replacement_csrf_token_hash THEN
        RAISE EXCEPTION 'replacement csrf token must rotate' USING ERRCODE = '22023';
    END IF;

    previous_switch_capability := current_setting('app.session_context_switch', true);
    PERFORM set_config('app.session_context_switch', 'on', true);

    -- Keep the order used by membership mutations: tenant before membership.
    PERFORM 1 FROM iam.tenants AS tenant
    WHERE tenant.id = p_target_tenant_id AND tenant.status = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'requested context is unavailable' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM iam.memberships AS membership
    WHERE membership.tenant_id = p_target_tenant_id
      AND membership.subject_id = locked_session.subject_id
      AND membership.status = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'requested context is unavailable' USING ERRCODE = '42501';
    END IF;
    SELECT workspace.id INTO selected_workspace_id
    FROM iam.workspaces AS workspace
    WHERE workspace.tenant_id = p_target_tenant_id
    ORDER BY workspace.created_at, workspace.id LIMIT 1
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'requested context is unavailable' USING ERRCODE = '42501';
    END IF;

    -- Tenant/membership/workspace locks can also wait beyond session expiry.
    IF locked_session.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'active session unavailable' USING ERRCODE = '42501';
    END IF;
    UPDATE iam.sessions AS session
    SET session_token_hash = p_replacement_session_token_hash,
        csrf_token_hash = p_replacement_csrf_token_hash,
        active_tenant_id = p_target_tenant_id,
        active_workspace_id = selected_workspace_id,
        rotated_at = clock_timestamp()
    WHERE session.id = locked_session.id;

    PERFORM set_config('app.session_context_switch', COALESCE(previous_switch_capability, ''), true);
    RETURN QUERY SELECT locked_session.id, p_target_tenant_id, selected_workspace_id, locked_session.expires_at;
END;
$$;

COMMENT ON COLUMN iam.sessions.generation IS 'Monotonic credential/context generation; managed by trigger and rolled back with the session mutation.';

COMMIT;
