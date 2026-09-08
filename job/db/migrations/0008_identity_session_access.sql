BEGIN;

CREATE FUNCTION iam.upsert_subject(
    p_subject_id uuid,
    p_external_subject text,
    p_display_name text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    subject_id uuid;
BEGIN
    IF p_subject_id IS NULL THEN
        RAISE EXCEPTION 'subject id is required' USING ERRCODE = '22023';
    END IF;
    IF p_external_subject IS NULL OR btrim(p_external_subject) = '' THEN
        RAISE EXCEPTION 'external subject is required' USING ERRCODE = '22023';
    END IF;
    IF p_display_name IS NULL OR char_length(p_display_name) NOT BETWEEN 1 AND 160 THEN
        RAISE EXCEPTION 'display name length must be between 1 and 160' USING ERRCODE = '22023';
    END IF;

    INSERT INTO iam.subjects (id, external_subject, display_name)
    VALUES (p_subject_id, p_external_subject, p_display_name)
    ON CONFLICT (external_subject) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        updated_at = now()
    RETURNING id INTO subject_id;

    RETURN subject_id;
END;
$$;

CREATE FUNCTION iam.create_session(
    p_session_id uuid,
    p_subject_id uuid,
    p_session_token_hash bytea,
    p_csrf_token_hash bytea,
    p_expires_at timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
BEGIN
    IF p_session_id IS NULL OR p_subject_id IS NULL THEN
        RAISE EXCEPTION 'session id and subject id are required' USING ERRCODE = '22023';
    END IF;
    IF p_session_token_hash IS NULL OR octet_length(p_session_token_hash) <> 32 THEN
        RAISE EXCEPTION 'session token hash must contain exactly 32 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_csrf_token_hash IS NULL OR octet_length(p_csrf_token_hash) <> 32 THEN
        RAISE EXCEPTION 'csrf token hash must contain exactly 32 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_expires_at IS NULL OR p_expires_at <= now() THEN
        RAISE EXCEPTION 'session expiry must be in the future' USING ERRCODE = '22023';
    END IF;

    INSERT INTO iam.sessions (
        id,
        subject_id,
        session_token_hash,
        csrf_token_hash,
        expires_at
    )
    VALUES (
        p_session_id,
        p_subject_id,
        p_session_token_hash,
        p_csrf_token_hash,
        p_expires_at
    );

    RETURN p_session_id;
END;
$$;

CREATE FUNCTION iam.get_active_session(p_session_token_hash bytea)
RETURNS TABLE (
    id uuid,
    subject_id uuid,
    csrf_token_hash bytea,
    active_tenant_id uuid,
    active_workspace_id uuid,
    expires_at timestamptz,
    rotated_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
    SELECT
        session.id,
        session.subject_id,
        session.csrf_token_hash,
        session.active_tenant_id,
        session.active_workspace_id,
        session.expires_at,
        session.rotated_at
    FROM iam.sessions AS session
    WHERE octet_length(p_session_token_hash) = 32
      AND session.session_token_hash = p_session_token_hash
      AND session.revoked_at IS NULL
      AND session.expires_at > now()
$$;

CREATE FUNCTION iam.revoke_session(p_session_token_hash bytea)
RETURNS void
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
    UPDATE iam.sessions
    SET revoked_at = COALESCE(revoked_at, now())
    WHERE octet_length(p_session_token_hash) = 32
      AND session_token_hash = p_session_token_hash
$$;

REVOKE ALL ON FUNCTION iam.upsert_subject(uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.create_session(uuid, uuid, bytea, bytea, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.get_active_session(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.revoke_session(bytea) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION iam.upsert_subject(uuid, text, text) TO machina_runtime;
GRANT EXECUTE ON FUNCTION iam.create_session(uuid, uuid, bytea, bytea, timestamptz) TO machina_runtime;
GRANT EXECUTE ON FUNCTION iam.get_active_session(bytea) TO machina_runtime;
GRANT EXECUTE ON FUNCTION iam.revoke_session(bytea) TO machina_runtime;

COMMENT ON FUNCTION iam.upsert_subject(uuid, text, text) IS 'Narrow runtime boundary for creating or refreshing a subject after verified identity-provider claims; direct runtime table access remains revoked.';
COMMENT ON FUNCTION iam.create_session(uuid, uuid, bytea, bytea, timestamptz) IS 'Narrow runtime boundary for creating server-side sessions from already-hashed high-entropy session and CSRF tokens.';
COMMENT ON FUNCTION iam.get_active_session(bytea) IS 'Loads only non-revoked, non-expired server-side sessions by token hash without exposing the stored session-token hash.';
COMMENT ON FUNCTION iam.revoke_session(bytea) IS 'Idempotently revokes a server-side session by token hash while direct runtime table access remains revoked.';

COMMIT;
