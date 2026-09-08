BEGIN;

CREATE FUNCTION iam.rotate_session(
    p_session_token_hash bytea,
    p_new_session_token_hash bytea,
    p_new_csrf_token_hash bytea
)
RETURNS TABLE (
    id uuid,
    subject_id uuid,
    expires_at timestamptz,
    rotated_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
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

    RETURN QUERY
    UPDATE iam.sessions AS session
    SET session_token_hash = p_new_session_token_hash,
        csrf_token_hash = p_new_csrf_token_hash,
        rotated_at = now()
    WHERE session.session_token_hash = p_session_token_hash
      AND session.revoked_at IS NULL
      AND session.expires_at > now()
      AND session.csrf_token_hash <> p_new_csrf_token_hash
    RETURNING session.id,
              session.subject_id,
              session.expires_at,
              session.rotated_at;
END;
$$;

REVOKE ALL ON FUNCTION iam.rotate_session(bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.rotate_session(bytea, bytea, bytea) TO machina_runtime;

COMMENT ON FUNCTION iam.rotate_session(bytea, bytea, bytea) IS 'Atomically rotates an active server-side session to fresh session and CSRF token hashes without extending the absolute expiry; replayed, revoked, and expired sessions return no row.';

COMMIT;
