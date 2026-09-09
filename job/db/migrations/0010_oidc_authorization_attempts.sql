BEGIN;

CREATE TABLE iam.oidc_authorization_attempts (
    state_hash bytea PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    nonce_hash bytea CHECK (nonce_hash IS NULL OR octet_length(nonce_hash) = 32),
    pkce_verifier text CHECK (
        pkce_verifier IS NULL
        OR pkce_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'
    ),
    redirect_uri text CHECK (
        redirect_uri IS NULL
        OR (
            char_length(redirect_uri) BETWEEN 1 AND 2048
            AND redirect_uri = btrim(redirect_uri)
        )
    ),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (
        (
            consumed_at IS NULL
            AND nonce_hash IS NOT NULL
            AND pkce_verifier IS NOT NULL
            AND redirect_uri IS NOT NULL
        )
        OR (
            consumed_at IS NOT NULL
            AND nonce_hash IS NULL
            AND pkce_verifier IS NULL
            AND redirect_uri IS NULL
        )
    )
);

CREATE INDEX oidc_authorization_attempts_active_expiry_idx
ON iam.oidc_authorization_attempts (expires_at)
WHERE consumed_at IS NULL;

ALTER TABLE iam.oidc_authorization_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.oidc_authorization_attempts FORCE ROW LEVEL SECURITY;

CREATE POLICY oidc_authorization_attempt_migrator_access
ON iam.oidc_authorization_attempts
FOR ALL
TO machina_migrator
USING (current_user = 'machina_migrator')
WITH CHECK (current_user = 'machina_migrator');

REVOKE ALL ON TABLE iam.oidc_authorization_attempts FROM PUBLIC;
REVOKE ALL ON TABLE iam.oidc_authorization_attempts FROM machina_runtime;

CREATE FUNCTION iam.create_oidc_authorization_attempt(
    p_state_hash bytea,
    p_nonce_hash bytea,
    p_pkce_verifier text,
    p_redirect_uri text,
    p_expires_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
BEGIN
    IF p_state_hash IS NULL OR octet_length(p_state_hash) <> 32 THEN
        RAISE EXCEPTION 'OIDC state hash must contain exactly 32 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_nonce_hash IS NULL OR octet_length(p_nonce_hash) <> 32 THEN
        RAISE EXCEPTION 'OIDC nonce hash must contain exactly 32 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_pkce_verifier IS NULL OR p_pkce_verifier !~ '^[A-Za-z0-9._~-]{43,128}$' THEN
        RAISE EXCEPTION 'OIDC PKCE verifier must be 43 to 128 RFC 7636 unreserved characters' USING ERRCODE = '22023';
    END IF;
    IF p_redirect_uri IS NULL
       OR char_length(p_redirect_uri) NOT BETWEEN 1 AND 2048
       OR p_redirect_uri <> btrim(p_redirect_uri) THEN
        RAISE EXCEPTION 'OIDC redirect URI must be a non-empty bounded value without surrounding whitespace' USING ERRCODE = '22023';
    END IF;
    IF p_expires_at IS NULL OR p_expires_at <= now() THEN
        RAISE EXCEPTION 'OIDC authorization attempt expiry must be in the future' USING ERRCODE = '22023';
    END IF;
    IF p_expires_at > now() + interval '15 minutes' THEN
        RAISE EXCEPTION 'OIDC authorization attempt lifetime must not exceed 15 minutes' USING ERRCODE = '22023';
    END IF;

    UPDATE iam.oidc_authorization_attempts
    SET nonce_hash = NULL,
        pkce_verifier = NULL,
        redirect_uri = NULL,
        consumed_at = now()
    WHERE consumed_at IS NULL
      AND expires_at <= now();

    INSERT INTO iam.oidc_authorization_attempts (
        state_hash,
        nonce_hash,
        pkce_verifier,
        redirect_uri,
        expires_at
    )
    VALUES (
        p_state_hash,
        p_nonce_hash,
        p_pkce_verifier,
        p_redirect_uri,
        p_expires_at
    );
END;
$$;

CREATE FUNCTION iam.consume_oidc_authorization_attempt(p_state_hash bytea)
RETURNS TABLE (
    nonce_hash bytea,
    pkce_verifier text,
    redirect_uri text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    stored_nonce_hash bytea;
    stored_pkce_verifier text;
    stored_redirect_uri text;
    stored_expires_at timestamptz;
BEGIN
    IF p_state_hash IS NULL OR octet_length(p_state_hash) <> 32 THEN
        RETURN;
    END IF;

    SELECT
        attempt.nonce_hash,
        attempt.pkce_verifier,
        attempt.redirect_uri,
        attempt.expires_at
    INTO
        stored_nonce_hash,
        stored_pkce_verifier,
        stored_redirect_uri,
        stored_expires_at
    FROM iam.oidc_authorization_attempts AS attempt
    WHERE attempt.state_hash = p_state_hash
      AND attempt.consumed_at IS NULL
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    UPDATE iam.oidc_authorization_attempts
    SET nonce_hash = NULL,
        pkce_verifier = NULL,
        redirect_uri = NULL,
        consumed_at = now()
    WHERE state_hash = p_state_hash
      AND consumed_at IS NULL;

    IF stored_expires_at <= now() THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT stored_nonce_hash, stored_pkce_verifier, stored_redirect_uri;
END;
$$;

REVOKE ALL ON FUNCTION iam.create_oidc_authorization_attempt(bytea, bytea, text, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.consume_oidc_authorization_attempt(bytea) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION iam.create_oidc_authorization_attempt(bytea, bytea, text, text, timestamptz) TO machina_runtime;
GRANT EXECUTE ON FUNCTION iam.consume_oidc_authorization_attempt(bytea) TO machina_runtime;

COMMENT ON TABLE iam.oidc_authorization_attempts IS 'Short-lived server-side OIDC authorization attempts. Raw state and nonce are never persisted; callback secrets are scrubbed on consumption or expiry maintenance.';
COMMENT ON FUNCTION iam.create_oidc_authorization_attempt(bytea, bytea, text, text, timestamptz) IS 'Narrow runtime boundary for storing hashed OIDC state/nonce plus the server-side PKCE verifier and exact allowlisted redirect URI for at most 15 minutes.';
COMMENT ON FUNCTION iam.consume_oidc_authorization_attempt(bytea) IS 'Atomically consumes an OIDC state exactly once under row lock, scrubs callback secrets before returning them, and returns nothing for missing, replayed, or expired state.';

COMMIT;
