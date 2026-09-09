BEGIN;

ALTER POLICY tenant_isolation ON ops.idempotency_keys TO machina_runtime, machina_migrator;
REVOKE ALL ON TABLE ops.idempotency_keys FROM machina_runtime;

CREATE FUNCTION ops.claim_idempotency_key(
    p_idempotency_key text,
    p_operation text,
    p_request_hash text,
    p_correlation_id uuid,
    p_expires_at timestamptz
)
RETURNS TABLE (
    claim_state text,
    response_status integer,
    response_body jsonb,
    correlation_id uuid
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    tenant_context uuid;
    inserted_count integer;
    existing_operation text;
    existing_request_hash text;
    existing_response_status integer;
    existing_response_body jsonb;
    existing_correlation_id uuid;
    existing_expires_at timestamptz;
BEGIN
    tenant_context := ops.current_tenant_id();
    IF tenant_context IS NULL THEN
        RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
    END IF;
    IF p_idempotency_key IS NULL OR char_length(p_idempotency_key) NOT BETWEEN 16 AND 128 THEN
        RAISE EXCEPTION 'invalid idempotency key' USING ERRCODE = '22023';
    END IF;
    IF p_operation IS NULL OR char_length(p_operation) NOT BETWEEN 1 AND 160 THEN
        RAISE EXCEPTION 'invalid idempotency operation' USING ERRCODE = '22023';
    END IF;
    IF p_request_hash IS NULL OR p_request_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid idempotency request hash' USING ERRCODE = '22023';
    END IF;
    IF p_correlation_id IS NULL THEN
        RAISE EXCEPTION 'correlation id is required' USING ERRCODE = '22023';
    END IF;
    IF p_expires_at IS NULL OR p_expires_at <= now() THEN
        RAISE EXCEPTION 'idempotency expiry must be in the future' USING ERRCODE = '22023';
    END IF;

    INSERT INTO ops.idempotency_keys (
        tenant_id,
        idempotency_key,
        operation,
        request_hash,
        correlation_id,
        expires_at
    )
    VALUES (
        tenant_context,
        p_idempotency_key,
        p_operation,
        p_request_hash,
        p_correlation_id,
        p_expires_at
    )
    ON CONFLICT (tenant_id, idempotency_key) DO NOTHING;

    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count = 1 THEN
        claim_state := 'claimed';
        response_status := NULL;
        response_body := NULL;
        correlation_id := p_correlation_id;
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT
        keyrow.operation,
        keyrow.request_hash,
        keyrow.response_status,
        keyrow.response_body,
        keyrow.correlation_id,
        keyrow.expires_at
    INTO
        existing_operation,
        existing_request_hash,
        existing_response_status,
        existing_response_body,
        existing_correlation_id,
        existing_expires_at
    FROM ops.idempotency_keys AS keyrow
    WHERE keyrow.tenant_id = tenant_context
      AND keyrow.idempotency_key = p_idempotency_key
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'idempotency claim changed concurrently' USING ERRCODE = '40001';
    END IF;

    IF existing_expires_at <= now() THEN
        UPDATE ops.idempotency_keys AS keyrow
        SET operation = p_operation,
            request_hash = p_request_hash,
            response_status = NULL,
            response_body = NULL,
            correlation_id = p_correlation_id,
            created_at = now(),
            expires_at = p_expires_at
        WHERE keyrow.tenant_id = tenant_context
          AND keyrow.idempotency_key = p_idempotency_key;

        claim_state := 'claimed';
        response_status := NULL;
        response_body := NULL;
        correlation_id := p_correlation_id;
        RETURN NEXT;
        RETURN;
    END IF;

    IF existing_operation <> p_operation OR existing_request_hash <> p_request_hash THEN
        claim_state := 'conflict';
        response_status := NULL;
        response_body := NULL;
        correlation_id := existing_correlation_id;
        RETURN NEXT;
        RETURN;
    END IF;

    IF existing_response_status IS NULL THEN
        claim_state := 'in_progress';
        response_status := NULL;
        response_body := NULL;
        correlation_id := existing_correlation_id;
        RETURN NEXT;
        RETURN;
    END IF;

    claim_state := 'replay';
    response_status := existing_response_status;
    response_body := existing_response_body;
    correlation_id := existing_correlation_id;
    RETURN NEXT;
END;
$$;

CREATE FUNCTION ops.complete_idempotency_key(
    p_idempotency_key text,
    p_operation text,
    p_request_hash text,
    p_response_status integer,
    p_response_body jsonb
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    tenant_context uuid;
    updated_count integer;
BEGIN
    tenant_context := ops.current_tenant_id();
    IF tenant_context IS NULL THEN
        RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
    END IF;
    IF p_response_status IS NULL OR p_response_status NOT BETWEEN 100 AND 599 THEN
        RAISE EXCEPTION 'invalid idempotency response status' USING ERRCODE = '22023';
    END IF;

    UPDATE ops.idempotency_keys AS keyrow
    SET response_status = p_response_status,
        response_body = p_response_body
    WHERE keyrow.tenant_id = tenant_context
      AND keyrow.idempotency_key = p_idempotency_key
      AND keyrow.operation = p_operation
      AND keyrow.request_hash = p_request_hash
      AND keyrow.response_status IS NULL
      AND keyrow.expires_at > now();

    GET DIAGNOSTICS updated_count = ROW_COUNT;
    IF updated_count <> 1 THEN
        RAISE EXCEPTION 'idempotency claim unavailable for completion' USING ERRCODE = 'P0002';
    END IF;

    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION ops.claim_idempotency_key(text, text, text, uuid, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION ops.complete_idempotency_key(text, text, text, integer, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.claim_idempotency_key(text, text, text, uuid, timestamptz) TO machina_runtime;
GRANT EXECUTE ON FUNCTION ops.complete_idempotency_key(text, text, text, integer, jsonb) TO machina_runtime;

COMMENT ON FUNCTION ops.claim_idempotency_key(text, text, text, uuid, timestamptz) IS 'Tenant-scoped idempotency claim boundary. Derives tenant from transaction-local server context, serializes same-key callers, returns claimed/replay/in_progress/conflict, and permits expired-key reuse.';
COMMENT ON FUNCTION ops.complete_idempotency_key(text, text, text, integer, jsonb) IS 'Completes exactly one matching, unexpired idempotency claim in the active tenant transaction; mismatched or stale completion fails closed.';

COMMIT;
