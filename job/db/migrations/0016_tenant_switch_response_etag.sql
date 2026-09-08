BEGIN;

ALTER TABLE ops.idempotency_keys
    ADD COLUMN response_etag text;

ALTER TABLE ops.idempotency_keys
    ADD CONSTRAINT idempotency_response_etag_format
    CHECK (response_etag IS NULL OR response_etag ~ '^"sha256:[0-9a-f]{64}"$');

CREATE FUNCTION ops.set_tenant_switch_response_etag(
    p_idempotency_key text,
    p_request_hash text,
    p_response_etag text
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
    IF p_idempotency_key IS NULL OR char_length(p_idempotency_key) NOT BETWEEN 16 AND 128 THEN
        RAISE EXCEPTION 'invalid idempotency key' USING ERRCODE = '22023';
    END IF;
    IF p_request_hash IS NULL OR p_request_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid idempotency request hash' USING ERRCODE = '22023';
    END IF;
    IF p_response_etag IS NULL OR p_response_etag !~ '^"sha256:[0-9a-f]{64}"$' THEN
        RAISE EXCEPTION 'invalid tenant-switch response etag' USING ERRCODE = '22023';
    END IF;

    UPDATE ops.idempotency_keys AS keyrow
    SET response_etag = p_response_etag
    WHERE keyrow.tenant_id = tenant_context
      AND keyrow.idempotency_key = p_idempotency_key
      AND keyrow.operation = 'tenant.switch.v1'
      AND keyrow.request_hash = p_request_hash
      AND keyrow.response_status = 200
      AND keyrow.response_body IS NOT NULL
      AND keyrow.response_etag IS NULL
      AND keyrow.expires_at > now();

    GET DIAGNOSTICS updated_count = ROW_COUNT;
    IF updated_count <> 1 THEN
        RAISE EXCEPTION 'tenant-switch response etag claim unavailable' USING ERRCODE = 'P0002';
    END IF;

    RETURN true;
END;
$$;

CREATE FUNCTION ops.get_tenant_switch_response_etag(
    p_idempotency_key text,
    p_request_hash text
)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
    SELECT keyrow.response_etag
    FROM ops.idempotency_keys AS keyrow
    WHERE keyrow.tenant_id = ops.current_tenant_id()
      AND keyrow.idempotency_key = p_idempotency_key
      AND keyrow.operation = 'tenant.switch.v1'
      AND keyrow.request_hash = p_request_hash
      AND keyrow.response_status = 200
      AND keyrow.response_body IS NOT NULL
      AND keyrow.response_etag IS NOT NULL
      AND keyrow.expires_at > now()
$$;

REVOKE ALL ON FUNCTION ops.set_tenant_switch_response_etag(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION ops.get_tenant_switch_response_etag(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.set_tenant_switch_response_etag(text, text, text) TO machina_runtime;
GRANT EXECUTE ON FUNCTION ops.get_tenant_switch_response_etag(text, text) TO machina_runtime;

COMMENT ON FUNCTION ops.set_tenant_switch_response_etag(text, text, text) IS 'Completes the tenant-switch response snapshot with its strong ETag while the target tenant transaction is still open.';
COMMENT ON FUNCTION ops.get_tenant_switch_response_etag(text, text) IS 'Returns the immutable strong ETag for a completed, unexpired tenant-switch response snapshot in the active tenant.';

COMMIT;
