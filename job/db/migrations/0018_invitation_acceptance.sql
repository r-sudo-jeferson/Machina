BEGIN;

-- Invitation acceptance starts from an opaque token before a tenant context is
-- known. The migration owner may resolve a token to its tenant, but every
-- mutation remains constrained by the ordinary tenant policy after the target
-- tenant is established transaction-locally. Runtime never receives this
-- unscoped SELECT capability.
ALTER POLICY tenant_isolation ON iam.invitations TO machina_runtime, machina_migrator;

CREATE POLICY invitation_token_resolution ON iam.invitations
    FOR SELECT
    TO machina_migrator
    USING (true);

CREATE FUNCTION iam.accept_invitation(
    p_token_hash bytea,
    p_subject_id uuid
)
RETURNS TABLE (
    tenant_id uuid,
    subject_id uuid,
    starter_role text,
    status text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    target_tenant_id uuid;
    tenant_status text;
    previous_tenant_context text;
    invitation iam.invitations%ROWTYPE;
    membership iam.memberships%ROWTYPE;
BEGIN
    IF p_token_hash IS NULL OR octet_length(p_token_hash) <> 32 THEN
        RAISE EXCEPTION 'invitation token hash must contain exactly 32 bytes'
            USING ERRCODE = '22023';
    END IF;
    IF p_subject_id IS NULL THEN
        RAISE EXCEPTION 'subject id is required'
            USING ERRCODE = '22023';
    END IF;

    PERFORM 1
    FROM iam.subjects AS subject
    WHERE subject.id = p_subject_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authenticated subject does not exist'
            USING ERRCODE = 'P0002';
    END IF;

    -- This is intentionally the only unscoped invitation-table lookup. It is
    -- executed as machina_migrator through the SELECT-only policy above and
    -- reveals no invitation data to the runtime caller.
    SELECT candidate.tenant_id
    INTO target_tenant_id
    FROM iam.invitations AS candidate
    WHERE candidate.token_hash = p_token_hash;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'invitation is unavailable'
            USING ERRCODE = 'P0002';
    END IF;

    previous_tenant_context := current_setting('app.tenant_id', true);

    BEGIN
        PERFORM set_config('app.tenant_id', target_tenant_id::text, true);

        -- The tenant row is the canonical serialization lock for security-
        -- sensitive membership mutations in this tenant.
        SELECT tenant.status
        INTO tenant_status
        FROM iam.tenants AS tenant
        WHERE tenant.id = target_tenant_id
        FOR UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'invitation tenant is unavailable'
                USING ERRCODE = 'P0002';
        END IF;
        IF tenant_status = 'suspended' THEN
            RAISE EXCEPTION 'invitation tenant is suspended'
                USING ERRCODE = '42501';
        END IF;

        -- Re-read and lock after tenant context is established so all state
        -- decisions below are based on the serialized canonical invitation.
        SELECT candidate.*
        INTO invitation
        FROM iam.invitations AS candidate
        WHERE candidate.tenant_id = target_tenant_id
          AND candidate.token_hash = p_token_hash
        FOR UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'invitation changed during acceptance'
                USING ERRCODE = '40001';
        END IF;

        IF invitation.status = 'revoked' THEN
            RAISE EXCEPTION 'invitation is revoked'
                USING ERRCODE = '42501';
        END IF;
        IF invitation.status = 'expired' THEN
            RAISE EXCEPTION 'invitation is expired'
                USING ERRCODE = '42501';
        END IF;
        IF invitation.expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'invitation is expired'
                USING ERRCODE = '42501';
        END IF;
        IF invitation.invited_subject_id IS NOT NULL
           AND invitation.invited_subject_id <> p_subject_id THEN
            RAISE EXCEPTION 'invitation is bound to another subject'
                USING ERRCODE = '42501';
        END IF;

        SELECT existing.*
        INTO membership
        FROM iam.memberships AS existing
        WHERE existing.tenant_id = invitation.tenant_id
          AND existing.subject_id = p_subject_id
        FOR UPDATE;

        IF invitation.status = 'accepted' THEN
            IF NOT FOUND
               OR membership.status = 'revoked'
               OR membership.starter_role <> invitation.starter_role THEN
                RAISE EXCEPTION 'accepted invitation no longer maps to the authorized membership'
                    USING ERRCODE = '42501';
            END IF;

            PERFORM set_config('app.tenant_id', COALESCE(previous_tenant_context, ''), true);
            RETURN QUERY
            SELECT membership.tenant_id,
                   membership.subject_id,
                   membership.starter_role,
                   membership.status;
            RETURN;
        END IF;

        IF invitation.status <> 'pending' THEN
            RAISE EXCEPTION 'invitation state is not acceptable'
                USING ERRCODE = '42501';
        END IF;

        IF FOUND THEN
            IF membership.status = 'revoked' THEN
                RAISE EXCEPTION 'revoked membership cannot be reactivated by invitation'
                    USING ERRCODE = '42501';
            END IF;
            IF membership.starter_role <> invitation.starter_role THEN
                RAISE EXCEPTION 'invitation cannot change an existing membership role'
                    USING ERRCODE = '42501';
            END IF;
        ELSE
            INSERT INTO iam.memberships (
                tenant_id,
                subject_id,
                starter_role,
                status
            )
            VALUES (
                invitation.tenant_id,
                p_subject_id,
                invitation.starter_role,
                'active'
            )
            RETURNING * INTO membership;
        END IF;

        UPDATE iam.invitations AS accepted
        SET invited_subject_id = p_subject_id,
            status = 'accepted',
            accepted_at = clock_timestamp()
        WHERE accepted.tenant_id = invitation.tenant_id
          AND accepted.id = invitation.id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'invitation disappeared during acceptance'
                USING ERRCODE = '40001';
        END IF;

        PERFORM set_config('app.tenant_id', COALESCE(previous_tenant_context, ''), true);
        RETURN QUERY
        SELECT membership.tenant_id,
               membership.subject_id,
               membership.starter_role,
               membership.status;
        RETURN;
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM set_config('app.tenant_id', COALESCE(previous_tenant_context, ''), true);
            RAISE;
    END;
END;
$$;

REVOKE ALL ON FUNCTION iam.accept_invitation(bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.accept_invitation(bytea, uuid) TO machina_runtime;

COMMENT ON FUNCTION iam.accept_invitation(bytea, uuid) IS 'Fail-closed invitation acceptance boundary: resolves only a hashed opaque token, serializes against the tenant, refuses suspended/revoked/expired/conflicting state, and idempotently returns only the authorized membership.';

COMMIT;
