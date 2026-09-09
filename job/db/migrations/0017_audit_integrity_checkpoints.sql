BEGIN;

-- The legacy previous_hash column never became an authoritative chain: callers
-- supplied it. Preserve the column for forward compatibility, but make the
-- invariant explicit before introducing the database-owned chain.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM audit.events
        WHERE previous_hash IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'audit.events contains caller-owned previous_hash values; migration requires explicit reconciliation'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM audit.events
        WHERE event_hash IS NULL OR octet_length(event_hash) <> 32
    ) THEN
        RAISE EXCEPTION 'audit.events contains missing or invalid event_hash values; chain backfill cannot proceed'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

ALTER TABLE audit.events
    ALTER COLUMN event_hash SET NOT NULL,
    ADD CONSTRAINT audit_events_previous_hash_not_authoritative
        CHECK (previous_hash IS NULL);

CREATE TABLE audit.chain_heads (
    tenant_id uuid PRIMARY KEY,
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    last_chain_hash bytea NOT NULL CHECK (octet_length(last_chain_hash) = 32),
    FOREIGN KEY (tenant_id) REFERENCES iam.tenants(id) ON DELETE RESTRICT
);

CREATE TABLE audit.event_chain (
    tenant_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_id uuid NOT NULL,
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    previous_chain_hash bytea NOT NULL CHECK (octet_length(previous_chain_hash) = 32),
    chain_hash bytea NOT NULL CHECK (octet_length(chain_hash) = 32),
    PRIMARY KEY (tenant_id, sequence),
    UNIQUE (tenant_id, event_id),
    UNIQUE (tenant_id, sequence, chain_hash),
    FOREIGN KEY (tenant_id, event_id)
        REFERENCES audit.events(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE audit.checkpoints (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    chain_sequence bigint NOT NULL CHECK (chain_sequence > 0),
    chain_hash bytea NOT NULL CHECK (octet_length(chain_hash) = 32),
    statement_digest bytea NOT NULL CHECK (octet_length(statement_digest) = 32),
    algorithm text NOT NULL CHECK (algorithm = 'ecdsa-p256-sha256'),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 200),
    signature bytea NOT NULL CHECK (octet_length(signature) BETWEEN 64 AND 256),
    signed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, chain_sequence, key_id),
    FOREIGN KEY (tenant_id, chain_sequence, chain_hash)
        REFERENCES audit.event_chain(tenant_id, sequence, chain_hash) ON DELETE RESTRICT
);

-- Backfill any pre-existing construction audit rows without rewriting history.
-- The canonical order is stable within a tenant and is used only once, before
-- the live append trigger is installed.
DO $$
DECLARE
    audit_row record;
    active_tenant uuid;
    next_sequence bigint := 0;
    previous_hash bytea := decode(repeat('00', 32), 'hex');
    next_hash bytea;
BEGIN
    FOR audit_row IN
        SELECT tenant_id, id, event_hash
        FROM audit.events
        ORDER BY tenant_id, occurred_at, id
    LOOP
        IF active_tenant IS DISTINCT FROM audit_row.tenant_id THEN
            IF active_tenant IS NOT NULL THEN
                INSERT INTO audit.chain_heads (tenant_id, last_sequence, last_chain_hash)
                VALUES (active_tenant, next_sequence, previous_hash);
            END IF;

            active_tenant := audit_row.tenant_id;
            next_sequence := 0;
            previous_hash := decode(repeat('00', 32), 'hex');
        END IF;

        next_sequence := next_sequence + 1;
        next_hash := sha256(previous_hash || audit_row.event_hash);

        INSERT INTO audit.event_chain (
            tenant_id,
            sequence,
            event_id,
            event_hash,
            previous_chain_hash,
            chain_hash
        ) VALUES (
            audit_row.tenant_id,
            next_sequence,
            audit_row.id,
            audit_row.event_hash,
            previous_hash,
            next_hash
        );

        previous_hash := next_hash;
    END LOOP;

    IF active_tenant IS NOT NULL THEN
        INSERT INTO audit.chain_heads (tenant_id, last_sequence, last_chain_hash)
        VALUES (active_tenant, next_sequence, previous_hash);
    END IF;
END;
$$;

ALTER TABLE audit.chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.chain_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.chain_heads
    FOR ALL TO machina_runtime, machina_migrator
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE audit.event_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.event_chain FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.event_chain
    FOR ALL TO machina_runtime, machina_migrator
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE audit.checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.checkpoints
    FOR ALL TO machina_runtime, machina_migrator
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

CREATE FUNCTION audit.reject_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'audit history is append-only'
        USING ERRCODE = '42501';
END;
$$;

REVOKE ALL ON FUNCTION audit.reject_history_mutation() FROM PUBLIC;

CREATE TRIGGER audit_events_reject_mutation
    BEFORE UPDATE OR DELETE ON audit.events
    FOR EACH ROW
    EXECUTE FUNCTION audit.reject_history_mutation();

CREATE TRIGGER audit_event_chain_reject_mutation
    BEFORE UPDATE OR DELETE ON audit.event_chain
    FOR EACH ROW
    EXECUTE FUNCTION audit.reject_history_mutation();

CREATE TRIGGER audit_checkpoints_reject_mutation
    BEFORE UPDATE OR DELETE ON audit.checkpoints
    FOR EACH ROW
    EXECUTE FUNCTION audit.reject_history_mutation();

CREATE FUNCTION audit.append_event_chain()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET row_security = on
AS $$
DECLARE
    tenant_context uuid;
    current_sequence bigint;
    current_hash bytea;
    next_hash bytea;
BEGIN
    tenant_context := ops.current_tenant_id();
    IF tenant_context IS NULL OR tenant_context <> NEW.tenant_id THEN
        RAISE EXCEPTION 'audit append requires matching transaction-local tenant context'
            USING ERRCODE = '42501';
    END IF;

    IF NEW.event_hash IS NULL OR octet_length(NEW.event_hash) <> 32 THEN
        RAISE EXCEPTION 'audit event_hash must be exactly 32 bytes'
            USING ERRCODE = '23514';
    END IF;

    INSERT INTO audit.chain_heads (tenant_id, last_sequence, last_chain_hash)
    VALUES (NEW.tenant_id, 0, decode(repeat('00', 32), 'hex'))
    ON CONFLICT (tenant_id) DO NOTHING;

    SELECT head.last_sequence, head.last_chain_hash
    INTO current_sequence, current_hash
    FROM audit.chain_heads AS head
    WHERE head.tenant_id = NEW.tenant_id
    FOR UPDATE;

    IF NOT FOUND OR current_sequence < 0 OR octet_length(current_hash) <> 32 THEN
        RAISE EXCEPTION 'audit chain head is missing or invalid'
            USING ERRCODE = '23514';
    END IF;

    next_hash := sha256(current_hash || NEW.event_hash);

    INSERT INTO audit.event_chain (
        tenant_id,
        sequence,
        event_id,
        event_hash,
        previous_chain_hash,
        chain_hash
    ) VALUES (
        NEW.tenant_id,
        current_sequence + 1,
        NEW.id,
        NEW.event_hash,
        current_hash,
        next_hash
    );

    UPDATE audit.chain_heads
    SET last_sequence = current_sequence + 1,
        last_chain_hash = next_hash
    WHERE tenant_id = NEW.tenant_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit chain head disappeared during append'
            USING ERRCODE = '40001';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION audit.append_event_chain() FROM PUBLIC;

CREATE TRIGGER audit_events_append_chain
    AFTER INSERT ON audit.events
    FOR EACH ROW
    EXECUTE FUNCTION audit.append_event_chain();

-- Existing 0007 grants included mutable privileges on audit.events. Harden the
-- runtime to append-only access and keep chain/head state trigger-owned.
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE audit.events FROM machina_runtime;
GRANT SELECT, INSERT ON TABLE audit.events TO machina_runtime;

REVOKE ALL ON TABLE audit.chain_heads, audit.event_chain, audit.checkpoints FROM machina_runtime;
GRANT SELECT ON TABLE audit.chain_heads, audit.event_chain TO machina_runtime;
GRANT SELECT, INSERT ON TABLE audit.checkpoints TO machina_runtime;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE
    audit.chain_heads,
    audit.event_chain,
    audit.checkpoints
FROM machina_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE machina_migrator IN SCHEMA audit REVOKE ALL ON TABLES FROM PUBLIC;

COMMENT ON TABLE audit.events IS 'Append-only tenant audit events. event_hash commits event content; authoritative chain linkage is maintained by audit.event_chain.';
COMMENT ON COLUMN audit.events.previous_hash IS 'Deprecated non-authoritative compatibility column. New and migrated S001 rows require NULL; chain linkage is database-owned in audit.event_chain.';
COMMENT ON TABLE audit.chain_heads IS 'Internal mutable per-tenant serialization head for append-only audit chaining; runtime may read but cannot write directly.';
COMMENT ON TABLE audit.event_chain IS 'Immutable per-tenant sequence linking each audit event hash by SHA-256(previous_chain_hash || event_hash).';
COMMENT ON TABLE audit.checkpoints IS 'Immutable signed attestations of audit-chain prefixes. Signature keys are external; only bounded key identifiers and signatures are stored.';
COMMENT ON FUNCTION audit.reject_history_mutation() IS 'Rejects UPDATE/DELETE attempts on append-only audit history tables without a role-based bypass.';
COMMENT ON FUNCTION audit.append_event_chain() IS 'Serializes each tenant audit append and persists its database-owned SHA-256 chain row in the same transaction as audit.events insertion.';

COMMIT;
