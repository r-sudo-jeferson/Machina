BEGIN;

CREATE TABLE audit.events (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    actor_subject_id uuid,
    event_type text NOT NULL CHECK (char_length(event_type) BETWEEN 3 AND 160),
    action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 160),
    decision text CHECK (decision IN ('allow', 'deny')),
    policy_version bigint CHECK (policy_version IS NULL OR policy_version > 0),
    correlation_id uuid NOT NULL,
    safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(safe_metadata) = 'object'),
    previous_hash bytea CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
    event_hash bytea CHECK (event_hash IS NULL OR octet_length(event_hash) = 32),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES iam.tenants(id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_subject_id) REFERENCES iam.subjects(id) ON DELETE SET NULL
);

CREATE INDEX audit_events_tenant_occurred_idx ON audit.events(tenant_id, occurred_at DESC, id);
CREATE INDEX audit_events_correlation_idx ON audit.events(tenant_id, correlation_id);

CREATE TABLE ops.outbox (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    event_type text NOT NULL CHECK (char_length(event_type) BETWEEN 3 AND 160),
    event_version integer NOT NULL CHECK (event_version > 0),
    correlation_id uuid NOT NULL,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    occurred_at timestamptz NOT NULL,
    available_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error_code text,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES iam.tenants(id) ON DELETE CASCADE
);

CREATE INDEX outbox_pending_idx ON ops.outbox(available_at, occurred_at, tenant_id, id)
    WHERE published_at IS NULL;

CREATE TABLE ops.idempotency_keys (
    tenant_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 128),
    operation text NOT NULL CHECK (char_length(operation) BETWEEN 1 AND 160),
    request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    response_status integer CHECK (response_status BETWEEN 100 AND 599),
    response_body jsonb,
    correlation_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id) REFERENCES iam.tenants(id) ON DELETE CASCADE,
    CHECK (response_body IS NULL OR response_status IS NOT NULL)
);

CREATE INDEX idempotency_expiry_idx ON ops.idempotency_keys(expires_at, tenant_id);

COMMIT;
