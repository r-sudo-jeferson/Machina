BEGIN;

CREATE TABLE ai.interactions (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    subject_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    provider text NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 80),
    model_id text NOT NULL CHECK (char_length(model_id) BETWEEN 1 AND 160),
    prompt_version text NOT NULL CHECK (char_length(prompt_version) BETWEEN 1 AND 80),
    tool_version text NOT NULL CHECK (char_length(tool_version) BETWEEN 1 AND 80),
    input_hash text NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    output_hash text CHECK (output_hash IS NULL OR output_hash ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('started', 'completed', 'cancelled', 'refused', 'failed', 'timed_out')),
    input_tokens integer CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens integer CHECK (output_tokens IS NULL OR output_tokens >= 0),
    cost_microusd bigint CHECK (cost_microusd IS NULL OR cost_microusd >= 0),
    latency_ms integer CHECK (latency_ms IS NULL OR latency_ms >= 0),
    first_token_ms integer CHECK (first_token_ms IS NULL OR first_token_ms >= 0),
    correlation_id uuid NOT NULL,
    error_code text,
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES iam.tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (subject_id) REFERENCES iam.subjects(id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES iam.workspaces(tenant_id, id) ON DELETE RESTRICT,
    CHECK ((status = 'started' AND completed_at IS NULL) OR status <> 'started')
);

CREATE INDEX ai_interactions_tenant_started_idx ON ai.interactions(tenant_id, started_at DESC, id);
CREATE INDEX ai_interactions_correlation_idx ON ai.interactions(tenant_id, correlation_id);

COMMIT;
