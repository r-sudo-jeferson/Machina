BEGIN;

CREATE TABLE authz.policy_snapshots (
    tenant_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    snapshot_hash text NOT NULL CHECK (snapshot_hash ~ '^[0-9a-f]{64}$'),
    cedar_schema jsonb NOT NULL CHECK (jsonb_typeof(cedar_schema) = 'object'),
    cedar_policies text NOT NULL,
    status text NOT NULL CHECK (status IN ('draft', 'active', 'retired')),
    created_by_subject_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    PRIMARY KEY (tenant_id, version),
    UNIQUE (tenant_id, snapshot_hash),
    FOREIGN KEY (tenant_id) REFERENCES iam.tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_subject_id) REFERENCES iam.subjects(id) ON DELETE RESTRICT,
    CHECK ((status = 'active' AND activated_at IS NOT NULL) OR status <> 'active')
);

CREATE UNIQUE INDEX policy_snapshots_one_active_per_tenant
    ON authz.policy_snapshots(tenant_id)
    WHERE status = 'active';

COMMIT;
