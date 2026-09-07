BEGIN;

CREATE TABLE iam.subjects (
    id uuid PRIMARY KEY,
    external_subject text NOT NULL UNIQUE,
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 160),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.tenants (
    id uuid PRIMARY KEY,
    slug text NOT NULL CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$' AND char_length(slug) BETWEEN 3 AND 63),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 160),
    status text NOT NULL CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.workspaces (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    slug text NOT NULL CHECK (char_length(slug) BETWEEN 1 AND 63),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 160),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, slug),
    FOREIGN KEY (tenant_id) REFERENCES iam.tenants(id) ON DELETE CASCADE
);

CREATE TABLE iam.memberships (
    tenant_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    starter_role text NOT NULL CHECK (starter_role IN ('owner', 'member')),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject_id),
    FOREIGN KEY (tenant_id) REFERENCES iam.tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (subject_id) REFERENCES iam.subjects(id) ON DELETE RESTRICT
);

CREATE INDEX memberships_subject_idx ON iam.memberships(subject_id, tenant_id);
CREATE INDEX memberships_tenant_role_status_idx ON iam.memberships(tenant_id, starter_role, status);

CREATE TABLE iam.invitations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    workspace_id uuid,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    invited_subject_id uuid,
    starter_role text NOT NULL CHECK (starter_role IN ('owner', 'member')),
    status text NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    created_by_subject_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES iam.tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES iam.workspaces(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (invited_subject_id) REFERENCES iam.subjects(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by_subject_id) REFERENCES iam.subjects(id) ON DELETE RESTRICT,
    CHECK (accepted_at IS NULL OR status = 'accepted')
);

CREATE INDEX invitations_tenant_status_idx ON iam.invitations(tenant_id, status, expires_at);

CREATE TABLE iam.sessions (
    id uuid PRIMARY KEY,
    subject_id uuid NOT NULL,
    session_token_hash bytea NOT NULL UNIQUE CHECK (octet_length(session_token_hash) = 32),
    csrf_token_hash bytea NOT NULL CHECK (octet_length(csrf_token_hash) = 32),
    active_tenant_id uuid,
    active_workspace_id uuid,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    rotated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (subject_id) REFERENCES iam.subjects(id) ON DELETE CASCADE,
    FOREIGN KEY (active_tenant_id) REFERENCES iam.tenants(id) ON DELETE SET NULL,
    FOREIGN KEY (active_tenant_id, active_workspace_id) REFERENCES iam.workspaces(tenant_id, id) MATCH FULL ON DELETE SET NULL,
    CHECK ((active_tenant_id IS NULL) = (active_workspace_id IS NULL))
);

CREATE INDEX sessions_subject_expiry_idx ON iam.sessions(subject_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE iam.preferences (
    tenant_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    theme text NOT NULL DEFAULT 'silver' CHECK (theme IN ('silver', 'space-black')),
    locale text NOT NULL DEFAULT 'en-US' CHECK (locale IN ('en-US', 'pt-BR')),
    preferences jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(preferences) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject_id),
    FOREIGN KEY (tenant_id, subject_id) REFERENCES iam.memberships(tenant_id, subject_id) ON DELETE CASCADE
);

COMMIT;
