-- name: GetTenant :one
SELECT id, slug, display_name, status, created_at, updated_at
FROM iam.tenants
WHERE id = sqlc.arg(tenant_id);

-- name: CreateTenant :one
INSERT INTO iam.tenants (id, slug, display_name, status)
VALUES (sqlc.arg(tenant_id), sqlc.arg(slug), sqlc.arg(display_name), 'active')
RETURNING id, slug, display_name, status, created_at, updated_at;

-- name: GetWorkspace :one
SELECT tenant_id, id, slug, display_name, created_at, updated_at
FROM iam.workspaces
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(workspace_id);

-- name: ListWorkspaces :many
SELECT tenant_id, id, slug, display_name, created_at, updated_at
FROM iam.workspaces
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY created_at, id;

-- name: CreateWorkspace :one
INSERT INTO iam.workspaces (tenant_id, id, slug, display_name)
VALUES (sqlc.arg(tenant_id), sqlc.arg(workspace_id), sqlc.arg(slug), sqlc.arg(display_name))
RETURNING tenant_id, id, slug, display_name, created_at, updated_at;

-- name: GetMembership :one
SELECT tenant_id, subject_id, starter_role, status, created_at, updated_at
FROM iam.memberships
WHERE tenant_id = sqlc.arg(tenant_id)
  AND subject_id = sqlc.arg(subject_id);

-- name: CreateMembership :one
INSERT INTO iam.memberships (tenant_id, subject_id, starter_role, status)
VALUES (sqlc.arg(tenant_id), sqlc.arg(subject_id), sqlc.arg(starter_role), 'active')
RETURNING tenant_id, subject_id, starter_role, status, created_at, updated_at;

-- name: GetPreference :one
SELECT tenant_id, subject_id, theme, locale, preferences, updated_at
FROM iam.preferences
WHERE tenant_id = sqlc.arg(tenant_id)
  AND subject_id = sqlc.arg(subject_id);

-- name: UpsertPreference :one
INSERT INTO iam.preferences (tenant_id, subject_id, theme, locale, preferences, updated_at)
VALUES (
  sqlc.arg(tenant_id),
  sqlc.arg(subject_id),
  sqlc.arg(theme),
  sqlc.arg(locale),
  sqlc.arg(preferences),
  now()
)
ON CONFLICT (tenant_id, subject_id) DO UPDATE
SET theme = EXCLUDED.theme,
    locale = EXCLUDED.locale,
    preferences = EXCLUDED.preferences,
    updated_at = now()
RETURNING tenant_id, subject_id, theme, locale, preferences, updated_at;
