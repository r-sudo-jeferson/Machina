BEGIN;

CREATE FUNCTION ops.current_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

REVOKE ALL ON FUNCTION ops.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.current_tenant_id() TO machina_runtime;

ALTER TABLE iam.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON iam.tenants
    FOR ALL TO machina_runtime
    USING (id = ops.current_tenant_id())
    WITH CHECK (id = ops.current_tenant_id());

ALTER TABLE iam.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.workspaces FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON iam.workspaces
    FOR ALL TO machina_runtime
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE iam.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON iam.memberships
    FOR ALL TO machina_runtime
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE iam.invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON iam.invitations
    FOR ALL TO machina_runtime
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE iam.preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.preferences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON iam.preferences
    FOR ALL TO machina_runtime
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE authz.policy_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz.policy_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON authz.policy_snapshots
    FOR ALL TO machina_runtime
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE audit.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.events
    FOR ALL TO machina_runtime
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE ops.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ops.outbox
    FOR ALL TO machina_runtime
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE ops.idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.idempotency_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ops.idempotency_keys
    FOR ALL TO machina_runtime
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

ALTER TABLE ai.interactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.interactions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ai.interactions
    FOR ALL TO machina_runtime
    USING (tenant_id = ops.current_tenant_id())
    WITH CHECK (tenant_id = ops.current_tenant_id());

COMMIT;
