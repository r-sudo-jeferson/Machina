BEGIN;

-- Invitation acceptance is the only authorized runtime mutation/read boundary
-- for iam.invitations. Earlier migrations granted ordinary tenant-scoped table
-- access to machina_runtime before the opaque-token acceptance function
-- existed. Once iam.accept_invitation(bytea, uuid) is available, retaining
-- those table privileges would allow application code to bypass the narrow
-- SECURITY DEFINER contract and couple itself to invitation storage.
REVOKE ALL PRIVILEGES ON TABLE iam.invitations FROM machina_runtime;

-- Keep only the explicit capability required by the product contract. The
-- function executes as machina_migrator with FORCE RLS still enabled, resolves
-- only a hashed opaque token, establishes the target tenant transaction-locally
-- and returns only the resulting authorized membership.
REVOKE ALL ON FUNCTION iam.accept_invitation(bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.accept_invitation(bytea, uuid) TO machina_runtime;

COMMENT ON TABLE iam.invitations IS 'Invitation storage is migration-owned; machina_runtime has no direct table privileges and accepts invitations only through iam.accept_invitation(bytea, uuid).';

COMMIT;
