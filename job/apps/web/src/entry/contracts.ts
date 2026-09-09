export type AlloyTheme = 'silver' | 'space-black';

export interface Identity {
  id: string;
  display_name: string;
}

export interface Tenant {
  id: string;
  slug: string;
  display_name: string;
  status: 'active' | 'suspended';
}

export interface Workspace {
  id: string;
  tenant_id: string;
  slug: string;
  display_name: string;
}

export interface Capability {
  id: string;
  allowed: boolean;
  reason_code?: string;
}

export interface AuthorizedContext {
  identity: Identity;
  tenant: Tenant;
  workspace: Workspace;
  capabilities: readonly Capability[];
  policy_version: number;
}

export interface SessionContext {
  identity: Identity;
  active: AuthorizedContext;
  available_tenants: readonly Tenant[];
  expires_at: string;
}

export interface CreateTenantInput {
  tenant_name: string;
  tenant_slug: string;
  workspace_name: string;
}

export interface Membership {
  tenant_id: string;
  subject_id: string;
  starter_role: 'owner' | 'member';
  status: 'active' | 'revoked';
}

export interface TenantBootstrap {
  tenant: Tenant;
  workspace: Workspace;
  membership: Membership;
}

export interface EntryGateway {
  loadSession(signal?: AbortSignal): Promise<SessionContext>;
  switchTenant(tenantId: string, signal?: AbortSignal): Promise<SessionContext>;
  createTenant(input: CreateTenantInput, signal?: AbortSignal): Promise<TenantBootstrap>;
  acceptInvitation(token: string, signal?: AbortSignal): Promise<Membership>;
}
