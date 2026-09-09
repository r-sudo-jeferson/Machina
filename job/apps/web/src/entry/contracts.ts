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

export interface EntryGateway {
  loadSession(signal?: AbortSignal): Promise<SessionContext>;
}

export interface TenantSwitchCommand {
  tenantId: string;
  idempotencyKey: string;
}

export interface EntryMutationGateway extends EntryGateway {
  switchTenant(command: TenantSwitchCommand, signal?: AbortSignal): Promise<SessionContext>;
}
