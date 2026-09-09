import type {
  AuthorizedContext,
  Capability,
  EntryGateway,
  Identity,
  SessionContext,
  Tenant,
  Workspace,
} from './contracts';

const SESSION_ENDPOINT = '/api/v1/session';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringField(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Invalid session payload: ${field} must be a non-empty string.`);
  }
  return value;
}

function parseIdentity(value: unknown): Identity {
  if (!isRecord(value)) {
    throw new Error('Invalid session payload: identity must be an object.');
  }
  return {id: stringField(value, 'id'), display_name: stringField(value, 'display_name')};
}

function parseTenant(value: unknown): Tenant {
  if (!isRecord(value)) {
    throw new Error('Invalid session payload: tenant must be an object.');
  }
  const status = stringField(value, 'status');
  if (status !== 'active' && status !== 'suspended') {
    throw new Error('Invalid session payload: tenant status is unsupported.');
  }
  return {
    id: stringField(value, 'id'),
    slug: stringField(value, 'slug'),
    display_name: stringField(value, 'display_name'),
    status,
  };
}

function parseWorkspace(value: unknown): Workspace {
  if (!isRecord(value)) {
    throw new Error('Invalid session payload: workspace must be an object.');
  }
  return {
    id: stringField(value, 'id'),
    tenant_id: stringField(value, 'tenant_id'),
    slug: stringField(value, 'slug'),
    display_name: stringField(value, 'display_name'),
  };
}

function parseCapability(value: unknown): Capability {
  if (!isRecord(value) || typeof value.allowed !== 'boolean') {
    throw new Error('Invalid session payload: capability is malformed.');
  }
  const capability: Capability = {
    id: stringField(value, 'id'),
    allowed: value.allowed,
  };
  if (value.reason_code !== undefined) {
    if (typeof value.reason_code !== 'string' || value.reason_code.length === 0) {
      throw new Error('Invalid session payload: capability reason_code is malformed.');
    }
    return {...capability, reason_code: value.reason_code};
  }
  return capability;
}

function parseAuthorizedContext(value: unknown): AuthorizedContext {
  if (!isRecord(value) || !Array.isArray(value.capabilities)) {
    throw new Error('Invalid session payload: active context is malformed.');
  }
  if (!Number.isInteger(value.policy_version) || Number(value.policy_version) < 1) {
    throw new Error('Invalid session payload: policy_version must be a positive integer.');
  }
  return {
    identity: parseIdentity(value.identity),
    tenant: parseTenant(value.tenant),
    workspace: parseWorkspace(value.workspace),
    capabilities: value.capabilities.map(parseCapability),
    policy_version: Number(value.policy_version),
  };
}

export function parseSessionContext(value: unknown): SessionContext {
  if (!isRecord(value) || !Array.isArray(value.available_tenants)) {
    throw new Error('Invalid session payload: session context is malformed.');
  }
  const identity = parseIdentity(value.identity);
  const active = parseAuthorizedContext(value.active);
  const expiresAt = stringField(value, 'expires_at');
  if (Number.isNaN(Date.parse(expiresAt))) {
    throw new Error('Invalid session payload: expires_at must be an ISO date-time.');
  }
  if (active.identity.id !== identity.id) {
    throw new Error('Invalid session payload: active identity does not match session identity.');
  }
  if (active.workspace.tenant_id !== active.tenant.id) {
    throw new Error('Invalid session payload: workspace tenant does not match active tenant.');
  }
  const availableTenants = value.available_tenants.map(parseTenant);
  if (!availableTenants.some((tenant) => tenant.id === active.tenant.id)) {
    throw new Error('Invalid session payload: active tenant is not in available_tenants.');
  }
  return {
    identity,
    active,
    available_tenants: availableTenants,
    expires_at: expiresAt,
  };
}

export class EntryHttpError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly correlationId: string | undefined;

  constructor(message: string, status: number, code?: string, correlationId?: string) {
    super(message);
    this.name = 'EntryHttpError';
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
  }
}

async function responseError(response: Response): Promise<EntryHttpError> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = undefined;
  }

  if (isRecord(payload)) {
    const title = typeof payload.title === 'string' ? payload.title : `Request failed (${response.status})`;
    const detail = typeof payload.detail === 'string' ? payload.detail : undefined;
    const code = typeof payload.code === 'string' ? payload.code : undefined;
    const correlationId = typeof payload.correlation_id === 'string' ? payload.correlation_id : undefined;
    return new EntryHttpError(
      detail === undefined ? title : `${title}: ${detail}`,
      response.status,
      code,
      correlationId,
    );
  }

  return new EntryHttpError(`Request failed (${response.status}).`, response.status);
}

export function createBrowserEntryGateway(fetcher: typeof fetch = globalThis.fetch): EntryGateway {
  return {
    async loadSession(signal?: AbortSignal): Promise<SessionContext> {
      const response = await fetcher(SESSION_ENDPOINT, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {Accept: 'application/json'},
        signal: signal ?? null,
      });
      if (!response.ok) {
        throw await responseError(response);
      }
      return parseSessionContext(await response.json());
    },
  };
}
