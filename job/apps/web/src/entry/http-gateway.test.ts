import {describe, expect, it} from 'vitest';
import {
  EntryHttpError,
  createBrowserEntryGateway,
  parseSessionContext,
} from './http-gateway';

function sessionPayload() {
  return {
    identity: {
      id: '00000000-0000-4000-8000-000000000001',
      display_name: 'Ada Lovelace',
    },
    active: {
      identity: {
        id: '00000000-0000-4000-8000-000000000001',
        display_name: 'Ada Lovelace',
      },
      tenant: {
        id: '00000000-0000-4000-8000-000000000010',
        slug: 'acme',
        display_name: 'Acme',
        status: 'active',
      },
      workspace: {
        id: '00000000-0000-4000-8000-000000000020',
        tenant_id: '00000000-0000-4000-8000-000000000010',
        slug: 'core',
        display_name: 'Core',
      },
      capabilities: [
        {id: 'context.read', allowed: true},
        {id: 'tenant.admin', allowed: false, reason_code: 'role_not_permitted'},
      ],
      policy_version: 7,
    },
    available_tenants: [
      {
        id: '00000000-0000-4000-8000-000000000010',
        slug: 'acme',
        display_name: 'Acme',
        status: 'active',
      },
    ],
    expires_at: '2026-09-10T12:00:00Z',
  };
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {'Content-Type': 'application/json'},
  });
}

describe('parseSessionContext', () => {
  it('accepts a coherent server-authorized session payload', () => {
    const session = parseSessionContext(sessionPayload());

    expect(session.active.tenant.slug).toBe('acme');
    expect(session.active.workspace.slug).toBe('core');
    expect(session.active.capabilities[1]).toEqual({
      id: 'tenant.admin',
      allowed: false,
      reason_code: 'role_not_permitted',
    });
  });

  it('rejects date-only values that are not OpenAPI date-time values', () => {
    const payload = sessionPayload();
    payload.expires_at = '2026-09-10';

    expect(() => parseSessionContext(payload)).toThrow(/expires_at/i);
  });

  it('rejects an active identity that differs from the session identity', () => {
    const payload = sessionPayload();
    payload.active.identity.id = '00000000-0000-4000-8000-000000000099';

    expect(() => parseSessionContext(payload)).toThrow(/active identity/i);
  });

  it('rejects a workspace owned by a different tenant', () => {
    const payload = sessionPayload();
    payload.active.workspace.tenant_id = '00000000-0000-4000-8000-000000000099';

    expect(() => parseSessionContext(payload)).toThrow(/workspace tenant/i);
  });

  it('rejects an active tenant absent from available_tenants', () => {
    const payload = sessionPayload();
    payload.available_tenants = [];

    expect(() => parseSessionContext(payload)).toThrow(/available_tenants/i);
  });
});

describe('createBrowserEntryGateway', () => {
  it('loads the session from the same-origin contract and forwards cancellation', async () => {
    let seenInput: RequestInfo | URL | undefined;
    let seenInit: RequestInit | undefined;
    const fetcher: typeof fetch = async (input, init) => {
      seenInput = input;
      seenInit = init;
      return jsonResponse(sessionPayload());
    };
    const controller = new AbortController();

    const session = await createBrowserEntryGateway(fetcher).loadSession(controller.signal);

    expect(seenInput).toBe('/api/v1/session');
    expect(seenInit?.method).toBe('GET');
    expect(seenInit?.credentials).toBe('same-origin');
    expect(seenInit?.headers).toEqual({Accept: 'application/json'});
    expect(seenInit?.signal).toBe(controller.signal);
    expect(session.active.tenant.display_name).toBe('Acme');
  });

  it('preserves RFC9457 problem code and correlation id on HTTP failures', async () => {
    const fetcher: typeof fetch = async () =>
      jsonResponse(
        {
          title: 'Unauthorized',
          detail: 'Session required.',
          code: 'session_required',
          correlation_id: 'corr-123',
        },
        401,
      );

    const error = await createBrowserEntryGateway(fetcher)
      .loadSession()
      .then(
        () => undefined,
        (caught: unknown) => caught,
      );

    expect(error).toBeInstanceOf(EntryHttpError);
    expect(error).toMatchObject({
      status: 401,
      code: 'session_required',
      correlationId: 'corr-123',
    });
    expect((error as Error).message).toContain('Session required.');
  });

  it('switches tenant with caller-stable idempotency and server-authorized response context', async () => {
    const switched = sessionPayload();
    switched.available_tenants.push({
      id: '00000000-0000-4000-8000-000000000011',
      slug: 'globex',
      display_name: 'Globex',
      status: 'active',
    });
    switched.active.tenant = switched.available_tenants[1]!;
    switched.active.workspace = {
      id: '00000000-0000-4000-8000-000000000021',
      tenant_id: '00000000-0000-4000-8000-000000000011',
      slug: 'ops',
      display_name: 'Operations',
    };

    let seenInput: RequestInfo | URL | undefined;
    let seenInit: RequestInit | undefined;
    const fetcher: typeof fetch = async (input, init) => {
      seenInput = input;
      seenInit = init;
      return jsonResponse(switched);
    };
    const controller = new AbortController();
    type MutationGateway = ReturnType<typeof createBrowserEntryGateway> & {
      switchTenant(
        request: {tenantId: string; idempotencyKey: string},
        signal?: AbortSignal,
      ): Promise<ReturnType<typeof parseSessionContext>>;
    };
    type GatewayFactory = (
      fetcher: typeof fetch,
      security: {readCSRFToken(): string},
    ) => MutationGateway;
    const gateway = (createBrowserEntryGateway as unknown as GatewayFactory)(fetcher, {
      readCSRFToken: () => 'csrf-token-value-that-is-long-enough',
    });

    const session = await gateway.switchTenant(
      {
        tenantId: '00000000-0000-4000-8000-000000000011',
        idempotencyKey: 'tenant-switch-operation-0001',
      },
      controller.signal,
    );

    expect(seenInput).toBe('/api/v1/tenant-switch');
    expect(seenInit?.method).toBe('POST');
    expect(seenInit?.credentials).toBe('same-origin');
    expect(seenInit?.headers).toEqual({
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'Idempotency-Key': 'tenant-switch-operation-0001',
      'X-CSRF-Token': 'csrf-token-value-that-is-long-enough',
    });
    expect(seenInit?.body).toBe(
      JSON.stringify({tenant_id: '00000000-0000-4000-8000-000000000011'}),
    );
    expect(seenInit?.signal).toBe(controller.signal);
    expect(session.active.tenant.slug).toBe('globex');
    expect(session.active.workspace.slug).toBe('ops');
  });

  it('fails closed before network I/O when the CSRF token is unavailable', async () => {
    let fetchCalls = 0;
    const fetcher: typeof fetch = async () => {
      fetchCalls += 1;
      return jsonResponse(sessionPayload());
    };
    const gateway = createBrowserEntryGateway(fetcher, {
      readCSRFToken: () => undefined,
    });

    const error = await gateway
      .switchTenant({
        tenantId: '00000000-0000-4000-8000-000000000011',
        idempotencyKey: 'tenant-switch-operation-0002',
      })
      .then(
        () => undefined,
        (caught: unknown) => caught,
      );

    expect(fetchCalls).toBe(0);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/csrf|secure request token/i);
  });
});
