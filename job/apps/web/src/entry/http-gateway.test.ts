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
});
