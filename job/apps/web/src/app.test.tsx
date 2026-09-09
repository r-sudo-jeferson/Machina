import {render, screen} from '@testing-library/react';
import type {ComponentType} from 'react';
import {describe, expect, it} from 'vitest';
import {MachinaEntryApp} from './app';
import type {EntryGateway, SessionContext} from './entry/contracts';

const readySession: SessionContext = {
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
    {
      id: '00000000-0000-4000-8000-000000000011',
      slug: 'forge-labs',
      display_name: 'Forge Labs',
      status: 'active',
    },
  ],
  expires_at: '2026-09-10T12:00:00Z',
};

function readyGateway(): EntryGateway {
  return {
    loadSession: async () => readySession,
    switchTenant: async () => readySession,
    createTenant: async () => {
      throw new Error('not exercised');
    },
    acceptInvitation: async () => {
      throw new Error('not exercised');
    },
  };
}

describe('Machina entry journey', () => {
  it('announces secure workspace bootstrap before exposing tenant context', () => {
    render(<MachinaEntryApp />);

    const status = screen.getByRole('status');
    expect(status.getAttribute('aria-live')).toBe('polite');
    expect(status.textContent).toMatch(/preparing your secure workspace/i);
  });

  it('renders the server-authorized tenant and workspace context without hiding denied capabilities', async () => {
    const AppWithGateway = MachinaEntryApp as ComponentType<{gateway: EntryGateway}>;
    render(<AppWithGateway gateway={readyGateway()} />);

    expect(await screen.findByRole('heading', {name: 'Acme / Core'})).toBeTruthy();
    expect(screen.getByText('Ada Lovelace')).toBeTruthy();
    expect(screen.getByText('context.read')).toBeTruthy();
    expect(screen.getByText('Allowed')).toBeTruthy();
    expect(screen.getByText('tenant.admin')).toBeTruthy();
    expect(screen.getByText('Denied')).toBeTruthy();
    expect(screen.getByText('role_not_permitted')).toBeTruthy();
    expect(screen.getByText('Policy v7')).toBeTruthy();
  });
});
