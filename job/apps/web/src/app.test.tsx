import {render, screen} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {describe, expect, it} from 'vitest';
import {MachinaEntryApp} from './app';
import type {
  EntryGateway,
  EntryMutationGateway,
  SessionContext,
  TenantSwitchCommand,
} from './entry/contracts';

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

const switchedSession: SessionContext = {
  ...readySession,
  active: {
    ...readySession.active,
    tenant: readySession.available_tenants[1]!,
    workspace: {
      id: '00000000-0000-4000-8000-000000000021',
      tenant_id: '00000000-0000-4000-8000-000000000011',
      slug: 'foundry',
      display_name: 'Foundry',
    },
    policy_version: 8,
  },
};

function pendingGateway(): EntryGateway {
  return {
    loadSession: async () => await new Promise<SessionContext>(() => {}),
  };
}

function readyGateway(): EntryGateway {
  return {
    loadSession: async () => readySession,
  };
}

describe('Machina entry journey', () => {
  it('announces secure workspace bootstrap before exposing tenant context', () => {
    render(<MachinaEntryApp gateway={pendingGateway()} />);

    const status = screen.getByRole('status');
    expect(status.getAttribute('aria-live')).toBe('polite');
    expect(status.textContent).toMatch(/preparing your secure workspace/i);
  });

  it('renders the server-authorized tenant and workspace context without hiding denied capabilities', async () => {
    render(<MachinaEntryApp gateway={readyGateway()} />);

    expect(await screen.findByRole('heading', {name: 'Acme / Core'})).toBeTruthy();
    expect(screen.getByText('Ada Lovelace')).toBeTruthy();
    expect(screen.getByText('context.read')).toBeTruthy();
    expect(screen.getByText('Allowed')).toBeTruthy();
    expect(screen.getByText('tenant.admin')).toBeTruthy();
    expect(screen.getByText('Denied')).toBeTruthy();
    expect(screen.getByText('role_not_permitted')).toBeTruthy();
    expect(screen.getByText('Policy v7')).toBeTruthy();
  });

  it('switches only to a server-provided tenant and adopts the returned authorized context', async () => {
    const commands: TenantSwitchCommand[] = [];
    const gateway: EntryMutationGateway = {
      loadSession: async () => readySession,
      switchTenant: async (command) => {
        commands.push(command);
        return switchedSession;
      },
    };
    const user = userEvent.setup();

    render(
      <MachinaEntryApp
        gateway={gateway}
        newIdempotencyKey={() => 'tenant-switch-ui-operation-0001'}
      />,
    );

    expect(await screen.findByRole('heading', {name: 'Acme / Core'})).toBeTruthy();
    await user.selectOptions(
      screen.getByRole('combobox', {name: 'Tenant context'}),
      '00000000-0000-4000-8000-000000000011',
    );
    await user.click(screen.getByRole('button', {name: 'Switch context'}));

    expect(commands).toEqual([
      {
        tenantId: '00000000-0000-4000-8000-000000000011',
        idempotencyKey: 'tenant-switch-ui-operation-0001',
      },
    ]);
    expect(await screen.findByRole('heading', {name: 'Forge Labs / Foundry'})).toBeTruthy();
    expect(screen.getByText('Policy v8')).toBeTruthy();
    expect(screen.queryByRole('heading', {name: 'Acme / Core'})).toBeNull();
  });

  it('reuses the same idempotency key when retrying the same failed tenant switch intent', async () => {
    const commands: TenantSwitchCommand[] = [];
    let attempts = 0;
    let keySequence = 0;
    const gateway: EntryMutationGateway = {
      loadSession: async () => readySession,
      switchTenant: async (command) => {
        commands.push(command);
        attempts += 1;
        if (attempts === 1) {
          throw new Error('Temporary switch failure.');
        }
        return switchedSession;
      },
    };
    const user = userEvent.setup();

    render(
      <MachinaEntryApp
        gateway={gateway}
        newIdempotencyKey={() => {
          keySequence += 1;
          return `tenant-switch-ui-recovery-000${keySequence}`;
        }}
      />,
    );

    expect(await screen.findByRole('heading', {name: 'Acme / Core'})).toBeTruthy();
    await user.selectOptions(
      screen.getByRole('combobox', {name: 'Tenant context'}),
      '00000000-0000-4000-8000-000000000011',
    );
    await user.click(screen.getByRole('button', {name: 'Switch context'}));

    expect(await screen.findByRole('alert')).toHaveTextContent('Temporary switch failure.');
    expect(screen.getByRole('heading', {name: 'Acme / Core'})).toBeTruthy();

    await user.click(screen.getByRole('button', {name: 'Switch context'}));

    expect(await screen.findByRole('heading', {name: 'Forge Labs / Foundry'})).toBeTruthy();
    expect(commands).toEqual([
      {
        tenantId: '00000000-0000-4000-8000-000000000011',
        idempotencyKey: 'tenant-switch-ui-recovery-0001',
      },
      {
        tenantId: '00000000-0000-4000-8000-000000000011',
        idempotencyKey: 'tenant-switch-ui-recovery-0001',
      },
    ]);
    expect(keySequence).toBe(1);
  });
});
