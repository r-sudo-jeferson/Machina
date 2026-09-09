import {render, screen} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {beforeEach, describe, expect, it} from 'vitest';
import {MachinaEntryApp} from './app';
import type {EntryGateway, SessionContext} from './entry/contracts';

const THEME_STORAGE_KEY = 'machina.appearance.theme.v1';

const session: SessionContext = {
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
    capabilities: [{id: 'context.read', allowed: true}],
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

const gateway: EntryGateway = {
  loadSession: async () => session,
};

describe('Machina appearance selection', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('switches the Alloy chassis between the two canonical themes through an accessible control', async () => {
    const user = userEvent.setup();
    const {container} = render(<MachinaEntryApp gateway={gateway} />);

    expect(await screen.findByRole('heading', {name: 'Acme / Core'})).toBeTruthy();
    const chassis = container.querySelector('.entry-chassis');
    expect(chassis?.getAttribute('data-alloy-theme')).toBe('silver');

    const appearance = screen.getByRole('combobox', {name: 'Appearance'});
    await user.selectOptions(appearance, 'space-black');
    expect(chassis?.getAttribute('data-alloy-theme')).toBe('space-black');

    await user.selectOptions(appearance, 'silver');
    expect(chassis?.getAttribute('data-alloy-theme')).toBe('silver');
  });

  it('restores the last valid theme across application remounts without a server preference contract', async () => {
    const user = userEvent.setup();
    const first = render(<MachinaEntryApp gateway={gateway} />);

    expect(await screen.findByRole('heading', {name: 'Acme / Core'})).toBeTruthy();
    await user.selectOptions(screen.getByRole('combobox', {name: 'Appearance'}), 'space-black');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('space-black');
    first.unmount();

    const second = render(<MachinaEntryApp gateway={gateway} />);
    expect(await screen.findByRole('heading', {name: 'Acme / Core'})).toBeTruthy();
    expect(second.container.querySelector('.entry-chassis')?.getAttribute('data-alloy-theme')).toBe(
      'space-black',
    );
  });
});
