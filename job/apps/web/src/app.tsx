import {useEffect, useRef, useState} from 'react';
import {AlloyChassis, AlloySurface, AlloyWell, Button, StatusLamp} from '@machina/alloy';
import type {EntryGateway, EntryMutationGateway, SessionContext} from './entry/contracts';

interface LoadingState {
  kind: 'loading';
}

interface ReadyState {
  kind: 'ready';
  session: SessionContext;
}

interface ErrorState {
  kind: 'error';
  message: string;
}

type EntryState = LoadingState | ReadyState | ErrorState;
type EntryAppGateway = EntryGateway & Partial<Pick<EntryMutationGateway, 'switchTenant'>>;

type TenantSwitchState =
  | {kind: 'idle'}
  | {kind: 'pending'}
  | {kind: 'error'; message: string};

export interface MachinaEntryAppProps {
  gateway: EntryAppGateway;
  newIdempotencyKey?: () => string;
}

function readableError(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }
  return 'The secure workspace could not be prepared.';
}

function defaultIdempotencyKey(): string {
  return globalThis.crypto.randomUUID();
}

export function MachinaEntryApp({
  gateway,
  newIdempotencyKey = defaultIdempotencyKey,
}: MachinaEntryAppProps) {
  const [state, setState] = useState<EntryState>({kind: 'loading'});
  const [selectedTenantId, setSelectedTenantId] = useState('');
  const [tenantSwitch, setTenantSwitch] = useState<TenantSwitchState>({kind: 'idle'});
  const tenantSwitchController = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setState({kind: 'loading'});
    setSelectedTenantId('');
    setTenantSwitch({kind: 'idle'});

    void gateway.loadSession(controller.signal).then(
      (session) => {
        if (!controller.signal.aborted) {
          setState({kind: 'ready', session});
        }
      },
      (error: unknown) => {
        if (!controller.signal.aborted) {
          setState({kind: 'error', message: readableError(error)});
        }
      },
    );

    return () => controller.abort();
  }, [gateway]);

  useEffect(
    () => () => {
      tenantSwitchController.current?.abort();
    },
    [],
  );

  if (state.kind === 'loading') {
    return (
      <AlloyChassis theme="silver" className="entry-chassis">
        <main className="entry-frame" aria-labelledby="machina-entry-title" aria-busy="true">
          <AlloySurface material="convex-low" className="entry-card entry-card--centered">
            <p className="entry-eyebrow">Secure tenant entry</p>
            <h1 id="machina-entry-title">Machina</h1>
            <div role="status" aria-live="polite" aria-atomic="true" className="entry-bootstrap-status">
              Preparing your secure workspace…
            </div>
          </AlloySurface>
        </main>
      </AlloyChassis>
    );
  }

  if (state.kind === 'error') {
    return (
      <AlloyChassis theme="silver" className="entry-chassis">
        <main className="entry-frame" aria-labelledby="machina-entry-title" aria-busy="false">
          <AlloySurface material="convex-low" className="entry-card entry-card--centered">
            <p className="entry-eyebrow">Secure tenant entry</p>
            <h1 id="machina-entry-title">Machina</h1>
            <div role="alert" className="entry-error">
              <strong>Workspace unavailable</strong>
              <span>{state.message}</span>
            </div>
          </AlloySurface>
        </main>
      </AlloyChassis>
    );
  }

  const {active} = state.session;
  const switchTenant = gateway.switchTenant;
  const resolvedTenantId = selectedTenantId || active.tenant.id;
  const targetIsServerProvided = state.session.available_tenants.some(
    (tenant) => tenant.id === resolvedTenantId,
  );
  const canSwitch =
    switchTenant !== undefined &&
    targetIsServerProvided &&
    resolvedTenantId !== active.tenant.id &&
    tenantSwitch.kind !== 'pending';

  const performTenantSwitch = () => {
    if (switchTenant === undefined || !canSwitch || state.kind !== 'ready') {
      return;
    }

    const targetTenantId = resolvedTenantId;
    if (!state.session.available_tenants.some((tenant) => tenant.id === targetTenantId)) {
      return;
    }

    tenantSwitchController.current?.abort();
    const controller = new AbortController();
    tenantSwitchController.current = controller;
    const command = {
      tenantId: targetTenantId,
      idempotencyKey: newIdempotencyKey(),
    };

    setTenantSwitch({kind: 'pending'});
    void switchTenant(command, controller.signal).then(
      (session) => {
        if (controller.signal.aborted) {
          return;
        }
        setState({kind: 'ready', session});
        setSelectedTenantId('');
        setTenantSwitch({kind: 'idle'});
        if (tenantSwitchController.current === controller) {
          tenantSwitchController.current = null;
        }
      },
      (error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setTenantSwitch({kind: 'error', message: readableError(error)});
        if (tenantSwitchController.current === controller) {
          tenantSwitchController.current = null;
        }
      },
    );
  };

  return (
    <AlloyChassis theme="silver" className="entry-chassis">
      <main
        className="entry-frame"
        aria-labelledby="active-context-title"
        aria-busy={tenantSwitch.kind === 'pending'}
      >
        <AlloySurface material="convex-low" className="entry-card">
          <header className="entry-context-header">
            <div>
              <p className="entry-eyebrow">Authorized context</p>
              <h1 id="active-context-title">
                {active.tenant.display_name} / {active.workspace.display_name}
              </h1>
            </div>
            <div className="entry-identity" aria-label="Signed-in identity">
              <span>{active.identity.display_name}</span>
              <span>Policy v{active.policy_version}</span>
            </div>
          </header>

          {switchTenant === undefined || state.session.available_tenants.length < 2 ? null : (
            <AlloyWell material="concave-low" className="entry-context-switch-well">
              <div className="entry-context-switch-copy">
                <h2>Tenant context</h2>
                <p id="tenant-context-help">
                  Choose a tenant already authorized for this session. The server selects the resulting workspace and capabilities.
                </p>
              </div>
              <div className="entry-context-switch-controls">
                <label className="alloy-label" htmlFor="tenant-context-select">
                  Tenant context
                </label>
                <select
                  id="tenant-context-select"
                  className="entry-context-select"
                  aria-describedby="tenant-context-help"
                  value={resolvedTenantId}
                  disabled={tenantSwitch.kind === 'pending'}
                  onChange={(event) => {
                    setSelectedTenantId(event.currentTarget.value);
                    if (tenantSwitch.kind === 'error') {
                      setTenantSwitch({kind: 'idle'});
                    }
                  }}
                >
                  {state.session.available_tenants.map((tenant) => (
                    <option key={tenant.id} value={tenant.id}>
                      {tenant.display_name}
                      {tenant.status === 'active' ? '' : ` — ${tenant.status}`}
                    </option>
                  ))}
                </select>
                <Button
                  isDisabled={!canSwitch}
                  isPending={tenantSwitch.kind === 'pending'}
                  pendingLabel="Switching tenant context"
                  onPress={performTenantSwitch}
                >
                  Switch context
                </Button>
              </div>
              {tenantSwitch.kind === 'error' ? (
                <div role="alert" className="entry-error">
                  <strong>Context switch unavailable</strong>
                  <span>{tenantSwitch.message}</span>
                </div>
              ) : null}
            </AlloyWell>
          )}

          <AlloyWell material="concave-low" className="entry-capability-well">
            <h2>Effective capabilities</h2>
            <ul className="entry-capability-list">
              {active.capabilities.map((capability) => (
                <li key={capability.id} className="entry-capability-item">
                  <div className="entry-capability-name">
                    <code>{capability.id}</code>
                    {capability.reason_code === undefined ? null : (
                      <span className="entry-reason">{capability.reason_code}</span>
                    )}
                  </div>
                  <StatusLamp tone={capability.allowed ? 'success' : 'danger'}>
                    {capability.allowed ? 'Allowed' : 'Denied'}
                  </StatusLamp>
                </li>
              ))}
            </ul>
          </AlloyWell>
        </AlloySurface>
      </main>
    </AlloyChassis>
  );
}
