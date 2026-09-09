import {useEffect, useState} from 'react';
import {AlloyChassis, AlloySurface, AlloyWell, StatusLamp} from '@machina/alloy';
import type {EntryGateway, SessionContext} from './entry/contracts';

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

export interface MachinaEntryAppProps {
  gateway: EntryGateway;
}

function readableError(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }
  return 'The secure workspace could not be prepared.';
}

export function MachinaEntryApp({gateway}: MachinaEntryAppProps) {
  const [state, setState] = useState<EntryState>({kind: 'loading'});

  useEffect(() => {
    const controller = new AbortController();
    setState({kind: 'loading'});

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

  return (
    <AlloyChassis theme="silver" className="entry-chassis">
      <main className="entry-frame" aria-labelledby="active-context-title" aria-busy="false">
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
