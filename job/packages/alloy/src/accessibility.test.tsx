import axe from 'axe-core';
import {cleanup, render} from '@testing-library/react';
import {afterEach, describe, expect, it} from 'vitest';
import {Button, IconButton, Switch, TextField} from './controls';
import {AlloyChassis, AlloySurface, AlloyWell, type AlloyChassisProps} from './material';
import {StatusLamp} from './status';

afterEach(() => cleanup());

const themes = ['silver', 'space-black'] as const satisfies readonly AlloyChassisProps['theme'][];
const blockingImpacts = new Set(['serious', 'critical']);

function AccessibilityMatrix({theme}: {theme: AlloyChassisProps['theme']}) {
  return (
    <AlloyChassis theme={theme}>
      <AlloySurface material="convex-low">
        <section aria-label={`${theme} Alloy accessibility matrix`}>
          <h1>Machina Alloy state matrix</h1>
          <Button>Save changes</Button>
          <Button isDisabled>Unavailable action</Button>
          <Button isPending pendingLabel="Saving changes">
            Save changes
          </Button>
          <IconButton label="Open command palette">
            <span aria-hidden="true">⌘</span>
          </IconButton>
          <TextField label="Workspace name" defaultValue="Operations" />
          <TextField
            label="Workspace slug"
            defaultValue="invalid slug"
            isInvalid
            errorMessage="Use lowercase letters, numbers, and hyphens only."
          />
          <Switch>Workspace notifications</Switch>
          <Switch defaultSelected>AI context citations</Switch>
          <Switch isDisabled>Locked by policy</Switch>
          <AlloyWell material="concave-low">
            <StatusLamp tone="neutral">Idle</StatusLamp>
            <StatusLamp tone="success">Connected</StatusLamp>
            <StatusLamp tone="warning">Synchronization delayed</StatusLamp>
            <StatusLamp tone="danger">Access denied</StatusLamp>
            <StatusLamp tone="ai">ASK context ready with citations</StatusLamp>
          </AlloyWell>
        </section>
      </AlloySurface>
    </AlloyChassis>
  );
}

describe('Alloy automated accessibility gate', () => {
  for (const theme of themes) {
    it(`has no serious or critical axe violations in the ${theme} state matrix`, async () => {
      const {container} = render(<AccessibilityMatrix theme={theme} />);
      const results = await axe.run(container);
      const blocking = results.violations.filter(
        (violation) =>
          typeof violation.impact === 'string' && blockingImpacts.has(violation.impact),
      );

      expect(
        blocking.map(({id, impact, help, nodes}) => ({
          id,
          impact,
          help,
          targets: nodes.flatMap((node) => node.target),
        })),
      ).toEqual([]);
    });
  }
});
