import {cleanup, render, screen} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {readFile} from 'node:fs/promises';
import {afterEach, describe, expect, it, vi} from 'vitest';
import {Button, IconButton, Switch, TextField} from './controls';
import {StatusLamp} from './status';

afterEach(() => cleanup());

describe('Alloy React Aria controls', () => {
  it('uses semantic Button press behavior and React Aria state attributes', async () => {
    const user = userEvent.setup();
    const onPress = vi.fn();
    render(<Button onPress={onPress}>Save changes</Button>);

    const button = screen.getByRole('button', {name: 'Save changes'});
    expect(button.tagName).toBe('BUTTON');
    await user.tab();
    expect(button.hasAttribute('data-focus-visible')).toBe(true);
    await user.click(button);
    expect(onPress).toHaveBeenCalledTimes(1);
  });

  it('keeps a pending button named, focusable, announced, and non-pressable', async () => {
    const user = userEvent.setup();
    const onPress = vi.fn();
    render(
      <Button isPending pendingLabel="Saving changes" onPress={onPress}>
        Save changes
      </Button>,
    );

    const button = screen.getByRole('button', {name: 'Save changes'});
    expect(button.hasAttribute('data-pending')).toBe(true);
    expect(screen.getByRole('progressbar', {name: 'Saving changes'})).toBeTruthy();
    await user.click(button);
    expect(onPress).not.toHaveBeenCalled();
    button.focus();
    expect(document.activeElement).toBe(button);
  });

  it('requires IconButton to provide a non-empty accessible label', () => {
    render(
      <IconButton label="Open command palette">
        <svg aria-hidden="true" />
      </IconButton>,
    );
    expect(screen.getByRole('button', {name: 'Open command palette'})).toBeTruthy();

    expect(() => render(
      <IconButton label=" ">
        <svg aria-hidden="true" />
      </IconButton>,
    )).toThrow(/accessible label/i);
  });

  it('composes TextField from labeled React Aria field primitives with error semantics', () => {
    render(
      <TextField
        label="Email"
        name="email"
        placeholder="name@example.com"
        isInvalid
        errorMessage="Enter a valid email address"
      />,
    );

    const input = screen.getByRole('textbox', {name: 'Email'});
    expect(input.tagName).toBe('INPUT');
    expect(input.getAttribute('aria-invalid')).toBe('true');
    expect(screen.getByText('Enter a valid email address')).toBeTruthy();
  });

  it('uses React Aria selection state for Switch rather than a parallel state machine', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Switch onChange={onChange}>Notifications</Switch>);

    const control = screen.getByRole('switch', {name: 'Notifications'});
    await user.click(control);
    expect(onChange).toHaveBeenLastCalledWith(true);
    const root = control.closest('.alloy-switch');
    expect(root?.hasAttribute('data-selected')).toBe(true);
  });

  it('forwards disabled semantics for Button, TextField, and Switch', () => {
    render(
      <>
        <Button isDisabled>Disabled action</Button>
        <TextField label="Disabled field" isDisabled />
        <Switch isDisabled>Disabled switch</Switch>
      </>,
    );

    expect((screen.getByRole('button', {name: 'Disabled action'}) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('textbox', {name: 'Disabled field'}) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole('switch', {name: 'Disabled switch'}) as HTMLInputElement).disabled).toBe(true);
  });
});

describe('Alloy semantic status', () => {
  it('never represents status by color alone', () => {
    render(<StatusLamp tone="success">Connected</StatusLamp>);
    expect(screen.getByRole('status').textContent).toContain('Connected');

    cleanup();
    render(<StatusLamp tone="warning" aria-label="Synchronization delayed" />);
    expect(screen.getByRole('status', {name: 'Synchronization delayed'})).toBeTruthy();

    expect(() => render(<StatusLamp tone="danger" />)).toThrow(/text or an accessible label/i);
  });
});

describe('Alloy control implementation contract', () => {
  it('delegates interaction state to React Aria and does not introduce local useState state machines', async () => {
    const source = await readFile(new URL('./controls.tsx', import.meta.url), 'utf8');
    expect(source).toContain("from 'react-aria-components'");
    expect(source).not.toMatch(/\buseState\s*\(/);
  });
});
