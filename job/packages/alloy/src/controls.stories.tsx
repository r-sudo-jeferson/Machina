import type {Meta, StoryObj} from '@storybook/react-vite';
import {Button, IconButton, Switch, TextField} from './controls';

const meta = {
  title: 'Alloy/Controls',
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

export const ButtonDefault: Story = {
  render: () => <Button>Save changes</Button>,
};

export const ButtonKeyboardFocus: Story = {
  render: () => <Button>Keyboard focus target</Button>,
  play: async ({canvas, userEvent}) => {
    const button = canvas.getByRole('button', {name: 'Keyboard focus target'});
    await userEvent.tab();
    if (document.activeElement !== button || !button.hasAttribute('data-focus-visible')) {
      throw new Error('Keyboard focus must reach Button with the React Aria focus-visible state.');
    }
  },
};

export const ButtonDisabled: Story = {
  render: () => <Button isDisabled>Unavailable action</Button>,
};

export const ButtonLoading: Story = {
  render: () => (
    <Button isPending pendingLabel="Saving changes">
      Save changes
    </Button>
  ),
};

export const ButtonPressed: Story = {
  render: () => <Button>Hold to confirm</Button>,
  play: async ({canvas, userEvent}) => {
    const button = canvas.getByRole('button', {name: 'Hold to confirm'});
    await userEvent.tab();
    await userEvent.keyboard('{Enter>}');
    if (!button.hasAttribute('data-pressed')) {
      throw new Error('Button must expose the React Aria pressed state during a real key press.');
    }
  },
};

export const IconButtonDefault: Story = {
  render: () => (
    <IconButton label="Open command palette">
      <span aria-hidden="true">⌘</span>
    </IconButton>
  ),
};

export const IconButtonDisabled: Story = {
  render: () => (
    <IconButton label="Command palette unavailable" isDisabled>
      <span aria-hidden="true">⌘</span>
    </IconButton>
  ),
};

export const IconButtonLoading: Story = {
  render: () => (
    <IconButton label="Open command palette" isPending pendingLabel="Opening command palette">
      <span aria-hidden="true">⌘</span>
    </IconButton>
  ),
};

export const TextFieldDefault: Story = {
  render: () => <TextField label="Workspace name" placeholder="Operations" />,
};

export const TextFieldDisabled: Story = {
  render: () => <TextField label="Workspace name" value="Operations" isDisabled />,
};

export const TextFieldError: Story = {
  render: () => (
    <TextField
      label="Workspace slug"
      value="invalid slug"
      isInvalid
      errorMessage="Use lowercase letters, numbers, and hyphens only."
      isReadOnly
    />
  ),
};

export const SwitchDefault: Story = {
  render: () => <Switch>Workspace notifications</Switch>,
};

export const SwitchKeyboardFocus: Story = {
  render: () => <Switch>Keyboard focus switch</Switch>,
  play: async ({canvas, userEvent}) => {
    const control = canvas.getByRole('switch', {name: 'Keyboard focus switch'});
    await userEvent.tab();
    const root = control.closest('.alloy-switch');
    if (document.activeElement !== control || !root?.hasAttribute('data-focus-visible')) {
      throw new Error('Keyboard focus must reach Switch with the React Aria focus-visible state.');
    }
  },
};

export const SwitchDisabled: Story = {
  render: () => <Switch isDisabled>Locked by policy</Switch>,
};

export const SwitchSelected: Story = {
  render: () => <Switch defaultSelected>AI context citations</Switch>,
};
