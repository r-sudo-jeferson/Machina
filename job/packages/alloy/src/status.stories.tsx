import type {Meta, StoryObj} from '@storybook/react-vite';
import {Button} from './controls';
import {StatusLamp} from './status';

const meta = {
  title: 'Alloy/Status',
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

export const StatusNeutral: Story = {
  render: () => <StatusLamp tone="neutral">Idle</StatusLamp>,
};

export const StatusSuccess: Story = {
  render: () => <StatusLamp tone="success">Connected</StatusLamp>,
};

export const StatusWarning: Story = {
  render: () => <StatusLamp tone="warning">Synchronization delayed</StatusLamp>,
};

export const StatusDangerDenied: Story = {
  render: () => (
    <div>
      <StatusLamp tone="danger">Access denied — membership must be restored.</StatusLamp>
      <div>
        <Button>Review access</Button>
      </div>
    </div>
  ),
};

export const StatusAI: Story = {
  render: () => <StatusLamp tone="ai">ASK context ready with citations</StatusLamp>,
};
