import type {CSSProperties} from 'react';
import type {Meta, StoryObj} from '@storybook/react-vite';
import {AlloyChassis, AlloySurface, AlloyWell, type AlloyChassisProps} from './material';

const meta = {
  title: 'Alloy/Material',
  parameters: {
    layout: 'fullscreen',
  },
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

type Theme = AlloyChassisProps['theme'];

const chassisStyle: CSSProperties = {
  boxSizing: 'border-box',
  minBlockSize: '100vh',
  padding: '32px',
};

const depthStyle: CSSProperties = {
  display: 'grid',
  gap: '16px',
  padding: '24px',
};

function DepthMatrix({theme}: {theme: Theme}) {
  return (
    <AlloyChassis theme={theme} style={chassisStyle}>
      <AlloySurface material="convex-low" style={depthStyle}>
        <strong>{theme === 'silver' ? 'Silver' : 'Space Black'} material depth</strong>
        <AlloyWell material="concave-low" style={depthStyle}>
          <span>Concave workspace well</span>
          <AlloySurface material="inlaid" style={depthStyle}>
            <span>Inlaid control plane — third and final local depth level</span>
          </AlloySurface>
        </AlloyWell>
      </AlloySurface>
    </AlloyChassis>
  );
}

export const SilverDepthMatrix: Story = {
  render: () => <DepthMatrix theme="silver" />,
};

export const SpaceBlackDepthMatrix: Story = {
  render: () => <DepthMatrix theme="space-black" />,
};
