import type {CSSProperties} from 'react';
import type {Meta, StoryObj} from '@storybook/react-vite';
import {alloyMaterialStates, type AlloyMaterialState} from '../generated/tokens';
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
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
};

const stateStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
  minBlockSize: '112px',
  padding: '20px',
};

function MaterialSample({state}: {state: AlloyMaterialState}) {
  const Component = state.startsWith('concave') ? AlloyWell : AlloySurface;
  return (
    <Component material={state} style={stateStyle}>
      <strong>{state}</strong>
      <span>Alloy material state</span>
    </Component>
  );
}

function DepthMatrix({theme}: {theme: Theme}) {
  return (
    <AlloyChassis theme={theme} style={chassisStyle}>
      <h1>{theme === 'silver' ? 'Silver' : 'Space Black'} material states</h1>
      <div style={depthStyle}>
        {alloyMaterialStates.map((state) => <MaterialSample key={state} state={state} />)}
      </div>
    </AlloyChassis>
  );
}

export const SilverDepthMatrix: Story = {
  render: () => <DepthMatrix theme="silver" />,
};

export const SpaceBlackDepthMatrix: Story = {
  render: () => <DepthMatrix theme="space-black" />,
};
