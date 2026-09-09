import {composeStories} from '@storybook/react-vite';
import {cleanup} from '@testing-library/react';
import {afterEach, describe, it} from 'vitest';
import * as stories from './controls.stories';

const {ButtonKeyboardFocus, ButtonPressed, SwitchKeyboardFocus} = composeStories(stories);

afterEach(() => cleanup());

describe('Alloy Storybook interaction evidence', () => {
  it('executes the Button keyboard-focus story through the Storybook story pipeline', async () => {
    await ButtonKeyboardFocus.run();
  });

  it('executes the Button pressed story through the Storybook story pipeline', async () => {
    await ButtonPressed.run();
  });

  it('executes the Switch keyboard-focus story through the Storybook story pipeline', async () => {
    await SwitchKeyboardFocus.run();
  });
});
