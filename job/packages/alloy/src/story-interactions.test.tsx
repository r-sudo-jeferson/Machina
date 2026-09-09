import {composeStories, setProjectAnnotations} from '@storybook/react-vite';
import {cleanup} from '@testing-library/react';
import {afterEach, beforeAll, describe, expect, it} from 'vitest';
import * as previewAnnotations from '../.storybook/preview';
import * as stories from './controls.stories';

const annotations = setProjectAnnotations(previewAnnotations);
const {ButtonKeyboardFocus, ButtonPressed, SwitchKeyboardFocus} = composeStories(stories);

beforeAll(annotations.beforeAll);
afterEach(() => cleanup());

describe('Alloy Storybook interaction evidence', () => {
  it('executes the Button keyboard-focus story through the Storybook story pipeline', async () => {
    await ButtonKeyboardFocus.run();
    expect(document.documentElement.getAttribute('data-alloy-theme')).toBe('silver');
  });

  it('executes the Button pressed story through the Storybook story pipeline', async () => {
    await ButtonPressed.run();
  });

  it('executes the Switch keyboard-focus story through the Storybook story pipeline', async () => {
    await SwitchKeyboardFocus.run();
  });
});
