import {render, screen} from '@testing-library/react';
import {describe, expect, it} from 'vitest';
import {MachinaEntryApp} from './app';

describe('Machina entry journey', () => {
  it('announces secure workspace bootstrap before exposing tenant context', () => {
    render(<MachinaEntryApp />);

    const status = screen.getByRole('status');
    expect(status.getAttribute('aria-live')).toBe('polite');
    expect(status.textContent).toMatch(/preparing your secure workspace/i);
  });
});
