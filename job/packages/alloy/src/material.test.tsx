import {cleanup, render, screen} from '@testing-library/react';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {afterEach, describe, expect, it} from 'vitest';
import {AlloyChassis, AlloySurface, AlloyWell} from './material';

afterEach(() => cleanup());

const sourcePath = (fileName: string) => path.resolve(process.cwd(), 'src', fileName);

describe('Alloy material primitives', () => {
  it('accepts only the canonical Silver and Space Black chassis themes', () => {
    const {rerender} = render(<AlloyChassis theme="silver">Silver chassis</AlloyChassis>);
    let chassis = screen.getByText('Silver chassis');
    expect(chassis.getAttribute('data-alloy-theme')).toBe('silver');

    rerender(<AlloyChassis theme="space-black">Space Black chassis</AlloyChassis>);
    chassis = screen.getByText('Space Black chassis');
    expect(chassis.getAttribute('data-alloy-theme')).toBe('space-black');

    expect(() => render(
      <AlloyChassis theme={'graphite' as never}>Invalid chassis</AlloyChassis>,
    )).toThrow(/unsupported alloy theme/i);
  });

  it('composes material state and consumer classes without owning app layout', () => {
    render(
      <>
        <AlloySurface className="consumer-surface">Surface</AlloySurface>
        <AlloyWell className="consumer-well">Well</AlloyWell>
      </>,
    );

    const surface = screen.getByText('Surface');
    const well = screen.getByText('Well');
    expect(surface.getAttribute('data-alloy-material')).toBe('convex-low');
    expect(well.getAttribute('data-alloy-material')).toBe('concave-low');
    expect(surface.className).toContain('alloy-surface');
    expect(surface.className).toContain('consumer-surface');
    expect(well.className).toContain('alloy-well');
    expect(well.className).toContain('consumer-well');
  });
});

describe('Alloy component CSS contract', () => {
  it('uses generated semantic variables and never duplicates canonical palette literals', async () => {
    const css = await readFile(sourcePath('alloy.css'), 'utf8');
    const canonicalHex = [
      '#D8DADD', '#F5F6F7', '#B4B8BE', '#C9CCD1', '#17191D', '#4D535B', '#737A84',
      '#1D1F22', '#34373C', '#090A0C', '#141619', '#F5F7FA', '#B2B8C1', '#7B828D',
      '#147DFF', '#00D9FF', '#AEFF3D', '#FF2D8D', '#FFB21A', '#FF3B45', '#20E37A',
    ];

    expect(css).toContain('var(--alloy-');
    for (const literal of canonicalHex) {
      expect(css).not.toContain(literal);
    }
  });

  it('keeps focus, targets, pending geometry, and forced-colors semantics explicit', async () => {
    const css = await readFile(sourcePath('alloy.css'), 'utf8');

    expect(css).toContain('[data-focus-visible]');
    expect(css).toMatch(/outline:\s*var\(--alloy-focus-width\)\s+solid\s+var\(--alloy-focus\)/);
    expect(css).toContain('outline-offset: var(--alloy-focus-offset);');
    expect(css).toMatch(/min-inline-size:\s*var\(--alloy-target-(?:minimum|preferred)\)/);
    expect(css).toMatch(/min-block-size:\s*var\(--alloy-target-(?:minimum|preferred)\)/);
    expect(css).toContain('[data-pending]');
    expect(css).toContain('.alloy-button__content');
    expect(css).toContain('.alloy-button__progress');
    expect(css).toContain('grid-area: 1 / 1;');
    expect(css).toContain('opacity: 0;');
    expect(css).toContain('@media (forced-colors: active)');
    expect(css).toContain('box-shadow: none;');
  });
});
