import {existsSync} from 'node:fs';
import {describe, expect, it} from 'vitest';

describe('Task 9 web entry boundary', () => {
  it('has an application entry module before journey behavior can be implemented', () => {
    const entryModule = new URL('./app.tsx', import.meta.url);

    expect(
      existsSync(entryModule),
      'Task 9 requires job/apps/web/src/app.tsx as the production entry boundary',
    ).toBe(true);
  });
});
