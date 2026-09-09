import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {describe, expect, it} from 'vitest';

describe('Task 9 web entry boundary', () => {
  it('has an application entry module before journey behavior can be implemented', () => {
    const entryModule = resolve(process.cwd(), 'src/app.tsx');

    expect(
      existsSync(entryModule),
      'Task 9 requires job/apps/web/src/app.tsx as the production entry boundary',
    ).toBe(true);
  });
});
