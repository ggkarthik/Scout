import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const result = spawnSync(process.execPath, [resolve(here, 'compile-ai-grid-release.mjs'),
  '--manifest', resolve(root, 'policy-packages/agcf/phase-1-manifest.json'),
  '--package-root', resolve(root, 'policy-packages/agcf'),
  ...process.argv.slice(2)], { stdio: 'inherit' });
process.exit(result.status ?? 1);
