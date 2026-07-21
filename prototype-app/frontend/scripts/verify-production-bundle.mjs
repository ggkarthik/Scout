import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, URL } from 'node:url';

const forbidden = ['change-me-in-prod', 'local-creator', 'local-analyst'];

async function files(root) {
  const entries = await readdir(root, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => {
    const path = join(root, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  }));
  return nested.flat();
}

const violations = [];
for (const path of await files(fileURLToPath(new URL('../dist', import.meta.url)))) {
  const content = await readFile(path, 'utf8').catch(() => '');
  for (const value of forbidden) {
    if (content.includes(value)) violations.push(`${path}: ${value}`);
  }
}
if (violations.length > 0) {
  throw new Error(`Production bundle contains development credentials:\n${violations.join('\n')}`);
}
