import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, URL } from 'node:url';

const forbidden = [
  'change-me-in-prod',
  'local-creator',
  'local-analyst',
  'VITE_OPENAI_API_KEY',
  'api.openai.com/v1/chat/completions',
];
const providerSecretPatterns = [
  /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bAKIA[A-Z0-9]{16}\b/g,
  /\bAIza[A-Za-z0-9_-]{30,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
];

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
  for (const pattern of providerSecretPatterns) {
    if (pattern.test(content)) violations.push(`${path}: provider secret matching ${pattern}`);
    pattern.lastIndex = 0;
  }
}
if (violations.length > 0) {
  throw new Error(`Production bundle contains development credentials:\n${violations.join('\n')}`);
}
