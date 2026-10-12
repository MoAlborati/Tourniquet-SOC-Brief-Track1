import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { root, samplesDir } from '../src/paths.js';

test('samples stay small and the fetch script points at Zenodo', () => {
  let bytes = 0;
  for (const name of readdirSync(samplesDir)) {
    const file = join(samplesDir, name);
    bytes += statSync(file).size;
    assert.equal(name.endsWith('.zip'), false);
  }
  assert.ok(bytes < 80_000, `samples are ${bytes} bytes`);

  const script = readFileSync(join(root, 'scripts/fetch-ait.sh'), 'utf8');
  assert.match(script, /zenodo\.org\/records\/8263181/);
  assert.match(script, /43db6b1f0996e0024befd617706c50e9/);
  assert.doesNotMatch(script, /\/Users\/|Downloads/);
  const ignore = readFileSync(join(root, '.gitignore'), 'utf8');
  assert.match(ignore, /^data\/$/m);
  assert.match(ignore, /^\.env$/m);
});

test('committed text does not contain an API key assignment', () => {
  const files = ['README.md', '.env.example', 'server.mjs', 'src/llm.js'];
  for (const name of files) {
    const text = readFileSync(join(root, name), 'utf8');
    assert.doesNotMatch(text, /sk-[A-Za-z0-9]{20,}/);
    assert.doesNotMatch(text, /OPENAI_API_KEY=\S+/);
  }
});
