import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parseLabels, phaseAt, phaseLabel } from '../src/labels.js';
import { loadWindows, loadCases } from '../src/cases.js';
import { root, samplesDir } from '../src/paths.js';

const windows = loadWindows();

test('paths resolve to the project root', () => {
  // After the Track 1 repo split the SOC Brief is hoisted to the repo root,
  // so `root` is the package root (containing package.json + samples/) rather
  // than a `track1/` subdirectory of the mono-repo.
  assert.ok(statSync(join(root, 'package.json')).isFile());
  assert.equal(samplesDir, join(root, 'samples'));
  assert.ok(statSync(samplesDir).isDirectory());
});

test('labels.csv covers all eight AIT-ADS scenarios with ordered attack phases', () => {
  const scenarios = [...windows.keys()].sort();
  assert.deepEqual(scenarios, ['fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']);
  const rm = windows.get('russellmitchell').map((w) => w.attack);
  assert.deepEqual(rm, ['network_scans', 'service_scans', 'dirb', 'wpscan', 'webshell', 'cracking', 'reverse_shell', 'privilege_escalation', 'service_stop', 'dnsteal']);
  for (const list of windows.values()) {
    for (const w of list) assert.ok(w.end >= w.start, `${w.attack} ${w.start}`);
  }
});

test('phaseAt returns the window for real timestamps and null outside', () => {
  assert.equal(phaseAt(windows, 'russellmitchell', 1642996754), 'webshell');
  assert.equal(phaseAt(windows, 'russellmitchell', 1642999086.24), 'privilege_escalation');
  assert.equal(phaseAt(windows, 'fox', 1642411593), 'dnsteal');
  assert.equal(phaseAt(windows, 'russellmitchell', 1642723201), null);
  assert.equal(phaseAt(windows, 'nobody', 1642996754), null);
  assert.equal(phaseAt(windows, 'russellmitchell', null), null);
  assert.equal(phaseAt(windows, 'russellmitchell', 'not a time'), null);
});

test('a shared boundary belongs to the earlier phase', () => {
  const w = parseLabels('scenario,attack,start,end\ns,a,10,20\ns,b,20,30\n');
  assert.equal(phaseAt(w, 's', 20), 'a');
  assert.equal(phaseAt(w, 's', 20.5), 'b');
  assert.equal(phaseAt(w, 's', 30), 'b');
  assert.equal(phaseAt(w, 's', 31), null);
  assert.equal(phaseLabel('privilege_escalation'), 'privilege escalation');
  assert.equal(phaseLabel(null), null);
});

test('every AIT sample record carries a scenario and its expected phase is the real label', () => {
  for (const item of loadCases()) {
    const rec = item.record;
    if (!rec.scenario) {
      assert.equal(item.expect.phase, null, item.id);
      continue;
    }
    const epoch = rec.DetectionTimestamp ?? Date.parse(rec['@timestamp']) / 1000;
    assert.equal(phaseAt(windows, rec.scenario, epoch), item.expect.phase, item.id);
  }
});

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

test('samples stay small, contain no zip, and keep webshell parameters redacted', () => {
  const files = walk(samplesDir);
  const total = files.reduce((sum, f) => sum + statSync(f).size, 0);
  assert.ok(total < 80 * 1024, `samples are ${total} bytes`);
  assert.ok(files.every((f) => !f.endsWith('.zip')));
  for (const f of files) {
    const body = readFileSync(f, 'utf8');
    assert.ok(!/wp_meta=(?!\[REDACTED)/.test(body), f);
  }
});

test('fetch script points at the Zenodo record with its checksum and no local paths', () => {
  const script = readFileSync(join(root, 'scripts', 'fetch-ait.sh'), 'utf8');
  assert.ok(script.includes('zenodo.org/records/8263181'));
  assert.ok(script.includes('43db6b1f0996e0024befd617706c50e9'));
  assert.ok(!script.includes('/Users/'));
  assert.ok(!script.includes('Downloads'));
  assert.match(script, /\$here\/data/);
});

test('gitignore keeps data and secrets out, env example has no key, attribution names the source', () => {
  const ignore = readFileSync(join(root, '.gitignore'), 'utf8').split(/\r?\n/);
  assert.ok(ignore.includes('data/'));
  assert.ok(ignore.includes('.env'));

  const env = readFileSync(join(root, '.env.example'), 'utf8');
  assert.ok(!/OPENAI_API_KEY=.+/.test(env));
  assert.ok(!/sk-[A-Za-z0-9]{10,}/.test(env));

  const attribution = readFileSync(join(root, 'ATTRIBUTION.md'), 'utf8');
  assert.ok(attribution.includes('AIT-ADS'));
  assert.ok(attribution.includes('CC-BY-4.0'));
  assert.ok(attribution.includes('https://zenodo.org/records/8263181'));
});
