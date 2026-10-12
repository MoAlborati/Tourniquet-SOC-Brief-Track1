// Build track1/eval-heldout/heldout.json from the full AIT-ADS archive.
//
// Needs the gitignored download: bash track1/scripts/fetch-ait.sh
// Run:  node track1/eval-heldout/build-sample.mjs
//
// The selection is deterministic and does not look at what the rules say:
//   - russellmitchell is skipped entirely, because all 13 curated AIT rows
//     come from it. Any record whose full_log matches a curated row is also skipped.
//   - one Wazuh/Suricata alert per labeled attack phase (10 phases), each from
//     a different non-curated scenario, taken at the median position of the
//     alerts inside that window
//   - one AMiner alert (the median alert inside a webshell window)
//   - two alerts from outside every labeled window (the median outside alert)
// Ground-truth phase comes from AIT's own labels.csv (data/labels.csv, the Zenodo copy).
import { createReadStream, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const track1 = dirname(here);
const dataDir = join(track1, 'data');
const aitDir = join(dataDir, 'ait_ads');

if (!existsSync(join(aitDir, 'fox_wazuh.json')) || !existsSync(join(dataDir, 'labels.csv'))) {
  console.error('AIT-ADS is not downloaded. Run: bash track1/scripts/fetch-ait.sh');
  process.exit(1);
}

function parseLabels(csv) {
  const out = new Map();
  for (const line of csv.split(/\r?\n/)) {
    const [scenario, attack, start, end] = line.trim().split(',');
    if (!scenario || scenario === 'scenario' || !attack) continue;
    if (!out.has(scenario)) out.set(scenario, []);
    out.get(scenario).push({ attack, start: Number(start), end: Number(end) });
  }
  return out;
}

// Same boundary rule as labels.csv order: first matching row wins.
function truthPhase(windows, scenario, epoch) {
  if (epoch == null) return null;
  for (const w of windows.get(scenario) || []) {
    if (epoch >= w.start && epoch <= w.end) return w.attack;
  }
  return null;
}

// Timestamp straight from the raw record, independent of track1/src/normalize.js.
function rawEpoch(record) {
  if (record['@timestamp']) return Date.parse(record['@timestamp']) / 1000;
  let det = record.LogData?.DetectionTimestamp;
  if (Array.isArray(det)) det = det[0];
  if (typeof det === 'number') return det;
  return null;
}

const windows = parseLabels(readFileSync(join(dataDir, 'labels.csv'), 'utf8'));
const curated = JSON.parse(readFileSync(join(track1, 'samples', 'curated.json'), 'utf8'));
const curatedLogs = new Set(curated.map((c) => c.record?.full_log).filter(Boolean));

const SCENARIOS = ['fox', 'harrison', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson'];
const PHASES = ['network_scans', 'service_scans', 'dirb', 'wpscan', 'webshell', 'cracking',
  'reverse_shell', 'privilege_escalation', 'service_stop', 'dnsteal'];

// Collect line numbers per (phase | outside) for a file, then read back the median.
async function indexFile(file, scenario) {
  const buckets = new Map();
  let n = 0;
  const rl = createInterface({ input: createReadStream(file), crlfDelay: Infinity });
  for await (const line of rl) {
    n += 1;
    if (!line.trim()) continue;
    let epoch = null;
    const ts = line.match(/"@timestamp": "([^"]+)"/);
    if (ts) epoch = Date.parse(ts[1]) / 1000;
    else {
      const det = line.match(/"DetectionTimestamp": \[?([0-9.]+)/);
      if (det) epoch = Number(det[1]);
    }
    const phase = truthPhase(windows, scenario, epoch) || 'outside';
    if (!buckets.has(phase)) buckets.set(phase, []);
    buckets.get(phase).push(n);
  }
  return buckets;
}

async function readLine(file, lineNo) {
  let n = 0;
  const rl = createInterface({ input: createReadStream(file), crlfDelay: Infinity });
  for await (const line of rl) {
    n += 1;
    if (n === lineNo) { rl.close(); return line; }
  }
  throw new Error(`line ${lineNo} not found in ${file}`);
}

const indexCache = new Map();
async function bucketsFor(scenario, kind) {
  const key = `${scenario}_${kind}`;
  if (!indexCache.has(key)) indexCache.set(key, await indexFile(join(aitDir, `${key}.json`), scenario));
  return indexCache.get(key);
}

// Mirror samples/ATTRIBUTION.md: drop query strings on PHP requests in the uploads folder.
function redact(line) {
  return line.replace(/(\/wp-content\/uploads\/[^\s"?]+\.php)\?[^\s"]*/g, '$1?[REDACTED]');
}

async function pick(scenarioOrder, kind, phase, why) {
  for (const scenario of scenarioOrder) {
    const buckets = await bucketsFor(scenario, kind);
    const list = buckets.get(phase) || [];
    if (!list.length) continue;
    for (let offset = 0; offset < list.length; offset += 1) {
      const lineNo = list[Math.floor(list.length / 2) + offset] ?? list[offset];
      const raw = await readLine(join(aitDir, `${scenario}_${kind}.json`), lineNo);
      const record = JSON.parse(redact(raw));
      if (record.full_log && curatedLogs.has(record.full_log)) continue;
      const epoch = rawEpoch(record);
      return {
        id: `ho-${scenario}-${kind}-${phase}`,
        origin: { dataset: 'AIT-ADS', file: `${scenario}_${kind}.json`, line: lineNo, windowAlerts: list.length, why },
        truth: { scenario, phase: truthPhase(windows, scenario, epoch) },
        scenario,
        record,
      };
    }
  }
  throw new Error(`no ${kind} alert for ${phase}`);
}

const rotate = (i) => SCENARIOS.slice(i).concat(SCENARIOS.slice(0, i));
const out = [];
for (let i = 0; i < PHASES.length; i += 1) {
  out.push(await pick(rotate(i % SCENARIOS.length), 'wazuh', PHASES[i], 'median alert in the labeled window'));
  console.error(`picked ${out.at(-1).id}`);
}
out.push(await pick(rotate(6), 'aminer', 'webshell', 'median AMiner alert in the labeled window'));
out.push(await pick(rotate(3), 'wazuh', 'outside', 'median alert outside every labeled window'));
out.push(await pick(rotate(4), 'wazuh', 'outside', 'median alert outside every labeled window'));

writeFileSync(join(here, 'heldout.json'), `${JSON.stringify(out, null, 1)}\n`);
console.error(`wrote ${out.length} AIT alerts to eval-heldout/heldout.json`);
