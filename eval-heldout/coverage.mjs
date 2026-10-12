// Data-rich coverage run: every alert in the non-curated AIT-ADS scenarios.
// Needs the gitignored download (bash track1/scripts/fetch-ait.sh). Offline, no key.
//
//   node track1/eval-heldout/coverage.mjs                 # all 7 non-curated scenarios, wazuh + aminer
//   COVERAGE_LIMIT=50000 node track1/eval-heldout/coverage.mjs   # cap lines per file
//
// Reports how often the rules fall through to "unclassified", inside and outside
// labeled windows, plus the phase join for each source. Phase truth is recomputed
// from the raw timestamp against labels.csv, independently of src/normalize.js.
import { createReadStream, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { brief } from '../src/briefing.js';
import { loadWindows } from '../src/cases.js';
import { phaseAt } from '../src/labels.js';
import { normalize } from '../src/normalize.js';

const here = dirname(fileURLToPath(import.meta.url));
const aitDir = join(dirname(here), 'data', 'ait_ads');
const SCENARIOS = ['fox', 'harrison', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson'];
const limit = Number(process.env.COVERAGE_LIMIT || Infinity);

if (!existsSync(join(aitDir, 'fox_wazuh.json'))) {
  console.error('AIT-ADS is not downloaded. Run: bash track1/scripts/fetch-ait.sh');
  process.exit(1);
}

function rawEpoch(record) {
  if (record['@timestamp']) return Date.parse(record['@timestamp']) / 1000;
  let det = record.LogData?.DetectionTimestamp;
  if (Array.isArray(det)) det = det[0];
  return typeof det === 'number' ? det : null;
}

const windows = loadWindows();
const blank = () => ({ alerts: 0, unclassified: 0, inWindow: 0, inWindowUnclassified: 0, phaseOk: 0, needsHumanIn: 0, needsHumanOut: 0, vendorRaised: 0, inWindowVendorRaised: 0 });
const bySource = {};
const byPhase = {};
const unclassifiedTitles = new Map();
const vendorRaisedTitles = new Map();

for (const scenario of SCENARIOS) {
  for (const kind of ['wazuh', 'aminer']) {
    const file = join(aitDir, `${scenario}_${kind}.json`);
    let n = 0;
    const rl = createInterface({ input: createReadStream(file), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      n += 1;
      if (n > limit) { rl.close(); break; }
      const record = JSON.parse(line);
      const truth = phaseAt(windows, scenario, rawEpoch(record));
      const card = normalize({ id: `${scenario}-${n}`, record: { ...record, scenario } }, windows);
      const b = brief(card);
      const s = (bySource[card.source] ||= blank());
      const p = (byPhase[truth || 'outside'] ||= blank());
      for (const bucket of [s, p]) {
        bucket.alerts += 1;
        if ((card.phase || null) === (truth || null)) bucket.phaseOk += 1;
        const nh = b.disposition === 'escalate' || b.disposition === 'investigate';
        if (b.activity === 'unclassified') bucket.unclassified += 1;
        // No local rule matched, but the vendor-severity fallback raised it to investigate/P2.
        if (b.ruleId === 'vendor-severity') bucket.vendorRaised += 1;
        if (truth) {
          if (b.ruleId === 'vendor-severity') bucket.inWindowVendorRaised += 1;
          bucket.inWindow += 1;
          if (b.activity === 'unclassified') bucket.inWindowUnclassified += 1;
          if (nh) bucket.needsHumanIn += 1;
        } else if (nh) bucket.needsHumanOut += 1;
      }
      if (b.ruleId === 'vendor-severity') {
        const key = `${card.source}: ${card.title}`.slice(0, 120);
        vendorRaisedTitles.set(key, (vendorRaisedTitles.get(key) || 0) + 1);
      }
      if (b.activity === 'unclassified') {
        const key = `${card.source}: ${card.title}`.slice(0, 120);
        unclassifiedTitles.set(key, (unclassifiedTitles.get(key) || 0) + 1);
      }
    }
    console.error(`done ${scenario}_${kind} (${n} alerts)`);
  }
}

const total = Object.values(bySource).reduce((acc, s) => {
  for (const k of Object.keys(acc)) acc[k] += s[k];
  return acc;
}, blank());
const top = [...unclassifiedTitles.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15);
const topVendor = [...vendorRaisedTitles.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
console.log(JSON.stringify({ scenarios: SCENARIOS, limitPerFile: limit === Infinity ? null : limit, total, bySource, byPhase, topUnclassified: top, topVendorRaised: topVendor }, null, 2));
