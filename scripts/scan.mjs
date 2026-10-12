import { createReadStream, existsSync } from 'node:fs';
import { basename } from 'node:path';
import { createInterface } from 'node:readline';
import { brief } from '../src/briefing.js';
import { loadLabels } from '../src/labels.js';
import { normalize } from '../src/normalize.js';
import { samplesDir } from '../src/paths.js';

const file = process.argv[2];
if (!file || !existsSync(file)) {
  console.log('No dataset file given. Run track1/scripts/fetch-ait.sh, then:');
  console.log('  node track1/scripts/scan.mjs track1/data/ait_ads/<scenario>_wazuh.json');
  process.exit(0);
}

const scenario = process.argv[3] || basename(file).split('_')[0];
const limit = Number(process.env.SCAN_LIMIT || 20000);
const windows = loadLabels(`${samplesDir}/labels.csv`);
const counts = { lines: 0, phased: 0, dispositions: {}, phases: {} };

const lines = createInterface({ input: createReadStream(file), crlfDelay: Infinity });
for await (const line of lines) {
  if (!line.trim()) continue;
  counts.lines += 1;
  if (counts.lines > limit) break;
  let record;
  try {
    record = JSON.parse(line);
  } catch {
    continue;
  }
  record.scenario = scenario;
  record.source = record.source || (file.includes('aminer') ? 'aminer' : 'wazuh');
  const card = normalize({ id: `scan-${counts.lines}`, record }, windows);
  const briefing = brief(card);
  counts.dispositions[briefing.disposition] = (counts.dispositions[briefing.disposition] || 0) + 1;
  counts.phases[card.phase || 'outside'] = (counts.phases[card.phase || 'outside'] || 0) + 1;
  if (card.phase) counts.phased += 1;
}

console.log(JSON.stringify({ file, scenario, limit, ...counts }, null, 2));
