import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadWindows } from '../src/cases.js';
import { phaseAt, parseLabels } from '../src/labels.js';

test('phase windows are inclusive and a shared boundary stays with the earlier phase', () => {
  const windows = loadWindows();
  assert.equal(phaseAt(windows, 'russellmitchell', 1642993260), 'network_scans');
  assert.equal(phaseAt(windows, 'russellmitchell', 1642996606), 'network_scans');
  assert.equal(phaseAt(windows, 'russellmitchell', 1642996606.1), 'service_scans');
  assert.equal(phaseAt(windows, 'russellmitchell', 1642996605.9), 'network_scans');
  assert.equal(phaseAt(windows, 'russellmitchell', 1642723347), null);
  assert.equal(phaseAt(windows, 'fox', 1642507140), 'network_scans');
  assert.equal(phaseAt(windows, 'missing', 1642507140), null);
  assert.equal(phaseAt(windows, 'fox', null), null);
});

test('the committed labels file has the eight scenarios', () => {
  const windows = loadWindows();
  assert.deepEqual([...windows.keys()].sort(), [
    'fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson',
  ]);
  assert.equal(parseLabels('scenario,attack,start,end\n').size, 0);
});
