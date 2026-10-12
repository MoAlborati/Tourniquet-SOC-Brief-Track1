import { phaseAt } from './labels.js';

export function epochFrom(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'string' || !value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms / 1000;
}

function asList(value) {
  if (!value) return [];
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

function detectSource(record) {
  const schema = String(record.SchemaVersion || '');
  if (schema.startsWith('sentinel.alert')) return 'sentinel';
  if (record.AnalysisComponent || record.AnalysisComponentName) return 'aminer';
  if (record.kind === 'email' || (record.from && record.subject)) return 'email';
  const groups = asList(record.rule?.groups).map((g) => g.toLowerCase());
  if (groups.includes('suricata') || record.decoder?.name === 'suricata') return 'suricata';
  return 'wazuh';
}

function flatten(value, out) {
  if (value == null) return;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    out.push(String(value));
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) flatten(item, out);
    return;
  }
  if (typeof value === 'object') {
    for (const item of Object.values(value)) flatten(item, out);
  }
}

function blob(...parts) {
  const out = [];
  flatten(parts, out);
  return out.join('\n');
}

function sentinelView(record) {
  const owasp = []
    .concat(record.OwaspLlm || [], record.OwaspAgentic || [])
    .map((item) => `${item.Id} ${item.Name}`)
    .filter(Boolean);
  return {
    severity: Number(record.Severity) || 0,
    severityName: record.SeverityName || '',
    tactic: record.Tactic || '',
    technique: record.Technique || '',
    techniqueId: record.TechniqueId || '',
    owasp,
    blocked: Boolean(record.PatternDispositionFlags?.Blocked),
    disposition: record.PatternDispositionDescription || '',
    narrative: record.CaseCard?.Narrative || record.DetectDescription || '',
    agent: record.Entities?.Agent?.Name || '',
    tool: record.Entities?.ToolCall?.Name || '',
    sink: record.Entities?.Sink?.Destination || '',
  };
}

export function normalize(item, windows) {
  const record = item.record || item;
  const source = record.source || detectSource(record);
  const id = item.id || record.AlertId || record.id || 'alert';
  const scenario = record.scenario || null;

  let epoch = null;
  let timestamp = null;
  let title = '';
  let host = null;
  let src = null;
  let dst = null;
  let ruleId = null;
  let vendorLevel = null;
  let groups = [];
  let email = null;
  let sentinel = null;
  let text = '';

  if (source === 'sentinel') {
    sentinel = sentinelView(record);
    timestamp = record.Timestamp || null;
    epoch = epochFrom(timestamp);
    title = record.DetectName || 'AI agent alert';
    host = sentinel.agent || null;
    ruleId = record.RuleId || null;
    vendorLevel = sentinel.severityName || String(sentinel.severity || '');
    text = blob(
      record.DetectName,
      record.DetectDescription,
      record.Category,
      record.RuleId,
      sentinel.narrative,
      sentinel.technique,
      sentinel.techniqueId,
      sentinel.owasp,
      record.Evidence,
    );
  } else if (source === 'email') {
    email = {
      from: String(record.from || ''),
      subject: String(record.subject || ''),
      body: String(record.body || ''),
      attachment: record.attachment || null,
    };
    title = email.subject || 'Email';
    host = email.from;
    text = blob(email.from, email.subject, email.body, email.attachment);
  } else if (source === 'aminer') {
    epoch = epochFrom(record.DetectionTimestamp ?? record.epoch);
    timestamp = epoch == null ? null : new Date(epoch * 1000).toISOString();
    title = record.AnalysisComponentName || 'AMiner alert';
    host = record.host || null;
    text = blob(
      record.AnalysisComponentName,
      record.AnalysisComponentType,
      record.Message,
      record.RawLogData,
      record.note,
    );
    const raw = String(record.RawLogData || '');
    const from = raw.match(/\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})/);
    if (from) src = from[1];
  } else {
    timestamp = record['@timestamp'] || record.timestamp || null;
    epoch = epochFrom(timestamp);
    const rule = record.rule || {};
    ruleId = rule.id != null ? String(rule.id) : null;
    vendorLevel = rule.level != null ? Number(rule.level) : null;
    groups = asList(rule.groups);
    title = rule.description || record.full_log || 'IDS alert';
    host = record.predecoder?.hostname || record.data?.http?.hostname || record.agent?.name || null;
    src = record.srcip || record.data?.src_ip || null;
    dst = record.data?.dest_ip || null;
    text = blob(rule.description, groups, record.full_log, record.data, record.note);
  }

  const phase = scenario ? phaseAt(windows, scenario, epoch) : null;
  const family = source === 'sentinel' ? 'sentinel' : source === 'email' ? 'email' : 'ait';

  return {
    id,
    source,
    family,
    scenario,
    timestamp,
    epoch,
    phase,
    title: String(title).slice(0, 180),
    text,
    textLower: text.toLowerCase(),
    host,
    src,
    dst,
    ruleId,
    vendorLevel,
    groups,
    email,
    sentinel,
  };
}
