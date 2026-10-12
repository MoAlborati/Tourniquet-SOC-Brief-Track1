import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export function parseDotEnv(text) {
  const out = {};
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

export function loadEnvFile(path, env = process.env) {
  if (!existsSync(path)) return env;
  const parsed = parseDotEnv(readFileSync(path, 'utf8'));
  for (const [key, value] of Object.entries(parsed)) {
    if (env[key] == null || env[key] === '') env[key] = value;
  }
  return env;
}

export const DEFAULT_BASE_URL = 'https://openrouter.ai/api/v1';
export const DEFAULT_MODEL = 'openrouter/free';

export function readConfig(env = process.env) {
  return {
    apiKey: env.OPENROUTER_API_KEY || env.LLM_API_KEY || env.OPENAI_API_KEY || '',
    baseUrl: String(env.LLM_BASE_URL || DEFAULT_BASE_URL).replace(/\/$/, ''),
    model: env.LLM_MODEL || DEFAULT_MODEL,
  };
}

export function createCompleter(config, fetchImpl = globalThis.fetch) {
  if (!config?.apiKey) return null;
  return async function complete({ system, user }) {
    const headers = {
      'content-type': 'application/json',
      authorization: `Bearer ${config.apiKey}`,
    };
    if (config.baseUrl.includes('openrouter.ai')) {
      headers['http-referer'] = 'http://127.0.0.1:8787';
      headers['x-title'] = 'SOC Brief';
    }
    const response = await fetchImpl(`${config.baseUrl}/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: config.model,
        temperature: 0,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      }),
    });
    if (!response.ok) {
      throw new Error(`model http ${response.status}`);
    }
    const body = await response.json();
    return body.choices?.[0]?.message?.content || '';
  };
}

export function completerFromEnv(root, env = process.env, fetchImpl = globalThis.fetch) {
  loadEnvFile(join(root, '.env'), env);
  return createCompleter(readConfig(env), fetchImpl);
}
