// src/cysicClient.js
// Thin OpenAI-compatible client for the Cysic Minimax token-gated API.
// No external HTTP deps - uses Node 18+ global fetch.
//
// Endpoint: POST {baseUrl}/chat/completions
// Auth:     Authorization: Bearer ${CYSIC_API_KEY}
//
// Exposed surface:
//   const client = new CysicClient({ apiKey, baseUrl, model, timeoutMs });
//   const text   = await client.chat(messages, { temperature, jsonMode });

"use strict";

const DEFAULT_BASE_URL = "https://token-ai.cysic.xyz/v1";
const DEFAULT_MODEL = "minimax-m3";
const DEFAULT_TIMEOUT_MS = 60_000;

class CysicApiError extends Error {
  constructor(message, { status, body, cause } = {}) {
    super(message);
    this.name = "CysicApiError";
    this.status = status ?? null;
    this.body = body ?? null;
    this.cause = cause ?? null;
  }
}

class CysicClient {
  /**
   * @param {object} [opts]
   * @param {string} [opts.apiKey]     - API key. Defaults to process.env.CYSIC_API_KEY.
   * @param {string} [opts.baseUrl]    - Defaults to process.env.CYSIC_BASE_URL or "https://token-ai.cysic.xyz/v1".
   * @param {string} [opts.model]      - Defaults to process.env.CYSIC_MODEL or "minimax-m3".
   * @param {number} [opts.timeoutMs]  - Per-request timeout. Defaults to 60s.
   * @param {number} [opts.maxRetries] - Retries on transient errors (5xx, network). Defaults to 1.
   */
  constructor(opts = {}) {
    this.apiKey = (opts.apiKey ?? process.env.CYSIC_API_KEY ?? "").trim();
    this.baseUrl = (opts.baseUrl ?? process.env.CYSIC_BASE_URL ?? DEFAULT_BASE_URL)
      .replace(/\/+$/, "");
    this.model = opts.model ?? process.env.CYSIC_MODEL ?? DEFAULT_MODEL;
    this.timeoutMs = Number.isFinite(opts.timeoutMs)
      ? opts.timeoutMs
      : Number.parseInt(process.env.CYSIC_TIMEOUT_MS, 10) || DEFAULT_TIMEOUT_MS;
    this.maxRetries = Number.isFinite(opts.maxRetries) ? opts.maxRetries : 1;

    if (!this.apiKey) {
      // Don't throw at construction time - the server may be started without
      // an API key for `--help` or `node --check` style usage. We do throw
      // loudly on the first chat() call. Tests can stub the network layer.
    }
  }

  _requireKey() {
    if (!this.apiKey) {
      throw new CysicApiError(
        "CYSIC_API_KEY is not set. Provide it via env, .env, or the constructor."
      );
    }
  }

  /**
   * Send a chat completion request and return the assistant text content.
   * @param {Array<{role: string, content: string}>} messages
   * @param {object} [opts]
   * @param {number} [opts.temperature=0.2]   - 0.0 - 1.0.
   * @param {boolean} [opts.jsonMode=true]    - Asks the model to return JSON only.
   * @param {string}  [opts.model]            - Override the default model.
   * @returns {Promise<string>}
   */
  async chat(messages, opts = {}) {
    this._requireKey();
    if (!Array.isArray(messages) || messages.length === 0) {
      throw new CysicApiError("chat() requires a non-empty `messages` array.");
    }
    const temperature = Number.isFinite(opts.temperature) ? opts.temperature : 0.2;
    const jsonMode = opts.jsonMode !== false; // default true for this auditor
    const model = opts.model || this.model;

    const body = {
      model,
      temperature,
      messages,
      // The Minimax/Cysic endpoint supports the OpenAI `response_format` field.
      // Setting {"type":"json_object"} is a strong hint; we also instruct the
      // model to return JSON in the system prompt as a belt-and-braces measure.
      response_format: jsonMode ? { type: "json_object" } : undefined,
    };

    const url = `${this.baseUrl}/chat/completions`;
    let lastErr = null;
    const attempts = Math.max(0, this.maxRetries) + 1;
    for (let i = 0; i < attempts; i++) {
      try {
        const res = await this._postWithTimeout(url, body);
        if (!res.ok) {
          const text = await safeReadText(res);
          const retriable = res.status >= 500 || res.status === 429;
          lastErr = new CysicApiError(
            `Cysic API ${res.status} ${res.statusText}: ${truncate(text, 400)}`,
            { status: res.status, body: text }
          );
          if (!retriable || i === attempts - 1) throw lastErr;
          await sleep(backoffMs(i));
          continue;
        }
        const data = await res.json();
        const content = extractContent(data);
        if (content == null) {
          throw new CysicApiError(
            "Cysic API returned a response with no assistant content.",
            { status: res.status, body: data }
          );
        }
        return content;
      } catch (err) {
        lastErr = err;
        if (err instanceof CysicApiError && err.status && err.status < 500 && err.status !== 429) {
          // 4xx (other than 429) is a client mistake - don't retry.
          throw err;
        }
        if (i === attempts - 1) {
          if (!(err instanceof CysicApiError)) {
            throw new CysicApiError(`Network error talking to Cysic: ${err.message}`, { cause: err });
          }
          throw err;
        }
        await sleep(backoffMs(i));
      }
    }
    throw lastErr ?? new CysicApiError("Cysic chat failed without a captured error.");
  }

  _postWithTimeout(url, body) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    return fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${this.apiKey}`,
        "Accept": "application/json",
      },
      body: JSON.stringify(body),
      signal: ctl.signal,
    }).finally(() => clearTimeout(t));
  }
}

function extractContent(data) {
  if (!data || typeof data !== "object") return null;
  const choice = Array.isArray(data.choices) ? data.choices[0] : null;
  if (!choice) return null;
  // OpenAI-compatible: choice.message.content
  const msg = choice.message || choice.delta;
  if (msg && typeof msg.content === "string") return msg.content;
  if (typeof choice.text === "string") return choice.text;
  return null;
}

async function safeReadText(res) {
  try { return await res.text(); } catch { return ""; }
}

function truncate(s, n) {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) + "..." : s;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffMs(i) {
  // 250ms, 750ms, ...
  return 250 * (3 * i + 1);
}

/**
 * Best-effort: extract a JSON object/array from a string. Handles
 *   - ```json ... ``` fenced blocks
 *   - "Here is the JSON: {...}" prose prefix
 *   - a raw JSON value
 * Returns the parsed value, or null on failure.
 */
function tryParseJsonLoose(text) {
  if (text == null) return null;
  if (typeof text === "object") return text;
  let s = String(text).trim();
  if (!s) return null;

  // 1. Strip ```json fences.
  const fence = s.match(/```(?:json|JSON)?\s*([\s\S]*?)```/);
  if (fence) s = fence[1].trim();

  // 2. Find the outermost balanced {...} or [...]
  const firstBrace = s.search(/[\{\[]/);
  if (firstBrace === -1) return null;
  const last = s.lastIndexOf(s[firstBrace] === "{" ? "}" : "]");
  if (last === -1) return null;
  const candidate = s.slice(firstBrace, last + 1);
  try {
    return JSON.parse(candidate);
  } catch (_) {
    // 3. Try to repair common LLM JSON errors: trailing commas, smart quotes.
    const repaired = candidate
      .replace(/[‘’]/g, "'")
      .replace(/[“”]/g, '"')
      .replace(/,(\s*[\}\]])/g, "$1");
    try { return JSON.parse(repaired); } catch { return null; }
  }
}

module.exports = {
  CysicClient,
  CysicApiError,
  tryParseJsonLoose,
  DEFAULT_BASE_URL,
  DEFAULT_MODEL,
  DEFAULT_TIMEOUT_MS,
};
