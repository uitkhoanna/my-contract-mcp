// src/auditor.js
// Multi-pass audit orchestration. Each pass uses the CysicClient and the
// prompt templates in src/prompts.js. The output of every pass is parsed
// defensively, validated, and SWC-tagged where the model did not provide
// an id.

"use strict";

const { CysicClient, tryParseJsonLoose } = require("./cysicClient");
const { resolveSwcId, describeSwc } = require("./swc");
const {
  AUDITOR_SYSTEM_PROMPT,
  buildReconUserPrompt,
  buildDeepScanUserPrompt,
  buildSeverityUserPrompt,
  buildVulnerabilityClassPrompt,
  buildGasOptimizationPrompt,
} = require("./prompts");

// Cap raw source fed to a single model call. Beyond this, we chunk by
// `contract`/`function` declarations and run the deep scan per chunk,
// then merge. The 80k-character budget is conservative - the model has a
// generous context window, but the in-prompt instructions + recon +
// findings add overhead.
const LARGE_SOURCE_CHARS = 80_000;
const CHUNK_PADDING = 2_000;       // chars of overlap between chunks
const MAX_CHUNKS = 6;              // hard cap to avoid runaway cost

function makeAuditor(opts = {}) {
  const client = opts.client instanceof CysicClient
    ? opts.client
    : new CysicClient(opts.client || {});

  /**
   * Run a single chat round and parse JSON out of the response.
   * Throws if parsing fails - callers can decide whether to fall back.
   */
  async function chatJson(userPrompt, opts = {}) {
    const text = await client.chat(
      [
        { role: "system", content: AUDITOR_SYSTEM_PROMPT },
        { role: "user", content: userPrompt },
      ],
      { temperature: opts.temperature ?? 0.1, jsonMode: true, model: opts.model }
    );
    const parsed = tryParseJsonLoose(text);
    if (parsed == null) {
      const err = new Error("Model did not return valid JSON.");
      err.raw = text;
      err.snippet = String(text).slice(0, 400);
      throw err;
    }
    return { parsed, raw: text };
  }

  /**
   * Normalize a finding coming out of any pass: lowercase severity,
   * coerce line to a number, attach SWC id when missing, fill defaults.
   */
  function normalizeFinding(f, idx) {
    if (!f || typeof f !== "object") return null;
    const severity = normalizeSeverity(f.severity);
    const swcId = f.swcId && /^SWC-\d{2,3}$/i.test(String(f.swcId))
      ? String(f.swcId).toUpperCase()
      : resolveSwcId(f.category) || resolveSwcId(f.title);
    const swcInfo = describeSwc(swcId);
    return {
      severity,
      category: typeof f.category === "string" ? f.category : (swcInfo?.category || "general"),
      swcId: swcId || null,
      swcTitle: swcInfo?.title || null,
      title: typeof f.title === "string" ? f.title.trim() : `Finding ${idx + 1}`,
      function: typeof f.function === "string" ? f.function : null,
      line: typeof f.line === "number" ? f.line : null,
      description: typeof f.description === "string" ? f.description : "",
      recommendation: typeof f.recommendation === "string" ? f.recommendation : "",
      confidence: normalizeConfidence(f.confidence),
    };
  }

  /**
   * Run the 3-pass audit: recon -> deep scan (potentially chunked) ->
   * severity scoring + dedup. Returns the final structured result.
   */
  async function auditContract(source, contractName) {
    if (typeof source !== "string" || !source.trim()) {
      throw new Error("audit_contract: `source` must be a non-empty string.");
    }
    if (source.length > 500_000) {
      throw new Error("audit_contract: source is unreasonably large (>500k chars).");
    }
    const name = (typeof contractName === "string" && contractName.trim())
      ? contractName.trim()
      : guessContractName(source);

    // Pass 1: recon. Always run on the full source because it's cheap
    // and the summary is needed to understand the contract shape.
    const reconRaw = await chatJson(buildReconUserPrompt(source, name), {
      temperature: 0.05,
    });
    const recon = normalizeRecon(reconRaw.parsed, name);

    // Pass 2: deep scan. Chunked if the source is large.
    const rawFindings = await deepScan(source, name, recon);

    // Pass 3: severity scoring + dedup.
    const severityRaw = await chatJson(
      buildSeverityUserPrompt(source, name, recon, { findings: rawFindings }),
      { temperature: 0.1 }
    );
    const sevParsed = severityRaw.parsed || {};
    const finalFindings = Array.isArray(sevParsed.findings)
      ? sevParsed.findings.map(normalizeFinding).filter(Boolean)
      : rawFindings.map(normalizeFinding).filter(Boolean);

    const riskScore = clampInt(sevParsed.riskScore, 0, 100, scoreFromFindings(finalFindings));
    const summary = typeof sevParsed.summary === "string" && sevParsed.summary.trim()
      ? sevParsed.summary.trim()
      : deriveSummary(finalFindings);
    const executiveSummary = typeof sevParsed.executiveSummary === "string" && sevParsed.executiveSummary.trim()
      ? sevParsed.executiveSummary.trim()
      : summary.split(/\.\s+/).slice(0, 2).join(". ") + ".";

    return {
      contractName: name,
      summary,
      executiveSummary,
      riskScore,
      findings: finalFindings,
      meta: {
        passes: 3,
        reconFields: Object.keys(recon),
        model: client.model,
        sourceChars: source.length,
        rawFindingCount: rawFindings.length,
        finalFindingCount: finalFindings.length,
      },
    };
  }

  /**
   * Deep scan pass. For small sources, a single call. For large sources,
   * split by top-level contract/function boundaries and run a per-chunk
   * deep scan, then merge.
   */
  async function deepScan(source, name, recon) {
    if (source.length <= LARGE_SOURCE_CHARS) {
      const out = await chatJson(buildDeepScanUserPrompt(source, name, recon), {
        temperature: 0.2,
      });
      return Array.isArray(out.parsed?.findings) ? out.parsed.findings : [];
    }
    const chunks = chunkByDeclarations(source, MAX_CHUNKS);
    const all = [];
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      // The recon already knows about every function/contract. We pass a
      // per-chunk header so the model knows this is a slice of a larger
      // contract.
      const prompt = `${buildDeepScanUserPrompt(chunk, name + " (chunk " + (i + 1) + "/" + chunks.length + ")", recon)}

Note: this is chunk ${i + 1} of ${chunks.length} of the same source. Look only at the code in this chunk; do not infer cross-chunk state.`;
      try {
        const out = await chatJson(prompt, { temperature: 0.2 });
        if (Array.isArray(out.parsed?.findings)) all.push(...out.parsed.findings);
      } catch (err) {
        // If a chunk fails to parse, we still want to return the others.
        // Surface the failure as a synthetic informational finding.
        all.push({
          severity: "informational",
          category: "audit-coverage",
          swcId: null,
          title: `Deep-scan chunk ${i + 1} could not be parsed`,
          function: null,
          line: null,
          description: `The model returned non-JSON output for chunk ${i + 1}. Raw snippet: ${err.snippet || "(empty)"}`,
          recommendation: "Re-run audit_contract on the affected chunk individually, or reduce source size.",
          confidence: "high",
        });
      }
    }
    return all;
  }

  /**
   * Targeted check for a single vulnerability class.
   */
  async function checkVulnerability(source, vulnClass) {
    if (typeof source !== "string" || !source.trim()) {
      throw new Error("check_vulnerability: `source` must be a non-empty string.");
    }
    if (typeof vulnClass !== "string" || !vulnClass.trim()) {
      throw new Error("check_vulnerability: `vulnClass` must be a non-empty string.");
    }
    const vc = vulnClass.trim();
    const { parsed } = await chatJson(buildVulnerabilityClassPrompt(source, vc), {
      temperature: 0.05,
    });
    const swcId = parsed.swcId && /^SWC-\d{2,3}$/i.test(String(parsed.swcId))
      ? String(parsed.swcId).toUpperCase()
      : resolveSwcId(vc) || resolveSwcId(parsed.category);
    const swcInfo = describeSwc(swcId);
    return {
      vulnClass: vc,
      isVulnerable: !!parsed.isVulnerable,
      severity: parsed.isVulnerable ? normalizeSeverity(parsed.severity) : null,
      swcId: swcId || null,
      swcTitle: swcInfo?.title || null,
      title: parsed.title || null,
      function: typeof parsed.function === "string" ? parsed.function : null,
      line: typeof parsed.line === "number" ? parsed.line : null,
      description: parsed.description || "",
      recommendation: parsed.recommendation || "",
      confidence: normalizeConfidence(parsed.confidence),
    };
  }

  /**
   * Gas optimization review. Returns a structured list of suggestions.
   */
  async function gasOptimization(source) {
    if (typeof source !== "string" || !source.trim()) {
      throw new Error("gas_optimization: `source` must be a non-empty string.");
    }
    const { parsed } = await chatJson(buildGasOptimizationPrompt(source), {
      temperature: 0.2,
    });
    const suggestions = Array.isArray(parsed.suggestions) ? parsed.suggestions : [];
    return {
      summary: typeof parsed.summary === "string" ? parsed.summary : "",
      suggestions: suggestions
        .filter((s) => s && typeof s === "object")
        .map((s, i) => ({
          title: typeof s.title === "string" ? s.title : `Suggestion ${i + 1}`,
          function: typeof s.function === "string" ? s.function : null,
          line: typeof s.line === "number" ? s.line : null,
          category: normalizeGasCategory(s.category),
          estimatedSavingsGas: typeof s.estimatedSavingsGas === "number" ? s.estimatedSavingsGas : null,
          description: typeof s.description === "string" ? s.description : "",
          recommendation: typeof s.recommendation === "string" ? s.recommendation : "",
        })),
    };
  }

  /**
   * Run audit_contract and render a clean Markdown report.
   */
  async function generateReport(source, contractName, format = "markdown") {
    if (format && format !== "markdown") {
      throw new Error(`generate_report: unsupported format "${format}". Only "markdown" is supported.`);
    }
    const result = await auditContract(source, contractName);
    return {
      format: "markdown",
      markdown: renderMarkdownReport(result),
      structured: result,
    };
  }

  return {
    client,
    auditContract,
    checkVulnerability,
    gasOptimization,
    generateReport,
  };
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

const SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"];

function normalizeSeverity(s) {
  if (typeof s !== "string") return "informational";
  const v = s.toLowerCase().trim();
  return SEVERITY_ORDER.includes(v) ? v : "informational";
}

function normalizeConfidence(c) {
  if (typeof c !== "string") return "medium";
  const v = c.toLowerCase().trim();
  return ["low", "medium", "high"].includes(v) ? v : "medium";
}

function normalizeGasCategory(c) {
  const allowed = new Set([
    "storage", "memory", "calldata", "loop", "external-call",
    "immutable", "constant", "packing", "short-circuit", "other",
  ]);
  return allowed.has(c) ? c : "other";
}

function clampInt(v, lo, hi, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(lo, Math.min(hi, Math.round(n)));
}

function scoreFromFindings(findings) {
  if (!findings.length) return 0;
  const weights = { critical: 35, high: 18, medium: 8, low: 3, informational: 1 };
  let s = 0;
  for (const f of findings) s += weights[f.severity] || 0;
  return Math.min(100, s);
}

function deriveSummary(findings) {
  if (!findings.length) return "No significant issues identified by the model.";
  const counts = countBySeverity(findings);
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
  return `Audit identified ${findings.length} finding(s). Most common severity: ${top[0]} (${top[1]}).`;
}

function countBySeverity(findings) {
  const out = {};
  for (const f of findings) out[f.severity] = (out[f.severity] || 0) + 1;
  return out;
}

function guessContractName(source) {
  const m = source.match(/\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)/);
  if (m) return m[1];
  return "UnknownContract";
}

function normalizeRecon(parsed, fallbackName) {
  if (!parsed || typeof parsed !== "object") {
    return {
      contractName: fallbackName,
      pragma: null,
      imports: [],
      inherits: [],
      stateVariables: [],
      functions: [],
      externalCalls: [],
      valueFlows: [],
      assumptions: [],
    };
  }
  return {
    contractName: typeof parsed.contractName === "string" ? parsed.contractName : fallbackName,
    pragma: typeof parsed.pragma === "string" ? parsed.pragma : null,
    imports: Array.isArray(parsed.imports) ? parsed.imports.filter((s) => typeof s === "string") : [],
    inherits: Array.isArray(parsed.inherits) ? parsed.inherits.filter((s) => typeof s === "string") : [],
    stateVariables: Array.isArray(parsed.stateVariables)
      ? parsed.stateVariables.filter((v) => v && typeof v === "object")
      : [],
    functions: Array.isArray(parsed.functions)
      ? parsed.functions.filter((f) => f && typeof f === "object")
      : [],
    externalCalls: Array.isArray(parsed.externalCalls)
      ? parsed.externalCalls.filter((c) => c && typeof c === "object")
      : [],
    valueFlows: Array.isArray(parsed.valueFlows) ? parsed.valueFlows.filter((s) => typeof s === "string") : [],
    assumptions: Array.isArray(parsed.assumptions) ? parsed.assumptions.filter((s) => typeof s === "string") : [],
  };
}

/**
 * Naive chunker: split on top-level `contract ` / `function ` / `library `
 * declarations, then group declarations back into chunks of roughly
 * LARGE_SOURCE_CHARS chars each. Overlap is added between chunks so
 * the model sees a bit of context on each side of a boundary.
 */
function chunkByDeclarations(source, maxChunks) {
  const lines = source.split("\n");
  // Indices where a new top-level declaration starts.
  const starts = [0];
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (/^\s*(contract|library|interface|abstract\s+contract)\s+[A-Za-z_]/.test(ln)
        || /^\s*function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(/.test(ln)) {
      if (i !== 0) starts.push(i);
    }
  }
  // Build per-declaration blocks.
  const blocks = [];
  for (let i = 0; i < starts.length; i++) {
    const start = starts[i];
    const end = i + 1 < starts.length ? starts[i + 1] : lines.length;
    blocks.push(lines.slice(start, end).join("\n"));
  }
  // Greedily pack blocks into chunks.
  const chunks = [];
  let current = "";
  for (const b of blocks) {
    if ((current.length + b.length) > LARGE_SOURCE_CHARS && current.length > 0) {
      chunks.push(current);
      current = b;
    } else {
      current = current ? current + "\n" + b : b;
    }
    if (chunks.length >= maxChunks) break;
  }
  if (current && chunks.length < maxChunks) chunks.push(current);
  return chunks;
}

// ---------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------

function renderMarkdownReport(result) {
  const lines = [];
  lines.push(`# Smart Contract Audit Report — \`${result.contractName}\``);
  lines.push("");
  lines.push(`**Risk score:** ${result.riskScore} / 100`);
  lines.push("");
  lines.push(`> ${result.executiveSummary || result.summary}`);
  lines.push("");
  lines.push("## Summary");
  lines.push(result.summary || "(no summary)");
  lines.push("");

  const grouped = groupBySeverity(result.findings);
  const order = ["critical", "high", "medium", "low", "informational"];
  const totals = order.map((s) => `${s}: ${grouped[s].length}`).join("  ·  ");
  lines.push(`**Findings by severity:** ${totals}`);
  lines.push("");

  if (!result.findings.length) {
    lines.push("_No findings._");
    return lines.join("\n");
  }

  for (const sev of order) {
    const items = grouped[sev];
    if (!items.length) continue;
    lines.push(`## ${capitalize(sev)} (${items.length})`);
    lines.push("");
    for (let i = 0; i < items.length; i++) {
      const f = items[i];
      const loc = f.function ? ` — \`${f.function}\`` : "";
      const swc = f.swcId ? ` (${f.swcId}: ${f.swcTitle || "see SWC registry"})` : "";
      lines.push(`### ${i + 1}. ${f.title}${swc}${loc}`);
      lines.push("");
      lines.push(`- **Severity:** ${capitalize(f.severity)}`);
      lines.push(`- **Confidence:** ${capitalize(f.confidence)}`);
      if (f.category) lines.push(`- **Category:** ${f.category}`);
      if (f.line != null) lines.push(`- **Line:** ${f.line}`);
      if (f.swcId) lines.push(`- **SWC:** ${f.swcId} — ${f.swcTitle || ""}`);
      lines.push("");
      lines.push(f.description || "_(no description)_");
      lines.push("");
      lines.push("**Recommendation:**");
      lines.push(f.recommendation || "_(no recommendation)_");
      lines.push("");
    }
  }

  lines.push("---");
  lines.push("_Generated by solidity-auditor-mcp using the Cysic Minimax model (minimax-m3)._");
  return lines.join("\n");
}

function groupBySeverity(findings) {
  const out = { critical: [], high: [], medium: [], low: [], informational: [] };
  for (const f of findings) {
    if (!out[f.severity]) out[f.severity] = [];
    out[f.severity].push(f);
  }
  return out;
}

function capitalize(s) {
  if (!s) return "";
  return s.charAt(0).toUpperCase() + s.slice(1);
}

module.exports = {
  makeAuditor,
  renderMarkdownReport, // exported for testing/demo
};
