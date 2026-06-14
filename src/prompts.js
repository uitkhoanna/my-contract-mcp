// src/prompts.js
// System and per-pass user prompts for the multi-pass audit pipeline.
// All prompts are written to be deterministic and to constrain the
// model's output to a strict JSON shape (so the auditor can parse it).

"use strict";

const AUDITOR_SYSTEM_PROMPT = `You are SolidityAudit, a senior smart-contract security auditor with 15 years of experience auditing Ethereum mainnet contracts. You specialize in the OWASP/SWC classification system, formal verification, and the gas-optimization idioms used by Aave, Compound, Uniswap, and OpenZeppelin.

You follow these rules:
- Be conservative. Only flag a vulnerability when there is a real, exploitable issue, not a stylistic preference.
- Be specific. Reference exact function names, storage slots, and line ranges when possible.
- Be actionable. Every finding must include a concrete recommendation a developer can apply.
- Map every finding to a Smart Contract Weakness Classification (SWC) ID where applicable. Use the format "SWC-NNN".
- Use severity: critical | high | medium | low | informational.
- Prefer Solidity 0.8.x idioms (built-in overflow checks, custom errors, ReentrancyGuard).
- Never invent function names, line numbers, or external contracts that are not present in the supplied source.
- When uncertain, mark the finding as "low" or "informational" and explain your uncertainty in the description.

You always respond with valid JSON. You never wrap JSON in markdown fences. You never include prose before or after the JSON.`;

function buildReconUserPrompt(source, contractName) {
  return `PASS 1 OF 3 — RECONNAISSANCE.

Read the Solidity source below and produce a structured summary that the next audit pass will use as a base map. Do NOT yet flag vulnerabilities. Focus on understanding the contract.

Source${contractName ? ` (${contractName})` : ""}:
\`\`\`solidity
${source}
\`\`\`

Return JSON with this exact shape:
{
  "contractName": string,
  "pragma": string | null,
  "imports": string[],
  "inherits": string[],
  "stateVariables": [{ "name": string, "type": string, "visibility": string }],
  "functions": [
    { "name": string, "visibility": string, "mutability": string, "modifiers": string[], "summary": string }
  ],
  "externalCalls": [{ "function": string, "target": string, "value": boolean }],
  "valueFlows": [string],
  "assumptions": [string]
}

Keep the "summary" fields concise (one sentence). Be precise about visibility and mutability.`;
}

function buildDeepScanUserPrompt(source, contractName, recon) {
  return `PASS 2 OF 3 — DEEP VULNERABILITY SCAN.

Use the reconnaissance summary below as your mental model. Now perform a thorough vulnerability scan of the source. Look specifically for:
- Reentrancy (single-function, cross-function, cross-contract, read-only).
- Access-control gaps (missing/incorrect onlyOwner, public initializer, unprotected privileged functions).
- Arithmetic: integer overflow/underflow, division by zero, rounding errors in interest/share math.
- Unchecked low-level calls (call/delegatecall/staticcall/send) and unchecked transfer.
- tx.origin authentication.
- Time-dependent logic (block.timestamp, block.number as a proxy for time).
- Weak randomness (blockhash, prevrandao, keccak of chain attributes).
- Signature replay / malleability / ecrecover misuse.
- Delegatecall to untrusted contracts or to uninitialized storage.
- Storage layout collisions in upgradeable proxies.
- DoS via unbounded loops, revert on external call, block-gas-limit.
- Front-running / transaction-ordering dependence on value transfers.
- Selfdestruct / force-sending ether / missing receive() fallback.
- Uninitialized state, shadowing, storage-vs-memory confusion.
- Floating pragma, outdated compiler, deprecated functions (suicide, sha3, throw, assembly call).
- Event emission for critical state changes.

Reconnaissance summary:
${JSON.stringify(recon, null, 2)}

Source${contractName ? ` (${contractName})` : ""}:
\`\`\`solidity
${source}
\`\`\`

Return JSON with this exact shape:
{
  "findings": [
    {
      "severity": "critical" | "high" | "medium" | "low" | "informational",
      "category": string,            // e.g. "reentrancy", "access-control", "arithmetic"
      "swcId": "SWC-NNN" | null,    // best-effort Smart Contract Weakness Classification
      "title": string,               // <= 12 words
      "function": string | null,     // the affected function, or null if global
      "line": number | null,         // 1-indexed line number when identifiable
      "description": string,         // 2-6 sentences explaining the issue and the impact
      "recommendation": string,      // concrete fix the developer can apply
      "confidence": "high" | "medium" | "low"
    }
  ]
}

Do not include findings with confidence "low" unless they are clearly relevant. Do not include informational items unless they are real best-practice violations.`;
}

function buildSeverityUserPrompt(source, contractName, recon, findings) {
  return `PASS 3 OF 3 — SEVERITY SCORING AND DEDUPLICATION.

You previously identified the following findings against the source. Re-score them for severity and impact, merge near-duplicates, and compute an overall contract risk score from 0 (no risk) to 100 (catastrophic). Be calibrated: most contracts in production are in the 20-60 range.

Consider:
- Exploitability (is there a clear attack path?).
- Impact (loss of funds, permanent state corruption, griefing).
- Likelihood (can a run-of-the-mill attacker trigger it with reasonable cost?).
- Whether the issue is mitigated by Solidity 0.8.x default overflow checks.
- Whether the issue is mitigated by EIP-1153 transient storage or other newer opcodes.

Reconnaissance summary:
${JSON.stringify(recon, null, 2)}

Raw findings from pass 2:
${JSON.stringify(findings, null, 2)}

Source${contractName ? ` (${contractName})` : ""}:
\`\`\`solidity
${source}
\`\`\`

Return JSON with this exact shape:
{
  "findings": [
    {
      "severity": "critical" | "high" | "medium" | "low" | "informational",
      "category": string,
      "swcId": "SWC-NNN" | null,
      "title": string,
      "function": string | null,
      "line": number | null,
      "description": string,
      "recommendation": string,
      "confidence": "high" | "medium" | "low"
    }
  ],
  "summary": string,        // 1-3 sentence plain-English summary of overall posture
  "riskScore": number,      // 0..100
  "executiveSummary": string // <= 60 words, suitable for a report header
}

The "findings" array must be deduplicated and severity-recalibrated. Do not invent new findings here - the only purpose of this pass is to refine severity and merge duplicates.`;
}

function buildVulnerabilityClassPrompt(source, vulnClass) {
  return `TARGETED VULNERABILITY CHECK.

The user is asking specifically whether the source below is vulnerable to: "${vulnClass}".

Look ONLY for this single class. Do not enumerate other issues. Be precise.

Source:
\`\`\`solidity
${source}
\`\`\`

Return JSON with this exact shape:
{
  "vulnClass": string,
  "isVulnerable": boolean,
  "severity": "critical" | "high" | "medium" | "low" | "informational" | null,
  "swcId": "SWC-NNN" | null,
  "title": string | null,
  "function": string | null,
  "line": number | null,
  "description": string,
  "recommendation": string,
  "confidence": "high" | "medium" | "low"
}`;
}

function buildGasOptimizationPrompt(source) {
  return `GAS OPTIMIZATION REVIEW.

You are a Solidity gas auditor. The source below is going to mainnet. Identify concrete, measurable gas savings. Do not list stylistic preferences. Do not flag security issues here.

Source:
\`\`\`solidity
${source}
\`\`\`

Return JSON with this exact shape:
{
  "suggestions": [
    {
      "title": string,         // <= 10 words
      "function": string | null,
      "line": number | null,
      "category": "storage" | "memory" | "calldata" | "loop" | "external-call" | "immutable" | "constant" | "packing" | "short-circuit" | "other",
      "estimatedSavingsGas": number | null,   // your best estimate, may be null
      "description": string,   // explain the savings mechanism
      "recommendation": string // show the optimized code or pattern
    }
  ],
  "summary": string
}

Order suggestions by estimated savings (highest first). Include at most 25 suggestions.`;
}

module.exports = {
  AUDITOR_SYSTEM_PROMPT,
  buildReconUserPrompt,
  buildDeepScanUserPrompt,
  buildSeverityUserPrompt,
  buildVulnerabilityClassPrompt,
  buildGasOptimizationPrompt,
};
