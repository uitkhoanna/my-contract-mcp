# Architecture — `solidity-auditor-mcp`

This document explains the runtime topology, the multi-pass audit
pipeline, and the design decisions behind the project. If you only read
one file in the repo, it should be [`README.md`](./README.md) — this
document is the longer, more technical companion.

## 1. Goals

`solidity-auditor-mcp` exists to make smart-contract auditing an
LLM-augmented, programmatic primitive. The non-goals are equally
important:

- **Not** a replacement for human auditors on a high-value protocol.
- **Not** a static analyzer (we do not run Slither/Mythril in-process).
- **Not** a code generator (we do not auto-patch contracts).

The auditor is a *signal generator* — a fast, SWC-tagged, severity-scored
first pass that an engineer can use to triage.

## 2. Runtime topology

```
                    +----------------------------+
                    |  MCP client (Claude,       |
                    |  Cursor, custom agent...)  |
                    +-------------+--------------+
                                  |  JSON-RPC over stdio
                                  v
                    +----------------------------+
                    |       server.js            |
                    |  (MCP server, stdio)       |
                    |                            |
                    |  - ListTools handler       |
                    |  - CallTool dispatcher     |
                    |  - input validation        |
                    +------+----------+----------+
                           |          |
            +--------------+          +-------------------+
            v                                         v
   +-------------------+                  +---------------------+
   |   src/auditor.js  |  <-----uses----> |  src/prompts.js     |
   |   (orchestration) |                  |  (system+per-pass   |
   |                   |                  |   templates)        |
   |   - 3-pass audit  |                  +---------------------+
   |   - chunking      |
   |   - normalize     |                  +---------------------+
   |   - dedup         |  <-----uses----> |  src/swc.js         |
   |   - scoring       |                  |  (SWC registry +    |
   |   - markdown      |                  |   category aliases) |
   +---------+---------+                  +---------------------+
             |
             v
   +-------------------+
   | src/cysicClient.js|  ---- HTTPS POST  --->  https://token-ai.cysic.xyz/v1/chat/completions
   |  (OpenAI-compat   |                                  (minimax-m3)
   |   fetch wrapper)  |  <----- JSON ------          Authorization: Bearer $CYSIC_API_KEY
   +-------------------+
```

### Module boundaries

| Module              | Responsibility                                                                                              | Talks to              |
|---------------------|-------------------------------------------------------------------------------------------------------------|-----------------------|
| `server.js`         | MCP server lifecycle, tool registration, input validation, error wrapping, JSON-RPC framing over stdio.     | `auditor.js`          |
| `src/auditor.js`    | Multi-pass orchestration, chunking, normalization, deduplication, severity scoring, Markdown rendering.     | `cysicClient.js`, `prompts.js`, `swc.js` |
| `src/cysicClient.js`| Thin OpenAI-compatible HTTPS client with auth, timeout, retry, and a tolerant JSON parser.                   | Cysic Minimax API     |
| `src/prompts.js`    | System prompt and per-pass user prompts. Constrains model output to a strict JSON shape.                    | (pure text)           |
| `src/swc.js`        | Curated SWC registry and category-to-SWC mapping. Pure data + small lookup helpers.                         | (pure data)           |

### Data flow for one tool call

1. The MCP client sends a `tools/call` request on stdin.
2. `server.js` validates the arguments, then dispatches to `auditor.js`.
3. `auditor.js` calls `cysicClient.chat()` 1..N times, one per pass (and
   per chunk for very large contracts).
4. Each `chat()` call sends a `POST /v1/chat/completions` request to
   Cysic, with `Authorization: Bearer $CYSIC_API_KEY` and
   `response_format: { "type": "json_object" }`.
5. The model returns a JSON string. `cysicClient.js` strips code
   fences, repairs trailing-comma errors, and parses it.
6. `auditor.js` normalizes each finding (lowercase severity, line
   coercion, SWC fallback), merges duplicates in pass 3, computes a
   risk score, and returns a structured object.
7. `server.js` wraps the object in a `content[].text` MCP result and
   writes it to stdout.

## 3. The 3-pass audit pipeline

Why three passes instead of one? Because the strongest single-prompt
audits we tested still conflate *reconnaissance* with *judgment*, and
they tend to over-flag stylistic issues. Splitting the work has three
measurable benefits.

### Pass 1 — Reconnaissance (`buildReconUserPrompt`)

A *summary* prompt. The model is told to extract the contract map:
state variables, function visibility, modifiers, external calls, value
flows, assumptions. No vulnerability claims are made yet. The result is
a stable mental model for the next pass.

Why it matters:
- A model that has to summarize first produces fewer "phantom" findings
  in pass 2 (findings that reference functions which do not exist).
- The recon object is serialized into pass 2's user message, which
  dramatically reduces the cost of the scan: the model does not have
  to re-derive the inheritance graph or the set of external calls.

### Pass 2 — Deep vulnerability scan (`buildDeepScanUserPrompt`)

The model is given the recon plus the full source and is asked to emit
a `findings` array. Each finding has severity, category, SWC id,
title, function, line, description, recommendation, and confidence.

For sources over 80k characters, this pass is *chunked* by top-level
declaration boundaries (`contract`/`library`/`interface`/`function`),
with up to 6 chunks. The recon is shared across chunks so the model
does not lose the big picture.

### Pass 3 — Severity scoring and dedup (`buildSeverityUserPrompt`)

Pass 2 tends to produce too many findings at too coarse a severity. The
third pass asks the model to:
- Re-score severity using exploitability, impact, likelihood.
- Merge near-duplicates (the same SWC-107 spotted in three places).
- Compute an overall `riskScore` 0..100.
- Produce a 1-3 sentence `summary` and a 60-word `executiveSummary`.

If the model fails on pass 3, the auditor falls back to pass 2's
findings and computes the risk score heuristically from severity
weights (`critical: 35, high: 18, medium: 8, low: 3, informational: 1`,
clamped to 100). The system never silently returns empty results.

### Why this beats a single prompt

A single-shot audit has to simultaneously: understand the contract,
find the bugs, judge their severity, and write a summary. The
3-pass pipeline is a *forced de-coupling* of those tasks. Empirically,
it:

- Reduces hallucinated function names (the recon forces the model to
  list the actual functions in pass 1).
- Reduces over-flagging (the severity pass is told to be "calibrated"
  and is given the pass-2 findings to refine, not to expand).
- Produces a more accurate risk score (the model is given explicit
  scoring criteria and is asked to commit to a single number).

## 4. Defensive JSON parsing

LLM JSON output is not a contract. We get:
- Fenced ```json blocks.
- Prose prefix ("Here is the JSON: ").
- Smart quotes from copy-paste.
- Trailing commas in arrays/objects.

`cysicClient.js` exposes `tryParseJsonLoose(text)`. The implementation:
1. Strip ```json fences if present.
2. Find the outermost balanced `{...}` or `[...]`.
3. Try `JSON.parse`. If that fails, normalize smart quotes and strip
   trailing commas, then retry.
4. Return `null` on final failure so callers can fall back.

The auditor wraps every model call with this parser. If a call returns
`null`, the auditor surfaces the raw text as a synthetic
"audit-coverage" informational finding rather than dropping the whole
audit on the floor.

## 5. Large-contract handling

For sources over 80k characters, the auditor:
1. Splits the source into blocks on top-level `contract`, `library`,
   `interface`, and `function` declaration lines.
2. Greedily packs blocks into chunks of roughly 80k characters.
3. Runs pass 2 per chunk, sharing the same recon across chunks.
4. Caps the total chunk count at 6 to avoid runaway cost. A source
   that does not fit in 6 chunks is a candidate for splitting at the
   file level by the caller, not for one mega-audit.

This is a deliberately conservative budget. The model has a larger
context window, but keeping the per-call prompt under 100k characters
keeps latency predictable and prevents the deep-scan prompt from
crowding out the recon, the SWC instructions, and the JSON schema.

## 6. SWC mapping

`src/swc.js` ships a curated subset of the SWC registry (37 IDs from
SWC-100 to SWC-136) plus a category-alias table that maps common
vulnerability keywords (`"reentrancy"`, `"unchecked call"`,
`"tx.origin"`, `"front running"`, ...) to the most likely SWC id.

When a finding from the model does not include a valid `swcId`, the
auditor derives one from `category` or `title` via `resolveSwcId()`.
This means every shipped finding has a standardized identifier suitable
for ticketing systems and dashboards.

## 7. Failure modes and recovery

| Failure                              | Behavior                                                                                          |
|--------------------------------------|---------------------------------------------------------------------------------------------------|
| `CYSIC_API_KEY` missing              | `cysicClient.chat()` throws `CysicApiError` on first call. The MCP tool returns an error result. |
| Network / 5xx / 429                  | Up to 1 retry with exponential backoff (250ms, 750ms).                                            |
| Model returns non-JSON               | The auditor surfaces the raw snippet as an `audit-coverage` informational finding.                |
| Pass 3 fails                         | The auditor falls back to pass-2 findings and a heuristic risk score.                             |
| Unknown tool name                    | MCP `CallToolRequest` returns an `isError: true` result with a clear message.                     |
| Source > 500k chars                  | `audit_contract` rejects up front (LLM cost guardrail).                                           |

## 8. Future work

- Optional Slither adapter that runs static analysis in parallel and
  merges the LLM findings with static findings.
- A `compare_contracts` tool that audits a "before/after" diff.
- Persistent report storage (S3 / local SQLite) keyed by source hash.
- A `--mock` mode that uses fixture responses for offline development
  and CI testing of the MCP plumbing.
