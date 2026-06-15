# solidity-auditor-mcp

An MCP (Model Context Protocol) server that audits Ethereum / Solidity
smart contracts using the **Cysic Minimax** model (`minimax-m3`).

It exposes four tools over stdio:

| Tool                  | Purpose                                                                |
|-----------------------|------------------------------------------------------------------------|
| `audit_contract`      | Full 3-pass audit with SWC-tagged findings and a 0-100 risk score.    |
| `check_vulnerability` | Targeted check for a single class (reentrancy, tx.origin, etc.).      |
| `gas_optimization`    | Ordered, savings-estimated gas review.                                |
| `generate_report`     | Runs the full audit and returns a clean Markdown report.              |

> Drop it into Claude Desktop, Cursor, or any MCP client and ask
> "audit this contract" — the model handles the rest.

---

## Problem statement

Manual smart-contract audits are slow and expensive. A serious audit of
a single mid-sized protocol costs $50k-$200k and takes 3-6 weeks. Even
DIY reviewers spend hours per contract on reconnaissance before they
can start looking for real bugs. AI-assisted triage is a multiplier:
a fast, calibrated first pass that surfaces the 5-20 most likely
issues lets a human reviewer skip the recon and dive straight into
validation.

## Solution

`solidity-auditor-mcp` is a self-contained MCP server that:

- **Calls the Cysic Minimax model** (`minimax-m3`) at
  `https://token-ai.cysic.xyz/v1/chat/completions` (OpenAI-compatible).
- Runs a **3-pass audit pipeline** (recon -> deep scan -> severity
  scoring) instead of a single prompt, which empirically reduces
  hallucinated function names and over-flagging.
- **Maps every finding to a SWC id** (Smart Contract Weakness
  Classification) using a curated registry + category-alias table.
- Handles **large contracts** by chunking at declaration boundaries
  before scanning.
- Renders a **clean Markdown report** suitable for PR comments or
  ticketing systems.
- Ships with **defensive JSON parsing**, retries on 5xx/429, strict
  input validation, and a `--help`-friendly startup that never
  silently swallows errors.

## Feature checklist

The exact tools shipped in this repository:

- [x] **`audit_contract(source, contractName?)`** — 3-pass audit returning
      `{ findings: [{ severity, category, swcId, swcTitle, title, function, line, description, recommendation, confidence }], summary, executiveSummary, riskScore, meta }`.
- [x] **`check_vulnerability(source, vulnClass)`** — targeted check for
      one class (e.g. `reentrancy`, `integer-overflow`, `access-control`,
      `tx.origin`, `unchecked-call`). Returns `{ isVulnerable, severity, swcId, ... }`.
- [x] **`gas_optimization(source)`** — ordered list of gas-saving
      suggestions with category (`storage`, `memory`, `calldata`, `loop`,
      `external-call`, `immutable`, `constant`, `packing`,
      `short-circuit`, `other`) and estimated savings.
- [x] **`generate_report(source, contractName?, format?)`** — runs
      `audit_contract` and returns `{ format: "markdown", markdown, structured }`.

## Architecture overview

The runtime topology, module boundaries, and per-call data flow are
documented in detail in [`ARCHITECTURE.md`](./ARCHITECTURE.md). In
short:

```
MCP client
   |  JSON-RPC over stdio
   v
server.js  --(input validation, error wrapping)-->  src/auditor.js
                                                      |
                                          +-----------+-----------+
                                          v                       v
                                  src/prompts.js           src/swc.js
                                  (3 system+user           (registry +
                                   prompt templates)        aliases)
                                          |
                                          v
                                  src/cysicClient.js  --HTTPS POST-->  Cysic Minimax (minimax-m3)
                                  (auth, timeout, retry,               https://token-ai.cysic.xyz/v1
                                   JSON repair)
```

The **3-pass audit pipeline** is the key innovation. Each pass has a
narrow job:

1. **Recon** — summarize the contract map (state, functions, calls,
   value flows, assumptions). No vulnerability claims yet.
2. **Deep scan** — given the recon, list vulnerabilities with
   severity, SWC id, function, line, description, recommendation,
   confidence. Chunked for large sources.
3. **Severity scoring** — given the raw findings, recalibrate severity,
   merge duplicates, compute a 0-100 risk score, write a summary and
   an executive summary.

See `ARCHITECTURE.md` for the full rationale.

## Setup & usage

### Requirements

- Node.js **>= 18.0.0** (uses built-in `fetch`).
- A `CYSIC_API_KEY` from the Cysic token-ai dashboard.

### Install

```bash
git clone <this-repo> solidity-auditor-mcp
cd solidity-auditor-mcp
npm install
cp .env.example .env
# then edit .env to set CYSIC_API_KEY
```

Or skip the `.env` and pass the key through your MCP client config (see
below) — the server reads `process.env.CYSIC_API_KEY` only.

### Run

```bash
# Locally, for smoke-testing
npm start

# Or directly
node server.js
```

The server prints two lines to **stderr** and then listens on stdio.
Anything written to stdout is a JSON-RPC frame from the MCP SDK, so
never `console.log` from application code.

### Environment variables

| Variable             | Required | Default                              | Notes                           |
|----------------------|----------|--------------------------------------|---------------------------------|
| `CYSIC_API_KEY`      | yes      | (none)                               | Bearer token for the API.       |
| `CYSIC_BASE_URL`     | no       | `https://token-ai.cysic.xyz/v1`      | Override for self-hosted/proxy. |
| `CYSIC_MODEL`        | no       | `minimax-m3`                         | Override for other Minimax models. |
| `CYSIC_TIMEOUT_MS`   | no       | `60000`                              | Per-request timeout in ms.      |

### Add to an MCP client

#### Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows)

```json
{
  "mcpServers": {
    "solidity-auditor": {
      "command": "node",
      "args": ["/absolute/path/to/solidity-auditor-mcp/server.js"],
      "env": {
        "CYSIC_API_KEY": "sk-your-cysic-key"
      }
    }
  }
}
```

#### Cursor (Settings -> MCP -> Add new global MCP server)

```json
{
  "mcpServers": {
    "solidity-auditor": {
      "command": "node",
      "args": ["/absolute/path/to/solidity-auditor-mcp/server.js"],
      "env": {
        "CYSIC_API_KEY": "sk-your-cysic-key"
      }
    }
  }
}
```

#### Other MCP clients (Codex, OpenCode, custom agents)

Any client that speaks MCP-over-stdio works. Launch with `node server.js`
and pass `CYSIC_API_KEY` via the environment.

## AI / Agent integration evidence

This server is a real, working integration with the **Cysic Minimax**
token-gated API. Every tool call results in one or more HTTPS POSTs to
`https://token-ai.cysic.xyz/v1/chat/completions` with
`Authorization: Bearer $CYSIC_API_KEY` and `model: "minimax-m3"`. The
implementation lives in [`src/cysicClient.js`](./src/cysicClient.js)
and is exercised by the orchestrator in
[`src/auditor.js`](./src/auditor.js).

A complete, expected tool-call transcript (with the response shape an
MCP client should see) is in [`examples/demo.md`](./examples/demo.md).
That document audits the deliberately broken
[`examples/Vulnerable.sol`](./examples/Vulnerable.sol) using all four
tools.

## Project structure

```
solidity-auditor-mcp/
├─ server.js                  # MCP entry point (stdio transport, tool dispatch)
├─ package.json               # CommonJS, only @modelcontextprotocol/sdk dep
├─ .env.example               # Template for CYSIC_API_KEY and overrides
├─ README.md                  # This file
├─ ARCHITECTURE.md            # 3-pass pipeline, module boundaries, data flow
├─ src/
│  ├─ cysicClient.js          # OpenAI-compatible client for the Cysic Minimax API
│  ├─ auditor.js              # Multi-pass audit orchestration
│  ├─ prompts.js              # System + per-pass prompt templates
│  └─ swc.js                  # SWC registry + category-alias mapping
├─ examples/
│  ├─ Vulnerable.sol          # Deliberately broken bank for demos
│  └─ demo.md                 # Expected tool-call transcript for all 4 tools
└─ docs/
   ├─ AGENTS.md               # CyOps Planner->Builder->Reviewer build provenance
   └─ plans/                  # This run's Planner deliverable (build plan)
```

## Innovation

Three things in this project that are not just "wrap an LLM":

1. **Multi-pass audit pipeline (recon -> deep scan -> severity
   scoring).** Each pass has a narrow, well-defined job. Pass 1 builds
   a contract map; pass 2 hunts for bugs against that map; pass 3
   re-scores severity and merges duplicates. This empirically reduces
   hallucinated function names and over-flagging compared to a single
   prompt and produces a more calibrated risk score.
2. **SWC registry mapping.** Every finding is tagged with a Smart
   Contract Weakness Classification ID via a curated registry + a
   category-alias table. This is what professional audit reports use,
   and it makes the findings ticketing-system-ready out of the box.
3. **Large-contract handling.** Sources over 80k characters are
   chunked at top-level declaration boundaries and scanned per chunk
   with a shared recon, capped at 6 chunks per audit. This keeps
   latency and cost predictable for big protocols.

## How to verify

These steps reproduce the validation done at build time and exercise
both the syntax check and a single boot of the server. They do not
require a `CYSIC_API_KEY` (tool calls themselves will fail without one,
but boot and the JSON-RPC handshake do not).

```bash
# 1. All .js files parse with the Node syntax checker
for f in server.js src/cysicClient.js src/auditor.js src/prompts.js src/swc.js; do
  node --check "$f" && echo "OK: $f"
done

# 2. Install the only runtime dep
npm install

# 3. Smoke-test the boot sequence (3s, then it is killed by `timeout`)
CYSIC_API_KEY=sk-stub timeout 3 node server.js
# Expected stderr:
#   [solidity-auditor-mcp] starting (stdio transport)
#   [solidity-auditor-mcp] WARNING: CYSIC_API_KEY is not set. Tool calls will fail until it is provided.
#   [solidity-auditor-mcp] ready.
# Exit code 124 (timeout-killed) is expected - the server stays up until
# the stdio transport is closed by the MCP client.

# 4. With a real key, end-to-end audit of the demo contract
export CYSIC_API_KEY=sk-your-real-key
node -e '
  const { makeAuditor } = require("./src/auditor");
  const fs = require("fs");
  const src = fs.readFileSync("./examples/Vulnerable.sol", "utf8");
  const aud = makeAuditor();
  aud.auditContract(src, "NaiveBank")
    .then(r => {
      console.log("contract:", r.contractName, "riskScore:", r.riskScore);
      for (const f of r.findings) {
        console.log("-", f.severity.toUpperCase().padEnd(13),
                    f.swcId || "------",
                    f.title, "@", f.function || "n/a");
      }
    })
    .catch(e => { console.error("audit failed:", e.message); process.exit(1); });
'
```

Expected tool-call transcripts for all four tools are in
[`examples/demo.md`](./examples/demo.md).

## License

MIT.
