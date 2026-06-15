# AGENTS.md — `solidity-auditor-mcp` build provenance

This codebase was built and hardened on **CyOps** via a
**Planner → Builder → Reviewer** workflow (one pass, multiple iterations).

## Project

- Name: `solidity-auditor-mcp`
- Version: `1.0.0`
- Runtime: Node ≥ 18, CommonJS, one dependency (`@modelcontextprotocol/sdk`).
- Surface: four MCP stdio tools — `audit_contract`, `check_vulnerability`,
  `gas_optimization`, `generate_report` — backed by the Cysic Minimax
  model `minimax-m3`.

## Endpoint

- Base URL: `https://token-ai.cysic.xyz/v1`
- Call path: `POST /chat/completions` (OpenAI-compatible)
- Auth: `Authorization: Bearer ${CYSIC_API_KEY}` (sourced only from
  `process.env.CYSIC_API_KEY`, never hardcoded, never logged)
- Model id: `minimax-m3`
- Per-request timeout: 60s (`AbortController`); retry with backoff on
  `5xx` and `429` (250ms / 750ms).

## Workflow roles

| Role | Responsibility | Deliverable |
| --- | --- | --- |
| **Planner** | Scope the pass, define acceptance criteria, enumerate verification commands. | `docs/plans/<uuid>.md` (this run's plan). |
| **Builder** | Apply minimum-edit, gap-closure changes; never refactor. | New `docs/AGENTS.md`; small additions to `ARCHITECTURE.md` and `examples/demo.md`; the `"docs"` entry in `package.json#files`. |
| **Reviewer** | Run the verification matrix; cross-check docs vs. code; gate merges. | Verdict on each AC (see `Acceptance Criteria` in the plan). |

## Reviewer verification commands

Run from the repo root. Each command is part of the AC verification
matrix and must exit `0` / return no hits before this AC set is
considered complete.

```bash
# AC-1, AC-5: endpoint, model, Bearer
grep -nE "minimax-m3|/chat/completions|Bearer" src/cysicClient.js

# AC-1, AC-8: no hardcoded API key
grep -RInE "sk-[A-Za-z0-9]{8,}|cysic_[A-Za-z0-9]{8,}" . \
  --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.humanize

# AC-2: per-tool source guards
grep -nE 'typeof .* !== "string"|!source.trim|stringField' \
  server.js src/auditor.js

# AC-7: syntax gate
for f in server.js src/cysicClient.js src/auditor.js src/prompts.js src/swc.js; do
  node --check "$f" || exit 1
done

# AC-4: npm tarball ships docs/
node -e 'const p=require("./package.json"); console.log(p.files)'
```

## How agents should read this repo

- `server.js` — MCP stdio entry point; thin shim over `src/auditor.js`.
- `src/auditor.js` — tool implementations, 3-pass pipeline, chunker,
  SWC mapping, severity scoring.
- `src/cysicClient.js` — the only file that talks to Cysic HTTPS.
- `src/prompts.js` — system + user prompt templates for each pass.
- `src/swc.js` — curated 37-id SWC registry + category alias table.
- `examples/Vulnerable.sol` — canonical test contract.
- `examples/demo.md` — full `tools/call` transcript for all four tools.
- `ARCHITECTURE.md` §9 — design rationale (3-pass, SWC, chunking).
- `README.md` — user-facing quickstart, feature checklist, project
  structure.

If you are an agent picking this repo up cold: start at
`ARCHITECTURE.md` §1, then skim §9, then read `src/auditor.js` top to
bottom. That gives you the whole design without touching the model
boundary.
