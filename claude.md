# `claude.md` — Project Standards for `solidity-auditor-mcp`

This file gives any future Claude (or compatible agent) the minimum it needs
to be productive in this repo without re-deriving the basics. Keep it terse
and evidence-shaped.

## What this is
- An MCP stdio server (Node ≥ 18, CommonJS) that audits Solidity contracts.
- Talks to the Cysic Minimax model `minimax-m3` at
  `https://token-ai.cysic.xyz/v1/chat/completions` (OpenAI-compatible, Bearer
  auth).
- Exposes four tools: `audit_contract`, `check_vulnerability`,
  `gas_optimization`, `generate_report`.

## Stack
- Language: CommonJS JavaScript (no TypeScript, no bundler).
- Runtime: Node ≥ 18 (uses global `fetch` and `AbortController`).
- Single runtime dependency: `@modelcontextprotocol/sdk`.
- No test framework in the box; the syntax gate is `node --check`.

## Layout
```
server.js                 # MCP stdio entry point and tool dispatch
src/cysicClient.js        # Thin HTTPS client (timeout, retry, JSON repair)
src/auditor.js            # 3-pass pipeline, SWC mapping, chunking
src/prompts.js            # System/user prompt templates
src/swc.js                # 37-entry SWC registry + category alias table
examples/Vulnerable.sol   # Canonical 17-issue fixture
examples/demo.md          # Realistic tool-call transcript
docs/                     # Project docs (AGENTS.md ships in npm tarball)
```

## Module boundaries (do not cross)
- `server.js` is the only place that talks to `@modelcontextprotocol/sdk`.
- `src/auditor.js` is the only place that orchestrates prompts + Cysic.
- `src/cysicClient.js` is the only place that constructs the `Authorization`
  header. Do not duplicate the Bearer header elsewhere.
- `src/swc.js` exports pure data; do not add I/O.

## Secrets
- The API key is read from `process.env.CYSIC_API_KEY` in
  `src/cysicClient.js` only. Never hardcode, never log, never echo.
- `.env` is git-ignored; `.env.example` is the only committed env file and it
  is intentionally empty.

## Coding conventions
- Prefer `const`, no transpilation.
- JSDoc on public exports; no `// @ts-ignore` style escape hatches.
- Errors are thrown with descriptive messages; the `McpServer` handler is the
  only place that converts them to `isError: true` responses.
- Defensive JSON parsing lives in `tryParseJsonLoose`; do not re-implement it
  inline.

## Verification (run before declaring done)
```bash
# Syntax gate (must exit 0 on every file)
for f in server.js src/cysicClient.js src/auditor.js src/prompts.js src/swc.js; do
  node --check "$f" || exit 1
done

# Secret pattern grep (must be silent)
grep -RInE "sk-[A-Za-z0-9]{8,}|cysic_[A-Za-z0-9]{8,}" . \
  --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.humanize

# Bearer/endpoint grep (exactly one match per symbol, inside _postWithTimeout)
grep -nE "minimax-m3|/chat/completions|Bearer" src/cysicClient.js
```

## Out of scope for this project
- New tools, new dependencies, new CLI flags, new env vars.
- Changing retry counts, timeout values, model ids, endpoints, prompts.
- Refactoring `auditor.js` (no class-based rewrite, no prompt-strategy swaps).
- Running the live Cysic API in CI.

## How to extend
- New tool: register it in `server.js`, implement in `auditor.js`, document
  in `README.md` "Feature checklist" *and* `examples/demo.md` transcript.
- New SWC id: append to `src/swc.js` registry; add an alias if the model
  commonly emits a free-text variant.
- New prompt template: add a builder in `src/prompts.js`, keep the JSON
  schema explicit in JSDoc.
