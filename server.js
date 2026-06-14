#!/usr/bin/env node
// server.js
// MCP entry point for solidity-auditor-mcp.
//
// Transport: stdio (JSON-RPC framed by the MCP SDK).
// Tools:    audit_contract, check_vulnerability, gas_optimization, generate_report.
//
// All tool handlers validate their input, then call into src/auditor.js,
// which in turn calls the Cysic Minimax model via src/cysicClient.js.

"use strict";

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");

const { makeAuditor } = require("./src/auditor");

// ---------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------

const TOOLS = [
  {
    name: "audit_contract",
    description:
      "Run a 3-pass (recon -> deep vulnerability scan -> severity scoring) audit " +
      "of a Solidity source file. Returns structured findings (severity, SWC id, " +
      "function, line, description, recommendation) plus an overall risk score (0-100) " +
      "and a short summary. Use this as the default entry point when reviewing a contract.",
    inputSchema: {
      type: "object",
      properties: {
        source: {
          type: "string",
          description: "The full Solidity source code to audit. Pastes, file dumps, and multi-contract files are all accepted.",
        },
        contractName: {
          type: "string",
          description: "Optional contract name. When omitted, the auditor infers it from `contract X { ... }`.",
        },
      },
      required: ["source"],
      additionalProperties: false,
    },
  },
  {
    name: "check_vulnerability",
    description:
      "Targeted check for a single vulnerability class (e.g. 'reentrancy', " +
      "'integer-overflow', 'access-control', 'tx.origin', 'unchecked-call'). " +
      "Returns whether the contract is vulnerable, the severity, an SWC id, and " +
      "a fix recommendation. Use this for quick spot-checks during development.",
    inputSchema: {
      type: "object",
      properties: {
        source: {
          type: "string",
          description: "The full Solidity source code to check.",
        },
        vulnClass: {
          type: "string",
          description: "The vulnerability class to check for, e.g. 'reentrancy', 'integer-overflow', 'access-control'.",
        },
      },
      required: ["source", "vulnClass"],
      additionalProperties: false,
    },
  },
  {
    name: "gas_optimization",
    description:
      "Run a gas optimization review of a Solidity source file. Returns a list of " +
      "concrete, ordered gas-saving suggestions (storage packing, calldata vs memory, " +
      "immutable/constant, loop optimizations, short-circuiting, etc.) with estimated " +
      "savings where possible.",
    inputSchema: {
      type: "object",
      properties: {
        source: {
          type: "string",
          description: "The full Solidity source code to review for gas savings.",
        },
      },
      required: ["source"],
      additionalProperties: false,
    },
  },
  {
    name: "generate_report",
    description:
      "Run a full audit_contract and render the result as a clean Markdown report. " +
      "Returns both the rendered Markdown and the underlying structured findings.",
    inputSchema: {
      type: "object",
      properties: {
        source: {
          type: "string",
          description: "The full Solidity source code to audit.",
        },
        contractName: {
          type: "string",
          description: "Optional contract name.",
        },
        format: {
          type: "string",
          enum: ["markdown"],
          description: "Currently only 'markdown' is supported.",
        },
      },
      required: ["source"],
      additionalProperties: false,
    },
  },
];

// ---------------------------------------------------------------------
// Handler plumbing
// ---------------------------------------------------------------------

function registerHandlers(server, auditor) {
  // List available tools.
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  // Dispatch a tool call.
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params || {};
    if (!name || typeof name !== "string") {
      return toolError("Tool name is required.");
    }
    const safeArgs = args && typeof args === "object" ? args : {};

    try {
      switch (name) {
        case "audit_contract":
          return okJson(await auditor.auditContract(
            stringField(safeArgs, "source"),
            stringField(safeArgs, "contractName", { optional: true })
          ));

        case "check_vulnerability":
          return okJson(await auditor.checkVulnerability(
            stringField(safeArgs, "source"),
            stringField(safeArgs, "vulnClass")
          ));

        case "gas_optimization":
          return okJson(await auditor.gasOptimization(
            stringField(safeArgs, "source")
          ));

        case "generate_report":
          return okJson(await auditor.generateReport(
            stringField(safeArgs, "source"),
            stringField(safeArgs, "contractName", { optional: true }),
            stringField(safeArgs, "format", { optional: true, default: "markdown" })
          ));

        default:
          return toolError(`Unknown tool: ${name}. Available tools: ${TOOLS.map(t => t.name).join(", ")}.`);
      }
    } catch (err) {
      return toolError(toMessage(err), { code: err && err.code });
    }
  });
}

// ---------------------------------------------------------------------
// MCP result helpers
// ---------------------------------------------------------------------

function okJson(payload) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function toolError(message, extra) {
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify(
          { error: message, ...(extra || {}) },
          null,
          2
        ),
      },
    ],
  };
}

function stringField(obj, key, { optional = false, default: def } = {}) {
  const v = obj[key];
  if (v === undefined || v === null) {
    if (optional) return def !== undefined ? def : undefined;
    throw new Error(`Missing required argument: "${key}".`);
  }
  if (typeof v !== "string") {
    throw new Error(`Argument "${key}" must be a string.`);
  }
  return v;
}

function toMessage(err) {
  if (!err) return "Unknown error";
  if (err instanceof Error) return err.message || String(err);
  if (typeof err === "string") return err;
  try { return JSON.stringify(err); } catch { return String(err); }
}

// ---------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------

async function main() {
  // The MCP SDK writes its own JSON-RPC frames to stdout. Anything we
  // print to stdout/console will corrupt the protocol - we therefore
  // log to stderr only.
  process.stderr.write("[solidity-auditor-mcp] starting (stdio transport)\n");

  if (!process.env.CYSIC_API_KEY) {
    process.stderr.write(
      "[solidity-auditor-mcp] WARNING: CYSIC_API_KEY is not set. Tool calls will fail until it is provided.\n"
    );
  }

  const auditor = makeAuditor();

  const server = new Server(
    {
      name: "solidity-auditor-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  registerHandlers(server, auditor);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("[solidity-auditor-mcp] ready.\n");

  // Graceful shutdown on SIGINT/SIGTERM (helps the MCP client recover cleanly).
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, async () => {
      process.stderr.write(`[solidity-auditor-mcp] received ${sig}, shutting down.\n`);
      try { await server.close(); } catch (_) { /* ignore */ }
      process.exit(0);
    });
  }
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`[solidity-auditor-mcp] fatal: ${err && err.stack || err}\n`);
    process.exit(1);
  });
}

module.exports = { TOOLS };
