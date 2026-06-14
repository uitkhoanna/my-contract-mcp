// src/swc.js
// Smart Contract Weakness Classification (SWC) registry.
// A curated subset of the most commonly encountered SWC IDs. The full
// registry has 100+ entries; this list is intentionally limited to the
// ones an LLM auditor can reasonably identify from a single source file.
//
// Each entry: { id, title, category }
//   - id      : the canonical SWC identifier (e.g. "SWC-107").
//   - title   : the official short title used in audit reports.
//   - category: the weakness class used to group findings.

const SWC_REGISTRY = Object.freeze({
  "SWC-100":  { title: "Function Default Visibility",                  category: "Visibility" },
  "SWC-101":  { title: "Integer Overflow and Underflow",               category: "Arithmetic" },
  "SWC-102":  { title: "Outdated Compiler Version",                    category: "Best Practices" },
  "SWC-103":  { title: "Floating Pragma",                              category: "Best Practices" },
  "SWC-104":  { title: "Unchecked Call Return Value",                  category: "Unhandled Exception" },
  "SWC-105":  { title: "Unprotected Ether Withdrawal",                category: "Access Control" },
  "SWC-106":  { title: "Unprotected SELFDESTRUCT Instruction",         category: "Access Control" },
  "SWC-107":  { title: "Reentrancy",                                   category: "Reentrancy" },
  "SWC-108":  { title: "State Variable Default Visibility",            category: "Visibility" },
  "SWC-109":  { title: "Uninitialized Storage Pointer",                category: "Data Location" },
  "SWC-110":  { title: "Assert Violation",                             category: "Best Practices" },
  "SWC-111":  { title: "Use of Deprecated Solidity Functions",         category: "Best Practices" },
  "SWC-112":  { title: "Delegatecall to Untrusted Contract",           category: "Delegatecall" },
  "SWC-113":  { title: "DoS with Failed Call",                         category: "Denial of Service" },
  "SWC-114":  { title: "Transaction Order Dependence",                 category: "Front Running" },
  "SWC-115":  { title: "Authorization through tx.origin",              category: "Access Control" },
  "SWC-116":  { title: "Block values as a proxy for time",             category: "Time" },
  "SWC-117":  { title: "Signature Malleability",                       category: "Cryptography" },
  "SWC-118":  { title: "Incorrect Constructor Name",                   category: "Best Practices" },
  "SWC-119":  { title: "Shadowing State Variables",                    category: "Shadowing" },
  "SWC-120":  { title: "Weak Sources of Randomness from Chain Attributes", category: "Randomness" },
  "SWC-121":  { title: "Missing Protection against Signature Replay Attacks", category: "Cryptography" },
  "SWC-122":  { title: "Lack of Proper Signature Verification",        category: "Cryptography" },
  "SWC-123":  { title: "Requirement Violation",                       category: "Best Practices" },
  "SWC-124":  { title: "Write to Arbitrary Storage Location",          category: "Data Location" },
  "SWC-125":  { title: "Incorrect Inheritance Order",                 category: "Best Practices" },
  "SWC-126":  { title: "Insufficient Gas Griefing",                    category: "Denial of Service" },
  "SWC-127":  { title: "Arbitrary Jump with Function Type Variable",   category: "Type Safety" },
  "SWC-128":  { title: "DoS With Block Gas Limit",                     category: "Denial of Service" },
  "SWC-129":  { title: "Typographical Error",                          category: "Best Practices" },
  "SWC-130":  { title: "Simple Reentrancy (Read-only)",                category: "Reentrancy" },
  "SWC-131":  { title: "Presence of unused variables",                 category: "Best Practices" },
  "SWC-132":  { title: "Unexpected Ether balance",                     category: "Best Practices" },
  "SWC-133":  { title: "Hash Collisions With Multiple Variable Length Arguments", category: "Cryptography" },
  "SWC-134":  { title: "Message call with hardcoded gas amount",       category: "Best Practices" },
  "SWC-135":  { title: "Code With No Effects (Dead Code)",             category: "Best Practices" },
  "SWC-136":  { title: "Unencrypted Private Data On-Chain",            category: "Data Exposure" },
});

// Map common vulnerability keywords / categories an LLM might emit to the
// most relevant SWC ID. Used to tag findings when the model itself does
// not emit an SWC id. Lookup is case-insensitive on the alias.
const CATEGORY_ALIASES = Object.freeze({
  "reentrancy": "SWC-107",
  "re-entrancy": "SWC-107",
  "reentrant": "SWC-107",
  "integer overflow": "SWC-101",
  "integer underflow": "SWC-101",
  "overflow": "SWC-101",
  "underflow": "SWC-101",
  "arithmetic": "SWC-101",
  "unchecked call": "SWC-104",
  "unchecked return": "SWC-104",
  "unchecked-call": "SWC-104",
  "access control": "SWC-105",
  "access-control": "SWC-105",
  "authorization": "SWC-105",
  "selfdestruct": "SWC-106",
  "self-destruct": "SWC-106",
  "self destruct": "SWC-106",
  "default visibility": "SWC-100",
  "visibility": "SWC-100",
  "state visibility": "SWC-108",
  "uninitialized": "SWC-109",
  "storage pointer": "SWC-109",
  "delegatecall": "SWC-112",
  "delegate call": "SWC-112",
  "dos": "SWC-113",
  "denial of service": "SWC-113",
  "denial-of-service": "SWC-113",
  "front running": "SWC-114",
  "front-running": "SWC-114",
  "front run": "SWC-114",
  "tx.origin": "SWC-115",
  "tx origin": "SWC-115",
  "timestamp": "SWC-116",
  "block.timestamp": "SWC-116",
  "block.number": "SWC-116",
  "randomness": "SWC-120",
  "weak randomness": "SWC-120",
  "signature replay": "SWC-121",
  "signature malleability": "SWC-117",
  "ecrecover": "SWC-122",
  "require violation": "SWC-123",
  "arbitrary storage": "SWC-124",
  "gas limit": "SWC-128",
  "block gas": "SWC-128",
  "read-only reentrancy": "SWC-130",
  "read only reentrancy": "SWC-130",
  "view reentrancy": "SWC-130",
  "floating pragma": "SWC-103",
  "outdated compiler": "SWC-102",
  "deprecated": "SWC-111",
  "assert": "SWC-110",
  "missing zero check": "SWC-105",
});

/**
 * Resolve an SWC id from a finding's category/title. Falls back to the
 * raw id string the model may have already produced. Returns null if no
 * reasonable mapping exists so callers can decide whether to omit the
 * swcId field.
 */
function resolveSwcId(categoryOrTitle) {
  if (!categoryOrTitle) return null;
  const s = String(categoryOrTitle).toLowerCase().trim();
  // Direct id match (e.g. "SWC-107" or "swc-107").
  const idMatch = s.match(/swc[-\s]?(\d{2,3})/i);
  if (idMatch) {
    const candidate = `SWC-${idMatch[1]}`;
    if (SWC_REGISTRY[candidate]) return candidate;
  }
  // Alias match.
  for (const alias of Object.keys(CATEGORY_ALIASES)) {
    if (s.includes(alias)) return CATEGORY_ALIASES[alias];
  }
  return null;
}

/**
 * Return a short label for an SWC id, e.g. { id: "SWC-107", title: "Reentrancy" }.
 * If the id is unknown, returns { id, title: null, category: null }.
 */
function describeSwc(id) {
  if (!id) return null;
  const entry = SWC_REGISTRY[id];
  if (!entry) return { id, title: null, category: null };
  return { id, title: entry.title, category: entry.category };
}

module.exports = {
  SWC_REGISTRY,
  CATEGORY_ALIASES,
  resolveSwcId,
  describeSwc,
};
