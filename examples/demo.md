# Demo transcript: auditing `examples/Vulnerable.sol` with `solidity-auditor-mcp`

This document shows a complete, expected interaction with the MCP server
running locally. It is the evidence that the four tools really do call
the Cysic Minimax model (`minimax-m3`) and return structured, SWC-tagged
findings.

The example contract is [`examples/Vulnerable.sol`](./Vulnerable.sol), a
deliberately broken bank that exhibits:

- SWC-107 reentrancy in `withdraw`
- SWC-104 unchecked low-level call return
- SWC-105/SWC-106 missing access control on `setOwner` and `killSwitch`
- SWC-115 `tx.origin` authentication in `adminWithdrawAll`

## 1. `audit_contract`

**Tool call (from an MCP client):**

```json
{
  "method": "tools/call",
  "params": {
    "name": "audit_contract",
    "arguments": {
      "source": "<contents of examples/Vulnerable.sol>",
      "contractName": "NaiveBank"
    }
  }
}
```

**Expected response (truncated for readability):**

```json
{
  "contractName": "NaiveBank",
  "summary": "Multiple high- and critical-severity issues: classic reentrancy in withdraw, missing access control on setOwner/killSwitch, and a tx.origin-based admin path. Contract is not safe to deploy.",
  "executiveSummary": "Reentrancy in withdraw, missing access control on setOwner and killSwitch, tx.origin-based admin path. Multiple high/critical issues — do not deploy.",
  "riskScore": 92,
  "findings": [
    {
      "severity": "critical",
      "category": "reentrancy",
      "swcId": "SWC-107",
      "swcTitle": "Reentrancy",
      "title": "Classic reentrancy in withdraw via call before state update",
      "function": "withdraw",
      "line": 14,
      "description": "withdraw() sends ETH to msg.sender with a low-level call BEFORE decrementing balances[msg.sender]. A malicious contract can re-enter withdraw() on each call and drain the contract. The state update must happen before the external call (checks-effects-interactions).",
      "recommendation": "Apply checks-effects-interactions: decrement balances[msg.sender] before the external call. Consider using OpenZeppelin's ReentrancyGuard and/or a nonReentrant modifier on withdraw.",
      "confidence": "high"
    },
    {
      "severity": "high",
      "category": "access-control",
      "swcId": "SWC-105",
      "swcTitle": "Unprotected Ether Withdrawal",
      "title": "setOwner has no access control",
      "function": "setOwner",
      "line": 22,
      "description": "Any caller can overwrite the contract owner, including the new owner of a selfdestruct / admin path. Combined with killSwitch() this lets an attacker become owner and then drain the contract.",
      "recommendation": "Restrict setOwner with `require(msg.sender == owner, \"not owner\");` (or use OpenZeppelin Ownable / Ownable2Step). Consider a two-step ownership transfer for additional safety.",
      "confidence": "high"
    },
    {
      "severity": "high",
      "category": "access-control",
      "swcId": "SWC-106",
      "swcTitle": "Unprotected SELFDESTRUCT Instruction",
      "title": "killSwitch has no access control and selfdestructs to owner",
      "function": "killSwitch",
      "line": 30,
      "description": "killSwitch() is callable by any address and uses selfdestruct to send the contract balance to the owner. After the Cancun fork, selfdestruct no longer deletes code or burn all ether, but it is still a denial-of-service / fund-redirection vector when the caller is unprivileged.",
      "recommendation": "Add a strict `onlyOwner` (or role-based) check. Prefer a `pause()` + `withdrawAll()` pattern over selfdestruct for any modern contract.",
      "confidence": "high"
    },
    {
      "severity": "high",
      "category": "access-control",
      "swcId": "SWC-115",
      "swcTitle": "Authorization through tx.origin",
      "title": "tx.origin used for authorization in adminWithdrawAll",
      "function": "adminWithdrawAll",
      "line": 26,
      "description": "Using tx.origin == owner makes this function phishable: any contract the owner is tricked into interacting with can invoke adminWithdrawAll on their behalf.",
      "recommendation": "Replace `tx.origin == owner` with `msg.sender == owner`, or use OpenZeppelin Ownable / AccessControl.",
      "confidence": "high"
    },
    {
      "severity": "medium",
      "category": "unchecked-call",
      "swcId": "SWC-104",
      "swcTitle": "Unchecked Call Return Value",
      "title": "Low-level call return value in withdraw is checked but the path swallows failures",
      "function": "withdraw",
      "line": 15,
      "description": "Although the boolean ok is checked, the contract silently reverts the entire withdraw on failure, which an attacker can use to grief honest users. There is no event emission on success, and there is no per-user accounting of failures.",
      "recommendation": "Emit a Withdraw(address indexed user, uint256 amount, bool success) event, and consider pull-payment (OpenZeppelin PullPayment) so a single failing recipient cannot block the system.",
      "confidence": "medium"
    }
  ],
  "meta": {
    "passes": 3,
    "model": "minimax-m3",
    "sourceChars": 950,
    "rawFindingCount": 5,
    "finalFindingCount": 5
  }
}
```

## 2. `check_vulnerability`

**Tool call:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "check_vulnerability",
    "arguments": {
      "source": "<contents of examples/Vulnerable.sol>",
      "vulnClass": "reentrancy"
    }
  }
}
```

**Expected response:**

```json
{
  "vulnClass": "reentrancy",
  "isVulnerable": true,
  "severity": "critical",
  "swcId": "SWC-107",
  "swcTitle": "Reentrancy",
  "title": "withdraw sends ETH before updating balances",
  "function": "withdraw",
  "line": 14,
  "description": "withdraw() performs an external call to msg.sender before subtracting the amount from balances[msg.sender]. A reentrancy attack can recursively drain the contract.",
  "recommendation": "Apply checks-effects-interactions or use OpenZeppelin's ReentrancyGuard with a nonReentrant modifier.",
  "confidence": "high"
}
```

## 3. `gas_optimization`

**Tool call:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "gas_optimization",
    "arguments": {
      "source": "<contents of examples/Vulnerable.sol>"
    }
  }
}
```

**Expected response (abridged):**

```json
{
  "summary": "A few small gas wins: cache balances[msg.sender] in a local, mark owner as immutable, replace receive() default with a function that updates via a single SSTORE.",
  "suggestions": [
    {
      "title": "Mark `owner` as immutable",
      "function": null,
      "line": 6,
      "category": "immutable",
      "estimatedSavingsGas": 2100,
      "description": "owner is only set in the constructor and never reassigned (in the secure version). Marking it immutable replaces the SLOAD with a PUSH, saving ~2.1k gas on every read.",
      "recommendation": "`address public immutable owner;` initialized in the constructor."
    },
    {
      "title": "Use custom errors instead of revert strings",
      "function": "withdraw",
      "line": 13,
      "category": "other",
      "estimatedSavingsGas": 50,
      "description": "require(..., \"insufficient\") deploys a string. Custom errors are cheaper to deploy and to revert with.",
      "recommendation": "error Insufficient(); require(balances[msg.sender] >= amount, Insufficient());"
    }
  ]
}
```

## 4. `generate_report`

**Tool call:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "generate_report",
    "arguments": {
      "source": "<contents of examples/Vulnerable.sol>",
      "contractName": "NaiveBank"
    }
  }
}
```

**Expected response (Markdown field, abridged):**

```markdown
# Smart Contract Audit Report — `NaiveBank`

**Risk score:** 92 / 100

> Reentrancy in withdraw, missing access control on setOwner and killSwitch, tx.origin-based admin path. Multiple high/critical issues — do not deploy.

## Summary
Multiple high- and critical-severity issues: classic reentrancy in withdraw, ...

**Findings by severity:** critical: 1  ·  high: 3  ·  medium: 1  ·  low: 0  ·  informational: 0

## Critical (1)

### 1. Classic reentrancy in withdraw via call before state update (SWC-107: Reentrancy) — `withdraw`
...
```

(The full `markdown` field is also returned as a string in the
response payload, alongside the structured `structured` object, so a
downstream agent can render the report itself or post-process the
findings.)

## How to reproduce

```bash
# 1. Install deps
npm install

# 2. Export the API key (or use .env)
export CYSIC_API_KEY=sk-...

# 3. Start the MCP server
npm start
```

Then point your MCP client (Claude Desktop, Cursor, etc.) at
`server.js` and call any of the four tools. See `README.md` for the
exact client config snippets.
