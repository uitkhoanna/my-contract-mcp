// examples/Vulnerable.sol
// Intentionally vulnerable Solidity contract used as a demo for
// solidity-auditor-mcp. The contract is the classic reentrancy + access
// control + unchecked call + tx.origin "NaiveBank". DO NOT USE IN
// PRODUCTION. It exists so the MCP tools have something to chew on.

pragma solidity ^0.8.0;

contract NaiveBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Reentrancy: external call is made BEFORE the state update.
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed"); // unchecked-call: returns `ok` but does not revert on failure to log / monitor
        balances[msg.sender] -= amount; // state update AFTER the external call
    }

    // Access control: anyone can call setOwner.
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // tx.origin authentication - phishable.
    function adminWithdrawAll() public {
        require(tx.origin == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    // Selfdestruct without access control.
    function killSwitch() public {
        selfdestruct(payable(owner));
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
