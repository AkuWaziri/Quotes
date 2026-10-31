// Deliberately vulnerable regression fixture for QUOTES heuristics only.
// Do not deploy or use as a production contract.
pragma solidity ^0.8.20;

contract HeuristicFixture {
    address public owner;
    address public implementation;

    function privileged() external view returns (bool) {
        return tx.origin == owner;
    }

    function sendValue(address payable recipient, uint256 amount) external {
        recipient.call{value: amount}("");
    }

    function execute(bytes calldata data) external {
        implementation.delegatecall(data);
    }

    function currentTime() external view returns (uint256) {
        return block.timestamp;
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {}
}
