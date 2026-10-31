// These strings are intentionally comments and should not create findings:
// tx.origin, .call(""), .delegatecall(""), block.timestamp, selfdestruct(address(0))
pragma solidity ^0.8.20;

contract CommentOnlyFixture {
    uint256 private value;

    function setValue(uint256 newValue) external {
        value = newValue;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}
