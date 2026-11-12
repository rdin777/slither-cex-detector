// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Vault {
    // ⚠️ VULNERABILITY: Hardcoded test key left in production!
    address public owner = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}
