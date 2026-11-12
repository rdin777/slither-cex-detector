// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract CEXOracle {
    address public owner;
    uint256 public btcPrice;

    constructor() {
        owner = msg.sender;
    }

    // ⚠️ VULNERABILITY: Updates state based on external data WITHOUT signature verification or access control
    function updatePrice(uint256 _newPrice) external {
        btcPrice = _newPrice;
    }

    // ✅ SAFE: This one has proper access control
    function updatePriceSafe(uint256 _newPrice) external {
        require(msg.sender == owner, "Not owner");
        btcPrice = _newPrice;
    }
}
