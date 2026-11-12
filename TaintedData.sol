// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IPriceFeed {
    function getPrice() external view returns (uint256);
}

contract TaintedLending {
    IPriceFeed public priceFeed;
    
    constructor(address _feed) {
        priceFeed = IPriceFeed(_feed);
    }

    // ⚠️ VULNERABLE: Tainted data flow
    // Source: priceFeed.getPrice() (external call)
    // Sink: payable().transfer() (critical operation)
    // Sanitizer: MISSING!
    function liquidate(address user) external {
        uint256 price = priceFeed.getPrice(); // SOURCE (Tainted data)
        
        // If the oracle returns 0, this will cause a division by zero or incorrect transfer
        uint256 liquidationAmount = (1000 * 1e18) / price; 
        
        payable(msg.sender).transfer(liquidationAmount); // SINK
    }

    // ✅ SAFE: Data is sanitized before use
    function liquidateSafe(address user) external {
        uint256 price = priceFeed.getPrice(); // SOURCE
        
        require(price > 0, "Invalid price"); // SANITIZER
        
        uint256 liquidationAmount = (1000 * 1e18) / price;
        payable(msg.sender).transfer(liquidationAmount); // SINK
    }
}
