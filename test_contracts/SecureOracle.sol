// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract SecureOracle is IPriceOracle {
    // Secure: the price is stored locally; there are no external calls
    uint256 private price;

    function setPrice(uint256 _price) external {
        price = _price;
    }

    function getPrice() external view override returns (uint256) {
        return price; // No external challenges
    }
}
