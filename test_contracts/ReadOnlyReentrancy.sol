// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IPriceOracle
 * @notice Price oracle interface
 */
interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

/**
 * @title VulnerableVault
 * @notice A vault that allows for borrowing funds against collateral.
 * @dev VULNERABILITY: Relies on an external view call for critical financial logic.
 *      If an oracle performs an external call (e.g., to an AMM), it may be susceptible 
 *      to read-only reentrancy or manipulation during that call.
 */
contract VulnerableVault {
    IPriceOracle public oracle;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debts;

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
    }

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        // 1. Read the current price from the oracle
        // DANGER: This is a view function, but if the oracle makes an external call,
        // it could be intercepted or manipulated (Read-Only Reentrancy).
        uint256 price = oracle.getPrice();
        
        uint256 collateralValue = collateral[msg.sender] * price;
        require(collateralValue >= amount * 1e18, "Insufficient collateral");

        // 2. Updating state
        debts[msg.sender] += amount;

        // 3. Transferring funds
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

/**
 * @title VulnerableOracle
 * @notice An oracle that retrieves a price via an external call.
 * @dev VULNERABILITY: Performs an external call within a `view` function. 
 *      If this is invoked within a state-changing context, the external call 
 *      can be intercepted (e.g., via an ERC-777 hook or flash loan manipulation).
 */
contract VulnerableOracle is IPriceOracle {
    address public amm;

    constructor(address _amm) {
        amm = _amm;
    }

    function getPrice() external view override returns (uint256) {
        // Simulation of an external call to an AMM or another contract
        // This external call serves as the entry point for a read-only reentrancy!
        (bool success, bytes memory data) = amm.staticcall(abi.encodeWithSignature("getReserves()"));
        
        if (success && data.length >= 32) {
            return abi.decode(data, (uint256));
        }
        return 1e18; // Fallback price
    }
}
