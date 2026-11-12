// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VulnerableStaking {
    IERC20 public token;
    mapping(address => uint256) public balances;
    uint256 public totalStaked;
    
    constructor(address _token) {
        token = IERC20(_token);
    }
    
    function stake(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        
        // ⚠️ VULNERABILITY: State update AFTER external call
        balances[msg.sender] += amount;
        totalStaked += amount;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // ⚠️ VULNERABILITY: External call BEFORE state update
        require(token.transfer(msg.sender, amount), "Transfer failed");
        
        balances[msg.sender] -= amount;
        totalStaked -= amount;
    }
    
    // ⚠️ VULNERABLE VIEW FUNCTION
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
    
    function getTotalStaked() external view returns (uint256) {
        return totalStaked;
    }
}

contract SafeStaking {
    IERC20 public token;
    mapping(address => uint256) public balances;
    uint256 public totalStaked;
    
    constructor(address _token) {
        token = IERC20(_token);
    }
    
    function stake(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        
        // ✅ SAFE: State update AFTER external call
        balances[msg.sender] += amount;
        totalStaked += amount;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // ✅ SAFE: Checks-Effects-Interactions pattern
        balances[msg.sender] -= amount;  // Effect first
        totalStaked -= amount;
        
        require(token.transfer(msg.sender, amount), "Transfer failed");  // Interaction last
    }
    
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
