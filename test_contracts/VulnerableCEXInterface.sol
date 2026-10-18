// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VulnerableCEXInterface {
    string public binanceApiKey = "pk_live_51HzK9xL2m3n4o5p6q7r8s9t0";
    string public apiSecret = "super_secret_key_123456789";
    mapping(address => string) public userCredentials;
    mapping(address => uint256) public lastRequestTime;
    address public owner;

    constructor() { owner = msg.sender; }

    function executeCEXCall(string calldata endpoint, bytes calldata data) 
        external returns (bytes memory) {
        lastRequestTime[msg.sender] = block.timestamp;
        (bool success, bytes memory result) = address(0x1234).call(data);
        require(success, "CEX call failed");
        return result;
    }

    function storeCredentials(string calldata apiKey, string calldata secret) external {
        userCredentials[msg.sender] = string(abi.encodePacked(apiKey, ":", secret));
    }

    function withdrawToCEX(address token, uint256 amount) external {
        lastRequestTime[msg.sender] = block.timestamp;
    }
}
