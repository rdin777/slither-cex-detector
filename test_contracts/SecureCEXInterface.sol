// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SecureCEXInterface {
    address public immutable OWNER;
    mapping(address => bytes32) private encryptedCredentials;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public lastRequestTime;
    uint256 public constant RATE_LIMIT = 60;

    event CEXCallExecuted(address indexed caller, string endpoint, uint256 timestamp);

    constructor() { OWNER = msg.sender; }

    function executeCEXCall(
        string calldata endpoint,
        bytes calldata data,
        bytes calldata signature
    ) external returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encodePacked(endpoint, data, nonces[msg.sender]));
        address signer = recoverSigner(messageHash, signature);
        require(signer == OWNER, "Invalid signature");
        
        require(block.timestamp - lastRequestTime[msg.sender] >= RATE_LIMIT, "Rate limit exceeded");
        
        nonces[msg.sender]++;
        lastRequestTime[msg.sender] = block.timestamp;
        
        (bool success, bytes memory result) = address(0x1234).call(data);
        require(success, "CEX call failed");
        
        emit CEXCallExecuted(msg.sender, endpoint, block.timestamp);
        return result;
    }

    function recoverSigner(bytes32 messageHash, bytes memory signature) 
        internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        return ecrecover(messageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) 
        internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
