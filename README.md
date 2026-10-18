# Slither CEX Detector

Custom Slither detector for identifying security vulnerabilities in CEX interface smart contracts.

## Installation

```bash
pip install slither-cex-detector
slither your_contract.sol --detect cex-interface-security
Detected Vulnerabilities
Hardcoded API keys
Missing signature verification
Insecure nonce handling (timestamp-based)
Plaintext credential storage
Missing rate limiting
License
MIT
