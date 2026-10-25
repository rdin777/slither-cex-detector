# 🛡️ Slither CEX Detector (v0.2.0)

Custom Slither detectors for identifying security vulnerabilities in CEX (Centralized Exchange) interface smart contracts and preventing catastrophic test-key leakage.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Slither Compatible](https://img.shields.io/badge/slither-0.11.x-green.svg)](https://github.com/crytic/slither)

---

## 🚀 What's New in v0.2.0
- **🆕 NEW DETECTOR:** `hardhat-test-keys` — Detects hardcoded well-known development private keys and addresses (e.g., Hardhat Account #0) to prevent immediate fund drainage on mainnet deployment.
- **⚡ Native Slither CLI Support:** Fully integrated via `pyproject.toml` entry points. No need for custom wrapper scripts; run directly with `slither --detect ...`.
- **🎯 Improved Accuracy:** Enhanced AST-based signature verification checks and better false-positive reduction for safe rate-limiting patterns.
- **📈 Upgraded Dependencies:** Now requires `slither-analyzer >= 0.11.0` for optimal performance and parsing.

---

## 📋 Table of Contents
- [Overview](#overview)
- [Detected Vulnerabilities](#-detected-vulnerabilities)
- [Installation](#-installation)
- [Usage](#-usage)
- [CI/CD Integration](#-cicd-integration)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [References](#-references)

---

## Overview
Slither CEX Detector is a custom security analysis tool built on top of [Slither](https://github.com/crytic/slither), the most popular static analyzer for Solidity smart contracts. This plugin specifically targets vulnerabilities in smart contracts that interact with centralized exchanges (CEX) or handle sensitive API credentials.

### Why CEX Interface Security Matters
Smart contracts interacting with CEX handle critical operations: API key management, cross-chain withdrawals, order execution, and price oracle feeds. A single vulnerability can lead to unauthorized withdrawals, replay attacks, or complete account compromise.

---

## 🔍 Detected Vulnerabilities

1. **🔑 Hardcoded API Keys (Critical)**  
   Credentials embedded directly in contract source code. Anyone can read the blockchain and extract them.
2. **🧪 Hardcoded Test Keys (Critical) `[NEW in v0.2.0]`**  
   Use of well-known development keys (e.g., Hardhat Account #0: `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`) in production code.
3. **🔐 Missing Signature Verification (High)**  
   External function calls that don't verify cryptographic signatures (e.g., missing `ecrecover` checks), allowing unauthorized parties to trigger actions.
4. **⏰ Insecure Nonce Handling (Medium)**  
   Using manipulable `block.timestamp` or `block.number` for request signing instead of incrementing state nonces. *(Note: Safe rate-limiting patterns are correctly ignored).*
5. **📄 Plaintext Credential Storage (Critical)**  
   Storing sensitive data as `string` or `bytes` types on-chain, making it publicly visible.

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Git

### Step 1: Clone the repository
```bash
git clone https://github.com/rdin777/slither-cex-detector.git
cd slither-cex-detector

Step 2: Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Step 3: Install the package
pip install -e .
This installs slither-analyzer (v0.11.0+) and registers the custom detectors natively with Slither.
🚀 Usage
Thanks to the package entry points, you can now run the detectors natively through the Slither CLI. This provides better JSON export, CI/CD integration, and unified output.
Basic Usage
Run both detectors on your contracts directory:
slither . --detect cex-interface-security,hardhat-test-keys
Or target a specific file:
slither test_contracts/VulnerableCEXInterface.sol --detect cex-interface-security,hardhat-test-keys
Export to JSON (Perfect for CI/CD)
slither . --detect cex-interface-security,hardhat-test-keys --json results.json
cat results.json
🔧 CI/CD Integration
Add this workflow to .github/workflows/security.yml to automatically check every PR:
name: CEX Interface Security Check

on:
  push:
    branches: [main, develop]
    paths: ['contracts/**/*.sol']
  pull_request:
    branches: [main]
    paths: ['contracts/**/*.sol']

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      
      - name: Install detector
        run: |
          git clone https://github.com/rdin777/slither-cex-detector.git
          cd slither-cex-detector
          python3 -m venv venv
          source venv/bin/activate
          pip install -e .
      
      - name: Run security check
        run: |
          cd slither-cex-detector
          source venv/bin/activate
          slither ../contracts/ --detect cex-interface-security,hardhat-test-keys --json results.json
      
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: slither-cex-detector/results.json
📁 Project Structure
slither-cex-detector/
├── slither_cex_detector/
│   ├── __init__.py          # Package initialization
│   └── detector.py          # Main detectors (CEX + Hardhat Keys)
├── test_contracts/
│   ├── VulnerableCEXInterface.sol  # Example with vulnerabilities
│   └── SecureCEXInterface.sol      # Secure implementation
├── pyproject.toml           # Python package configuration (v0.2.0)
├── CHANGELOG.md             # Version history
├── README.md                # This file
├── LICENSE                  # MIT License
└── .gitignore               # Git ignore rules
🤝 Contributing
Contributions are welcome!
Fork the repository.
Create a feature branch (git checkout -b feature/amazing-feature).
Commit your changes (git commit -m 'Add amazing feature').
Push to the branch (git push origin feature/amazing-feature).
Open a Pull Request.
Please ensure your code follows PEP 8, includes type hints, and adds tests for new detection patterns.
📚 References & Learn More
📖 The Next Frontier: Using AI Agents to Build Custom Slither Detectors — Deep dive into the methodology behind this detector and the future of AI-assisted Web3 security.
Slither Documentation
Smart Contract Security Best Practices
SWC Registry
📧 Contact
GitHub: @rdin777
Twitter: @DinRid56379
Project Link: https://github.com/rdin777/slither-cex-detector
Made with ❤️ for the Web3 security community.

