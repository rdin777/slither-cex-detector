<<<<<<< HEAD
# 🛡️ Slither CEX Detector Toolkit (v0.4.0)
=======
## 🎥 Demo

Watch Slither in action: [How Slither Catches Smart Contract Vulnerabilities](https://youtu.be/B9Xwe2WeU60)

If you find this useful, please ⭐ star the repo!


# 🛡️ Slither CEX Detector (v0.2.0)
>>>>>>> 67c13bf0400de9283923997cd62e8094024386ba

A collection of custom [Slither](https://github.com/crytic/slither) detectors designed to identify specific smart contract vulnerabilities, with a focus on CEX integrations, oracle manipulations, and DeFi security patterns.

![Version](https://img.shields.io/badge/version-0.4.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🚀 Features

This toolkit currently includes **3 production-ready custom detectors**:

| Detector | Description | Target Vulnerability |
|----------|-------------|----------------------|
| **UnprotectedCEXCallback** | Detects functions handling external data (oracle/CEX updates) without access control or signature verification. | Missing `onlyOwner` / `require` checks on state-changing functions. |
| **ReadOnlyReentrancy** | Heuristic detector that identifies `view` functions reading state variables modified by functions containing external calls. | Stale data exposure during external calls (Checks-Effects-Interactions violations). |
| **TaintedDataFlow** | Tracks unvalidated external data flowing directly into critical operations (transfers, calculations). | Missing input validation (e.g., `require(price > 0)`) before using oracle data. |

---

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rdin777/slither-cex-detector.git
   cd slither-cex-detector
2 Create and activate a virtual environment:
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
3 Install dependencies (Slither):
   pip install slither-analyzer
💻 Usage
A unified Python runner script (run_detector.py) is provided to execute any detector against a target Solidity file.
python run_detector.py <detector_name> <target_contract.sol>
Available Detectors:
unprotected-cex-callback
readonly-reentrancy
tainted-data-flow
Examples:
1. Check for unprotected CEX callbacks:
python run_detector.py unprotected-cex-callback CEXOracle.sol
2. Check for ReadOnly Reentrancy risks:
python run_detector.py readonly-reentrancy ReadOnlyReentrancy.sol
3. Check for Tainted Data Flow:
python run_detector.py tainted-data-flow TaintedData.sol
(Note: Test contracts demonstrating both vulnerable and safe patterns are included in the repository for each detector.)🎥 Live Demos
See the detectors in action:
🎬 Building 3 Custom Slither Detectors: Complete Toolkit (v0.4.0) (Full demo with voiceover)
🎬 Basic Vulnerabilities Demo (v0.2.0)
🗺️ Roadmap
Improve ReadOnlyReentrancy to analyze AST execution order and reduce false positives.
Add GitHub Actions CI/CD workflow to run detectors automatically on PRs.
Expand Taint Analysis to track multi-hop data flows.
🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.
Fork the Project
Create your Feature Branch (git checkout -b feature/AmazingDetector)
Commit your Changes (git commit -m 'Add some AmazingDetector')
Push to the Branch (git push origin feature/AmazingDetector)
Open a Pull Request
📜 License
Distributed under the MIT License. See LICENSE for more information.
Built with ❤️ for the Web3 Security Community.
