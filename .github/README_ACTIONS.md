# GitHub Actions Workflows

This repository includes automated security checks using GitHub Actions.

## Workflows

### 1. CEX Interface Security Check
**File:** `.github/workflows/security-check.yml`

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main`
- Only when Solidity files change

**What it does:**
- Installs the CEX detector
- Runs analysis on test contracts
- Exports results to JSON
- Uploads results as artifacts
- Warns if vulnerabilities are found

### 2. Test CEX Detector
**File:** `.github/workflows/test-detector.yml`

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main`
- Only when Python files change

**What it does:**
- Installs dependencies
- Tests detector on vulnerable contract
- Tests detector on secure contract
- Verifies JSON export functionality

## Viewing Results

1. Go to the **Actions** tab in the repository
2. Click on a workflow run
3. Download artifacts to see detailed results

## Adding Your Own Contracts

To analyze your contracts:

1. Add them to the `contracts/` directory
2. Update the workflow to include your contract paths:
   ```yaml
   - name: Run security check
     run: |
       python3 run_detector.py contracts/YourContract.sol --json
Customization
You can customize the workflows by:
Adding more contracts to analyze
Changing Python version
Adding notification steps (Slack, email)
Integrating with other CI/CD tools
