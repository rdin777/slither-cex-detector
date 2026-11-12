#!/usr/bin/env python3
"""
Custom Slither Detector Runner for CEX/Oracle Security Checks
Analyzes Solidity contracts for unprotected external data handlers
"""

import sys
import logging
from slither.slither import Slither
from slither_cex_detector.detectors.unprotected_cex_callback import UnprotectedCEXCallback


def main():
    """Main execution function"""
    
    # Check command line arguments
    if len(sys.argv) != 2:
        print("Usage: python run_cex_detector.py <solidity_file.sol>")
        print("Example: python run_cex_detector.py CEXOracle.sol")
        sys.exit(1)
    
    solidity_file = sys.argv[1]
    print(f"\n{'='*60}")
    print(f"[*] Starting CEX/Oracle Security Analysis")
    print(f"[*] Target file: {solidity_file}")
    print(f"{'='*60}\n")
    
    try:
        # Initialize Slither with the target contract
        print("[*] Loading contract into Slither...")
        slither = Slither(solidity_file)
        print("[+] Contract loaded successfully\n")
        
        # Create logger
        logger = logging.getLogger("Slither")
        
        # Get compilation unit
        if not slither.compilation_units:
            print("[ERROR] No compilation units found!")
            sys.exit(2)
        
        compilation_unit = slither.compilation_units[0]
        
        # Create detector instance - CORRECT ORDER: compilation_unit, slither, logger
        print("[*] Initializing UnprotectedCEXCallback detector...")
        detector = UnprotectedCEXCallback(compilation_unit, slither, logger)
        
        # Run detection
        print("[*] Running security analysis...\n")
        results = detector.detect()
        
        # Display results
        print(f"{'='*60}")
        if results:
            print(f"[!] VULNERABILITIES FOUND: {len(results)}")
            print(f"{'='*60}\n")
            
            for idx, result in enumerate(results, 1):
                print(f"[{idx}] {result}")
                print("-" * 60)
            
            print(f"\n[!] Total issues: {len(results)}")
            print("[!] Recommendation: Add access control or signature verification")
            print("[!] Reference: https://github.com/rdin777/slither-cex-detector\n")
            
            sys.exit(1)
        else:
            print("[+] No vulnerabilities detected!")
            print("[+] Contract appears to be secure against CEX/Oracle attacks")
            print(f"{'='*60}\n")
            
            sys.exit(0)
            
    except FileNotFoundError:
        print(f"[ERROR] File not found: {solidity_file}")
        sys.exit(2)
    except Exception as e:
        print(f"[ERROR] Analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(3)


if __name__ == "__main__":
    main()
