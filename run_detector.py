#!/usr/bin/env python3
"""
Run CEX Interface Security Detector
Compatible with Slither 0.11.6
Usage: python3 run_detector.py <contract.sol> [--json]
"""

import sys
import json
import logging
from slither.slither import Slither
from slither_cex_detector.detector import CEXInterfaceDetector

def serialize_element(element):
    """Safely extract info from Slither element"""
    info = {}
    
    if hasattr(element, 'name'):
        info['name'] = element.name
    
    # Безопасно получаем тип
    if hasattr(element, 'type'):
        try:
            type_val = element.type
            if hasattr(type_val, '__str__') and 'object at' not in str(type_val):
                info['type'] = str(type_val)
            elif hasattr(type_val, 'name'):
                info['type'] = type_val.name
            else:
                info['type'] = 'function'
        except:
            info['type'] = 'function'
    
    if hasattr(element, 'visibility'):
        info['visibility'] = str(element.visibility)
    
    if hasattr(element, 'source_mapping'):
        info['source_mapping'] = str(element.source_mapping)
    
    if hasattr(element, 'contract'):
        info['contract'] = element.contract.name
    
    return info

def serialize_result(result):
    """Convert Slither result to JSON-serializable dict"""
    return {
        'type': result.get('type', 'unknown'),
        'message': result.get('message', ''),
        'impact': result.get('impact', ''),
        'confidence': result.get('confidence', ''),
        'element': serialize_element(result.get('element'))
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run_detector.py <contract.sol> [--json]")
        print("Example: python3 run_detector.py test_contracts/VulnerableCEXInterface.sol")
        sys.exit(1)
    
    contract_path = sys.argv[1]
    export_json = '--json' in sys.argv
    
    print(f"Analyzing {contract_path}...\n")
    
    try:
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger("Slither")
        
        slither = Slither(contract_path)
        all_results = []
        
        for compilation_unit in slither.compilation_units:
            detector = CEXInterfaceDetector(compilation_unit, slither, logger)
            results = detector._detect()
            all_results.extend(results)
        
        if all_results:
            print(f"Found {len(all_results)} vulnerabilities:\n")
            for i, result in enumerate(all_results, 1):
                print(f"{i}. {result['message']}")
                print(f"   Impact: {result['impact']}")
                print(f"   Confidence: {result['confidence']}\n")
        else:
            print("No vulnerabilities found!")
        
        if export_json:
            serializable_results = [serialize_result(r) for r in all_results]
            with open('results.json', 'w') as f:
                json.dump(serializable_results, f, indent=2)
            print(f"Results saved to results.json ({len(serializable_results)} vulnerabilities)")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
