from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class TaintedDataFlow(AbstractDetector):
    ARGUMENT = 'tainted-data-flow'
    HELP = 'Detect usage of unvalidated external data in critical operations'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = 'https://github.com/rdin777/slither-cex-detector'
    WIKI_TITLE = 'Tainted Data Flow'
    WIKI_DESCRIPTION = 'Data returned from external calls (oracles, CEX APIs) is used in critical operations (transfers, state changes) without proper validation.'
    WIKI_EXPLOIT_SCENARIO = '''
1. Contract fetches data from an external oracle or CEX.
2. The data is manipulated or returns an invalid value (e.g., 0).
3. Contract uses this tainted data directly in a transfer or calculation.
4. Attacker drains funds or causes a denial of service.
'''
    WIKI_RECOMMENDATION = 'Always validate external data (e.g., require(price > 0)) before using it in critical logic.'

    def _detect(self):
        results = []
        
        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                # Skip constructors and view/pure functions
                if function.is_constructor or function.view or function.pure:
                    continue
                
                # 1. Check for external calls (Source) - e.g., priceFeed.getPrice()
                has_external_call = False
                for node in function.nodes:
                    if node.high_level_calls:
                        has_external_call = True
                        break
                
                # 2. Check for critical operations (Sink) - transfer, send, or state changes
                has_critical_op = False
                for node in function.nodes:
                    # Check expression strings for transfer/send
                    if hasattr(node, 'expression') and node.expression:
                        expr_str = str(node.expression).lower()
                        if 'transfer' in expr_str or 'send' in expr_str:
                            has_critical_op = True
                            break
                    # Check high_level_calls for transfer/send function names
                    if node.high_level_calls:
                        for _, func_name in node.high_level_calls:
                            if func_name in ['transfer', 'send']:
                                has_critical_op = True
                                break
                    if has_critical_op:
                        break
                
                # 3. Check for validation (Sanitizer) - require statements
                has_validation = False
                for node in function.nodes:
                    if hasattr(node, 'expression') and node.expression:
                        if 'require' in str(node.expression).lower():
                            has_validation = True
                            break
                
                # If there is a Source and a Sink, but no Sanitizer -> Vulnerability
                if has_external_call and has_critical_op and not has_validation:
                    info = [
                        f"Function {function.name} in {contract.name} uses external data ",
                        f"without validation before critical operations.\n"
                    ]
                    
                    res = self.generate_result(info)
                    res.add(function)
                    results.append(res)
                    
        return results
