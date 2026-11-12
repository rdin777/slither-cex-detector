from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class UnprotectedCEXCallback(AbstractDetector):
    ARGUMENT = 'unprotected-cex-callback'
    HELP = 'Detect CEX/Oracle update functions lacking access control or signature verification'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    
    WIKI = 'https://github.com/rdin777/slither-cex-detector'
    WIKI_TITLE = 'Unprotected CEX Callback'
    WIKI_DESCRIPTION = 'Functions that handle external data (e.g., CEX callbacks, oracle updates) without proper access control or signature verification can be exploited by attackers to manipulate contract state.'
    WIKI_EXPLOIT_SCENARIO = '''
An attacker can call the unprotected update function with arbitrary values, manipulating oracle prices or contract state. For example:
1. Attacker calls `updatePrice(999999)` on a price oracle
2. Other contracts relying on this price execute trades at manipulated rates
3. Attacker profits from arbitrage or liquidations
'''
    WIKI_RECOMMENDATION = 'Add access control modifiers (e.g., onlyOwner, onlyRole) or implement cryptographic signature verification for all functions that handle external data.'

    # Keywords that suggest the function handles external data
    DANGEROUS_KEYWORDS = ['update', 'set', 'handle', 'callback', 'oracle', 'feed']

    def _has_access_control(self, function):
        """Check if function has access control via modifiers or require statements"""
        
        # Check modifiers (e.g., onlyOwner, onlyRole)
        has_modifier = any(
            mod.lower() in ['onlyowner', 'onlyrole', 'restricted', 'authorized'] 
            for mod in function.modifiers
        )
        
        if has_modifier:
            return True
        
        # Check for require(msg.sender == ...) in function body
        for node in function.nodes:
            # Look for require statements
            if 'require' in str(node.expression) if hasattr(node, 'expression') else False:
                # Check if it involves msg.sender
                node_str = str(node)
                if 'msg.sender' in node_str:
                    return True
        
        return False

    def _has_signature_verification(self, function):
        """Check if function has cryptographic signature verification"""
        for node in function.nodes:
            node_str = str(node)
            if 'ecrecover' in node_str or 'verify' in node_str.lower():
                return True
        return False

    def _detect(self):
        results = []
        
        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                # Skip constructors and standard view functions
                if function.is_constructor or function.view or function.pure:
                    continue
                
                func_name_lower = function.name.lower()
                
                # Check if function name matches dangerous keywords AND has parameters
                if any(keyword in func_name_lower for keyword in self.DANGEROUS_KEYWORDS):
                    if len(function.parameters) > 0:
                        
                        # Check for access control (modifiers OR require statements)
                        has_access_control = self._has_access_control(function)
                        
                        # Check for signature verification
                        has_sig_check = self._has_signature_verification(function)

                        # If it has neither, it's a high-risk vulnerability
                        if not has_access_control and not has_sig_check:
                            info = [
                                f"Function {function.name} in {contract.name} handles external data ",
                                f"but lacks access control or signature verification.\n"
                            ]
                            
                            res = self.generate_result(info)
                            res.add(function)
                            results.append(res)
                            
        return results
