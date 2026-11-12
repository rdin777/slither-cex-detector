from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class ReadOnlyReentrancy(AbstractDetector):
    ARGUMENT = 'readonly-reentrancy'
    HELP = 'Detect view functions that may return stale data during external calls'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = 'https://github.com/rdin777/slither-cex-detector'
    WIKI_TITLE = 'ReadOnly Reentrancy'
    WIKI_DESCRIPTION = 'View functions that read state variables modified by functions with external calls can return stale data if called during the external call execution.'
    WIKI_EXPLOIT_SCENARIO = '''
1. Contract has a function that makes an external call (e.g., token transfer)
2. State is updated AFTER the external call
3. Attacker calls a view function during the external call
4. View function returns stale/unupdated state
5. Attacker exploits stale data for profit (e.g., arbitrage, liquidation)
'''
    WIKI_RECOMMENDATION = 'Follow Checks-Effects-Interactions pattern: update state BEFORE external calls. Consider using reentrancy guards or mutex locks for view functions if they expose critical state.'

    def _get_state_variables_read(self, function):
        """Get all state variables read by a function"""
        variables_read = set()
        for node in function.nodes:
            for variable in node.state_variables_read:
                variables_read.add(variable.name)
        return variables_read
    
    def _get_state_variables_written(self, function):
        """Get all state variables written by a function"""
        variables_written = set()
        for node in function.nodes:
            for variable in node.state_variables_written:
                variables_written.add(variable.name)
        return variables_written
    
    def _has_external_call(self, function):
        """Check if function makes external calls"""
        for node in function.nodes:
            # Check for high-level calls (e.g., token.transfer(), token.transferFrom())
            if node.high_level_calls:
                return True
            # Check for low-level calls (call, delegatecall, staticcall)
            if node.low_level_calls:
                return True
            # Check for external calls via expression
            if hasattr(node, 'expression') and node.expression:
                expr_str = str(node.expression)
                if 'call' in expr_str.lower() or 'transfer' in expr_str.lower():
                    return True
        return False
    
    def _detect(self):
        results = []
        
        for contract in self.compilation_unit.contracts:
            # Find functions with external calls
            functions_with_external_calls = []
            for function in contract.functions:
                if function.is_constructor or function.view or function.pure:
                    continue
                
                if self._has_external_call(function):
                    functions_with_external_calls.append(function)
            
            if not functions_with_external_calls:
                continue
            
            # Find view functions that read state modified by external call functions
            for view_function in contract.functions:
                if not view_function.view:
                    continue
                
                view_vars_read = self._get_state_variables_read(view_function)
                
                if not view_vars_read:
                    continue
                
                # Check if any external call function writes to these variables
                for ext_function in functions_with_external_calls:
                    ext_vars_written = self._get_state_variables_written(ext_function)
                    
                    # If view function reads variables that external call function writes
                    common_vars = view_vars_read.intersection(ext_vars_written)
                    
                    if common_vars:
                        info = [
                            f"View function {view_function.name} in {contract.name} ",
                            f"reads state variables ({', '.join(common_vars)}) that are ",
                            f"modified by {ext_function.name} which contains external calls.\n",
                            f"This may lead to ReadOnlyReentrancy if {view_function.name} ",
                            f"is called during the external call in {ext_function.name}.\n"
                        ]
                        
                        res = self.generate_result(info)
                        res.add(view_function)
                        res.add(ext_function)
                        results.append(res)
        
        return results
