"""
CEX Interface Security Detector
Detects vulnerabilities in CEX interface smart contracts.
Compatible with Slither 0.11.x
"""

import re
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CEXInterfaceDetector(AbstractDetector):
    ARGUMENT = 'cex-interface-security'
    HELP = 'Detects security vulnerabilities in CEX interface contracts'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = 'https://github.com/rdin777/slither-cex-detector'
    WIKI_TITLE = 'CEX Interface Security'
    WIKI_DESCRIPTION = 'Custom detector for identifying hardcoded API keys, missing signature verification, insecure nonces, and plaintext credentials in CEX interface contracts.'
    WIKI_EXPLOIT_SCENARIO = '''
An attacker can extract hardcoded API keys from the contract source code and use them to make unauthorized API calls to centralized exchanges, potentially draining funds or manipulating orders.
'''
    WIKI_RECOMMENDATION = '''
Use environment variables or secure key management systems instead of hardcoding API keys. Implement signature verification for all external calls. Use incrementing nonces instead of block.timestamp. Encrypt credentials before storing on-chain.
'''

    API_KEY_PATTERNS = [
        r'(?i)api[_\s-]*key\s*=\s*["\'][a-zA-Z0-9_\-]{8,}["\']',
        r'(?i)api[_\s-]*secret\s*=\s*["\'][a-zA-Z0-9_\-]{8,}["\']',
        r'(?i)(binance|coinbase|kraken|bybit|okx)[_\s-]*api',
        r'(?i)private[_\s-]*key\s*=\s*0x[a-fA-F0-9]{64}',
    ]

    CEX_KEYWORDS = [
        'cex', 'exchange', 'api', 'oracle', 'bridge',
        'binance', 'coinbase', 'kraken', 'bybit',
        'withdraw', 'deposit', 'order', 'trade'
    ]

    def _is_cex_related(self, contract):
        name = contract.name.lower()
        return any(k in name for k in self.CEX_KEYWORDS)

    def _has_signature_verification(self, func, contract):
        """Check if function or contract has signature verification"""
        # Проверяем саму функцию
        for node in func.nodes:
            node_str = str(node).lower()
            if any(p in node_str for p in ['ecrecover', 'verify', 'validatesig']):
                return True
        
        # Проверяем внутренние вызовы функций (например, recoverSigner)
        for internal_call in func.internal_calls:
            if hasattr(internal_call, 'name'):
                call_name = internal_call.name.lower()
                if any(p in call_name for p in ['recover', 'verify', 'validate', 'check']):
                    # Проверяем, есть ли ecrecover в вызываемой функции
                    if hasattr(internal_call, 'nodes'):
                        for node in internal_call.nodes:
                            if 'ecrecover' in str(node).lower():
                                return True
        
        # Проверяем все функции контракта на наличие ecrecover
        for c_func in contract.functions:
            if c_func.name != func.name:
                for node in c_func.nodes:
                    if 'ecrecover' in str(node).lower():
                        return True
        
        return False

    def _is_rate_limiting(self, func):
        """Check if timestamp is used for rate limiting (safe pattern)"""
        for node in func.nodes:
            node_str = str(node).lower()
            # Если есть сравнение timestamp с lastRequestTime или cooldown — это rate limiting
            if ('lastrequest' in node_str or 'cooldown' in node_str or 'ratelimit' in node_str):
                if 'block.timestamp' in str(node) or 'block.number' in str(node):
                    return True
        return False

    def _detect_hardcoded_keys(self, contract):
        results = []
        for var in contract.state_variables:
            name = var.name.lower()
            
            if any(k in name for k in ['api_key', 'api_secret', 'private_key', 'secret_key']):
                if hasattr(var, 'expression') and var.expression:
                    expr_str = str(var.expression)
                    if '"' in expr_str or "'" in expr_str:
                        results.append({
                            'element': var,
                            'type': 'hardcoded_api_key',
                            'message': f"Hardcoded API key: '{var.name}'",
                            'impact': 'Critical',
                            'confidence': 'High'
                        })
                    else:
                        results.append({
                            'element': var,
                            'type': 'sensitive_variable',
                            'message': f"Sensitive variable '{var.name}' may be hardcoded",
                            'impact': 'Critical',
                            'confidence': 'Medium'
                        })
        return results

    def _detect_missing_signature(self, contract):
        results = []
        for func in contract.functions_entry_points:
            visibility = str(func.visibility) if hasattr(func, 'visibility') else 'public'
            
            if visibility in ['external', 'public']:
                is_view = hasattr(func, 'view') and func.view
                is_pure = hasattr(func, 'pure') and func.pure
                
                if not is_view and not is_pure:
                    has_ext = any(func.external_calls_as_expressions)
                    if has_ext:
                        # Проверяем наличие проверки подписи в функции или контракте
                        if not self._has_signature_verification(func, contract):
                            results.append({
                                'element': func,
                                'type': 'missing_signature',
                                'message': f"Function '{func.name}' lacks signature verification",
                                'impact': 'High',
                                'confidence': 'Medium'
                            })
        return results

    def _detect_insecure_nonce(self, contract):
        results = []
        for func in contract.functions_entry_points:
            # Проверяем использование timestamp
            uses_timestamp = any('block.timestamp' in str(n) or 'block.number' in str(n) for n in func.nodes)
            
            if uses_timestamp:
                # Исключаем rate limiting (безопасный паттерн)
                if not self._is_rate_limiting(func):
                    results.append({
                        'element': func,
                        'type': 'insecure_nonce',
                        'message': f"Function '{func.name}' uses manipulable block.timestamp/number",
                        'impact': 'Medium',
                        'confidence': 'High'
                    })
        return results

    def _detect_plaintext_creds(self, contract):
        results = []
        for var in contract.state_variables:
            name = var.name.lower()
            vtype = str(var.type).lower()
            
            # Исключаем переменные с "encrypted" в имени
            if 'encrypted' in name:
                continue
            
            # Исключаем bytes32 (это хэши, не plaintext)
            if 'bytes32' in vtype:
                continue
            
            if any(k in name for k in ['api_key', 'secret', 'password', 'credential']):
                if 'string' in vtype or 'bytes' in vtype:
                    results.append({
                        'element': var,
                        'type': 'plaintext_creds',
                        'message': f"Plaintext credentials: '{var.name}'",
                        'impact': 'Critical',
                        'confidence': 'High'
                    })
        return results

    def _detect(self):
        """Main detection method"""
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if self._is_cex_related(contract):
                results.extend(self._detect_hardcoded_keys(contract))
                results.extend(self._detect_missing_signature(contract))
                results.extend(self._detect_insecure_nonce(contract))
                results.extend(self._detect_plaintext_creds(contract))
        return results


def register_detectors(slither):
    slither.register_detector(CEXInterfaceDetector)
