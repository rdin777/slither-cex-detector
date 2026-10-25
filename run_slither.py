#!/usr/bin/env python3
"""
Final wrapper to run custom Slither detectors with beautiful output
"""
import sys
from slither import Slither
from slither_cex_detector.detector import CEXInterfaceDetector, HardhatTestKeyDetector

def format_result(result, index):
    """Форматирует результат детектора в читаемый вид"""
    if isinstance(result, dict):
        # Старый формат (словарь)
        msg = result.get('message', str(result))
        impact = result.get('impact', 'Unknown')
        return f"{index}. [{impact}] {msg}"
    else:
        # Новый формат (Slither Output объект)
        try:
            data = result.data
            impact = data.get('impact', 'Unknown')
            desc = data.get('description', 'Unknown vulnerability').strip()
            
            # Добавляем имя переменной/элемента для контекста
            elements = data.get('elements', [])
            if elements:
                elem_name = elements[0].get('name', '').split('=')[0].strip()
                return f"{index}. [{impact}] {desc} (Variable: {elem_name})"
            
            return f"{index}. [{impact}] {desc}"
        except Exception:
            return f"{index}. {str(result)}"

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run_slither.py <contract.sol>")
        sys.exit(1)
    
    contract_path = sys.argv[1]
    print(f"🔍 Analyzing {contract_path}...\n")
    
    # Инициализируем Slither
    slither = Slither(contract_path)
    
    # Регистрируем кастомные детекторы
    slither.register_detector(CEXInterfaceDetector)
    slither.register_detector(HardhatTestKeyDetector)
    
    # Запускаем анализ
    all_results = []
    for detector in slither.detectors:
        results = detector._detect()
        all_results.extend(results)
    
    # Выводим результаты
    if all_results:
        print(f"✅ Found {len(all_results)} vulnerabilities:\n")
        for i, result in enumerate(all_results, 1):
            print(format_result(result, i))
        print("\n💡 Tip: Run with --json for CI/CD integration")
    else:
        print("🎉 No vulnerabilities found!")

if __name__ == "__main__":
    main()
