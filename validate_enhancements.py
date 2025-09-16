#!/usr/bin/env python3
"""
Simple validation test for enhanced Azaz-El framework
Tests key functionality and interface improvements
"""

import sys
import subprocess
from pathlib import Path

def test_compilation():
    """Test that all Python files compile without syntax errors"""
    print("🧪 Testing Python compilation...")
    
    files_to_test = [
        'moloch.py',
        'azaz_el_unified.py',
        'moloch_integration.py',
        'demo_unified_dashboard.py'
    ]
    
    for file_path in files_to_test:
        if Path(file_path).exists():
            try:
                result = subprocess.run(['python3', '-m', 'py_compile', file_path], 
                                     capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"  ✅ {file_path} - Compilation successful")
                else:
                    print(f"  ❌ {file_path} - Compilation failed: {result.stderr}")
                    return False
            except Exception as e:
                print(f"  ❌ {file_path} - Error: {e}")
                return False
        else:
            print(f"  ⚠️  {file_path} - File not found")
    
    return True

def test_banner_display():
    """Test that the enhanced banner displays correctly"""
    print("\n🎨 Testing banner display...")
    
    try:
        # Test moloch.py banner function
        with open('moloch.py', 'r') as f:
            content = f.read()
            if '.S_SSSs     sdSSSSSSSbs' in content and 'MAIN COMMAND CENTER' in content:
                print("  ✅ moloch.py - Enhanced banner found")
            else:
                print("  ❌ moloch.py - Enhanced banner missing")
                return False
        
        # Test azaz_el_unified.py banner
        with open('azaz_el_unified.py', 'r') as f:
            content = f.read()
            if '.S_SSSs     sdSSSSSSSbs' in content:
                print("  ✅ azaz_el_unified.py - Enhanced banner found")
            else:
                print("  ❌ azaz_el_unified.py - Enhanced banner missing")
                return False
        
        return True
    except Exception as e:
        print(f"  ❌ Banner test failed: {e}")
        return False

def test_menu_enhancements():
    """Test that menu enhancements are present"""
    print("\n🎛️  Testing menu enhancements...")
    
    try:
        with open('moloch.py', 'r') as f:
            content = f.read()
            
            # Check for enhanced menu elements
            enhancements = [
                'TARGET MANAGEMENT CENTER',
                'SYSTEM CONFIGURATION CENTER',
                'TOOL STATUS DIAGNOSTICS',
                '🎯 Select an option:',
                '╔═══════════════════════════════════════════════════════════════════════════════╗'
            ]
            
            for enhancement in enhancements:
                if enhancement in content:
                    print(f"  ✅ Found: {enhancement[:30]}...")
                else:
                    print(f"  ❌ Missing: {enhancement[:30]}...")
                    return False
        
        return True
    except Exception as e:
        print(f"  ❌ Menu enhancement test failed: {e}")
        return False

def test_installation_files():
    """Test that installation files are present and valid"""
    print("\n📦 Testing installation files...")
    
    files_to_check = {
        'requirements.txt': ['aiohttp', 'cryptography'],
        'install.sh': ['AZAZ-EL INSTALLATION WIZARD', '#!/bin/bash'],
        'README.md': ['Automatic Installation', 'One-Line Installation']
    }
    
    for file_path, required_content in files_to_check.items():
        if Path(file_path).exists():
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                for req_content in required_content:
                    if req_content in content:
                        print(f"  ✅ {file_path} - Contains: {req_content[:30]}...")
                    else:
                        print(f"  ❌ {file_path} - Missing: {req_content[:30]}...")
                        return False
            except Exception as e:
                print(f"  ❌ {file_path} - Error reading: {e}")
                return False
        else:
            print(f"  ❌ {file_path} - File not found")
            return False
    
    return True

def test_configuration():
    """Test configuration file validation"""
    print("\n⚙️  Testing configuration...")
    
    config_file = 'moloch.cfg.json'
    if Path(config_file).exists():
        try:
            import json
            with open(config_file, 'r') as f:
                config = json.load(f)
                
            required_sections = ['tools', 'modules', 'performance']
            for section in required_sections:
                if section in config:
                    print(f"  ✅ Configuration section: {section}")
                else:
                    print(f"  ❌ Missing configuration section: {section}")
                    return False
            
            return True
        except Exception as e:
            print(f"  ❌ Configuration test failed: {e}")
            return False
    else:
        print(f"  ⚠️  {config_file} - Configuration file not found (will be created on first run)")
        return True

def main():
    """Run all validation tests"""
    print("🔱 AZAZ-EL FRAMEWORK VALIDATION TESTS 🔱")
    print("=" * 60)
    
    tests = [
        ("Compilation", test_compilation),
        ("Banner Display", test_banner_display),
        ("Menu Enhancements", test_menu_enhancements),
        ("Installation Files", test_installation_files),
        ("Configuration", test_configuration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
    
    print("\n" + "=" * 60)
    print(f"🎯 TEST RESULTS: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! Framework enhancements validated successfully.")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())