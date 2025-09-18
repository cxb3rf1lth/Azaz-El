#!/usr/bin/env python3
"""
Dependency Manager for Azaz-El Framework
Handles dependency installation and graceful degradation when modules are unavailable
"""

import os
import sys
import subprocess
import importlib
import warnings
from typing import Dict, List, Optional, Tuple

class DependencyManager:
    """Manages dependencies and provides fallbacks for missing modules"""
    
    def __init__(self):
        self.required_modules = {
            'psutil': 'psutil>=5.9.0',
            'aiohttp': 'aiohttp>=3.9.0',
            'requests': 'requests>=2.31.0',
            'beautifulsoup4': 'beautifulsoup4>=4.12.0',
            'lxml': 'lxml>=4.9.0',
            'pyyaml': 'pyyaml>=6.0.1',
            'colorama': 'colorama>=0.4.6',
            'rich': 'rich>=13.7.0',
            'click': 'click>=8.1.0'
        }
        
        self.optional_modules = {
            'selenium': 'selenium>=4.15.0',
            'pandas': 'pandas>=2.1.0',
            'numpy': 'numpy>=1.24.0',
            'dnspython': 'dnspython>=2.4.0',
            'python-nmap': 'python-nmap>=0.7.1',
            'shodan': 'shodan>=1.30.0',
            'censys': 'censys>=2.2.0',
            'aiofiles': 'aiofiles>=23.2.0',
            'jinja2': 'jinja2>=3.1.0',
            'tabulate': 'tabulate>=0.9.0'
        }
        
        self.available_modules = {}
        self.missing_modules = []
        
    def check_dependencies(self) -> Tuple[List[str], List[str]]:
        """Check which dependencies are available and which are missing"""
        available = []
        missing = []
        
        # Check required modules
        for module_name, package_spec in self.required_modules.items():
            if self._check_module(module_name):
                available.append(module_name)
                self.available_modules[module_name] = True
            else:
                missing.append(package_spec)
                self.available_modules[module_name] = False
                self.missing_modules.append(package_spec)
        
        # Check optional modules
        for module_name, package_spec in self.optional_modules.items():
            if self._check_module(module_name):
                available.append(module_name)
                self.available_modules[module_name] = True
            else:
                self.available_modules[module_name] = False
        
        return available, missing
    
    def _check_module(self, module_name: str) -> bool:
        """Check if a module can be imported"""
        try:
            # Handle special cases
            if module_name == 'beautifulsoup4':
                importlib.import_module('bs4')
            elif module_name == 'python-nmap':
                importlib.import_module('nmap')
            elif module_name == 'pyyaml':
                importlib.import_module('yaml')
            else:
                importlib.import_module(module_name)
            return True
        except ImportError:
            return False
    
    def install_missing_dependencies(self, missing: List[str], force: bool = False) -> bool:
        """Attempt to install missing dependencies"""
        if not missing:
            return True
        
        print(f"🔧 Installing {len(missing)} missing dependencies...")
        
        for package in missing:
            try:
                print(f"  Installing {package}...")
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', package, '--user'],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    print(f"  ✅ {package} installed successfully")
                else:
                    print(f"  ⚠️  Failed to install {package}: {result.stderr}")
                    if not force:
                        return False
                        
            except subprocess.TimeoutExpired:
                print(f"  ⏰ Installation of {package} timed out")
                if not force:
                    return False
            except Exception as e:
                print(f"  ❌ Error installing {package}: {e}")
                if not force:
                    return False
        
        return True
    
    def get_fallback_imports(self) -> Dict[str, object]:
        """Provide fallback objects for missing modules"""
        fallbacks = {}
        
        # Create mock objects for missing modules
        class MockModule:
            def __init__(self, name):
                self.name = name
            
            def __getattr__(self, item):
                def mock_function(*args, **kwargs):
                    warnings.warn(f"Module {self.name} not available. Function {item} is mocked.")
                    return None
                return mock_function
        
        # Provide fallbacks for critical modules
        if not self.available_modules.get('psutil', False):
            fallbacks['psutil'] = MockModule('psutil')
        
        if not self.available_modules.get('aiohttp', False):
            fallbacks['aiohttp'] = MockModule('aiohttp')
        
        if not self.available_modules.get('requests', False):
            # For requests, we can provide a basic fallback
            import urllib.request
            import urllib.parse
            
            class RequestsFallback:
                @staticmethod
                def get(url, **kwargs):
                    return urllib.request.urlopen(url)
                
                @staticmethod
                def post(url, data=None, **kwargs):
                    if data:
                        data = urllib.parse.urlencode(data).encode()
                    req = urllib.request.Request(url, data=data)
                    return urllib.request.urlopen(req)
            
            fallbacks['requests'] = RequestsFallback()
        
        return fallbacks
    
    def setup_environment(self) -> bool:
        """Setup the environment with dependencies"""
        print("🔍 Checking dependencies...")
        available, missing = self.check_dependencies()
        
        print(f"✅ Available modules: {len(available)}")
        if available:
            print(f"   {', '.join(available)}")
        
        if missing:
            print(f"❌ Missing modules: {len(missing)}")
            print(f"   {', '.join(missing)}")
            
            # Try to install missing dependencies
            if self.install_missing_dependencies(missing, force=True):
                print("✅ All dependencies installed successfully")
                return True
            else:
                print("⚠️  Some dependencies could not be installed. Using fallbacks...")
                return False
        else:
            print("✅ All dependencies are available")
            return True

# Global dependency manager instance
dependency_manager = DependencyManager()

def ensure_dependencies():
    """Ensure all dependencies are available or provide fallbacks"""
    return dependency_manager.setup_environment()

def get_safe_import(module_name: str):
    """Safely import a module with fallback"""
    if dependency_manager.available_modules.get(module_name, False):
        return importlib.import_module(module_name)
    else:
        fallbacks = dependency_manager.get_fallback_imports()
        return fallbacks.get(module_name, None)