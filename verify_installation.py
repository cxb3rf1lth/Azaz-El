#!/usr/bin/env python3
"""
Azaz-El Framework Installation Verifier and System Health Checker
Advanced validation script for comprehensive security assessment tools
"""

import os
import sys
import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Any
import time

class AzazElVerifier:
    """Comprehensive system verification for Azaz-El framework"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.config_file = self.base_dir / "moloch.cfg.json"
        self.results = {
            "system": {},
            "tools": {},
            "wordlists": {},
            "payloads": {},
            "configuration": {},
            "performance": {},
            "overall_score": 0
        }
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from moloch.cfg.json"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Failed to load configuration: {e}")
            return {}
    
    def check_system_requirements(self) -> None:
        """Check system requirements and dependencies"""
        print("🏗️  Checking System Requirements...")
        
        # Check Python version
        python_version = sys.version_info
        if python_version >= (3, 8):
            self.results["system"]["python"] = f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}"
        else:
            self.results["system"]["python"] = f"❌ Python {python_version.major}.{python_version.minor}.{python_version.micro} (requires 3.8+)"
        
        # Check essential system tools
        essential_tools = ["git", "wget", "curl", "go", "python3", "pip3"]
        for tool in essential_tools:
            if shutil.which(tool):
                version = self.get_tool_version(tool)
                self.results["system"][tool] = f"✅ {tool} {version}"
            else:
                self.results["system"][tool] = f"❌ {tool} not found"
        
        # Check package managers
        package_managers = ["apt", "yum", "dnf", "brew", "pacman"]
        available_pm = []
        for pm in package_managers:
            if shutil.which(pm):
                available_pm.append(pm)
        
        if available_pm:
            self.results["system"]["package_manager"] = f"✅ Available: {', '.join(available_pm)}"
        else:
            self.results["system"]["package_manager"] = "❌ No package manager detected"
    
    def get_tool_version(self, tool: str) -> str:
        """Get version of a tool"""
        try:
            if tool == "go":
                result = subprocess.run([tool, "version"], capture_output=True, text=True, timeout=5)
                return result.stdout.split()[2] if result.returncode == 0 else "unknown"
            elif tool == "python3":
                return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            else:
                result = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5)
                return result.stdout.split()[0] if result.returncode == 0 else "unknown"
        except:
            return "unknown"
    
    def check_security_tools(self) -> None:
        """Check availability of security tools"""
        print("🔧 Checking Security Tools...")
        
        config = self.load_config()
        tools_config = config.get("tools", {})
        
        available_count = 0
        total_count = len(tools_config)
        
        for tool_name, tool_config in tools_config.items():
            if shutil.which(tool_name):
                version = self.get_security_tool_version(tool_name)
                self.results["tools"][tool_name] = f"✅ {tool_name} {version}"
                available_count += 1
            else:
                install_method = "Go" if "go install" in tool_config.get("install_cmd", "") else "Package Manager"
                self.results["tools"][tool_name] = f"❌ {tool_name} missing ({install_method})"
        
        # Calculate tool availability score
        tool_score = (available_count / total_count) * 100 if total_count > 0 else 0
        self.results["tools"]["summary"] = f"📊 {available_count}/{total_count} tools available ({tool_score:.1f}%)"
    
    def get_security_tool_version(self, tool: str) -> str:
        """Get version of security tools with specific handling"""
        try:
            if tool in ["nuclei", "httpx", "subfinder", "naabu", "katana"]:
                result = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=5)
            elif tool == "nmap":
                result = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5)
            elif tool == "nikto":
                result = subprocess.run([tool, "-Version"], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run([tool, "-h"], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Extract version from output
                output = result.stdout + result.stderr
                for line in output.split('\n'):
                    if 'version' in line.lower() or 'v' in line:
                        return line.strip()[:50] + "..." if len(line) > 50 else line.strip()
                return "available"
            else:
                return "unknown"
        except:
            return "unknown"
    
    def check_wordlists_and_payloads(self) -> None:
        """Check wordlists and payloads availability and size"""
        print("📚 Checking Wordlists and Payloads...")
        
        # Check wordlists
        wordlists_dir = self.base_dir / "wordlists"
        if wordlists_dir.exists():
            wordlist_files = list(wordlists_dir.glob("*.txt"))
            total_lines = 0
            for wl_file in wordlist_files:
                try:
                    with open(wl_file, 'r') as f:
                        lines = len(f.readlines())
                        total_lines += lines
                        self.results["wordlists"][wl_file.name] = f"✅ {lines:,} entries"
                except:
                    self.results["wordlists"][wl_file.name] = "❌ Error reading file"
            
            self.results["wordlists"]["summary"] = f"📊 {len(wordlist_files)} files, {total_lines:,} total entries"
        else:
            self.results["wordlists"]["summary"] = "❌ Wordlists directory not found"
        
        # Check payloads
        payloads_dir = self.base_dir / "payloads"
        if payloads_dir.exists():
            payload_files = list(payloads_dir.glob("*.txt"))
            total_payloads = 0
            for payload_file in payload_files:
                try:
                    with open(payload_file, 'r') as f:
                        lines = len(f.readlines())
                        total_payloads += lines
                        self.results["payloads"][payload_file.name] = f"✅ {lines:,} payloads"
                except:
                    self.results["payloads"][payload_file.name] = "❌ Error reading file"
            
            self.results["payloads"]["summary"] = f"📊 {len(payload_files)} files, {total_payloads:,} total payloads"
        else:
            self.results["payloads"]["summary"] = "❌ Payloads directory not found"
    
    def check_configuration(self) -> None:
        """Check configuration completeness"""
        print("⚙️  Checking Configuration...")
        
        config = self.load_config()
        
        # Check essential configuration sections
        essential_sections = ["tools", "wordlists", "payloads", "performance", "auth", "modules"]
        for section in essential_sections:
            if section in config:
                self.results["configuration"][section] = f"✅ {section} configured"
            else:
                self.results["configuration"][section] = f"❌ {section} missing"
        
        # Check advanced features
        advanced_config = config.get("advanced", {})
        enabled_features = sum(1 for v in advanced_config.values() if v is True)
        total_features = len([k for k, v in advanced_config.items() if isinstance(v, bool)])
        
        if total_features > 0:
            self.results["configuration"]["advanced_features"] = f"📊 {enabled_features}/{total_features} advanced features enabled"
        
        # Check API keys
        auth_config = config.get("auth", {})
        configured_apis = sum(1 for v in auth_config.values() if v and v.strip())
        total_apis = len(auth_config)
        
        self.results["configuration"]["api_keys"] = f"🔑 {configured_apis}/{total_apis} API keys configured"
    
    def check_performance_settings(self) -> None:
        """Check performance and optimization settings"""
        print("⚡ Checking Performance Settings...")
        
        config = self.load_config()
        perf_config = config.get("performance", {})
        
        # Check key performance settings
        settings_check = {
            "max_workers": (perf_config.get("max_workers", 0), "workers"),
            "rate_limit": (perf_config.get("rate_limit", 0), "req/min"),
            "tool_timeout": (perf_config.get("tool_timeout", 0), "seconds"),
            "concurrent_scans": (perf_config.get("concurrent_scans", 0), "scans"),
            "max_retries": (perf_config.get("max_retries", 0), "retries")
        }
        
        for setting, (value, unit) in settings_check.items():
            if value > 0:
                self.results["performance"][setting] = f"✅ {setting}: {value} {unit}"
            else:
                self.results["performance"][setting] = f"❌ {setting}: not configured"
        
        # Check user agents
        user_agents = perf_config.get("user_agents", [])
        if user_agents:
            self.results["performance"]["user_agents"] = f"✅ {len(user_agents)} user agents configured"
        else:
            self.results["performance"]["user_agents"] = "❌ No user agents configured"
    
    def calculate_overall_score(self) -> None:
        """Calculate overall framework health score"""
        total_checks = 0
        passed_checks = 0
        
        for category, items in self.results.items():
            if category == "overall_score":
                continue
                
            for key, value in items.items():
                if key != "summary":
                    total_checks += 1
                    if "✅" in str(value):
                        passed_checks += 1
        
        if total_checks > 0:
            score = (passed_checks / total_checks) * 100
            self.results["overall_score"] = score
        else:
            self.results["overall_score"] = 0
    
    def generate_report(self) -> None:
        """Generate comprehensive verification report"""
        print("\n" + "=" * 80)
        print("🎯 AZAZ-EL FRAMEWORK VERIFICATION REPORT")
        print("=" * 80)
        
        # Overall score
        score = self.results["overall_score"]
        if score >= 90:
            status = "🎉 EXCELLENT"
            color = "\033[1;32m"
        elif score >= 70:
            status = "👍 GOOD" 
            color = "\033[1;33m"
        elif score >= 50:
            status = "⚠️  FAIR"
            color = "\033[1;93m"
        else:
            status = "❌ POOR"
            color = "\033[1;91m"
        
        print(f"\n🏥 Overall Health: {color}{status} ({score:.1f}%)\033[0m")
        
        # Detailed results by category
        categories = {
            "system": "🏗️  System Requirements",
            "tools": "🔧 Security Tools", 
            "wordlists": "📚 Wordlists",
            "payloads": "💥 Payloads",
            "configuration": "⚙️  Configuration",
            "performance": "⚡ Performance Settings"
        }
        
        for category, title in categories.items():
            if category in self.results:
                print(f"\n{title}:")
                print("-" * 50)
                
                items = self.results[category]
                for key, value in items.items():
                    if key == "summary":
                        print(f"  {value}")
                    else:
                        print(f"  {value}")
        
        # Recommendations
        print(f"\n🎯 RECOMMENDATIONS:")
        print("-" * 50)
        
        if score < 90:
            print("  • Install missing security tools using the framework's auto-installer")
            print("  • Configure API keys for enhanced reconnaissance capabilities")
            print("  • Enable additional advanced features in configuration")
        
        if score < 70:
            print("  • Update system dependencies and package managers")
            print("  • Review and optimize performance settings")
            print("  • Ensure all essential wordlists and payloads are available")
        
        if score < 50:
            print("  • Run system diagnostics and address critical issues")
            print("  • Consider manual installation of core security tools")
            print("  • Review system requirements and compatibility")
        
        print("\n📖 For detailed installation instructions, run:")
        print("   python3 master_azaz_el.py --install-tools")
        print("   python3 master_azaz_el.py --help")
        
        print("\n" + "=" * 80)
    
    def run_verification(self) -> None:
        """Run complete verification process"""
        print("🔍 Starting Azaz-El Framework Verification...")
        print("=" * 60)
        
        start_time = time.time()
        
        self.check_system_requirements()
        self.check_security_tools()
        self.check_wordlists_and_payloads()
        self.check_configuration()
        self.check_performance_settings()
        self.calculate_overall_score()
        
        end_time = time.time()
        
        self.generate_report()
        
        print(f"\n⏱️  Verification completed in {end_time - start_time:.2f} seconds")
        
        return self.results["overall_score"]

def main():
    """Main entry point"""
    try:
        verifier = AzazElVerifier()
        score = verifier.run_verification()
        
        # Exit with appropriate code
        if score >= 70:
            sys.exit(0)  # Success
        elif score >= 50:
            sys.exit(1)  # Warning
        else:
            sys.exit(2)  # Critical issues
            
    except KeyboardInterrupt:
        print("\n\n🔄 Verification interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Verification failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()