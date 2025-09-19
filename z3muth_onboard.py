#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Z3MUTH Onboarding and Quick Setup Script
This script helps users quickly onboard and configure Z3MUTH for optimal use
"""

import os
import sys
import json
import subprocess
import platform
from pathlib import Path

def print_banner():
    """Print Z3MUTH onboarding banner"""
    banner = """
██████╗ ███╗   ███╗██╗   ██╗████████╗██╗  ██╗
╚════██╗████╗ ████║██║   ██║╚══██╔══╝██║  ██║
 █████╔╝██╔████╔██║██║   ██║   ██║   ███████║
 ╚═══██╗██║╚██╔╝██║██║   ██║   ██║   ██╔══██║
██████╔╝██║ ╚═╝ ██║╚██████╔╝   ██║   ██║  ██║
╚═════╝ ╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝

🚀 Z3MUTH Onboarding & Setup Assistant
Zenith of Advanced Multi-threaded Universal Testing Hub
"""
    print(banner)

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'aiohttp', 'rich', 'psutil', 'requests', 'cryptography',
        'yaml', 'bs4', 'dns'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package}")
            missing.append(package)
    
    if missing:
        print(f"\n⚠️  Missing packages: {', '.join(missing)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    print("✅ All dependencies are installed!")
    return True

def check_system_requirements():
    """Check system requirements"""
    print("\n🖥️  Checking system requirements...")
    
    # Check Python version
    python_version = sys.version_info
    if python_version >= (3, 8):
        print(f"  ✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}")
    else:
        print(f"  ❌ Python {python_version.major}.{python_version.minor}.{python_version.micro} (requires 3.8+)")
        return False
    
    # Check available memory
    try:
        import psutil
        memory = psutil.virtual_memory()
        memory_gb = memory.total / (1024**3)
        if memory_gb >= 2:
            print(f"  ✅ Memory: {memory_gb:.1f} GB")
        else:
            print(f"  ⚠️  Memory: {memory_gb:.1f} GB (recommended: 4+ GB)")
    except ImportError:
        print("  ⚠️  Cannot check memory (psutil not available)")
    
    # Check disk space
    disk = Path('/').stat() if os.name == 'posix' else Path('C:\\').stat()
    try:
        import shutil
        disk_usage = shutil.disk_usage('/')
        free_gb = disk_usage.free / (1024**3)
        if free_gb >= 5:
            print(f"  ✅ Disk Space: {free_gb:.1f} GB free")
        else:
            print(f"  ⚠️  Disk Space: {free_gb:.1f} GB free (recommended: 10+ GB)")
    except:
        print("  ⚠️  Cannot check disk space")
    
    return True

def setup_configuration():
    """Setup Z3MUTH configuration"""
    print("\n⚙️  Setting up Z3MUTH configuration...")
    
    config_file = Path("z3muth_config.json")
    
    if config_file.exists():
        print("  📋 Configuration file already exists")
        choice = input("  Do you want to reset it to defaults? (y/N): ")
        if choice.lower() != 'y':
            return True
    
    # Enhanced default configuration
    default_config = {
        "version": "1.0.0-ZENITH",
        "core": {
            "max_concurrent_scans": 25,
            "default_timeout": 300,
            "max_memory_usage": 0.7,
            "max_cpu_usage": 0.8,
            "enable_logging": True,
            "log_level": "INFO"
        },
        "tools": {
            "nuclei": {
                "enabled": True,
                "path": "nuclei",
                "flags": ["-silent", "-severity", "medium,high,critical"],
                "timeout": 600
            },
            "subfinder": {
                "enabled": True,
                "path": "subfinder",
                "flags": ["-all", "-recursive"],
                "timeout": 300
            },
            "httpx": {
                "enabled": True,
                "path": "httpx",
                "flags": ["-silent", "-title", "-tech-detect"],
                "timeout": 180
            },
            "nmap": {
                "enabled": True,
                "path": "nmap",
                "flags": ["-sV", "-O", "--version-intensity", "5"],
                "timeout": 900
            }
        },
        "scanning": {
            "default_scan_type": "quick",
            "enable_passive_recon": True,
            "enable_active_scanning": True,
            "enable_vulnerability_assessment": True,
            "enable_web_scanning": True,
            "enable_network_scanning": True,
            "max_scan_depth": 3,
            "rate_limit": 10
        },
        "wordlists": {
            "directories": [
                "wordlists/",
                "/usr/share/wordlists/"
            ],
            "subdomains": "wordlists/subdomains.txt",
            "directories_web": "wordlists/directories.txt",
            "common_files": "wordlists/common-files.txt"
        },
        "payloads": {
            "directories": [
                "payloads/",
                "wordlists/payloads/"
            ],
            "xss": "payloads/xss-payloads.txt",
            "sqli": "payloads/sql-injection.txt",
            "lfi": "payloads/lfi-payloads.txt",
            "rce": "payloads/rce-payloads.txt"
        },
        "reporting": {
            "output_dir": "z3muth_reports",
            "formats": ["html", "json"],
            "include_screenshots": False,
            "include_raw_output": False,
            "max_report_size_mb": 100
        },
        "dashboard": {
            "refresh_rate": 2,
            "max_history_items": 50,
            "show_system_info": True,
            "show_network_stats": True
        },
        "api_keys": {
            "shodan": "",
            "censys": "",
            "securitytrails": "",
            "chaos": "",
            "github": ""
        }
    }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        print("  ✅ Configuration file created successfully")
        return True
    except Exception as e:
        print(f"  ❌ Failed to create configuration: {e}")
        return False

def setup_directories():
    """Setup required directories"""
    print("\n📁 Setting up directories...")
    
    directories = [
        "z3muth_reports",
        "logs",
        "wordlists",
        "payloads",
        "temp"
    ]
    
    for directory in directories:
        path = Path(directory)
        if not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
                print(f"  ✅ Created: {directory}")
            except Exception as e:
                print(f"  ❌ Failed to create {directory}: {e}")
                return False
        else:
            print(f"  📂 Exists: {directory}")
    
    return True

def create_quick_start_scripts():
    """Create quick start scripts"""
    print("\n📜 Creating quick start scripts...")
    
    # Dashboard launcher
    dashboard_script = """#!/bin/bash
# Z3MUTH Dashboard Quick Launcher
cd "$(dirname "$0")"
echo "🚀 Launching Z3MUTH Dashboard..."
python3 z3muth.py --dashboard
"""
    
    # CLI launcher
    cli_script = """#!/bin/bash
# Z3MUTH CLI Quick Launcher
cd "$(dirname "$0")"
echo "🎯 Launching Z3MUTH Interactive CLI..."
python3 z3muth.py --cli
"""
    
    try:
        # Create dashboard launcher
        with open("start_dashboard.sh", "w") as f:
            f.write(dashboard_script)
        os.chmod("start_dashboard.sh", 0o755)
        print("  ✅ Created: start_dashboard.sh")
        
        # Create CLI launcher
        with open("start_cli.sh", "w") as f:
            f.write(cli_script)
        os.chmod("start_cli.sh", 0o755)
        print("  ✅ Created: start_cli.sh")
        
        return True
    except Exception as e:
        print(f"  ❌ Failed to create scripts: {e}")
        return False

def run_initial_test():
    """Run initial Z3MUTH test"""
    print("\n🧪 Running initial Z3MUTH test...")
    
    try:
        result = subprocess.run([
            sys.executable, "z3muth.py", "--version"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("  ✅ Z3MUTH is working correctly!")
            return True
        else:
            print(f"  ❌ Z3MUTH test failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("  ❌ Z3MUTH test timed out")
        return False
    except Exception as e:
        print(f"  ❌ Z3MUTH test error: {e}")
        return False

def show_getting_started():
    """Show getting started information"""
    print("\n" + "="*60)
    print("🎉 Z3MUTH Onboarding Complete!")
    print("="*60)
    print("""
Quick Start Commands:
  
🎛️  Dashboard Mode:
  ./start_dashboard.sh
  # OR
  python3 z3muth.py --dashboard

🎯 Interactive CLI Mode:
  ./start_cli.sh
  # OR  
  python3 z3muth.py --cli

🚀 Direct Scanning:
  python3 z3muth.py --target example.com --ultimate-scan
  python3 z3muth.py --target example.com --quick-scan
  python3 z3muth.py --target example.com --web-scan

📋 Management:
  python3 z3muth.py --list-scans
  python3 z3muth.py --scan-history

📖 Help:
  python3 z3muth.py --help

Configuration file: z3muth_config.json
Reports directory: z3muth_reports/
""")
    
    print("🔧 Next Steps:")
    print("  1. Configure API keys in z3muth_config.json (optional)")
    print("  2. Add custom wordlists to wordlists/ directory")
    print("  3. Start with a quick scan to test functionality")
    print("  4. Use dashboard mode for real-time monitoring")
    print("\n⚠️  Remember: Only scan targets you own or have permission to test!")

def main():
    """Main onboarding function"""
    print_banner()
    
    print("Welcome to Z3MUTH! This script will help you get started quickly.\n")
    
    # Check all prerequisites
    steps = [
        ("Dependencies", check_dependencies),
        ("System Requirements", check_system_requirements),
        ("Configuration", setup_configuration),
        ("Directories", setup_directories),
        ("Quick Start Scripts", create_quick_start_scripts),
        ("Initial Test", run_initial_test)
    ]
    
    all_passed = True
    for step_name, step_func in steps:
        if not step_func():
            print(f"\n❌ {step_name} step failed!")
            all_passed = False
            break
    
    if all_passed:
        show_getting_started()
    else:
        print("\n❌ Onboarding incomplete. Please fix the issues above and try again.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 Onboarding cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Onboarding error: {e}")
        sys.exit(1)