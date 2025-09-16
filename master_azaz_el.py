#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 .S_SSSs     sdSSSSSSSbs   .S_SSSs     sdSSSSSSSbs    sSSs  S.      
.SS~SSSSS    YSSSSSSSS%S  .SS~SSSSS    YSSSSSSSS%S   d%%SP  SS.     
S%S   SSSS          S%S   S%S   SSSS          S%S   d%S'    S%S     
S%S    S%S         S&S    S%S    S%S         S&S    S%S     S%S     
S%S SSSS%S        S&S     S%S SSSS%S        S&S     S&S     S&S     
S&S  SSS%S        S&S     S&S  SSS%S        S&S     S&S_Ss  S&S     
S&S    S&S       S&S      S&S    S&S       S&S      S&S~SP  S&S     
S&S    S&S      S*S       S&S    S&S      S*S       S&S     S&S     
S*S    S&S     S*S        S*S    S&S     S*S        S*b     S*b     
S*S    S*S   .s*S         S*S    S*S   .s*S         S*S.    S*S.    
S*S    S*S   sY*SSSSSSSP  S*S    S*S   sY*SSSSSSSP   SSSbs   SSSbs  
SSS    S*S  sY*SSSSSSSSP  SSS    S*S  sY*SSSSSSSSP    YSSP    YSSP  
       SP                        SP                                 
       Y                         Y                                  
                                                                      
Azaz-El v6.0.0-MASTER - Unified Professional Security Assessment Framework
Advanced Master TUI with Complete Integration of All Security Tools and Modules
"""

import os
import sys
import asyncio
import argparse
import json
import time
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import shutil
import uuid
import webbrowser
import psutil

# Add project root to path
sys.path.append(str(Path(__file__).parent))

# Import all modules and integrations
try:
    from core.config import ConfigurationManager
    from core.logging import get_logger
    from core.reporting import AdvancedReportGenerator
    from scanners.web_scanner import AdvancedWebScanner
    from scanners.api_scanner import AdvancedAPIScanner
    from scanners.cloud_scanner import CloudSecurityScanner
    from scanners.infrastructure_scanner import InfrastructureScanner
    from moloch_integration import MolochIntegration, EnhancedScanner
    
    # Import moloch core functions
    from moloch import (
        run_subdomain_discovery, run_dns_resolution, run_http_probing,
        run_vulnerability_scan, run_port_scan, run_ssl_scan,
        run_crawling, run_xss_scan, run_directory_fuzzing,
        execute_tool, load_config, new_run, setup_logging,
        filter_and_save_positive_results, generate_simple_report,
        check_and_install_dependencies, initialize_environment
    )
except ImportError as e:
    print(f"Warning: Some modules could not be imported: {e}")
    print("The master tool will run with limited functionality.")

# --- Master Configuration ---
MASTER_APP = "Azaz-El"
MASTER_VERSION = "v6.0.0-MASTER"
MASTER_AUTHOR = "Advanced Security Research Team"

MASTER_BANNER = r"""
 .S_SSSs     sdSSSSSSSbs   .S_SSSs     sdSSSSSSSbs    sSSs  S.      
.SS~SSSSS    YSSSSSSSS%S  .SS~SSSSS    YSSSSSSSS%S   d%%SP  SS.     
S%S   SSSS          S%S   S%S   SSSS          S%S   d%S'    S%S     
S%S    S%S         S&S    S%S    S%S         S&S    S%S     S%S     
S%S SSSS%S        S&S     S%S SSSS%S        S&S     S&S     S&S     
S&S  SSS%S        S&S     S&S  SSS%S        S&S     S&S_Ss  S&S     
S&S    S&S       S&S      S&S    S&S       S&S      S&S~SP  S&S     
S&S    S&S      S*S       S&S    S&S      S*S       S&S     S&S     
S*S    S&S     S*S        S*S    S&S     S*S        S*b     S*b     
S*S    S*S   .s*S         S*S    S*S   .s*S         S*S.    S*S.    
S*S    S*S   sY*SSSSSSSP  S*S    S*S   sY*SSSSSSSP   SSSbs   SSSbs  
SSS    S*S  sY*SSSSSSSSP  SSS    S*S  sY*SSSSSSSSP    YSSP    YSSP  
       SP                        SP                                 
       Y                         Y                                  
                                                                      
"""

class MasterAzazElFramework:
    """
    Unified Master Security Assessment Framework
    Advanced Professional TUI with Complete Integration
    """
    
    def __init__(self) -> None:
        """Initialize the master unified framework"""
        self.version = MASTER_VERSION
        self.app_name = MASTER_APP
        self.author = MASTER_AUTHOR
        
        # Initialize logging
        self.setup_master_logging()
        self.logger = logging.getLogger("master-azaz-el")
        
        # Initialize configuration management
        try:
            self.config_manager = ConfigurationManager(Path("moloch.cfg.json"))
            self.config = self.config_manager.load_config()
        except:
            self.config = load_config()
            self.config_manager = None
        
        # Initialize integrations
        self.initialize_integrations()
        
        # Master dashboard state
        self.active_scans = {}
        self.scan_history = []
        self.system_status = {
            "scanners": {},
            "tools": {},
            "resources": {},
            "health": "Unknown"
        }
        
        # Performance monitoring
        self.performance_metrics = {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0,
            "network_status": "Unknown"
        }
        
        # Initialize master framework
        self.initialize_master_framework()
    
    def setup_master_logging(self) -> None:
        """Setup enhanced logging for master framework"""
        try:
            setup_logging()
        except:
            # Fallback logging setup
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
    
    def initialize_integrations(self) -> None:
        """Initialize all framework integrations"""
        self.logger.info("Initializing Master Framework Integrations")
        
        try:
            # Initialize moloch integration
            self.moloch_integration = MolochIntegration(self.config_manager)
            self.enhanced_scanner = EnhancedScanner(self.config_manager)
            
            # Initialize advanced scanners
            self.web_scanner = AdvancedWebScanner(self.config)
            self.api_scanner = AdvancedAPIScanner(self.config)
            self.cloud_scanner = CloudSecurityScanner(self.config)
            self.infrastructure_scanner = InfrastructureScanner(self.config)
            
            # Initialize reporting
            self.report_generator = AdvancedReportGenerator(self.config)
            
            self.integrations_available = True
            self.logger.info("All integrations initialized successfully")
            
        except Exception as e:
            self.logger.warning(f"Some integrations failed to initialize: {e}")
            self.integrations_available = False
    
    def initialize_master_framework(self) -> None:
        """Initialize the master framework environment"""
        self.logger.info("Initializing Master Azaz-El Framework")
        
        # Initialize targets
        self.targets = set()
        self.load_targets()
        
        # Update system status
        self.update_system_status()
        
        # Setup directories
        self.base_dir = Path("runs")
        self.base_dir.mkdir(exist_ok=True)
        
        # Initialize environment if needed (skip tool installation for now)
        try:
            # Skip automatic tool installation to prevent prompts
            pass
        except:
            self.logger.warning("Environment initialization had issues, continuing...")
        
        self.logger.info("Master framework initialization complete")
        
    def load_targets(self) -> None:
        """Load targets from targets.txt file"""
        try:
            targets_file = Path("targets.txt")
            if targets_file.exists():
                with open(targets_file, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                    self.targets = set(targets)
                    self.logger.info(f"Loaded {len(self.targets)} targets")
            else:
                self.targets = set()
                self.logger.info("No targets file found, starting with empty target list")
        except Exception as e:
            self.logger.warning(f"Error loading targets: {e}")
            self.targets = set()
    
    def update_system_status(self) -> None:
        """Update comprehensive system status"""
        try:
            # Check scanner availability
            if self.integrations_available:
                scanners = {
                    "web_scanner": self.web_scanner,
                    "api_scanner": self.api_scanner,
                    "cloud_scanner": self.cloud_scanner,
                    "infrastructure_scanner": self.infrastructure_scanner,
                    "moloch_integration": self.moloch_integration,
                    "enhanced_scanner": self.enhanced_scanner
                }
                
                for name, scanner in scanners.items():
                    if scanner:
                        self.system_status["scanners"][name] = "✅ Available"
                    else:
                        self.system_status["scanners"][name] = "❌ Not Available"
            
            # Update performance metrics
            self.performance_metrics["cpu_usage"] = psutil.cpu_percent()
            self.performance_metrics["memory_usage"] = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/')
            self.performance_metrics["disk_usage"] = (disk.used / disk.total) * 100
            
            # Check tools availability
            essential_tools = [
                "subfinder", "nuclei", "httpx", "ffuf", "nmap", 
                "katana", "dalfox", "gobuster", "naabu", "dnsx"
            ]
            
            for tool in essential_tools:
                if shutil.which(tool):
                    self.system_status["tools"][tool] = "✅ Available"
                else:
                    self.system_status["tools"][tool] = "❌ Not Installed"
            
            # Overall health assessment
            available_tools = sum(1 for status in self.system_status["tools"].values() if "Available" in status)
            total_tools = len(self.system_status["tools"])
            
            if available_tools >= total_tools * 0.8:
                self.system_status["health"] = "Excellent"
            elif available_tools >= total_tools * 0.6:
                self.system_status["health"] = "Good"
            elif available_tools >= total_tools * 0.4:
                self.system_status["health"] = "Fair"
            else:
                self.system_status["health"] = "Poor"
                
        except Exception as e:
            self.logger.error(f"Error updating system status: {e}")
            self.system_status["health"] = "Error"
    
    def print_master_banner(self) -> None:
        """Print the enhanced master banner with comprehensive status"""
        # Clear screen for better presentation
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Print the main banner with gradient colors
        print(f"\033[1;36m{MASTER_BANNER}\033[0m")
        
        # Enhanced master title section
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print(f"║\033[1;91m                🔱 {MASTER_APP} {MASTER_VERSION} MASTER FRAMEWORK 🔱\033[0m                 ║")
        print("║\033[1;92m        Unified Professional Security Assessment & Penetration Testing\033[0m        ║")
        print("╠═══════════════════════════════════════════════════════════════════════════════╣")
        print(f"║  Author: \033[1;97m{MASTER_AUTHOR}\033[0m  │  Health: \033[1;{'92m' if self.system_status['health'] == 'Excellent' else '93m' if self.system_status['health'] == 'Good' else '91m'}{self.system_status['health']}\033[0m     ║")
        print(f"║  Status: \033[1;92mOperational\033[0m                    │  Platform: \033[1;97mMulti-Cloud Ready\033[0m    ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        
        # System performance display
        cpu_color = "92" if self.performance_metrics["cpu_usage"] < 70 else "93" if self.performance_metrics["cpu_usage"] < 90 else "91"
        mem_color = "92" if self.performance_metrics["memory_usage"] < 70 else "93" if self.performance_metrics["memory_usage"] < 90 else "91"
        
        print(f"⏰ Session: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} │ "
              f"CPU: \033[1;{cpu_color}m{self.performance_metrics['cpu_usage']:.1f}%\033[0m │ "
              f"RAM: \033[1;{mem_color}m{self.performance_metrics['memory_usage']:.1f}%\033[0m │ "
              f"Scanners: \033[1;92m{len([s for s in self.system_status['scanners'].values() if 'Available' in s])}\033[0m")
        
        print()  # Add spacing
    
    def display_master_menu(self) -> None:
        """Display the modern TUI interface"""
        self.create_modern_tui_interface()
    
    def create_modern_tui_interface(self) -> None:
        """Create the modern, sophisticated TUI interface"""
        while True:
            try:
                self.clear_screen()
                self.display_modern_header()
                self.display_system_dashboard()
                self.display_navigation_menu()
                
                choice = self.get_user_input()
                if not self.handle_navigation_choice(choice):
                    break
                    
            except KeyboardInterrupt:
                self.show_info("🔄 Returning to main menu...")
                break
            except Exception as e:
                self.show_error(f"TUI Error: {e}")
                self.wait_for_continue()
    
    def clear_screen(self) -> None:
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def display_modern_header(self) -> None:
        """Display the modern header with system information"""
        import datetime
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print("╔" + "═" * 98 + "╗")
        print(f"║ \033[1;91m{MASTER_APP} {MASTER_VERSION}\033[0m - \033[1;96mUnified Security Assessment Framework\033[0m".ljust(120) + f"\033[1;90m{current_time}\033[0m ║")
        print("╠" + "═" * 98 + "╣")
    
    def display_system_dashboard(self) -> None:
        """Display real-time system dashboard"""
        # Update performance metrics
        self.update_performance_metrics()
        
        # System health indicator
        health = self.system_status.get("health", "Unknown")
        health_color = {
            "Excellent": "\033[1;32m",
            "Good": "\033[1;33m", 
            "Fair": "\033[1;93m",
            "Poor": "\033[1;91m"
        }.get(health, "\033[1;90m")
        
        print(f"║ \033[1;97mSYSTEM DASHBOARD\033[0m".ljust(108) + " ║")
        print("╠" + "─" * 98 + "╣")
        print(f"║  🏥 Health: {health_color}{health}\033[0m" + 
              f"  💾 Memory: \033[1;94m{self.performance_metrics['memory_usage']:.1f}%\033[0m" +
              f"  🖥️  CPU: \033[1;92m{self.performance_metrics['cpu_usage']:.1f}%\033[0m" +
              f"  💽 Disk: \033[1;93m{self.performance_metrics['disk_usage']:.1f}%\033[0m".ljust(80) + " ║")
        
        # Active scans info
        active_count = len(self.active_scans)
        scan_info = f"\033[1;95m{active_count} Active\033[0m" if active_count > 0 else "\033[1;90mNone\033[0m"
        
        # Tools status
        available_tools = len([t for t in self.system_status.get("tools", {}).values() if "Available" in str(t)])
        total_tools = len(self.system_status.get("tools", {}))
        tools_ratio = f"{available_tools}/{total_tools}" if total_tools > 0 else "0/0"
        
        print(f"║  🔄 Scans: {scan_info}" +
              f"  🔧 Tools: \033[1;96m{tools_ratio}\033[0m" +
              f"  📊 History: \033[1;97m{len(self.scan_history)}\033[0m".ljust(80) + " ║")
        print("╠" + "═" * 98 + "╣")
    
    def display_navigation_menu(self) -> None:
        """Display the enhanced navigation menu with visual indicators"""
        print("║ \033[1;97mMAIN NAVIGATION CONTROL CENTER\033[0m".ljust(108) + " ║")
        print("╠" + "─" * 98 + "╣")
        
        # Core functionality
        print("║ \033[1;92m[1]\033[0m 🚀 \033[1;97mFULL AUTOMATION PIPELINE\033[0m - Complete security assessment workflow    ║")
        print("║     └─ Recon → Vuln Scan → Web Testing → Cloud → API → Infrastructure → Report  ║")
        print("╠" + "─" * 98 + "╣")
        
        # Target management
        print("║ \033[1;93m[2]\033[0m 🎯 \033[1;97mTARGET MANAGEMENT HUB\033[0m - Advanced target configuration and validation  ║")
        
        # Scanning modules  
        print("║ \033[1;94m[3]\033[0m 🔍 \033[1;97mRECONNAISSANCE SUITE\033[0m - Intelligence gathering and enumeration        ║")
        print("║ \033[1;95m[4]\033[0m 🛡️  \033[1;97mVULNERABILITY ASSESSMENT\033[0m - Advanced security vulnerability scanning    ║")
        print("║ \033[1;96m[5]\033[0m 🌐 \033[1;97mWEB APPLICATION TESTING\033[0m - Comprehensive web security analysis         ║")
        print("║ \033[1;97m[6]\033[0m ☁️  \033[1;97mCLOUD SECURITY AUDIT\033[0m - Multi-cloud security assessment              ║")
        print("║ \033[1;91m[7]\033[0m 🔌 \033[1;97mAPI SECURITY TESTING\033[0m - RESTful and GraphQL API security analysis    ║")
        print("║ \033[1;92m[8]\033[0m 🏗️  \033[1;97mINFRASTRUCTURE SCANNING\033[0m - Network infrastructure security assessment  ║")
        
        print("╠" + "─" * 98 + "╣")
        
        # System management
        print("║ \033[1;90m[9]\033[0m 🔧 \033[1;97mSYSTEM CONFIGURATION\033[0m - Framework settings and tool management        ║")
        print("║ \033[1;90m[A]\033[0m 📊 \033[1;97mREPORTING & ANALYTICS\033[0m - Advanced reporting and data visualization    ║")
        print("║ \033[1;90m[B]\033[0m 📈 \033[1;97mMONITORING DASHBOARD\033[0m - Real-time system monitoring and metrics      ║")
        print("║ \033[1;90m[C]\033[0m ⚙️  \033[1;97mADVANCED SETTINGS\033[0m - Expert configuration and tool installation    ║")
        
        print("╠" + "─" * 98 + "╣")
        
        # Navigation help
        print("║ \033[1;90m[H]\033[0m ❓ \033[1;97mHELP & DOCUMENTATION\033[0m   \033[1;90m[Q]\033[0m 🚪 \033[1;97mEXIT FRAMEWORK\033[0m                     ║")
        print("╚" + "═" * 98 + "╝")
        
        # Navigation tips
        print("\n\033[1;96m💡 Navigation Tips:\033[0m")
        print("   • Use number keys [1-9] or letters [A-C] for main functions")
        print("   • Press [H] for detailed help and keyboard shortcuts")
        print("   • Press [Ctrl+C] at any time to return to this menu")
        print("   • Use [Q] or [Ctrl+D] to exit the framework")
    
    def get_user_input(self) -> str:
        """Get user input with enhanced prompt"""
        try:
            return input("\n\033[1;97m🎮 Select option: \033[0m").strip().upper()
        except (EOFError, KeyboardInterrupt):
            return "Q"
    
    def handle_navigation_choice(self, choice: str) -> bool:
        """Handle navigation choices with comprehensive routing"""
        if choice in ['Q', 'QUIT', 'EXIT']:
            return False
        elif choice == '1':
            asyncio.run(self.run_full_automation_pipeline())
        elif choice == '2':
            self.target_management_hub()
        elif choice == '3':
            self.reconnaissance_suite_menu()
        elif choice == '4':
            self.vulnerability_scanning_menu() 
        elif choice == '5':
            self.web_application_testing_menu()
        elif choice == '6':
            self.cloud_security_assessment_menu()
        elif choice == '7':
            self.api_security_testing_menu()
        elif choice == '8':
            self.infrastructure_scanning_menu()
        elif choice == '9':
            self.system_configuration_menu()
        elif choice == 'A':
            self.reporting_analytics_menu()
        elif choice == 'B':
            self.system_dashboard_menu()
        elif choice == 'C':
            self.advanced_settings_menu()
        elif choice == 'H':
            self.show_help_documentation()
        else:
            self.show_error("Invalid option selected. Please try again.")
            self.wait_for_continue()
        
        return True
    
    def update_performance_metrics(self) -> None:
        """Update real-time performance metrics"""
        try:
            # CPU usage
            self.performance_metrics["cpu_usage"] = psutil.cpu_percent(interval=0.1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.performance_metrics["memory_usage"] = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            self.performance_metrics["disk_usage"] = disk.percent
            
            # Network status (simplified)
            self.performance_metrics["network_status"] = "Active"
            
        except Exception as e:
            self.logger.debug(f"Error updating performance metrics: {e}")
    
    def target_management_hub(self) -> None:
        """Enhanced target management with validation and bulk operations"""
        self.show_info("🎯 Launching Enhanced Target Management Hub...")
        # For now, delegate to moloch's target management
        try:
            from moloch import target_management_menu
            target_management_menu()
        except Exception as e:
            self.show_error(f"Target management error: {e}")
            self.wait_for_continue()
    
    def advanced_settings_menu(self) -> None:
        """Advanced settings and tool installation menu"""
        self.show_info("⚙️ Launching Advanced Settings Panel...")
        try:
            from moloch import tool_status_menu, settings_menu
            
            while True:
                self.clear_screen()
                print("╔" + "═" * 80 + "╗")
                print("║\033[1;95m                    ⚙️  ADVANCED SETTINGS PANEL ⚙️\033[0m                    ║")
                print("╠" + "═" * 80 + "╣")
                print("║  \033[1;92m1.\033[0m 🔧 \033[1;97mTOOL STATUS & INSTALLATION\033[0m - Manage security tools        ║")
                print("║  \033[1;94m2.\033[0m ⚙️  \033[1;97mFRAMEWORK CONFIGURATION\033[0m - System settings management     ║")
                print("║  \033[1;96m3.\033[0m 🔄 \033[1;97mUPDATE ALL TOOLS\033[0m - Update all installed security tools    ║")
                print("║  \033[1;93m4.\033[0m 🏗️  \033[1;97mSYSTEM DIAGNOSTICS\033[0m - Comprehensive system health check  ║")
                print("║  \033[1;90m5.\033[0m 🔙 \033[1;97mRETURN TO MAIN MENU\033[0m - Back to navigation center         ║")
                print("╚" + "═" * 80 + "╝")
                
                choice = input("\n\033[1;97m🎮 Select option: \033[0m").strip()
                
                if choice == '1':
                    tool_status_menu()
                elif choice == '2':
                    settings_menu()
                elif choice == '3':
                    self.update_all_tools()
                elif choice == '4':
                    self.run_system_diagnostics()
                elif choice == '5':
                    break
                else:
                    self.show_error("Invalid option. Please try again.")
                    
        except Exception as e:
            self.show_error(f"Advanced settings error: {e}")
            self.wait_for_continue()
    
    def update_all_tools(self) -> None:
        """Update all installed security tools"""
        self.show_info("🔄 Updating all security tools...")
        
        # Update Go-based tools
        go_tools = [
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest", 
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "github.com/projectdiscovery/katana/cmd/katana@latest"
        ]
        
        for tool in go_tools:
            try:
                self.show_info(f"Updating {tool.split('/')[-1].split('@')[0]}...")
                subprocess.run(['go', 'install', '-v', tool], check=True, capture_output=True)
            except Exception as e:
                self.show_error(f"Failed to update {tool}: {e}")
        
        # Update nuclei templates
        try:
            self.show_info("Updating Nuclei templates...")
            subprocess.run(['nuclei', '-update-templates'], check=True, capture_output=True)
        except Exception as e:
            self.show_error(f"Failed to update nuclei templates: {e}")
        
        self.show_success("🎉 Tool update process completed!")
        self.wait_for_continue()
    
    def run_system_diagnostics(self) -> None:
        """Run comprehensive system diagnostics"""
        self.show_info("🏗️ Running comprehensive system diagnostics...")
        
        print("\n╔" + "═" * 80 + "╗")
        print("║\033[1;96m                       🏗️  SYSTEM DIAGNOSTICS 🏗️\033[0m                       ║")
        print("╠" + "═" * 80 + "╣")
        
        # System information
        import platform
        print(f"║  OS: \033[1;97m{platform.system()} {platform.release()}\033[0m")
        print(f"║  Python: \033[1;97m{platform.python_version()}\033[0m")
        print(f"║  Architecture: \033[1;97m{platform.machine()}\033[0m")
        
        # Performance metrics
        self.update_performance_metrics()
        print(f"║  CPU Usage: \033[1;92m{self.performance_metrics['cpu_usage']:.1f}%\033[0m")
        print(f"║  Memory Usage: \033[1;94m{self.performance_metrics['memory_usage']:.1f}%\033[0m")
        print(f"║  Disk Usage: \033[1;93m{self.performance_metrics['disk_usage']:.1f}%\033[0m")
        
        # Tool availability
        config = load_config()
        tools_config = config.get("tools", {})
        available = sum(1 for tool in tools_config if which(tool))
        total = len(tools_config)
        
        print(f"║  Tools Available: \033[1;96m{available}/{total}\033[0m ({available/total*100:.1f}%)")
        
        # Framework health
        health_score = (available/total) * 100 if total > 0 else 0
        if health_score >= 90:
            health = "\033[1;32mEXCELLENT\033[0m"
        elif health_score >= 70:
            health = "\033[1;33mGOOD\033[0m"
        elif health_score >= 50:
            health = "\033[1;93mFAIR\033[0m"
        else:
            health = "\033[1;91mPOOR\033[0m"
        
        print(f"║  Overall Health: {health}")
        print("╚" + "═" * 80 + "╝")
        
        self.wait_for_continue()
    
    def show_help_documentation(self) -> None:
        """Display comprehensive help and documentation"""
        self.clear_screen()
        print("╔" + "═" * 80 + "╗")
        print("║\033[1;93m                      ❓ HELP & DOCUMENTATION ❓\033[0m                      ║") 
        print("╠" + "═" * 80 + "╣")
        print("║  \033[1;97mKEYBOARD SHORTCUTS:\033[0m")
        print("║    Ctrl+C     - Return to main menu from any screen")
        print("║    Ctrl+D     - Exit framework")
        print("║    H          - Show this help screen")
        print("║    Q          - Quit/Exit current screen")
        print("║")
        print("║  \033[1;97mMAIN FUNCTIONS:\033[0m")
        print("║    [1] Full Pipeline    - Complete automated security assessment")
        print("║    [2] Target Mgmt      - Add/remove/validate targets")
        print("║    [3] Reconnaissance   - Information gathering")
        print("║    [4] Vulnerability    - Security vulnerability scanning")
        print("║    [5] Web Testing      - Web application security")
        print("║    [6] Cloud Security   - Multi-cloud assessment") 
        print("║    [7] API Testing      - API security analysis")
        print("║    [8] Infrastructure   - Network infrastructure scanning")
        print("║")
        print("║  \033[1;97mSYSTEM MANAGEMENT:\033[0m")
        print("║    [9] Configuration    - Framework settings")
        print("║    [A] Reporting        - Generate reports")
        print("║    [B] Monitoring       - Real-time dashboard")
        print("║    [C] Advanced         - Tool installation & updates")
        print("║")
        print("║  \033[1;97mTIPS:\033[0m")
        print("║    • Ensure targets are added before running scans")
        print("║    • Install missing tools via Advanced Settings")
        print("║    • Monitor system resources during large scans")
        print("║    • Review reports for detailed findings")
        print("╚" + "═" * 80 + "╝")
        
        self.wait_for_continue()
    
    async def run_full_automation_pipeline(self):
        """Execute the complete automated security assessment pipeline"""
        self.print_master_banner()
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;91m                    🔄 FULL AUTOMATION PIPELINE 🔄\033[0m                    ║")
        print("║\033[1;97m              Complete Security Assessment Execution\033[0m              ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        
        try:
            # Get target configuration
            target = input("\n🎯 Enter target domain/IP: ").strip()
            if not target:
                self.show_error("Target is required for pipeline execution")
                return
            
            # Get pipeline options
            print("\n📋 \033[1;97mPipeline Configuration:\033[0m")
            aggressive = input("   Enable aggressive scanning? [y/N]: ").lower() == 'y'
            include_cloud = input("   Include cloud security assessment? [y/N]: ").lower() == 'y'
            include_api = input("   Include API security testing? [y/N]: ").lower() == 'y'
            
            # Display pipeline plan
            print(f"\n🚀 \033[1;92mStarting Full Pipeline for: {target}\033[0m")
            print("📋 \033[1;97mPipeline Phases:\033[0m")
            print("   Phase 1: 🔍 Reconnaissance & Intelligence Gathering")
            print("   Phase 2: 🛡️  Vulnerability Scanning & Assessment")
            print("   Phase 3: 🌐 Web Application Security Testing")
            print("   Phase 4: 💥 Fuzzing & Directory Discovery")
            if include_cloud:
                print("   Phase 5: ☁️  Cloud Security Assessment")
            if include_api:
                print("   Phase 6: 🔌 API Security Testing")
            print("   Final:   📊 Report Generation & Analysis")
            
            input("\n⏳ Press Enter to start pipeline execution...")
            
            # Execute pipeline using moloch integration
            if self.integrations_available and hasattr(self, 'moloch_integration'):
                scan_id = f"master_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                
                self.active_scans[scan_id] = {
                    "target": target,
                    "start_time": datetime.now(),
                    "status": "running",
                    "phase": "initialization",
                    "aggressive": aggressive,
                    "include_cloud": include_cloud,
                    "include_api": include_api
                }
                
                print(f"\n✅ \033[1;92mPipeline initiated with scan ID: {scan_id}\033[0m")
                
                # Execute the full pipeline
                pipeline_results = await self.moloch_integration.execute_full_pipeline(
                    target, aggressive, include_cloud
                )
                
                # Update scan status
                self.active_scans[scan_id]["status"] = pipeline_results.get("status", "completed")
                self.active_scans[scan_id]["end_time"] = datetime.now()
                self.active_scans[scan_id]["results"] = pipeline_results
                
                if pipeline_results.get("status") == "completed":
                    print(f"\n✅ \033[1;92mPipeline execution completed successfully!\033[0m")
                    print(f"📊 Run ID: {pipeline_results.get('run_id', scan_id)}")
                    print(f"📁 Results directory: runs/{pipeline_results.get('run_id', scan_id)}")
                    
                    # Offer to generate report
                    if input("\n📋 Generate comprehensive report? [Y/n]: ").lower() != 'n':
                        await self.generate_pipeline_report(scan_id)
                        
                else:
                    print(f"\n❌ \033[1;91mPipeline execution failed\033[0m")
                    if "error" in pipeline_results:
                        print(f"Error: {pipeline_results['error']}")
                
                # Move to history
                self.scan_history.append(self.active_scans.pop(scan_id))
                
            else:
                print("❌ \033[1;91mMoloch integration not available. Please check system configuration.\033[0m")
                
        except Exception as e:
            self.logger.error(f"Pipeline execution error: {e}")
            print(f"\n❌ \033[1;91mPipeline execution failed: {e}\033[0m")
        
        self.wait_for_continue()
    
    def target_management_menu(self):
        """Target management interface"""
        while True:
            self.print_master_banner()
            print("╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;93m                        🎯 TARGET MANAGEMENT 🎯\033[0m                        ║")
            print("║\033[1;97m                   Configure & Manage Scan Targets\033[0m                   ║")
            print("╠═══════════════════════════════════════════════════════════════════════════════╣")
            print("║  1. 📝 Add Single Target                2. 📄 Import Target List           ║")
            print("║  3. 📋 View Current Targets             4. 🗑️  Remove Targets              ║")
            print("║  5. ✅ Validate Targets                 6. 📊 Target Analysis Summary      ║")
            print("║  7. 💾 Export Target List               8. 🔄 Bulk Target Operations      ║")
            print("║  0. ⬅️  Back to Main Menu                                                  ║")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            
            choice = input("\n🎯 Select target operation [1-8, 0]: ").strip()
            
            if choice == "0":
                break
            elif choice == "1":
                self.add_single_target()
            elif choice == "2":
                self.import_target_list()
            elif choice == "3":
                self.view_current_targets()
            elif choice == "4":
                self.remove_targets()
            elif choice == "5":
                self.validate_targets()
            elif choice == "6":
                self.target_analysis_summary()
            elif choice == "7":
                self.export_target_list()
            elif choice == "8":
                self.bulk_target_operations()
            else:
                self.show_error(f"Invalid option: {choice}")
    
    def show_error(self, message: str) -> None:
        """Display error message with formatting"""
        print(f"\n❌ \033[1;91mError:\033[0m {message}")
        self.wait_for_continue()
    
    def show_success(self, message: str) -> None:
        """Display success message with formatting"""
        print(f"\n✅ \033[1;92mSuccess:\033[0m {message}")
    
    def show_info(self, message: str) -> None:
        """Display info message with formatting"""
        print(f"\n💡 \033[1;94mInfo:\033[0m {message}")
    
    def wait_for_continue(self) -> None:
        """Wait for user input to continue"""
        input("\n⏳ Press Enter to continue...")
    
    def exit_framework(self):
        """Exit the master framework gracefully"""
        self.print_master_banner()
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;91m                        🚪 EXITING FRAMEWORK 🚪\033[0m                        ║")
        print("║\033[1;97m                     Thank you for using Azaz-El\033[0m                     ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        
        # Save active scans to history
        if self.active_scans:
            print(f"\n💾 Saving {len(self.active_scans)} active scan(s) to history...")
            self.scan_history.extend(self.active_scans.values())
            self.active_scans.clear()
        
        # Show session summary
        print(f"\n📊 \033[1;97mSession Summary:\033[0m")
        print(f"   • Total scans performed: {len(self.scan_history)}")
        print(f"   • Framework health: {self.system_status['health']}")
        print(f"   • Session duration: {datetime.now().strftime('%H:%M:%S')}")
        
        print(f"\n🙏 \033[1;97mThank you for using {MASTER_APP} {MASTER_VERSION}!\033[0m")
        print(f"   Visit us at: \033[1;94mhttps://github.com/cxb3rf1lth/Azaz-El\033[0m")
        
        # Graceful shutdown
        try:
            # Clean up any background processes
            pass
        except:
            pass
        
        print("\n👋 \033[1;92mGoodbye!\033[0m")
        sys.exit(0)
    
    # Placeholder methods for menu implementations
    def reconnaissance_suite_menu(self):
        """Reconnaissance suite interface"""
        while True:
            self.print_master_banner()
            print("╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;94m                      🔍 RECONNAISSANCE SUITE\033[0m                      ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m1.\033[0m 🌐 Subdomain Discovery (subfinder, assetfinder, amass)              ║")
            print("║  \033[1;97m2.\033[0m 🔍 DNS Resolution & Validation                                    ║")
            print("║  \033[1;97m3.\033[0m 🌍 HTTP Service Probing (httpx)                                 ║") 
            print("║  \033[1;97m4.\033[0m ⚡ Full Reconnaissance Pipeline                                  ║")
            print("║  \033[1;97m5.\033[0m 📊 View Recent Reconnaissance Results                           ║")
            print("║  \033[1;97m6.\033[0m ⚙️ Configure Reconnaissance Settings                            ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m0.\033[0m ↩️ Return to Main Menu                                           ║")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            
            choice = self.get_user_input()
            
            if choice == "0":
                break
            elif choice == "1":
                self.handle_subdomain_discovery()
            elif choice == "2":
                self.handle_dns_resolution()
            elif choice == "3":
                self.handle_http_probing()
            elif choice == "4":
                asyncio.run(self.handle_full_reconnaissance())
            elif choice == "5":
                self.view_reconnaissance_results()
            elif choice == "6":
                self.configure_reconnaissance_settings()
            else:
                self.show_error(f"Invalid option: {choice}")
                
    def handle_subdomain_discovery(self):
        """Handle subdomain discovery operations"""
        if not self.targets:
            self.show_error("No targets configured. Please add targets first.")
            return
            
        target = self.select_target_interactive()
        if not target:
            return
            
        try:
            self.show_info(f"Starting subdomain discovery for {target}")
            
            # Create run directory
            run_dir = self.moloch_integration.config['general']['runs_dir']
            run_path = Path(run_dir) / f"recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute subdomain discovery using moloch
            from moloch import run_subdomain_discovery
            success = run_subdomain_discovery(target, run_path / "subdomains", self.moloch_integration.config)
            
            if success:
                self.show_success(f"Subdomain discovery completed for {target}")
                print(f"📁 Results saved to: {run_path / 'subdomains'}")
            else:
                self.show_error("Subdomain discovery failed")
                
        except Exception as e:
            self.show_error(f"Error during subdomain discovery: {e}")
        
        self.wait_for_continue()
        
    def handle_dns_resolution(self):
        """Handle DNS resolution operations"""
        if not self.targets:
            self.show_error("No targets configured. Please add targets first.")
            return
            
        # Look for recent subdomain files
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        subdomain_files = list(runs_dir.glob("*/subdomains/*.txt"))
        
        if not subdomain_files:
            self.show_error("No subdomain files found. Please run subdomain discovery first.")
            return
            
        try:
            # Use most recent subdomain file
            latest_file = max(subdomain_files, key=lambda x: x.stat().st_mtime)
            output_file = latest_file.parent.parent / "resolved_hosts.txt"
            
            self.show_info(f"Resolving subdomains from {latest_file.name}")
            
            from moloch import run_dns_resolution
            success = run_dns_resolution(latest_file, output_file, self.moloch_integration.config)
            
            if success:
                self.show_success("DNS resolution completed")
                print(f"📁 Results saved to: {output_file}")
            else:
                self.show_error("DNS resolution failed")
                
        except Exception as e:
            self.show_error(f"Error during DNS resolution: {e}")
            
        self.wait_for_continue()
        
    def handle_http_probing(self):
        """Handle HTTP service probing"""
        # Look for recent resolved host files
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        resolved_files = list(runs_dir.glob("*/resolved_hosts.txt"))
        
        if not resolved_files:
            self.show_error("No resolved host files found. Please run DNS resolution first.")
            return
            
        try:
            # Use most recent resolved file
            latest_file = max(resolved_files, key=lambda x: x.stat().st_mtime)
            output_file = latest_file.parent / "live_hosts.txt"
            
            self.show_info(f"Probing HTTP services from {latest_file.name}")
            
            from moloch import run_http_probing
            success = run_http_probing(latest_file, output_file, self.moloch_integration.config)
            
            if success:
                self.show_success("HTTP probing completed")
                print(f"📁 Results saved to: {output_file}")
                
                # Show quick stats
                if output_file.exists():
                    with open(output_file, 'r') as f:
                        live_count = len([line.strip() for line in f if line.strip()])
                    print(f"🌍 Found {live_count} live HTTP services")
            else:
                self.show_error("HTTP probing failed")
                
        except Exception as e:
            self.show_error(f"Error during HTTP probing: {e}")
            
        self.wait_for_continue()
        
    async def handle_full_reconnaissance(self):
        """Handle full reconnaissance pipeline"""
        if not self.targets:
            self.show_error("No targets configured. Please add targets first.")
            return
            
        target = self.select_target_interactive()
        if not target:
            return
            
        try:
            self.show_info(f"Starting full reconnaissance pipeline for {target}")
            print("🔄 This will run: Subdomain Discovery → DNS Resolution → HTTP Probing")
            
            confirm = input("\n⚠️ Continue with full reconnaissance? (y/N): ")
            if confirm.lower() != 'y':
                return
                
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"full_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute full reconnaissance using moloch integration
            results = await self.moloch_integration.run_reconnaissance_suite(
                target, run_path, aggressive=False
            )
            
            if results and not results.get('errors'):
                self.show_success(f"Full reconnaissance completed for {target}")
                print(f"📁 Results saved to: {run_path}")
                print(f"🌐 Found {len(results.get('subdomains', []))} subdomains")
                print(f"🌍 Found {len(results.get('live_hosts', []))} live hosts")
            else:
                self.show_error("Reconnaissance pipeline failed")
                if results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during reconnaissance pipeline: {e}")
            
        self.wait_for_continue()
        
    def view_reconnaissance_results(self):
        """View recent reconnaissance results"""
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        
        # Find recent reconnaissance runs
        recon_dirs = [d for d in runs_dir.iterdir() if d.is_dir() and 
                     ('recon_' in d.name or 'full_recon_' in d.name)]
        recon_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not recon_dirs:
            self.show_info("No reconnaissance results found")
            self.wait_for_continue()
            return
            
        print("\n📊 \033[1;97mRecent Reconnaissance Results:\033[0m")
        print("=" * 60)
        
        for i, run_dir in enumerate(recon_dirs[:10], 1):
            print(f"\n{i}. 📁 {run_dir.name}")
            
            # Check for subdomain files
            subdomain_dir = run_dir / "subdomains"
            if subdomain_dir.exists():
                subdomain_files = list(subdomain_dir.glob("*.txt"))
                total_subdomains = 0
                for file in subdomain_files:
                    with open(file, 'r') as f:
                        total_subdomains += len([line.strip() for line in f if line.strip()])
                print(f"   🌐 Subdomains: {total_subdomains}")
            
            # Check for resolved hosts
            resolved_file = run_dir / "resolved_hosts.txt"
            if resolved_file.exists():
                with open(resolved_file, 'r') as f:
                    resolved_count = len([line.strip() for line in f if line.strip()])
                print(f"   🔍 Resolved: {resolved_count}")
            
            # Check for live hosts
            live_file = run_dir / "live_hosts.txt"
            if live_file.exists():
                with open(live_file, 'r') as f:
                    live_count = len([line.strip() for line in f if line.strip()])
                print(f"   🌍 Live: {live_count}")
                    
        self.wait_for_continue()
        
    def configure_reconnaissance_settings(self):
        """Configure reconnaissance settings"""
        print("\n⚙️ \033[1;97mReconnaissance Configuration:\033[0m")
        print("=" * 50)
        
        config = self.moloch_integration.config
        recon_config = config.get('reconnaissance', {})
        
        print(f"📊 Current Settings:")
        print(f"   • Subdomain Tools: {', '.join(recon_config.get('subdomain_tools', ['subfinder']))}")
        print(f"   • DNS Resolver: {recon_config.get('dns_resolver', 'system')}")
        print(f"   • HTTP Timeout: {recon_config.get('http_timeout', 10)}s")
        print(f"   • Threads: {recon_config.get('threads', 20)}")
        print(f"   • Aggressive Mode: {recon_config.get('aggressive_mode', False)}")
        
        print(f"\n💡 Use moloch.cfg.json to modify these settings")
        self.wait_for_continue()
        
    def select_target_interactive(self):
        """Interactive target selection"""
        if len(self.targets) == 1:
            return list(self.targets)[0]
            
        print(f"\n🎯 \033[1;97mSelect Target:\033[0m")
        targets_list = list(self.targets)
        for i, target in enumerate(targets_list, 1):
            print(f"  {i}. {target}")
            
        try:
            choice = input(f"\nSelect target (1-{len(targets_list)}): ")
            index = int(choice) - 1
            if 0 <= index < len(targets_list):
                return targets_list[index]
        except (ValueError, IndexError):
            pass
            
        self.show_error("Invalid target selection")
        return None
    
    def vulnerability_scanning_menu(self):
        """Vulnerability scanning interface"""
        while True:
            self.print_master_banner()
            print("╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;95m                      🛡️ VULNERABILITY SCANNING\033[0m                      ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m1.\033[0m ⚡ Nuclei Templates (5000+ vulnerability checks)               ║")
            print("║  \033[1;97m2.\033[0m 🔌 Port Scanning (Nmap/Naabu)                                ║")
            print("║  \033[1;97m3.\033[0m 🔒 SSL/TLS Security Analysis (testssl.sh)                    ║")
            print("║  \033[1;97m4.\033[0m 💥 Full Vulnerability Assessment                             ║")
            print("║  \033[1;97m5.\033[0m 📊 View Vulnerability Results                               ║")
            print("║  \033[1;97m6.\033[0m ⚙️ Configure Vulnerability Scans                            ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m0.\033[0m ↩️ Return to Main Menu                                           ║")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            
            choice = self.get_user_input()
            
            if choice == "0":
                break
            elif choice == "1":
                self.handle_nuclei_scan()
            elif choice == "2":
                self.handle_port_scan()
            elif choice == "3":
                self.handle_ssl_scan()
            elif choice == "4":
                asyncio.run(self.handle_full_vulnerability_assessment())
            elif choice == "5":
                self.view_vulnerability_results()
            elif choice == "6":
                self.configure_vulnerability_settings()
            else:
                self.show_error(f"Invalid option: {choice}")
                
    def handle_nuclei_scan(self):
        """Handle Nuclei vulnerability scanning"""
        # Look for live hosts from reconnaissance
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        live_files = list(runs_dir.glob("*/live_hosts.txt"))
        
        if not live_files:
            self.show_error("No live hosts found. Please run reconnaissance first.")
            return
            
        try:
            # Use most recent live hosts file
            latest_file = max(live_files, key=lambda x: x.stat().st_mtime)
            
            # Create run directory
            run_path = Path(self.moloch_integration.config['general']['runs_dir'])
            vuln_dir = run_path / f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            vuln_dir.mkdir(parents=True, exist_ok=True)
            
            self.show_info(f"Starting Nuclei scan on hosts from {latest_file.name}")
            
            from moloch import run_vulnerability_scan
            success = run_vulnerability_scan(latest_file, vuln_dir, self.moloch_integration.config)
            
            if success:
                self.show_success("Nuclei vulnerability scan completed")
                print(f"📁 Results saved to: {vuln_dir}")
                
                # Show quick stats
                results_file = vuln_dir / "nuclei_results.json"
                if results_file.exists():
                    with open(results_file, 'r') as f:
                        try:
                            results = [json.loads(line) for line in f if line.strip()]
                            print(f"🔍 Found {len(results)} vulnerabilities")
                        except:
                            print("🔍 Scan completed, check results file")
            else:
                self.show_error("Nuclei scan failed")
                
        except Exception as e:
            self.show_error(f"Error during Nuclei scan: {e}")
            
        self.wait_for_continue()
        
    def handle_port_scan(self):
        """Handle port scanning"""
        if not self.targets:
            self.show_error("No targets configured. Please add targets first.")
            return
            
        target = self.select_target_interactive()
        if not target:
            return
            
        try:
            # Create run directory
            run_path = Path(self.moloch_integration.config['general']['runs_dir'])
            port_dir = run_path / f"port_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            port_dir.mkdir(parents=True, exist_ok=True)
            
            self.show_info(f"Starting port scan for {target}")
            
            from moloch import run_port_scan
            success = run_port_scan(target, port_dir, self.moloch_integration.config)
            
            if success:
                self.show_success(f"Port scan completed for {target}")
                print(f"📁 Results saved to: {port_dir}")
            else:
                self.show_error("Port scan failed")
                
        except Exception as e:
            self.show_error(f"Error during port scan: {e}")
            
        self.wait_for_continue()
        
    def handle_ssl_scan(self):
        """Handle SSL/TLS security analysis"""
        # Look for live HTTPS hosts
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        live_files = list(runs_dir.glob("*/live_hosts.txt"))
        
        if not live_files:
            self.show_error("No live hosts found. Please run reconnaissance first.")
            return
            
        try:
            # Use most recent live hosts file
            latest_file = max(live_files, key=lambda x: x.stat().st_mtime)
            
            # Filter for HTTPS hosts
            https_hosts = []
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and 'https://' in line.strip():
                        https_hosts.append(line.strip())
            
            if not https_hosts:
                self.show_error("No HTTPS hosts found in live hosts file")
                return
            
            # Create run directory
            run_path = Path(self.moloch_integration.config['general']['runs_dir'])
            ssl_dir = run_path / f"ssl_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            ssl_dir.mkdir(parents=True, exist_ok=True)
            
            # Create HTTPS hosts file
            https_file = ssl_dir / "https_hosts.txt"
            with open(https_file, 'w') as f:
                f.write('\n'.join(https_hosts))
            
            self.show_info(f"Starting SSL/TLS scan on {len(https_hosts)} HTTPS hosts")
            
            from moloch import run_ssl_scan
            success = run_ssl_scan(https_file, ssl_dir, self.moloch_integration.config)
            
            if success:
                self.show_success("SSL/TLS scan completed")
                print(f"📁 Results saved to: {ssl_dir}")
            else:
                self.show_error("SSL/TLS scan failed")
                
        except Exception as e:
            self.show_error(f"Error during SSL/TLS scan: {e}")
            
        self.wait_for_continue()
        
    async def handle_full_vulnerability_assessment(self):
        """Handle full vulnerability assessment pipeline"""
        if not self.targets:
            self.show_error("No targets configured. Please add targets first.")
            return
            
        target = self.select_target_interactive()
        if not target:
            return
            
        try:
            self.show_info(f"Starting full vulnerability assessment for {target}")
            print("🔄 This will run: Nuclei → Port Scan → SSL/TLS Analysis")
            
            confirm = input("\n⚠️ Continue with full vulnerability assessment? (y/N): ")
            if confirm.lower() != 'y':
                return
                
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"full_vuln_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute vulnerability assessment using moloch integration
            results = await self.moloch_integration.run_vulnerability_suite(
                target, run_path, aggressive=False
            )
            
            if results and not results.get('errors'):
                self.show_success(f"Full vulnerability assessment completed for {target}")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                vuln_count = len(results.get('vulnerabilities', []))
                port_count = len(results.get('open_ports', []))
                ssl_issues = len(results.get('ssl_issues', []))
                
                print(f"🔍 Found {vuln_count} vulnerabilities")
                print(f"🔌 Found {port_count} open ports")
                print(f"🔒 Found {ssl_issues} SSL/TLS issues")
            else:
                self.show_error("Vulnerability assessment failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during vulnerability assessment: {e}")
            
        self.wait_for_continue()
        
    def view_vulnerability_results(self):
        """View recent vulnerability scan results"""
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        
        # Find recent vulnerability scan runs
        vuln_dirs = [d for d in runs_dir.iterdir() if d.is_dir() and 
                    ('vuln_scan_' in d.name or 'port_scan_' in d.name or 'ssl_scan_' in d.name or 'full_vuln_' in d.name)]
        vuln_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not vuln_dirs:
            self.show_info("No vulnerability scan results found")
            self.wait_for_continue()
            return
            
        print("\n📊 \033[1;97mRecent Vulnerability Scan Results:\033[0m")
        print("=" * 60)
        
        for i, run_dir in enumerate(vuln_dirs[:10], 1):
            print(f"\n{i}. 📁 {run_dir.name}")
            
            # Check for nuclei results
            nuclei_file = run_dir / "nuclei_results.json"
            if nuclei_file.exists():
                try:
                    with open(nuclei_file, 'r') as f:
                        results = [json.loads(line) for line in f if line.strip()]
                        severities = {}
                        for result in results:
                            severity = result.get('info', {}).get('severity', 'unknown')
                            severities[severity] = severities.get(severity, 0) + 1
                        
                        total = len(results)
                        print(f"   ⚡ Nuclei: {total} findings")
                        if severities:
                            severity_str = ", ".join([f"{k}: {v}" for k, v in severities.items()])
                            print(f"      ({severity_str})")
                except:
                    print("   ⚡ Nuclei: Results file present")
            
            # Check for port scan results
            nmap_files = list(run_dir.glob("*nmap*"))
            if nmap_files:
                print(f"   🔌 Port scan: {len(nmap_files)} files")
            
            # Check for SSL scan results
            ssl_files = list(run_dir.glob("*ssl*"))
            if ssl_files:
                print(f"   🔒 SSL scan: {len(ssl_files)} files")
                    
        self.wait_for_continue()
        
    def configure_vulnerability_settings(self):
        """Configure vulnerability scanning settings"""
        print("\n⚙️ \033[1;97mVulnerability Scan Configuration:\033[0m")
        print("=" * 50)
        
        config = self.moloch_integration.config
        vuln_config = config.get('vulnerability', {})
        
        print(f"📊 Current Settings:")
        print(f"   • Nuclei Templates: {vuln_config.get('nuclei_templates', 'default')}")
        print(f"   • Port Scan Method: {vuln_config.get('port_scanner', 'nmap')}")
        print(f"   • SSL Scanner: {vuln_config.get('ssl_scanner', 'testssl')}")
        print(f"   • Scan Intensity: {vuln_config.get('intensity', 'normal')}")
        print(f"   • Timeout: {vuln_config.get('timeout', 300)}s")
        
        print(f"\n💡 Use moloch.cfg.json to modify these settings")
        self.wait_for_continue()
    
    def web_application_testing_menu(self):
        """Web application testing interface"""
        while True:
            self.print_master_banner()
            print("╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;96m                    🌐 WEB APPLICATION TESTING\033[0m                      ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m1.\033[0m 🕷️ Web Crawling & Content Discovery (katana)                   ║")
            print("║  \033[1;97m2.\033[0m 💥 XSS Testing (dalfox)                                       ║")
            print("║  \033[1;97m3.\033[0m 📁 Directory & File Fuzzing (ffuf, gobuster)                 ║")
            print("║  \033[1;97m4.\033[0m 🔍 Parameter Discovery (arjun)                               ║")
            print("║  \033[1;97m5.\033[0m 🌐 Full Web Application Assessment                           ║")
            print("║  \033[1;97m6.\033[0m 📊 View Web Testing Results                                  ║")
            print("║  \033[1;97m7.\033[0m ⚙️ Configure Web Testing Settings                            ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m0.\033[0m ↩️ Return to Main Menu                                           ║")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            
            choice = self.get_user_input()
            
            if choice == "0":
                break
            elif choice == "1":
                self.handle_web_crawling()
            elif choice == "2":
                self.handle_xss_testing()
            elif choice == "3":
                self.handle_directory_fuzzing()
            elif choice == "4":
                self.handle_parameter_discovery()
            elif choice == "5":
                asyncio.run(self.handle_full_web_assessment())
            elif choice == "6":
                self.view_web_testing_results()
            elif choice == "7":
                self.configure_web_testing_settings()
            else:
                self.show_error(f"Invalid option: {choice}")
                
    def handle_web_crawling(self):
        """Handle web crawling and content discovery"""
        # Look for live web hosts
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        live_files = list(runs_dir.glob("*/live_hosts.txt"))
        
        if not live_files:
            self.show_error("No live hosts found. Please run reconnaissance first.")
            return
            
        try:
            # Use most recent live hosts file
            latest_file = max(live_files, key=lambda x: x.stat().st_mtime)
            
            # Create run directory
            run_path = Path(self.moloch_integration.config['general']['runs_dir'])
            crawl_dir = run_path / f"web_crawl_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            crawl_dir.mkdir(parents=True, exist_ok=True)
            
            self.show_info(f"Starting web crawling on hosts from {latest_file.name}")
            
            from moloch import run_crawling
            success = run_crawling(latest_file, crawl_dir, self.moloch_integration.config)
            
            if success:
                self.show_success("Web crawling completed")
                print(f"📁 Results saved to: {crawl_dir}")
                
                # Show quick stats
                katana_files = list(crawl_dir.glob("*katana*"))
                if katana_files:
                    print(f"🕷️ Generated {len(katana_files)} crawl result files")
            else:
                self.show_error("Web crawling failed")
                
        except Exception as e:
            self.show_error(f"Error during web crawling: {e}")
            
        self.wait_for_continue()
        
    def handle_xss_testing(self):
        """Handle XSS vulnerability testing"""
        # Look for crawled URLs
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        crawl_dirs = [d for d in runs_dir.iterdir() if d.is_dir() and 'web_crawl_' in d.name]
        
        if not crawl_dirs:
            self.show_error("No crawled URLs found. Please run web crawling first.")
            return
            
        try:
            # Use most recent crawl directory
            latest_crawl = max(crawl_dirs, key=lambda x: x.stat().st_mtime)
            
            # Find katana output files
            katana_files = list(latest_crawl.glob("*katana*"))
            if not katana_files:
                self.show_error("No katana output files found")
                return
            
            # Create run directory
            run_path = Path(self.moloch_integration.config['general']['runs_dir'])
            xss_dir = run_path / f"xss_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            xss_dir.mkdir(parents=True, exist_ok=True)
            
            self.show_info(f"Starting XSS testing on crawled URLs")
            
            from moloch import run_xss_scan
            success = run_xss_scan(katana_files[0], xss_dir, self.moloch_integration.config)
            
            if success:
                self.show_success("XSS testing completed")
                print(f"📁 Results saved to: {xss_dir}")
            else:
                self.show_error("XSS testing failed")
                
        except Exception as e:
            self.show_error(f"Error during XSS testing: {e}")
            
        self.wait_for_continue()
        
    def handle_directory_fuzzing(self):
        """Handle directory and file fuzzing"""
        # Look for live web hosts
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        live_files = list(runs_dir.glob("*/live_hosts.txt"))
        
        if not live_files:
            self.show_error("No live hosts found. Please run reconnaissance first.")
            return
            
        try:
            # Use most recent live hosts file
            latest_file = max(live_files, key=lambda x: x.stat().st_mtime)
            
            # Create run directory
            run_path = Path(self.moloch_integration.config['general']['runs_dir'])
            fuzz_dir = run_path / f"dir_fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            fuzz_dir.mkdir(parents=True, exist_ok=True)
            
            self.show_info(f"Starting directory fuzzing on hosts from {latest_file.name}")
            
            from moloch import run_directory_fuzzing
            success = run_directory_fuzzing(latest_file, fuzz_dir, self.moloch_integration.config)
            
            if success:
                self.show_success("Directory fuzzing completed")
                print(f"📁 Results saved to: {fuzz_dir}")
                
                # Show quick stats
                fuzz_files = list(fuzz_dir.glob("*"))
                if fuzz_files:
                    print(f"📁 Generated {len(fuzz_files)} fuzzing result files")
            else:
                self.show_error("Directory fuzzing failed")
                
        except Exception as e:
            self.show_error(f"Error during directory fuzzing: {e}")
            
        self.wait_for_continue()
        
    def handle_parameter_discovery(self):
        """Handle parameter discovery"""
        # Look for live web hosts
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        live_files = list(runs_dir.glob("*/live_hosts.txt"))
        
        if not live_files:
            self.show_error("No live hosts found. Please run reconnaissance first.")
            return
            
        try:
            # Use most recent live hosts file
            latest_file = max(live_files, key=lambda x: x.stat().st_mtime)
            
            # Create run directory
            run_path = Path(self.moloch_integration.config['general']['runs_dir'])
            param_dir = run_path / f"param_disc_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            param_dir.mkdir(parents=True, exist_ok=True)
            
            self.show_info(f"Starting parameter discovery (arjun) on hosts from {latest_file.name}")
            
            # Use arjun for parameter discovery
            from moloch import execute_tool
            
            # Extract just the base URLs
            with open(latest_file, 'r') as f:
                hosts = [line.strip() for line in f if line.strip()]
            
            if hosts:
                # Run arjun on first few hosts
                target_hosts = hosts[:5]  # Limit to first 5 hosts for demo
                for i, host in enumerate(target_hosts):
                    output_file = param_dir / f"arjun_params_{i}.json"
                    self.show_info(f"Discovering parameters for {host}")
                    
                    # Run arjun (if available)
                    success = execute_tool("arjun", ["-u", host, "-o", str(output_file)], 
                                         output_file=output_file, run_dir=param_dir)
                    
                    if not success:
                        self.show_info(f"Arjun not available or failed for {host}")
                
                self.show_success("Parameter discovery completed")
                print(f"📁 Results saved to: {param_dir}")
            else:
                self.show_error("No valid hosts found")
                
        except Exception as e:
            self.show_error(f"Error during parameter discovery: {e}")
            
        self.wait_for_continue()
        
    async def handle_full_web_assessment(self):
        """Handle full web application assessment"""
        # Look for live web hosts
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        live_files = list(runs_dir.glob("*/live_hosts.txt"))
        
        if not live_files:
            self.show_error("No live hosts found. Please run reconnaissance first.")
            return
            
        try:
            self.show_info("Starting full web application assessment")
            print("🔄 This will run: Crawling → XSS Testing → Directory Fuzzing")
            
            confirm = input("\n⚠️ Continue with full web assessment? (y/N): ")
            if confirm.lower() != 'y':
                return
                
            # Use most recent live hosts file
            latest_file = max(live_files, key=lambda x: x.stat().st_mtime)
            
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"full_web_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute web testing suite using moloch integration
            results = await self.moloch_integration.run_web_testing_suite(
                str(latest_file), run_path, aggressive=False
            )
            
            if results and not results.get('errors'):
                self.show_success("Full web assessment completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                crawled_urls = len(results.get('crawled_urls', []))
                xss_findings = len(results.get('xss_findings', []))
                directories = len(results.get('directories', []))
                
                print(f"🕷️ Crawled {crawled_urls} URLs")
                print(f"💥 Found {xss_findings} XSS vulnerabilities")
                print(f"📁 Discovered {directories} directories")
            else:
                self.show_error("Web assessment failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during web assessment: {e}")
            
        self.wait_for_continue()
        
    def view_web_testing_results(self):
        """View recent web testing results"""
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        
        # Find recent web testing runs
        web_dirs = [d for d in runs_dir.iterdir() if d.is_dir() and 
                   any(x in d.name for x in ['web_crawl_', 'xss_scan_', 'dir_fuzz_', 'param_disc_', 'full_web_'])]
        web_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not web_dirs:
            self.show_info("No web testing results found")
            self.wait_for_continue()
            return
            
        print("\n📊 \033[1;97mRecent Web Testing Results:\033[0m")
        print("=" * 60)
        
        for i, run_dir in enumerate(web_dirs[:10], 1):
            print(f"\n{i}. 📁 {run_dir.name}")
            
            # Check for different types of results
            if 'web_crawl_' in run_dir.name:
                katana_files = list(run_dir.glob("*katana*"))
                print(f"   🕷️ Crawling: {len(katana_files)} result files")
            elif 'xss_scan_' in run_dir.name:
                dalfox_files = list(run_dir.glob("*dalfox*"))
                print(f"   💥 XSS: {len(dalfox_files)} result files")
            elif 'dir_fuzz_' in run_dir.name:
                fuzz_files = list(run_dir.glob("*"))
                print(f"   📁 Directory Fuzzing: {len(fuzz_files)} files")
            elif 'param_disc_' in run_dir.name:
                param_files = list(run_dir.glob("*arjun*"))
                print(f"   🔍 Parameter Discovery: {len(param_files)} files")
            elif 'full_web_' in run_dir.name:
                all_files = list(run_dir.glob("*"))
                print(f"   🌐 Full Assessment: {len(all_files)} files")
                    
        self.wait_for_continue()
        
    def configure_web_testing_settings(self):
        """Configure web testing settings"""
        print("\n⚙️ \033[1;97mWeb Testing Configuration:\033[0m")
        print("=" * 50)
        
        config = self.moloch_integration.config
        web_config = config.get('web_testing', {})
        
        print(f"📊 Current Settings:")
        print(f"   • Crawler: {web_config.get('crawler', 'katana')}")
        print(f"   • XSS Scanner: {web_config.get('xss_scanner', 'dalfox')}")
        print(f"   • Directory Fuzzer: {web_config.get('dir_fuzzer', 'ffuf')}")
        print(f"   • Parameter Discovery: {web_config.get('param_discovery', 'arjun')}")
        print(f"   • Crawl Depth: {web_config.get('crawl_depth', 3)}")
        print(f"   • Request Timeout: {web_config.get('timeout', 30)}s")
        
        print(f"\n💡 Use moloch.cfg.json to modify these settings")
        self.wait_for_continue()
    
    def cloud_security_assessment_menu(self):
        """Cloud security assessment interface"""
        while True:
            self.print_master_banner()
            print("╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;93m                    ☁️ CLOUD SECURITY ASSESSMENT\033[0m                     ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m1.\033[0m ☁️ AWS Security Assessment                                     ║")
            print("║  \033[1;97m2.\033[0m 🔵 Azure Security Assessment                                   ║")
            print("║  \033[1;97m3.\033[0m 🌐 GCP Security Assessment                                     ║")
            print("║  \033[1;97m4.\033[0m 🪣 S3 Bucket Enumeration & Analysis                           ║")
            print("║  \033[1;97m5.\033[0m 🔐 Cloud IAM Policy Analysis                                  ║")
            print("║  \033[1;97m6.\033[0m 📊 View Cloud Security Results                               ║")
            print("║  \033[1;97m7.\033[0m ⚙️ Configure Cloud Security Settings                         ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m0.\033[0m ↩️ Return to Main Menu                                           ║")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            
            choice = self.get_user_input()
            
            if choice == "0":
                break
            elif choice == "1":
                asyncio.run(self.handle_aws_assessment())
            elif choice == "2":
                asyncio.run(self.handle_azure_assessment())
            elif choice == "3":
                asyncio.run(self.handle_gcp_assessment())
            elif choice == "4":
                asyncio.run(self.handle_s3_bucket_enum())
            elif choice == "5":
                asyncio.run(self.handle_iam_analysis())
            elif choice == "6":
                self.view_cloud_security_results()
            elif choice == "7":
                self.configure_cloud_security_settings()
            else:
                self.show_error(f"Invalid option: {choice}")
                
    async def handle_aws_assessment(self):
        """Handle AWS security assessment"""
        if not self.integrations_available or not hasattr(self, 'cloud_scanner'):
            self.show_error("Cloud scanner not available")
            return
            
        try:
            self.show_info("Starting AWS security assessment")
            print("🔄 This will check: IAM, S3, EC2, VPC, CloudTrail, and more")
            
            confirm = input("\n⚠️ Continue with AWS assessment? (requires AWS credentials) (y/N): ")
            if confirm.lower() != 'y':
                return
                
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"aws_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute AWS assessment
            results = await self.cloud_scanner.assess_aws_security(
                output_dir=run_path,
                comprehensive=True
            )
            
            if results and not results.get('errors'):
                self.show_success("AWS security assessment completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                findings = results.get('findings', [])
                high_risk = len([f for f in findings if f.get('severity') == 'high'])
                medium_risk = len([f for f in findings if f.get('severity') == 'medium'])
                
                print(f"🔍 Found {len(findings)} total findings")
                print(f"🚨 High risk: {high_risk}")
                print(f"⚠️ Medium risk: {medium_risk}")
            else:
                self.show_error("AWS assessment failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during AWS assessment: {e}")
            
        self.wait_for_continue()
        
    async def handle_azure_assessment(self):
        """Handle Azure security assessment"""
        if not self.integrations_available or not hasattr(self, 'cloud_scanner'):
            self.show_error("Cloud scanner not available")
            return
            
        try:
            self.show_info("Starting Azure security assessment")
            print("🔄 This will check: Azure AD, Storage, VMs, Key Vault, and more")
            
            confirm = input("\n⚠️ Continue with Azure assessment? (requires Azure credentials) (y/N): ")
            if confirm.lower() != 'y':
                return
                
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"azure_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute Azure assessment
            results = await self.cloud_scanner.assess_azure_security(
                output_dir=run_path,
                comprehensive=True
            )
            
            if results and not results.get('errors'):
                self.show_success("Azure security assessment completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                findings = results.get('findings', [])
                critical = len([f for f in findings if f.get('severity') == 'critical'])
                high_risk = len([f for f in findings if f.get('severity') == 'high'])
                
                print(f"🔍 Found {len(findings)} total findings")
                print(f"💥 Critical: {critical}")
                print(f"🚨 High risk: {high_risk}")
            else:
                self.show_error("Azure assessment failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during Azure assessment: {e}")
            
        self.wait_for_continue()
        
    async def handle_gcp_assessment(self):
        """Handle GCP security assessment"""
        if not self.integrations_available or not hasattr(self, 'cloud_scanner'):
            self.show_error("Cloud scanner not available")
            return
            
        try:
            self.show_info("Starting GCP security assessment")
            print("🔄 This will check: IAM, Storage, Compute, VPC, and more")
            
            confirm = input("\n⚠️ Continue with GCP assessment? (requires GCP credentials) (y/N): ")
            if confirm.lower() != 'y':
                return
                
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"gcp_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute GCP assessment
            results = await self.cloud_scanner.assess_gcp_security(
                output_dir=run_path,
                comprehensive=True
            )
            
            if results and not results.get('errors'):
                self.show_success("GCP security assessment completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                findings = results.get('findings', [])
                print(f"🔍 Found {len(findings)} total findings")
            else:
                self.show_error("GCP assessment failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during GCP assessment: {e}")
            
        self.wait_for_continue()
        
    async def handle_s3_bucket_enum(self):
        """Handle S3 bucket enumeration and analysis"""
        if not self.integrations_available or not hasattr(self, 'cloud_scanner'):
            self.show_error("Cloud scanner not available")
            return
            
        try:
            self.show_info("Starting S3 bucket enumeration")
            
            # Get target domains for bucket enumeration
            if not self.targets:
                domain = input("\n🎯 Enter domain for S3 bucket enumeration: ").strip()
                if not domain:
                    return
            else:
                domain = self.select_target_interactive()
                if not domain:
                    return
            
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"s3_enum_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute S3 enumeration
            results = await self.cloud_scanner.enumerate_s3_buckets(
                domain=domain,
                output_dir=run_path
            )
            
            if results and not results.get('errors'):
                self.show_success("S3 bucket enumeration completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                buckets = results.get('buckets', [])
                public_buckets = results.get('public_buckets', [])
                
                print(f"🪣 Found {len(buckets)} buckets")
                print(f"🚨 Public buckets: {len(public_buckets)}")
                
                if public_buckets:
                    print("\n⚠️ Public buckets found:")
                    for bucket in public_buckets[:5]:  # Show first 5
                        print(f"   • {bucket}")
            else:
                self.show_error("S3 enumeration failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during S3 enumeration: {e}")
            
        self.wait_for_continue()
        
    async def handle_iam_analysis(self):
        """Handle cloud IAM policy analysis"""
        if not self.integrations_available or not hasattr(self, 'cloud_scanner'):
            self.show_error("Cloud scanner not available")
            return
            
        try:
            self.show_info("Starting IAM policy analysis")
            
            # Select cloud provider
            print("\n☁️ Select cloud provider:")
            print("1. AWS")
            print("2. Azure")
            print("3. GCP")
            
            choice = input("\nSelect provider (1-3): ").strip()
            provider_map = {"1": "aws", "2": "azure", "3": "gcp"}
            
            if choice not in provider_map:
                self.show_error("Invalid provider selection")
                return
                
            provider = provider_map[choice]
            
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"iam_analysis_{provider}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute IAM analysis
            results = await self.cloud_scanner.analyze_iam_policies(
                provider=provider,
                output_dir=run_path
            )
            
            if results and not results.get('errors'):
                self.show_success(f"{provider.upper()} IAM analysis completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                policies = results.get('policies', [])
                risky_policies = results.get('risky_policies', [])
                
                print(f"📋 Analyzed {len(policies)} policies")
                print(f"⚠️ Risky policies: {len(risky_policies)}")
            else:
                self.show_error("IAM analysis failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during IAM analysis: {e}")
            
        self.wait_for_continue()
        
    def view_cloud_security_results(self):
        """View recent cloud security results"""
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        
        # Find recent cloud security runs
        cloud_dirs = [d for d in runs_dir.iterdir() if d.is_dir() and 
                     any(x in d.name for x in ['aws_scan_', 'azure_scan_', 'gcp_scan_', 's3_enum_', 'iam_analysis_'])]
        cloud_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not cloud_dirs:
            self.show_info("No cloud security results found")
            self.wait_for_continue()
            return
            
        print("\n📊 \033[1;97mRecent Cloud Security Results:\033[0m")
        print("=" * 60)
        
        for i, run_dir in enumerate(cloud_dirs[:10], 1):
            print(f"\n{i}. 📁 {run_dir.name}")
            
            # Check for different types of results
            if 'aws_scan_' in run_dir.name:
                results_files = list(run_dir.glob("*.json"))
                print(f"   ☁️ AWS Assessment: {len(results_files)} result files")
            elif 'azure_scan_' in run_dir.name:
                results_files = list(run_dir.glob("*.json"))
                print(f"   🔵 Azure Assessment: {len(results_files)} result files")
            elif 'gcp_scan_' in run_dir.name:
                results_files = list(run_dir.glob("*.json"))
                print(f"   🌐 GCP Assessment: {len(results_files)} result files")
            elif 's3_enum_' in run_dir.name:
                bucket_files = list(run_dir.glob("*bucket*"))
                print(f"   🪣 S3 Enumeration: {len(bucket_files)} files")
            elif 'iam_analysis_' in run_dir.name:
                policy_files = list(run_dir.glob("*policy*"))
                print(f"   🔐 IAM Analysis: {len(policy_files)} files")
                    
        self.wait_for_continue()
        
    def configure_cloud_security_settings(self):
        """Configure cloud security settings"""
        print("\n⚙️ \033[1;97mCloud Security Configuration:\033[0m")
        print("=" * 50)
        
        config = self.moloch_integration.config
        cloud_config = config.get('cloud_security', {})
        
        print(f"📊 Current Settings:")
        print(f"   • AWS Profile: {cloud_config.get('aws_profile', 'default')}")
        print(f"   • Azure Subscription: {cloud_config.get('azure_subscription', 'default')}")
        print(f"   • GCP Project: {cloud_config.get('gcp_project', 'default')}")
        print(f"   • S3 Enumeration: {cloud_config.get('s3_enumeration', True)}")
        print(f"   • Comprehensive Scan: {cloud_config.get('comprehensive', False)}")
        print(f"   • Timeout: {cloud_config.get('timeout', 300)}s")
        
        print(f"\n💡 Use moloch.cfg.json to modify these settings")
        print(f"📋 Ensure cloud credentials are properly configured")
        self.wait_for_continue()
    
    def api_security_testing_menu(self):
        """API security testing interface"""
        while True:
            self.print_master_banner()
            print("╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;92m                      🔌 API SECURITY TESTING\033[0m                       ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m1.\033[0m 🔍 REST API Discovery & Testing                                ║")
            print("║  \033[1;97m2.\033[0m 📊 GraphQL API Security Testing                               ║")
            print("║  \033[1;97m3.\033[0m 🧽 SOAP API Security Testing                                  ║")
            print("║  \033[1;97m4.\033[0m 🔐 API Authentication Testing                                ║")
            print("║  \033[1;97m5.\033[0m 📋 API Documentation Analysis                                ║")
            print("║  \033[1;97m6.\033[0m 💥 Full API Security Assessment                              ║")
            print("║  \033[1;97m7.\033[0m 📊 View API Testing Results                                  ║")
            print("║  \033[1;97m8.\033[0m ⚙️ Configure API Testing Settings                            ║")
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;97m0.\033[0m ↩️ Return to Main Menu                                           ║")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            
            choice = self.get_user_input()
            
            if choice == "0":
                break
            elif choice == "1":
                asyncio.run(self.handle_rest_api_testing())
            elif choice == "2":
                asyncio.run(self.handle_graphql_testing())
            elif choice == "3":
                asyncio.run(self.handle_soap_testing())
            elif choice == "4":
                asyncio.run(self.handle_api_auth_testing())
            elif choice == "5":
                asyncio.run(self.handle_api_documentation_analysis())
            elif choice == "6":
                asyncio.run(self.handle_full_api_assessment())
            elif choice == "7":
                self.view_api_testing_results()
            elif choice == "8":
                self.configure_api_testing_settings()
            else:
                self.show_error(f"Invalid option: {choice}")
                
    async def handle_rest_api_testing(self):
        """Handle REST API discovery and testing"""
        if not self.integrations_available or not hasattr(self, 'api_scanner'):
            self.show_error("API scanner not available")
            return
            
        try:
            # Get target URL for API testing
            if not self.targets:
                api_url = input("\n🎯 Enter API base URL (e.g., https://api.example.com): ").strip()
                if not api_url:
                    return
            else:
                print("\n🎯 Select target or enter custom API URL:")
                print("0. Enter custom URL")
                target = self.select_target_interactive()
                if target == "0" or not target:
                    api_url = input("Enter API base URL: ").strip()
                    if not api_url:
                        return
                else:
                    api_url = target
            
            self.show_info(f"Starting REST API testing for {api_url}")
            
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"rest_api_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute REST API testing
            results = await self.api_scanner.test_rest_api(
                base_url=api_url,
                output_dir=run_path,
                comprehensive=True
            )
            
            if results and not results.get('errors'):
                self.show_success("REST API testing completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                endpoints = results.get('endpoints', [])
                vulnerabilities = results.get('vulnerabilities', [])
                
                print(f"🔍 Discovered {len(endpoints)} API endpoints")
                print(f"🚨 Found {len(vulnerabilities)} vulnerabilities")
                
                if vulnerabilities:
                    high_vuln = len([v for v in vulnerabilities if v.get('severity') == 'high'])
                    if high_vuln > 0:
                        print(f"💥 High severity vulnerabilities: {high_vuln}")
            else:
                self.show_error("REST API testing failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during REST API testing: {e}")
            
        self.wait_for_continue()
        
    async def handle_graphql_testing(self):
        """Handle GraphQL API security testing"""
        if not self.integrations_available or not hasattr(self, 'api_scanner'):
            self.show_error("API scanner not available")
            return
            
        try:
            # Get GraphQL endpoint
            graphql_url = input("\n🎯 Enter GraphQL endpoint URL: ").strip()
            if not graphql_url:
                return
                
            self.show_info(f"Starting GraphQL API testing for {graphql_url}")
            
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"graphql_api_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute GraphQL testing
            results = await self.api_scanner.test_graphql_api(
                endpoint_url=graphql_url,
                output_dir=run_path
            )
            
            if results and not results.get('errors'):
                self.show_success("GraphQL API testing completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                queries = results.get('queries', [])
                mutations = results.get('mutations', [])
                vulnerabilities = results.get('vulnerabilities', [])
                
                print(f"📊 Found {len(queries)} queries, {len(mutations)} mutations")
                print(f"🚨 Found {len(vulnerabilities)} vulnerabilities")
            else:
                self.show_error("GraphQL API testing failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during GraphQL testing: {e}")
            
        self.wait_for_continue()
        
    async def handle_soap_testing(self):
        """Handle SOAP API security testing"""
        if not self.integrations_available or not hasattr(self, 'api_scanner'):
            self.show_error("API scanner not available")
            return
            
        try:
            # Get SOAP WSDL URL
            wsdl_url = input("\n🎯 Enter SOAP WSDL URL: ").strip()
            if not wsdl_url:
                return
                
            self.show_info(f"Starting SOAP API testing for {wsdl_url}")
            
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"soap_api_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute SOAP testing
            results = await self.api_scanner.test_soap_api(
                wsdl_url=wsdl_url,
                output_dir=run_path
            )
            
            if results and not results.get('errors'):
                self.show_success("SOAP API testing completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                operations = results.get('operations', [])
                vulnerabilities = results.get('vulnerabilities', [])
                
                print(f"🧽 Found {len(operations)} SOAP operations")
                print(f"🚨 Found {len(vulnerabilities)} vulnerabilities")
            else:
                self.show_error("SOAP API testing failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during SOAP testing: {e}")
            
        self.wait_for_continue()
        
    async def handle_api_auth_testing(self):
        """Handle API authentication testing"""
        if not self.integrations_available or not hasattr(self, 'api_scanner'):
            self.show_error("API scanner not available")
            return
            
        try:
            # Get API endpoint
            api_url = input("\n🎯 Enter API URL for authentication testing: ").strip()
            if not api_url:
                return
                
            self.show_info(f"Starting API authentication testing for {api_url}")
            
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"api_auth_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute API authentication testing
            results = await self.api_scanner.test_api_authentication(
                api_url=api_url,
                output_dir=run_path
            )
            
            if results and not results.get('errors'):
                self.show_success("API authentication testing completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                auth_methods = results.get('auth_methods', [])
                weaknesses = results.get('auth_weaknesses', [])
                
                print(f"🔐 Detected {len(auth_methods)} authentication methods")
                print(f"⚠️ Found {len(weaknesses)} authentication weaknesses")
            else:
                self.show_error("API authentication testing failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during API authentication testing: {e}")
            
        self.wait_for_continue()
        
    async def handle_api_documentation_analysis(self):
        """Handle API documentation analysis"""
        if not self.integrations_available or not hasattr(self, 'api_scanner'):
            self.show_error("API scanner not available")
            return
            
        try:
            print("\n📋 API Documentation Analysis Options:")
            print("1. OpenAPI/Swagger documentation")
            print("2. RAML documentation") 
            print("3. API Blueprint documentation")
            
            choice = input("\nSelect documentation type (1-3): ").strip()
            
            if choice == "1":
                doc_url = input("Enter OpenAPI/Swagger URL: ").strip()
                doc_type = "openapi"
            elif choice == "2":
                doc_url = input("Enter RAML URL: ").strip()
                doc_type = "raml"
            elif choice == "3":
                doc_url = input("Enter API Blueprint URL: ").strip()
                doc_type = "blueprint"
            else:
                self.show_error("Invalid documentation type")
                return
                
            if not doc_url:
                return
                
            self.show_info(f"Starting {doc_type.upper()} documentation analysis")
            
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"api_docs_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute documentation analysis
            results = await self.api_scanner.analyze_api_documentation(
                doc_url=doc_url,
                doc_type=doc_type,
                output_dir=run_path
            )
            
            if results and not results.get('errors'):
                self.show_success("API documentation analysis completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show summary
                endpoints = results.get('endpoints', [])
                security_issues = results.get('security_issues', [])
                
                print(f"📋 Analyzed {len(endpoints)} documented endpoints")
                print(f"⚠️ Found {len(security_issues)} security issues in documentation")
            else:
                self.show_error("API documentation analysis failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during API documentation analysis: {e}")
            
        self.wait_for_continue()
        
    async def handle_full_api_assessment(self):
        """Handle full API security assessment"""
        if not self.integrations_available or not hasattr(self, 'api_scanner'):
            self.show_error("API scanner not available")
            return
            
        try:
            # Get API URL
            api_url = input("\n🎯 Enter API base URL for full assessment: ").strip()
            if not api_url:
                return
                
            self.show_info(f"Starting full API security assessment for {api_url}")
            print("🔄 This will run: Discovery → Testing → Authentication → Documentation Analysis")
            
            confirm = input("\n⚠️ Continue with full API assessment? (y/N): ")
            if confirm.lower() != 'y':
                return
                
            # Create run directory
            run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
            run_path = run_dir / f"full_api_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_path.mkdir(parents=True, exist_ok=True)
            
            # Execute full API assessment
            results = await self.api_scanner.full_api_assessment(
                api_url=api_url,
                output_dir=run_path
            )
            
            if results and not results.get('errors'):
                self.show_success("Full API security assessment completed")
                print(f"📁 Results saved to: {run_path}")
                
                # Show comprehensive summary
                endpoints = results.get('endpoints', [])
                vulnerabilities = results.get('vulnerabilities', [])
                auth_issues = results.get('auth_issues', [])
                
                print(f"🔍 Discovered {len(endpoints)} API endpoints")
                print(f"🚨 Found {len(vulnerabilities)} vulnerabilities")
                print(f"🔐 Found {len(auth_issues)} authentication issues")
                
                # Categorize vulnerabilities by severity
                severity_count = {}
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'unknown')
                    severity_count[severity] = severity_count.get(severity, 0) + 1
                
                if severity_count:
                    print("\n📊 Vulnerability breakdown:")
                    for severity, count in severity_count.items():
                        print(f"   {severity.capitalize()}: {count}")
            else:
                self.show_error("Full API assessment failed")
                if results and results.get('errors'):
                    for error in results['errors']:
                        print(f"   ❌ {error}")
                        
        except Exception as e:
            self.show_error(f"Error during full API assessment: {e}")
            
        self.wait_for_continue()
        
    def view_api_testing_results(self):
        """View recent API testing results"""
        runs_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        
        # Find recent API testing runs
        api_dirs = [d for d in runs_dir.iterdir() if d.is_dir() and 
                   any(x in d.name for x in ['rest_api_', 'graphql_api_', 'soap_api_', 'api_auth_', 'api_docs_', 'full_api_'])]
        api_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not api_dirs:
            self.show_info("No API testing results found")
            self.wait_for_continue()
            return
            
        print("\n📊 \033[1;97mRecent API Testing Results:\033[0m")
        print("=" * 60)
        
        for i, run_dir in enumerate(api_dirs[:10], 1):
            print(f"\n{i}. 📁 {run_dir.name}")
            
            # Check for different types of results
            if 'rest_api_' in run_dir.name:
                result_files = list(run_dir.glob("*.json"))
                print(f"   🔍 REST API Testing: {len(result_files)} result files")
            elif 'graphql_api_' in run_dir.name:
                result_files = list(run_dir.glob("*.json"))
                print(f"   📊 GraphQL Testing: {len(result_files)} result files")
            elif 'soap_api_' in run_dir.name:
                result_files = list(run_dir.glob("*.json"))
                print(f"   🧽 SOAP Testing: {len(result_files)} result files")
            elif 'api_auth_' in run_dir.name:
                auth_files = list(run_dir.glob("*auth*"))
                print(f"   🔐 Auth Testing: {len(auth_files)} result files")
            elif 'api_docs_' in run_dir.name:
                doc_files = list(run_dir.glob("*"))
                print(f"   📋 Documentation Analysis: {len(doc_files)} files")
            elif 'full_api_' in run_dir.name:
                all_files = list(run_dir.glob("*"))
                print(f"   🔌 Full API Assessment: {len(all_files)} files")
                    
        self.wait_for_continue()
        
    def configure_api_testing_settings(self):
        """Configure API testing settings"""
        print("\n⚙️ \033[1;97mAPI Testing Configuration:\033[0m")
        print("=" * 50)
        
        config = self.moloch_integration.config
        api_config = config.get('api_testing', {})
        
        print(f"📊 Current Settings:")
        print(f"   • Request Timeout: {api_config.get('request_timeout', 30)}s")
        print(f"   • Rate Limiting: {api_config.get('rate_limit', 10)} req/sec")
        print(f"   • Authentication Methods: {', '.join(api_config.get('auth_methods', ['bearer', 'basic', 'oauth']))}")
        print(f"   • Payload Fuzzing: {api_config.get('payload_fuzzing', True)}")
        print(f"   • Schema Validation: {api_config.get('schema_validation', True)}")
        print(f"   • Deep Testing: {api_config.get('deep_testing', False)}")
        
        print(f"\n💡 Use moloch.cfg.json to modify these settings")
        self.wait_for_continue()
    
    def infrastructure_scanning_menu(self):
        """Infrastructure scanning interface - placeholder"""
        self.show_info("Infrastructure Scanning interface will be implemented in the full version")
        self.wait_for_continue()
    
    def fuzzing_discovery_menu(self):
        """Fuzzing and discovery interface - placeholder"""
        self.show_info("Fuzzing & Discovery interface will be implemented in the full version")
        self.wait_for_continue()
    
    def system_configuration_menu(self):
        """System configuration interface - placeholder"""
        self.show_info("System Configuration interface will be implemented in the full version")
        self.wait_for_continue()
    
    def reporting_analytics_menu(self):
        """Reporting and analytics interface - placeholder"""
        self.show_info("Reporting & Analytics interface will be implemented in the full version")
        self.wait_for_continue()
    
    def system_dashboard_menu(self):
        """System dashboard interface - placeholder"""
        self.show_info("System Dashboard interface will be implemented in the full version")
        self.wait_for_continue()
    
    # Additional placeholder methods for submenu handlers
    def handle_reconnaissance_submenu(self, choice):
        self.show_info(f"Reconnaissance submenu {choice} will be implemented")
        self.wait_for_continue()
    
    def handle_vulnerability_submenu(self, choice):
        self.show_info(f"Vulnerability submenu {choice} will be implemented")
        self.wait_for_continue()
    
    def handle_web_testing_submenu(self, choice):
        self.show_info(f"Web testing submenu {choice} will be implemented")
        self.wait_for_continue()
    
    def handle_cloud_submenu(self, choice):
        self.show_info(f"Cloud submenu {choice} will be implemented")
        self.wait_for_continue()
    
    def handle_system_config_submenu(self, choice):
        self.show_info(f"System config submenu {choice} will be implemented")
        self.wait_for_continue()
    
    def handle_reporting_submenu(self, choice):
        self.show_info(f"Reporting submenu {choice} will be implemented")
        self.wait_for_continue()
    
    def handle_dashboard_submenu(self, choice):
        self.show_info(f"Dashboard submenu {choice} will be implemented")
        self.wait_for_continue()
    
    # Target management implementations
    def _validate_target_format(self, target: str) -> tuple[bool, str]:
        """Validate target format and return (is_valid, error_message)"""
        if not target or not target.strip():
            return False, "Target cannot be empty"
        
        target = target.strip()
        
        if ' ' in target:
            return False, "Target cannot contain spaces"
        
        if len(target) > 253:  # DNS limit
            return False, "Target is too long (max 253 characters)"
        
        # Check for basic format
        if target.startswith(('http://', 'https://')):
            # URL validation
            if not '.' in target or target.count('.') < 1:
                return False, "Invalid URL format"
        elif '.' in target:
            # Domain validation
            if target.startswith('.') or target.endswith('.') or '..' in target:
                return False, "Invalid domain format"
            if not all(c.isalnum() or c in '.-' for c in target):
                return False, "Domain contains invalid characters"
        elif ':' in target:
            # IPv6 or port validation
            pass  # Accept for now
        elif target.replace('.', '').isdigit():
            # IPv4 validation
            parts = target.split('.')
            if len(parts) != 4:
                return False, "Invalid IPv4 format"
            try:
                if not all(0 <= int(part) <= 255 for part in parts):
                    return False, "Invalid IPv4 address range"
            except ValueError:
                return False, "Invalid IPv4 format"
        else:
            return False, "Unrecognized target format"
        
        return True, ""

    def add_single_target(self) -> None:
        """Add a single target to the target list"""
        self.print_master_banner()
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;92m                        📝 ADD SINGLE TARGET 📝\033[0m                        ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        
        print("\n💡 \033[1;97mSupported target formats:\033[0m")
        print("   • Domain: example.com")
        print("   • Subdomain: sub.example.com")
        print("   • IP Address: 192.168.1.1")
        print("   • URL: https://example.com")
        
        target = input("\n🎯 \033[1;97mEnter target: \033[0m").strip()
        
        # Validate target format
        is_valid, error_message = self._validate_target_format(target)
        if not is_valid:
            self.show_error(error_message)
            return
        
        # Load existing targets
        try:
            targets_file = Path("targets.txt")
            if targets_file.exists():
                existing_targets = targets_file.read_text().strip().split('\n')
                existing_targets = [t.strip() for t in existing_targets if t.strip()]
            else:
                existing_targets = []
            
            if target in existing_targets:
                self.show_error(f"Target '{target}' already exists in target list")
                return
            
            # Add target
            existing_targets.append(target)
            targets_file.write_text('\n'.join(existing_targets) + '\n')
            
            self.show_success(f"Target '{target}' added successfully!")
            print(f"   Total targets: {len(existing_targets)}")
            
        except Exception as e:
            self.show_error(f"Failed to add target: {e}")
        
        self.wait_for_continue()
    
    def import_target_list(self):
        """Import target list from file"""
        print("\n📥 \033[1;97mImport Target List:\033[0m")
        print("Supported formats: TXT (one target per line), CSV, JSON")
        
        file_path = input("\n📁 Enter file path: ").strip()
        if not file_path:
            return
            
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                self.show_error(f"File not found: {file_path}")
                return
                
            new_targets = set()
            
            if file_path.suffix.lower() == '.txt':
                # Plain text file
                with open(file_path, 'r') as f:
                    for line in f:
                        target = line.strip()
                        if target and not target.startswith('#'):
                            new_targets.add(target)
                            
            elif file_path.suffix.lower() == '.csv':
                # CSV file
                import csv
                with open(file_path, 'r') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row and len(row) > 0:
                            target = row[0].strip()
                            if target and not target.startswith('#'):
                                new_targets.add(target)
                                
            elif file_path.suffix.lower() == '.json':
                # JSON file
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for target in data:
                            if isinstance(target, str):
                                new_targets.add(target.strip())
                            elif isinstance(target, dict) and 'target' in target:
                                new_targets.add(target['target'].strip())
                    elif isinstance(data, dict) and 'targets' in data:
                        for target in data['targets']:
                            if isinstance(target, str):
                                new_targets.add(target.strip())
            else:
                self.show_error("Unsupported file format. Use .txt, .csv, or .json")
                return
                
            if new_targets:
                # Show preview
                print(f"\n📋 Found {len(new_targets)} targets:")
                for i, target in enumerate(list(new_targets)[:10], 1):
                    print(f"  {i}. {target}")
                if len(new_targets) > 10:
                    print(f"  ... and {len(new_targets) - 10} more")
                
                # Confirm import
                confirm = input(f"\n✅ Import {len(new_targets)} targets? (y/N): ")
                if confirm.lower() == 'y':
                    # Add to existing targets
                    original_count = len(self.targets)
                    self.targets.update(new_targets)
                    new_count = len(self.targets) - original_count
                    
                    # Save to targets.txt
                    self.save_targets()
                    
                    self.show_success(f"Imported {new_count} new targets (total: {len(self.targets)})")
                else:
                    print("Import cancelled")
            else:
                self.show_info("No valid targets found in file")
                
        except Exception as e:
            self.show_error(f"Error importing targets: {e}")
            
        self.wait_for_continue()
        
    def save_targets(self):
        """Save targets to targets.txt file"""
        try:
            targets_file = Path("targets.txt")
            with open(targets_file, 'w') as f:
                for target in sorted(self.targets):
                    f.write(f"{target}\n")
            self.logger.info(f"Saved {len(self.targets)} targets to {targets_file}")
        except Exception as e:
            self.logger.error(f"Error saving targets: {e}")
    
    def view_current_targets(self) -> None:
        """View current targets in the target list"""
        self.print_master_banner()
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;94m                        📋 CURRENT TARGETS 📋\033[0m                        ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        
        try:
            targets_file = Path("targets.txt")
            if not targets_file.exists():
                print("\n📋 \033[1;93mNo targets file found.\033[0m")
                print("   Use 'Add Single Target' to create your first target.")
                self.wait_for_continue()
                return
            
            content = targets_file.read_text().strip()
            if not content:
                print("\n📋 \033[1;93mTarget list is empty.\033[0m")
                print("   Use 'Add Single Target' to add your first target.")
                self.wait_for_continue()
                return
            
            targets = [t.strip() for t in content.split('\n') if t.strip()]
            
            print(f"\n📊 \033[1;97mTotal targets: {len(targets)}\033[0m")
            print("═" * 60)
            
            for i, target in enumerate(targets, 1):
                # Basic target type detection
                if target.startswith(('http://', 'https://')):
                    icon = "🌐"
                    type_name = "URL"
                elif target.replace('.', '').replace(':', '').isdigit() or ':' in target:
                    icon = "🖥️"
                    type_name = "IP"
                else:
                    icon = "🌍"
                    type_name = "Domain"
                
                print(f"{i:3d}. {icon} \033[1;97m{target:<40}\033[0m ({type_name})")
            
            print("═" * 60)
            
        except Exception as e:
            self.show_error(f"Failed to load targets: {e}")
        
        self.wait_for_continue()
    
    def remove_targets(self):
        """Remove targets from the list"""
        if not self.targets:
            self.show_info("No targets to remove")
            self.wait_for_continue()
            return
            
        while True:
            print("\n🗑️ \033[1;97mRemove Targets:\033[0m")
            print("1. Remove specific target")
            print("2. Remove multiple targets")
            print("3. Clear all targets")
            print("4. Remove by pattern/filter")
            print("0. Return to previous menu")
            
            choice = input("\nSelect option (0-4): ").strip()
            
            if choice == "0":
                break
            elif choice == "1":
                self.remove_single_target()
            elif choice == "2":
                self.remove_multiple_targets()
            elif choice == "3":
                self.clear_all_targets()
            elif choice == "4":
                self.remove_targets_by_pattern()
            else:
                self.show_error("Invalid option")
                
    def remove_single_target(self):
        """Remove a single target"""
        print(f"\n🎯 \033[1;97mCurrent Targets ({len(self.targets)}):\033[0m")
        targets_list = list(self.targets)
        
        for i, target in enumerate(targets_list, 1):
            print(f"  {i}. {target}")
            
        try:
            choice = input(f"\nSelect target to remove (1-{len(targets_list)}): ")
            index = int(choice) - 1
            
            if 0 <= index < len(targets_list):
                target_to_remove = targets_list[index]
                confirm = input(f"\n⚠️ Remove '{target_to_remove}'? (y/N): ")
                
                if confirm.lower() == 'y':
                    self.targets.remove(target_to_remove)
                    self.save_targets()
                    self.show_success(f"Removed target: {target_to_remove}")
                else:
                    print("Removal cancelled")
            else:
                self.show_error("Invalid target selection")
                
        except (ValueError, IndexError):
            self.show_error("Invalid input")
            
    def remove_multiple_targets(self):
        """Remove multiple targets"""
        print(f"\n🎯 \033[1;97mCurrent Targets ({len(self.targets)}):\033[0m")
        targets_list = list(self.targets)
        
        for i, target in enumerate(targets_list, 1):
            print(f"  {i}. {target}")
            
        print("\n💡 Enter target numbers separated by commas (e.g., 1,3,5)")
        selection = input("Select targets to remove: ").strip()
        
        if not selection:
            return
            
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            targets_to_remove = []
            
            for index in indices:
                if 0 <= index < len(targets_list):
                    targets_to_remove.append(targets_list[index])
                    
            if targets_to_remove:
                print(f"\n📋 Targets to remove:")
                for target in targets_to_remove:
                    print(f"  • {target}")
                    
                confirm = input(f"\n⚠️ Remove {len(targets_to_remove)} targets? (y/N): ")
                
                if confirm.lower() == 'y':
                    for target in targets_to_remove:
                        self.targets.remove(target)
                    self.save_targets()
                    self.show_success(f"Removed {len(targets_to_remove)} targets")
                else:
                    print("Removal cancelled")
            else:
                self.show_error("No valid targets selected")
                
        except ValueError:
            self.show_error("Invalid input format")
            
    def clear_all_targets(self):
        """Clear all targets"""
        if not self.targets:
            self.show_info("No targets to clear")
            return
            
        print(f"\n⚠️ \033[1;91mThis will remove ALL {len(self.targets)} targets!\033[0m")
        confirm = input("Are you sure? Type 'DELETE ALL' to confirm: ")
        
        if confirm == "DELETE ALL":
            self.targets.clear()
            self.save_targets()
            self.show_success("All targets removed")
        else:
            print("Clear operation cancelled")
            
    def remove_targets_by_pattern(self):
        """Remove targets by pattern/filter"""
        pattern = input("\n🔍 Enter pattern to match (supports wildcards *): ").strip()
        if not pattern:
            return
            
        import fnmatch
        matching_targets = []
        
        for target in self.targets:
            if fnmatch.fnmatch(target.lower(), pattern.lower()):
                matching_targets.append(target)
                
        if matching_targets:
            print(f"\n📋 Targets matching pattern '{pattern}':")
            for target in matching_targets:
                print(f"  • {target}")
                
            confirm = input(f"\n⚠️ Remove {len(matching_targets)} matching targets? (y/N): ")
            
            if confirm.lower() == 'y':
                for target in matching_targets:
                    self.targets.remove(target)
                self.save_targets()
                self.show_success(f"Removed {len(matching_targets)} targets matching pattern")
            else:
                print("Removal cancelled")
        else:
            self.show_info(f"No targets match pattern: {pattern}")
    
    def validate_targets(self) -> None:
        """Validate targets in the target list"""
        self.print_master_banner()
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;95m                        ✅ VALIDATE TARGETS ✅\033[0m                        ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        
        try:
            targets_file = Path("targets.txt")
            if not targets_file.exists():
                self.show_error("No targets file found")
                return
            
            content = targets_file.read_text().strip()
            if not content:
                self.show_error("Target list is empty")
                return
            
            targets = [t.strip() for t in content.split('\n') if t.strip()]
            
            print(f"\n🔍 \033[1;97mValidating {len(targets)} targets...\033[0m")
            print("═" * 60)
            
            valid_targets = []
            invalid_targets = []
            
            for i, target in enumerate(targets, 1):
                print(f"🔍 Validating {i}/{len(targets)}: {target}")
                
                # Use our validation function
                is_valid, error_message = self._validate_target_format(target)
                
                if is_valid:
                    valid_targets.append(target)
                    print(f"   ✅ Valid")
                else:
                    invalid_targets.append((target, [error_message]))
                    print(f"   ❌ Invalid: {error_message}")
            
            print("═" * 60)
            print(f"📊 \033[1;97mValidation Summary:\033[0m")
            print(f"   ✅ Valid targets: {len(valid_targets)}")
            print(f"   ❌ Invalid targets: {len(invalid_targets)}")
            
            if invalid_targets:
                print(f"\n❌ \033[1;91mInvalid targets found:\033[0m")
                for target, issues in invalid_targets:
                    print(f"   • {target}: {', '.join(issues)}")
                
                if input("\n🗑️  Remove invalid targets? [y/N]: ").strip().lower() == 'y':
                    targets_file.write_text('\n'.join(valid_targets) + '\n')
                    self.show_success(f"Removed {len(invalid_targets)} invalid targets")
            else:
                self.show_success("All targets are valid!")
            
        except Exception as e:
            self.show_error(f"Validation failed: {e}")
        
        self.wait_for_continue()
    
    def target_analysis_summary(self):
        self.show_info("Target analysis summary functionality will be implemented")
        self.wait_for_continue()
    
    def export_target_list(self):
        """Export target list to various formats"""
        if not self.targets:
            self.show_info("No targets to export")
            self.wait_for_continue()
            return
            
        print("\n📤 \033[1;97mExport Target List:\033[0m")
        print("1. Plain text (.txt)")
        print("2. CSV format (.csv)")
        print("3. JSON format (.json)")
        print("4. XML format (.xml)")
        print("5. Custom format")
        
        choice = input("\nSelect export format (1-5): ").strip()
        
        if choice not in ['1', '2', '3', '4', '5']:
            self.show_error("Invalid format selection")
            return
            
        # Get output filename
        default_name = f"targets_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filename = input(f"\nEnter filename (default: {default_name}): ").strip()
        
        if not filename:
            filename = default_name
            
        try:
            if choice == "1":
                # Plain text
                filepath = Path(f"{filename}.txt")
                with open(filepath, 'w') as f:
                    for target in sorted(self.targets):
                        f.write(f"{target}\n")
                        
            elif choice == "2":
                # CSV format
                import csv
                filepath = Path(f"{filename}.csv")
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Target', 'Added_Date', 'Status'])
                    for target in sorted(self.targets):
                        writer.writerow([target, datetime.now().strftime('%Y-%m-%d'), 'Active'])
                        
            elif choice == "3":
                # JSON format
                filepath = Path(f"{filename}.json")
                export_data = {
                    "export_info": {
                        "timestamp": datetime.now().isoformat(),
                        "tool": f"{MASTER_APP} {MASTER_VERSION}",
                        "total_targets": len(self.targets)
                    },
                    "targets": [
                        {
                            "target": target,
                            "added_date": datetime.now().isoformat(),
                            "status": "active"
                        } for target in sorted(self.targets)
                    ]
                }
                with open(filepath, 'w') as f:
                    json.dump(export_data, f, indent=2)
                    
            elif choice == "4":
                # XML format
                filepath = Path(f"{filename}.xml")
                with open(filepath, 'w') as f:
                    f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                    f.write('<targets>\n')
                    f.write(f'  <export_info>\n')
                    f.write(f'    <timestamp>{datetime.now().isoformat()}</timestamp>\n')
                    f.write(f'    <tool>{MASTER_APP} {MASTER_VERSION}</tool>\n')
                    f.write(f'    <total_targets>{len(self.targets)}</total_targets>\n')
                    f.write(f'  </export_info>\n')
                    for target in sorted(self.targets):
                        f.write(f'  <target>\n')
                        f.write(f'    <url>{target}</url>\n')
                        f.write(f'    <status>active</status>\n')
                        f.write(f'  </target>\n')
                    f.write('</targets>\n')
                    
            elif choice == "5":
                # Custom format
                print("\n⚙️ Custom Export Format:")
                print("Enter format template (use {target} as placeholder)")
                print("Example: Target: {target} | Status: Active")
                
                template = input("Format template: ").strip()
                if not template:
                    template = "{target}"
                    
                filepath = Path(f"{filename}.txt")
                with open(filepath, 'w') as f:
                    for target in sorted(self.targets):
                        f.write(template.format(target=target) + '\n')
                        
            self.show_success(f"Exported {len(self.targets)} targets to {filepath}")
            print(f"📁 File saved: {filepath.absolute()}")
            
        except Exception as e:
            self.show_error(f"Error exporting targets: {e}")
            
        self.wait_for_continue()
    
    def bulk_target_operations(self):
        """Bulk operations on targets"""
        if not self.targets:
            self.show_info("No targets available for bulk operations")
            self.wait_for_continue()
            return
            
        while True:
            print("\n📦 \033[1;97mBulk Target Operations:\033[0m")
            print(f"Current targets: {len(self.targets)}")
            print("")
            print("1. 🔍 Validate all targets (connectivity check)")
            print("2. 🌐 Resolve all domains to IPs")
            print("3. 📊 Generate target statistics")
            print("4. 🔄 Deduplicate targets")
            print("5. 🏷️ Categorize targets by type")
            print("6. 🚀 Mass reconnaissance")
            print("7. 📋 Bulk export with metadata")
            print("0. Return to previous menu")
            
            choice = input("\nSelect operation (0-7): ").strip()
            
            if choice == "0":
                break
            elif choice == "1":
                self.validate_all_targets()
            elif choice == "2":
                self.resolve_all_targets()
            elif choice == "3":
                self.generate_target_statistics()
            elif choice == "4":
                self.deduplicate_targets()
            elif choice == "5":
                self.categorize_targets()
            elif choice == "6":
                asyncio.run(self.mass_reconnaissance())
            elif choice == "7":
                self.bulk_export_with_metadata()
            else:
                self.show_error("Invalid option")
                
    def validate_all_targets(self):
        """Validate connectivity for all targets"""
        print(f"\n🔍 \033[1;97mValidating {len(self.targets)} targets...\033[0m")
        
        valid_targets = []
        invalid_targets = []
        
        import requests
        from urllib.parse import urlparse
        
        for i, target in enumerate(self.targets, 1):
            print(f"\r[{i}/{len(self.targets)}] Checking {target[:50]}...", end="", flush=True)
            
            try:
                # Ensure URL format
                if not target.startswith(('http://', 'https://')):
                    test_url = f"https://{target}"
                else:
                    test_url = target
                    
                response = requests.head(test_url, timeout=10, allow_redirects=True)
                if response.status_code < 500:  # Accept redirects and client errors
                    valid_targets.append(target)
                else:
                    invalid_targets.append((target, f"HTTP {response.status_code}"))
                    
            except Exception as e:
                invalid_targets.append((target, str(e)[:50]))
                
        print(f"\n\n📊 \033[1;97mValidation Results:\033[0m")
        print(f"✅ Valid targets: {len(valid_targets)}")
        print(f"❌ Invalid targets: {len(invalid_targets)}")
        
        if invalid_targets:
            print(f"\n❌ Invalid targets:")
            for target, error in invalid_targets[:10]:
                print(f"  • {target} - {error}")
            if len(invalid_targets) > 10:
                print(f"  ... and {len(invalid_targets) - 10} more")
                
            remove_invalid = input(f"\n🗑️ Remove {len(invalid_targets)} invalid targets? (y/N): ")
            if remove_invalid.lower() == 'y':
                for target, _ in invalid_targets:
                    self.targets.discard(target)
                self.save_targets()
                self.show_success(f"Removed {len(invalid_targets)} invalid targets")
                
        self.wait_for_continue()
        
    def resolve_all_targets(self):
        """Resolve all domain targets to IP addresses"""
        print(f"\n🌐 \033[1;97mResolving {len(self.targets)} targets...\033[0m")
        
        import socket
        from urllib.parse import urlparse
        
        resolved_data = {}
        
        for i, target in enumerate(self.targets, 1):
            print(f"\r[{i}/{len(self.targets)}] Resolving {target[:50]}...", end="", flush=True)
            
            try:
                # Extract domain from URL if needed
                if target.startswith(('http://', 'https://')):
                    domain = urlparse(target).netloc
                else:
                    domain = target
                    
                # Remove port if present
                domain = domain.split(':')[0]
                
                # Resolve to IP
                ip = socket.gethostbyname(domain)
                resolved_data[target] = {
                    'domain': domain,
                    'ip': ip,
                    'status': 'resolved'
                }
                
            except Exception as e:
                resolved_data[target] = {
                    'domain': domain if 'domain' in locals() else target,
                    'ip': None,
                    'status': f'failed: {str(e)[:30]}'
                }
                
        print(f"\n\n📊 \033[1;97mResolution Results:\033[0m")
        
        resolved_count = len([d for d in resolved_data.values() if d['ip']])
        failed_count = len(resolved_data) - resolved_count
        
        print(f"✅ Resolved: {resolved_count}")
        print(f"❌ Failed: {failed_count}")
        
        # Save results
        output_file = Path(f"target_resolution_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(output_file, 'w') as f:
            json.dump(resolved_data, f, indent=2)
            
        print(f"\n📁 Results saved to: {output_file}")
        self.wait_for_continue()
        
    def generate_target_statistics(self):
        """Generate comprehensive target statistics"""
        print(f"\n📊 \033[1;97mTarget Statistics:\033[0m")
        print("=" * 50)
        
        from urllib.parse import urlparse
        from collections import defaultdict
        
        stats = {
            'total': len(self.targets),
            'protocols': defaultdict(int),
            'domains': defaultdict(int),
            'tlds': defaultdict(int),
            'ports': defaultdict(int),
            'subdomains': 0,
            'ips': 0,
            'urls': 0
        }
        
        for target in self.targets:
            # Check if it's an IP address
            import re
            ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            
            if re.match(ip_pattern, target.split(':')[0]):
                stats['ips'] += 1
                if ':' in target:
                    port = target.split(':')[1]
                    stats['ports'][port] += 1
            elif target.startswith(('http://', 'https://')):
                stats['urls'] += 1
                parsed = urlparse(target)
                stats['protocols'][parsed.scheme] += 1
                
                domain = parsed.netloc.split(':')[0]
                if '.' in domain:
                    tld = domain.split('.')[-1]
                    stats['tlds'][tld] += 1
                    
                if domain.count('.') > 1:
                    stats['subdomains'] += 1
                    
                if parsed.port:
                    stats['ports'][str(parsed.port)] += 1
                    
            else:
                # Assume it's a domain
                if '.' in target:
                    tld = target.split('.')[-1]
                    stats['tlds'][tld] += 1
                    
                if target.count('.') > 1:
                    stats['subdomains'] += 1
                    
        print(f"📈 Total Targets: {stats['total']}")
        print(f"🌐 Domains/URLs: {stats['urls']}")
        print(f"📱 IP Addresses: {stats['ips']}")
        print(f"🔗 Subdomains: {stats['subdomains']}")
        
        if stats['protocols']:
            print(f"\n🔒 Protocols:")
            for protocol, count in sorted(stats['protocols'].items()):
                print(f"  • {protocol}: {count}")
                
        if stats['tlds']:
            print(f"\n🌍 Top TLDs:")
            top_tlds = sorted(stats['tlds'].items(), key=lambda x: x[1], reverse=True)[:10]
            for tld, count in top_tlds:
                print(f"  • .{tld}: {count}")
                
        if stats['ports']:
            print(f"\n🔌 Ports:")
            for port, count in sorted(stats['ports'].items()):
                print(f"  • {port}: {count}")
                
        # Save detailed stats
        output_file = Path(f"target_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(output_file, 'w') as f:
            # Convert defaultdict to regular dict for JSON serialization
            stats_dict = {k: dict(v) if isinstance(v, defaultdict) else v for k, v in stats.items()}
            json.dump(stats_dict, f, indent=2)
            
        print(f"\n📁 Detailed stats saved to: {output_file}")
        self.wait_for_continue()
        
    def deduplicate_targets(self):
        """Remove duplicate targets"""
        original_count = len(self.targets)
        
        # Targets are already in a set, so they're unique
        # But let's normalize and check for similar entries
        normalized_targets = set()
        duplicates_found = []
        
        for target in self.targets:
            # Normalize target
            normalized = target.lower().strip()
            
            # Remove trailing slash
            if normalized.endswith('/'):
                normalized = normalized[:-1]
                
            # Check for www variants
            if normalized.startswith('www.'):
                base_domain = normalized[4:]
                if base_domain in normalized_targets:
                    duplicates_found.append((target, f"Duplicate of {base_domain}"))
                    continue
                    
            if f"www.{normalized}" in normalized_targets:
                duplicates_found.append((target, f"Duplicate with www variant"))
                continue
                
            normalized_targets.add(normalized)
            
        if duplicates_found:
            print(f"\n🔍 \033[1;97mFound {len(duplicates_found)} potential duplicates:\033[0m")
            for target, reason in duplicates_found[:10]:
                print(f"  • {target} - {reason}")
                
            if len(duplicates_found) > 10:
                print(f"  ... and {len(duplicates_found) - 10} more")
                
            remove_dupes = input(f"\n🗑️ Remove {len(duplicates_found)} duplicates? (y/N): ")
            if remove_dupes.lower() == 'y':
                for target, _ in duplicates_found:
                    self.targets.discard(target)
                self.save_targets()
                self.show_success(f"Removed {len(duplicates_found)} duplicates")
        else:
            self.show_info("No duplicates found")
            
        self.wait_for_continue()
        
    def categorize_targets(self):
        """Categorize targets by type"""
        from urllib.parse import urlparse
        import re
        
        categories = {
            'web_applications': [],
            'api_endpoints': [],
            'ip_addresses': [],
            'subdomains': [],
            'main_domains': [],
            'unknown': []
        }
        
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        for target in self.targets:
            if re.match(ip_pattern, target.split(':')[0]):
                categories['ip_addresses'].append(target)
            elif 'api' in target.lower() or '/api/' in target.lower():
                categories['api_endpoints'].append(target)
            elif target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                domain = parsed.netloc.split(':')[0]
                if domain.count('.') > 1:
                    categories['subdomains'].append(target)
                else:
                    categories['web_applications'].append(target)
            elif '.' in target:
                if target.count('.') > 1:
                    categories['subdomains'].append(target)
                else:
                    categories['main_domains'].append(target)
            else:
                categories['unknown'].append(target)
                
        print(f"\n📂 \033[1;97mTarget Categories:\033[0m")
        print("=" * 40)
        
        for category, targets in categories.items():
            if targets:
                print(f"\n{category.replace('_', ' ').title()}: {len(targets)}")
                for target in targets[:5]:
                    print(f"  • {target}")
                if len(targets) > 5:
                    print(f"  ... and {len(targets) - 5} more")
                    
        # Save categorized results
        output_file = Path(f"target_categories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(output_file, 'w') as f:
            json.dump(categories, f, indent=2)
            
        print(f"\n📁 Categories saved to: {output_file}")
        self.wait_for_continue()
        
    async def mass_reconnaissance(self):
        """Perform reconnaissance on all targets"""
        if not self.integrations_available:
            self.show_error("Moloch integration not available")
            return
            
        print(f"\n🚀 \033[1;97mMass Reconnaissance on {len(self.targets)} targets\033[0m")
        print("⚠️ This will run reconnaissance on ALL targets!")
        
        confirm = input("\nContinue with mass reconnaissance? (y/N): ")
        if confirm.lower() != 'y':
            return
            
        # Create master run directory
        run_dir = Path(self.moloch_integration.config['general']['runs_dir'])
        mass_run_path = run_dir / f"mass_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        mass_run_path.mkdir(parents=True, exist_ok=True)
        
        results = {}
        completed = 0
        failed = 0
        
        for i, target in enumerate(self.targets, 1):
            print(f"\n[{i}/{len(self.targets)}] 🎯 Processing {target}")
            
            try:
                target_dir = mass_run_path / target.replace('.', '_').replace(':', '_').replace('/', '_')
                target_dir.mkdir(exist_ok=True)
                
                # Run reconnaissance
                recon_results = await self.moloch_integration.run_reconnaissance_suite(
                    target, target_dir, aggressive=False
                )
                
                results[target] = recon_results
                completed += 1
                
                print(f"  ✅ Completed: {len(recon_results.get('live_hosts', []))} live hosts found")
                
            except Exception as e:
                print(f"  ❌ Failed: {e}")
                results[target] = {'error': str(e)}
                failed += 1
                
        # Save master results
        master_results_file = mass_run_path / "mass_reconnaissance_results.json"
        with open(master_results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        print(f"\n📊 \033[1;97mMass Reconnaissance Summary:\033[0m")
        print(f"✅ Completed: {completed}")
        print(f"❌ Failed: {failed}")
        print(f"📁 Results saved to: {mass_run_path}")
        
        self.wait_for_continue()
        
    def bulk_export_with_metadata(self):
        """Export targets with comprehensive metadata"""
        print(f"\n📋 \033[1;97mBulk Export with Metadata\033[0m")
        
        # Collect metadata for all targets
        metadata = {}
        
        print("🔍 Collecting metadata...")
        for target in self.targets:
            print(f"\rProcessing {target[:50]}...", end="", flush=True)
            
            target_data = {
                'target': target,
                'added_date': datetime.now().isoformat(),
                'type': self.classify_target_type(target),
                'status': 'active'
            }
            
            metadata[target] = target_data
            
        print(f"\n\n📊 Export Options:")
        print("1. Detailed JSON with metadata")
        print("2. CSV with basic info")
        print("3. Excel spreadsheet")
        print("4. Markdown report")
        
        choice = input("\nSelect export format (1-4): ").strip()
        
        filename = f"targets_bulk_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            if choice == "1":
                # Detailed JSON
                filepath = Path(f"{filename}.json")
                export_data = {
                    'export_info': {
                        'timestamp': datetime.now().isoformat(),
                        'tool': f"{MASTER_APP} {MASTER_VERSION}",
                        'total_targets': len(self.targets),
                        'categories': self.get_target_category_summary()
                    },
                    'targets': metadata
                }
                with open(filepath, 'w') as f:
                    json.dump(export_data, f, indent=2)
                    
            elif choice == "2":
                # CSV format
                import csv
                filepath = Path(f"{filename}.csv")
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Target', 'Type', 'Status', 'Added_Date'])
                    for target_data in metadata.values():
                        writer.writerow([
                            target_data['target'],
                            target_data['type'],
                            target_data['status'],
                            target_data['added_date']
                        ])
                        
            elif choice == "3":
                # Try to create Excel file (requires openpyxl)
                try:
                    import openpyxl
                    from openpyxl import Workbook
                    
                    wb = Workbook()
                    ws = wb.active
                    ws.title = "Targets"
                    
                    # Headers
                    headers = ['Target', 'Type', 'Status', 'Added Date']
                    for col, header in enumerate(headers, 1):
                        ws.cell(row=1, column=col, value=header)
                        
                    # Data
                    for row, target_data in enumerate(metadata.values(), 2):
                        ws.cell(row=row, column=1, value=target_data['target'])
                        ws.cell(row=row, column=2, value=target_data['type'])
                        ws.cell(row=row, column=3, value=target_data['status'])
                        ws.cell(row=row, column=4, value=target_data['added_date'])
                        
                    filepath = Path(f"{filename}.xlsx")
                    wb.save(filepath)
                    
                except ImportError:
                    self.show_error("openpyxl not installed. Install with: pip install openpyxl")
                    return
                    
            elif choice == "4":
                # Markdown report
                filepath = Path(f"{filename}.md")
                with open(filepath, 'w') as f:
                    f.write(f"# Target List Report\n\n")
                    f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"**Tool:** {MASTER_APP} {MASTER_VERSION}\n")
                    f.write(f"**Total Targets:** {len(self.targets)}\n\n")
                    
                    f.write("## Target Summary\n\n")
                    f.write("| Target | Type | Status |\n")
                    f.write("|--------|------|--------|\n")
                    
                    for target_data in metadata.values():
                        f.write(f"| {target_data['target']} | {target_data['type']} | {target_data['status']} |\n")
                        
            else:
                self.show_error("Invalid export format")
                return
                
            self.show_success(f"Bulk export completed: {filepath}")
            print(f"📁 File saved: {filepath.absolute()}")
            
        except Exception as e:
            self.show_error(f"Error during bulk export: {e}")
            
        self.wait_for_continue()
        
    def classify_target_type(self, target):
        """Classify target type"""
        import re
        from urllib.parse import urlparse
        
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        if re.match(ip_pattern, target.split(':')[0]):
            return 'IP Address'
        elif 'api' in target.lower():
            return 'API Endpoint'
        elif target.startswith(('http://', 'https://')):
            return 'Web Application'
        elif '.' in target:
            if target.count('.') > 1:
                return 'Subdomain'
            else:
                return 'Domain'
        else:
            return 'Unknown'
            
    def get_target_category_summary(self):
        """Get summary of target categories"""
        from collections import defaultdict
        
        categories = defaultdict(int)
        for target in self.targets:
            category = self.classify_target_type(target)
            categories[category] += 1
            
        return dict(categories)
    
    def show_detailed_system_status(self):
        """Show detailed system status"""
        self.print_master_banner()
        self.update_system_status()
        
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;94m                      📊 DETAILED SYSTEM STATUS 📊\033[0m                      ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        
        print(f"\n🏥 \033[1;97mSystem Health:\033[0m {self.system_status['health']}")
        print(f"🔧 \033[1;97mFramework Version:\033[0m {MASTER_VERSION}")
        print(f"📊 \033[1;97mActive Scans:\033[0m {len(self.active_scans)}")
        print(f"📋 \033[1;97mScan History:\033[0m {len(self.scan_history)}")
        
        print(f"\n⚡ \033[1;97mPerformance Metrics:\033[0m")
        print(f"   CPU Usage: {self.performance_metrics['cpu_usage']:.1f}%")
        print(f"   Memory Usage: {self.performance_metrics['memory_usage']:.1f}%")
        print(f"   Disk Usage: {self.performance_metrics['disk_usage']:.1f}%")
        
        print(f"\n🔧 \033[1;97mScanner Status:\033[0m")
        for scanner, status in self.system_status['scanners'].items():
            print(f"   {scanner}: {status}")
        
        print(f"\n🛠️  \033[1;97mTool Status:\033[0m")
        for tool, status in self.system_status['tools'].items():
            print(f"   {tool}: {status}")
        
        self.wait_for_continue()
    
    def show_help_menu(self):
        """Show help and usage information"""
        self.print_master_banner()
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;96m                           📚 HELP & USAGE 📚\033[0m                           ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        
        print("\n🎯 \033[1;97mQuick Start Guide:\033[0m")
        print("   1. Use option 1 for complete automated security assessment")
        print("   2. Use option 2 to manage targets before scanning")
        print("   3. Use individual modules (3-9) for specific assessments")
        print("   4. Use option 10 to configure tools and settings")
        print("   5. Use option 11 to generate reports from scan results")
        print("   6. Use option 12 for real-time monitoring")
        
        print("\n💡 \033[1;97mTips:\033[0m")
        print("   • Type 'status' anytime to check system health")
        print("   • Use submenu numbers (e.g., '3.1') for direct access")
        print("   • Press Ctrl+C to cancel operations safely")
        print("   • All scan results are automatically saved")
        
        print(f"\n📖 \033[1;97mDocumentation:\033[0m")
        print("   • GitHub: https://github.com/cxb3rf1lth/Azaz-El")
        print("   • README: Contains detailed usage instructions")
        print("   • Wiki: Advanced configuration and customization")
        
        self.wait_for_continue()
    
    async def generate_pipeline_report(self, scan_id: str):
        """Generate comprehensive report for pipeline execution"""
        print(f"\n📊 \033[1;97mGenerating comprehensive report for scan: {scan_id}\033[0m")
        
        try:
            if hasattr(self, 'report_generator'):
                # Generate report using the advanced report generator
                scan_data = self.scan_history[-1] if self.scan_history else {}
                report_path = await self.report_generator.generate_comprehensive_report(scan_data)
                self.show_success(f"Report generated: {report_path}")
            else:
                self.show_info("Report generation functionality will be enhanced in future versions")
                
        except Exception as e:
            self.show_error(f"Report generation failed: {e}")


def setup_argument_parser() -> argparse.ArgumentParser:
    """Setup comprehensive command line argument parser"""
    parser = argparse.ArgumentParser(
        description=f"{MASTER_APP} {MASTER_VERSION} - Unified Master Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive Master Dashboard (default)
  python3 master_azaz_el.py
  
  # Quick CLI Operations
  python3 master_azaz_el.py --target example.com --full-pipeline
  python3 master_azaz_el.py --target example.com --reconnaissance
  python3 master_azaz_el.py --target-file targets.txt --vulnerability-scan
  
  # Advanced Operations
  python3 master_azaz_el.py --target example.com --aggressive --cloud-scan
  python3 master_azaz_el.py --status --system-health
  python3 master_azaz_el.py --install-tools --update-config
        """
    )
    
    # Target configuration
    target_group = parser.add_argument_group('Target Configuration')
    target_group.add_argument('--target', '-t', help='Single target (domain, IP, or URL)')
    target_group.add_argument('--target-file', '-tf', help='File containing list of targets')
    target_group.add_argument('--target-list', '-tl', nargs='+', help='Multiple targets as space-separated list')
    
    # Scanning operations
    scan_group = parser.add_argument_group('Scanning Operations')
    scan_group.add_argument('--full-pipeline', '-fp', action='store_true', help='Execute complete security assessment pipeline')
    scan_group.add_argument('--reconnaissance', '-r', action='store_true', help='Reconnaissance and intelligence gathering only')
    scan_group.add_argument('--vulnerability-scan', '-v', action='store_true', help='Vulnerability scanning only')
    scan_group.add_argument('--web-scan', '-w', action='store_true', help='Web application security testing only')
    scan_group.add_argument('--cloud-scan', '-c', action='store_true', help='Cloud security assessment only')
    scan_group.add_argument('--api-scan', '-a', action='store_true', help='API security testing only')
    scan_group.add_argument('--infrastructure-scan', '-i', action='store_true', help='Infrastructure security scanning only')
    
    # Scan configuration
    config_group = parser.add_argument_group('Scan Configuration')
    config_group.add_argument('--aggressive', action='store_true', help='Enable aggressive scanning mode')
    config_group.add_argument('--passive', action='store_true', help='Passive scanning mode only')
    config_group.add_argument('--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    config_group.add_argument('--timeout', type=int, default=300, help='Scan timeout in seconds (default: 300)')
    config_group.add_argument('--output-dir', '-o', help='Output directory for results')
    
    # System management
    system_group = parser.add_argument_group('System Management')
    system_group.add_argument('--dashboard', '-d', action='store_true', help='Launch interactive dashboard (default)')
    system_group.add_argument('--status', '-s', action='store_true', help='Show system status and exit')
    system_group.add_argument('--system-health', action='store_true', help='Detailed system health check')
    system_group.add_argument('--install-tools', action='store_true', help='Install required security tools')
    system_group.add_argument('--update-tools', action='store_true', help='Update installed security tools')
    system_group.add_argument('--update-config', action='store_true', help='Update configuration files')
    
    # Output control
    output_group = parser.add_argument_group('Output Control')
    output_group.add_argument('--verbose', '-vv', action='store_true', help='Increase verbosity level')
    output_group.add_argument('--quiet', '-q', action='store_true', help='Suppress non-essential output')
    output_group.add_argument('--no-color', action='store_true', help='Disable colored output')
    output_group.add_argument('--json-output', action='store_true', help='Output results in JSON format')
    
    return parser


async def handle_cli_operations(args, framework):
    """Handle command line interface operations"""
    
    # Handle system status requests
    if args.status:
        framework.update_system_status()
        print(f"System Health: {framework.system_status['health']}")
        return True
    
    if args.system_health:
        framework.show_detailed_system_status()
        return True
    
    # Handle tool management
    if args.install_tools:
        framework.show_info("Tool installation will be implemented in full version")
        return True
    
    if args.update_tools:
        framework.show_info("Tool update will be implemented in full version")
        return True
    
    # Handle scanning operations
    if args.target or args.target_file or args.target_list:
        # Determine target(s)
        targets = []
        if args.target:
            targets.append(args.target)
        if args.target_file:
            framework.show_info(f"Target file processing: {args.target_file}")
        if args.target_list:
            targets.extend(args.target_list)
        
        if not targets and not args.target_file:
            framework.show_error("No valid targets specified")
            return True
        
        # Execute requested scan type
        if args.full_pipeline:
            for target in targets:
                print(f"Executing full pipeline for: {target}")
                await framework.run_full_automation_pipeline()
        elif args.reconnaissance:
            framework.show_info("CLI reconnaissance scanning will be implemented")
        elif args.vulnerability_scan:
            framework.show_info("CLI vulnerability scanning will be implemented")
        elif args.web_scan:
            framework.show_info("CLI web scanning will be implemented")
        elif args.cloud_scan:
            framework.show_info("CLI cloud scanning will be implemented")
        elif args.api_scan:
            framework.show_info("CLI API scanning will be implemented")
        elif args.infrastructure_scan:
            framework.show_info("CLI infrastructure scanning will be implemented")
        else:
            framework.show_info("No specific scan type specified, defaulting to full pipeline")
            await framework.run_full_automation_pipeline()
        
        return True
    
    return False


async def main():
    """Main entry point for the master framework"""
    
    # Setup argument parser
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    try:
        # Initialize the master framework
        framework = MasterAzazElFramework()
        
        # Handle CLI operations if specified
        cli_handled = await handle_cli_operations(args, framework)
        
        # If no CLI operations were handled, launch interactive dashboard
        if not cli_handled:
            framework.display_master_menu()
            
    except KeyboardInterrupt:
        print("\n\n🔄 \033[1;93mMaster framework interrupted by user\033[0m")
        print("👋 \033[1;92mGoodbye!\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ \033[1;91mFatal error:\033[0m {e}")
        logging.exception("Fatal error in master framework")
        sys.exit(1)


if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        sys.exit(1)
    
    # Run the master framework
    asyncio.run(main())