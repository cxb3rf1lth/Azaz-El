#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azaz-El v4.0.0 - Advanced Automated Penetration Testing Framework
Enhanced with AI-powered scanning, comprehensive vulnerability detection,
and enterprise-grade reporting capabilities.
"""

import os
import sys
import subprocess
import json
import time
import asyncio
import argparse
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import shutil
import uuid

# Add current directory to path for imports
sys.path.append(str(Path(__file__).parent))

# Import enhanced core modules
from core.exceptions import *
from core.validators import InputValidator
from core.config import ConfigurationManager
from core.logging import get_logger
from scanners.web_scanner import AdvancedWebScanner

# --- Application Constants ---
APP = "Azaz-El"
VERSION = "v4.0.0-ENHANCED"
AUTHOR = "Professional Penetration Tester"
GITHUB_REPO = "https://github.com/cxb3rf1lth/Azaz-El"

BANNER = r"""
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

# --- Directory Structure ---
HERE = Path(__file__).resolve().parent
TARGETS_FILE = HERE / "targets.txt"
RUNS_DIR = HERE / "runs"
LOG_DIR = HERE / "logs"
CFG_FILE = HERE / "moloch.cfg.json"
PAYLOADS_DIR = HERE / "payloads"
WORDLISTS_DIR = HERE / "wordlists"

class AzazelFramework:
    """Enhanced Azaz-El penetration testing framework"""
    
    def __init__(self):
        """Initialize the enhanced framework"""
        self.logger = None
        self.config_manager = None
        self.config = None
        self.current_run_dir = None
        
        # Initialize core components
        self._initialize_framework()
    
    def _initialize_framework(self):
        """Initialize all framework components"""
        try:
            # Create directory structure
            self._create_directories()
            
            # Initialize logging
            self.logger = get_logger("azaz-el", LOG_DIR, "INFO")
            self.logger.info(f"Initializing {APP} {VERSION}")
            
            # Initialize configuration
            self.config_manager = ConfigurationManager(CFG_FILE)
            self.config = self.config_manager.load_config()
            
            # Create enhanced wordlists
            self._create_enhanced_wordlists_and_payloads()
            
        except Exception as e:
            print(f"Critical error during framework initialization: {e}")
            sys.exit(1)
    
    def _create_directories(self):
        """Create all required directories"""
        directories = [RUNS_DIR, LOG_DIR, PAYLOADS_DIR, WORDLISTS_DIR]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        print(f"Directory structure initialized in {HERE}")
    
    def _create_enhanced_wordlists_and_payloads(self):
        """Create comprehensive wordlists and payload files"""
        
        # Enhanced XSS payloads
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)></iframe>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video><source onerror="alert(1)">',
            '<audio src=x onerror=alert(1)>',
            '<body onload=alert(1)>',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            'javascript:alert(1)',
            'vbscript:msgbox("XSS")',
            'data:text/html,<script>alert(1)</script>',
        ]
        
        # Enhanced SQL injection payloads
        sqli_payloads = [
            "'", '"', "1'", "1\"", "1' OR '1'='1", "1\" OR \"1\"=\"1",
            "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#", "\" OR 1=1#",
            "1' UNION SELECT null--", "1\" UNION SELECT null--",
            "1' UNION SELECT null,null--", "1\" UNION SELECT null,null--",
            "1' AND SLEEP(5)--", "1\" AND SLEEP(5)--",
            "1' WAITFOR DELAY '00:00:05'--", "1\" WAITFOR DELAY '00:00:05'--",
            "1' AND 1=1--", "1' AND 1=2--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
            "'; return true; var x='", "'; return true; //",
            "*)(uid=*))(|(uid=*", "*)(|(password=*))",
            "' or '1'='1", "' or 1=1 or ''='",
        ]
        
        # Create payload files
        payload_files = {
            "xss-payloads-enhanced.txt": xss_payloads,
            "sqli-payloads-enhanced.txt": sqli_payloads,
        }
        
        # Create payload files
        for filename, content in payload_files.items():
            file_path = PAYLOADS_DIR / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content))
        
        self.logger.info(f"Created enhanced wordlists and payloads")
    
    def display_banner(self):
        """Display application banner"""
        print(f"\033[91m{BANNER}\033[0m")
        print(f"\033[94m{APP} {VERSION} - Advanced Automated Penetration Testing Framework\033[0m")
        print(f"\033[93mAuthor: {AUTHOR}\033[0m")
        print(f"\033[92mGitHub: {GITHUB_REPO}\033[0m")
        print("\033[96m" + "="*80 + "\033[0m")
        print(f"\033[95mFramework initialized with enhanced capabilities:\033[0m")
        print(f"  • Advanced vulnerability detection with 8+ attack types")
        print(f"  • Intelligent payload generation and evasion techniques")
        print(f"  • Structured logging with JSON output and rotation")
        print(f"  • Encrypted configuration management")
        print(f"  • Comprehensive input validation and sanitization")
        print(f"  • Async web scanning with concurrent request handling")
        print("\033[96m" + "="*80 + "\033[0m\n")
    
    def create_new_run(self) -> Path:
        """Create a new run directory with enhanced structure"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_id = str(uuid.uuid4())[:8]
        run_name = f"azaz_el_{timestamp}_{run_id}"
        
        run_dir = RUNS_DIR / run_name
        run_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories for organized output
        subdirs = [
            "reconnaissance", "scanning", "enumeration", "exploitation",
            "web_testing", "api_testing", "network_analysis", "reports",
            "logs", "screenshots", "payloads", "evidence"
        ]
        
        for subdir in subdirs:
            (run_dir / subdir).mkdir(exist_ok=True)
        
        self.current_run_dir = run_dir
        self.logger.info(f"Created new run: {run_name}")
        
        return run_dir
    
    def load_targets(self) -> List[str]:
        """Load and validate targets from file"""
        if not TARGETS_FILE.exists():
            return []
        
        targets = []
        try:
            with open(TARGETS_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            validated_target = InputValidator.validate_target(line)
                            targets.append(validated_target)
                        except ValidationError as e:
                            self.logger.warning(f"Invalid target skipped: {line} - {e}")
            
            self.logger.info(f"Loaded {len(targets)} valid targets")
            return targets
            
        except Exception as e:
            self.logger.error(f"Failed to load targets: {e}")
            return []
    
    def add_target(self, target: str) -> bool:
        """Add and validate a new target"""
        try:
            validated_target = InputValidator.validate_target(target)
            
            # Load existing targets
            existing_targets = self.load_targets()
            
            if validated_target not in existing_targets:
                existing_targets.append(validated_target)
                
                # Save updated targets
                with open(TARGETS_FILE, 'w') as f:
                    for t in existing_targets:
                        f.write(f"{t}\n")
                
                self.logger.info(f"Added target: {validated_target}")
                return True
            else:
                self.logger.info(f"Target already exists: {validated_target}")
                return False
                
        except ValidationError as e:
            self.logger.error(f"Invalid target: {target} - {e}")
            return False
    
    async def run_web_scan(self, target: str) -> Dict[str, Any]:
        """Run web security scan for a target"""
        try:
            # Create run directory
            run_dir = self.create_new_run()
            
            self.logger.info(f"Starting web scan for: {target}")
            
            # Initialize web scanner
            web_scanner = AdvancedWebScanner(self.config, self.logger)
            
            # Run scan
            findings = await web_scanner.scan_target(target, {
                'test_xss': True,
                'test_sqli': True,
                'test_lfi': True,
                'test_command_injection': True,
                'test_csrf': True,
                'test_ssrf': True,
                'test_xxe': True,
                'crawl_depth': 2
            })
            
            # Generate results
            scan_results = {
                "status": "completed",
                "start_time": datetime.now().isoformat(),
                "target": target,
                "run_directory": str(run_dir),
                "findings": [],
                "statistics": {
                    "total_vulnerabilities": len(findings),
                    "critical_vulns": 0,
                    "high_vulns": 0,
                    "medium_vulns": 0,
                    "low_vulns": 0,
                }
            }
            
            # Process findings
            for finding in findings:
                finding_dict = {
                    "vulnerability_type": finding.vuln_type,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "url": finding.url,
                    "parameter": finding.parameter,
                    "payload": finding.payload,
                    "evidence": finding.evidence,
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "cwe_id": finding.cwe_id,
                    "discovery_time": datetime.now().isoformat()
                }
                
                scan_results["findings"].append(finding_dict)
                
                # Update statistics
                severity = finding.severity.lower()
                if severity == "critical":
                    scan_results["statistics"]["critical_vulns"] += 1
                elif severity == "high":
                    scan_results["statistics"]["high_vulns"] += 1
                elif severity == "medium":
                    scan_results["statistics"]["medium_vulns"] += 1
                elif severity == "low":
                    scan_results["statistics"]["low_vulns"] += 1
            
            # Generate report
            await self._generate_html_report(scan_results, run_dir / "reports")
            
            self.logger.info(f"Web scan completed for {target}: {len(findings)} findings")
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Web scan failed for {target}: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _generate_html_report(self, scan_results: Dict[str, Any], output_dir: Path):
        """Generate comprehensive HTML report"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Azaz-El Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .finding {{ background: #fff; border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #f39c12; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #27ae60; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Azaz-El Security Assessment Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Framework Version: {VERSION}</p>
        <p>Target: {scan_results.get('target', 'Unknown')}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> {scan_results['statistics']['total_vulnerabilities']}</p>
        <p><strong>Critical:</strong> {scan_results['statistics']['critical_vulns']}</p>
        <p><strong>High:</strong> {scan_results['statistics']['high_vulns']}</p>
        <p><strong>Medium:</strong> {scan_results['statistics']['medium_vulns']}</p>
        <p><strong>Low:</strong> {scan_results['statistics']['low_vulns']}</p>
    </div>
    
    <h2>Detailed Findings</h2>
"""
        
        for finding in scan_results.get('findings', []):
            severity_class = finding['severity'].lower()
            html_content += f"""
    <div class="finding {severity_class}">
        <h3>{finding['vulnerability_type']} - {finding['severity']}</h3>
        <p><strong>URL:</strong> {finding['url']}</p>
        <p><strong>Parameter:</strong> {finding.get('parameter', 'N/A')}</p>
        <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>
        <p><strong>Remediation:</strong> {finding.get('remediation', 'N/A')}</p>
        <p><strong>CWE ID:</strong> {finding.get('cwe_id', 'N/A')}</p>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        report_file = output_dir / "security_assessment_report.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {report_file}")
    
    def display_interactive_menu(self):
        """Display interactive menu for framework operations"""
        while True:
            print("\n" + "="*60)
            print(f"{APP} {VERSION} - Interactive Menu")
            print("="*60)
            print("1. Add Target")
            print("2. View Targets")
            print("3. Run Web Security Scan")
            print("4. View Recent Runs")
            print("5. Framework Information")
            print("0. Exit")
            print("="*60)
            
            try:
                choice = input("Select option [0-5]: ").strip()
                
                if choice == "1":
                    self._menu_add_target()
                elif choice == "2":
                    self._menu_view_targets()
                elif choice == "3":
                    self._menu_run_web_scan()
                elif choice == "4":
                    self._menu_view_recent_runs()
                elif choice == "5":
                    self._menu_framework_info()
                elif choice == "0":
                    print("\nExiting Azaz-El Framework. Stay secure!")
                    break
                else:
                    print("Invalid option. Please try again.")
                    
            except KeyboardInterrupt:
                print("\n\nExiting Azaz-El Framework. Stay secure!")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _menu_add_target(self):
        """Menu option: Add target"""
        print("\n--- Add Target ---")
        target = input("Enter target (domain or IP): ").strip()
        
        if target:
            if self.add_target(target):
                print(f"Target added successfully: {target}")
            else:
                print(f"Failed to add target or target already exists: {target}")
        else:
            print("No target specified.")
    
    def _menu_view_targets(self):
        """Menu option: View targets"""
        print("\n--- Current Targets ---")
        targets = self.load_targets()
        
        if targets:
            for i, target in enumerate(targets, 1):
                print(f"{i}. {target}")
        else:
            print("No targets configured.")
    
    def _menu_run_web_scan(self):
        """Menu option: Run web scan"""
        print("\n--- Web Security Scan ---")
        target = input("Enter target URL (with http/https): ").strip()
        
        if not target:
            print("No target specified.")
            return
        
        try:
            target = InputValidator.validate_target(target)
            print(f"Starting web scan for: {target}")
            
            # Run web scan
            results = asyncio.run(self.run_web_scan(target))
            
            if results["status"] == "completed":
                print(f"\nWeb scan completed!")
                print(f"Findings: {results['statistics']['total_vulnerabilities']}")
                print(f"Run directory: {results['run_directory']}")
                
                # Ask to open report
                if input("\nOpen HTML report? (y/n): ").lower().startswith('y'):
                    report_path = Path(results['run_directory']) / "reports" / "security_assessment_report.html"
                    if report_path.exists():
                        webbrowser.open(f"file://{report_path.absolute()}")
            else:
                print(f"Scan failed: {results.get('error', 'Unknown error')}")
                
        except Exception as e:
            print(f"Scan failed: {e}")
    
    def _menu_view_recent_runs(self):
        """Menu option: View recent runs"""
        print("\n--- Recent Runs ---")
        
        if not RUNS_DIR.exists():
            print("No runs directory found.")
            return
        
        runs = sorted(RUNS_DIR.glob("azaz_el_*"), key=lambda x: x.stat().st_mtime, reverse=True)[:10]
        
        if runs:
            for i, run_dir in enumerate(runs, 1):
                print(f"{i}. {run_dir.name} - {datetime.fromtimestamp(run_dir.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print("No recent runs found.")
    
    def _menu_framework_info(self):
        """Menu option: Framework information"""
        print(f"\n--- {APP} Framework Information ---")
        print(f"Version: {VERSION}")
        print(f"Author: {AUTHOR}")
        print(f"GitHub: {GITHUB_REPO}")
        print(f"Installation Directory: {HERE}")
        print(f"Configuration File: {CFG_FILE}")
        print(f"Runs Directory: {RUNS_DIR}")
        print(f"Logs Directory: {LOG_DIR}")
        
        print(f"\nFramework Features:")
        print(f"• Advanced vulnerability detection with 8+ attack types")
        print(f"• Intelligent payload generation and evasion techniques")
        print(f"• Structured logging with JSON output and rotation")
        print(f"• Encrypted configuration management")
        print(f"• Comprehensive input validation and sanitization")
        print(f"• Async web scanning with concurrent request handling")
        print(f"• Modular architecture with plugin support")
        print(f"• Professional-grade reporting and visualization")

def setup_argument_parser() -> argparse.ArgumentParser:
    """Setup command line argument parser"""
    parser = argparse.ArgumentParser(
        description=f"{APP} {VERSION} - Advanced Automated Penetration Testing Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
Examples:
  python3 {Path(__file__).name}                    # Run interactive menu
  python3 {Path(__file__).name} -t example.com     # Add target and run interactive menu
  python3 {Path(__file__).name} -t example.com -w  # Run web scan only
  python3 {Path(__file__).name} --list-targets     # List configured targets
  python3 {Path(__file__).name} --test-framework   # Test framework components
        """
    )
    
    parser.add_argument("--target", "-t", help="Add a single target")
    parser.add_argument("--web-scan", "-w", action="store_true", help="Run web security scan only")
    parser.add_argument("--list-targets", action="store_true", help="List all configured targets")
    parser.add_argument("--test-framework", action="store_true", help="Test framework components")
    parser.add_argument("--version", "-v", action="version", version=f"{APP} {VERSION}")
    
    return parser

async def main():
    """Main application entry point"""
    
    # Parse command line arguments
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    try:
        # Initialize framework
        framework = AzazelFramework()
        
        # Display banner
        framework.display_banner()
        
        # Handle command line arguments
        if args.target:
            framework.add_target(args.target)
            print(f"Target added: {args.target}")
        
        if args.list_targets:
            targets = framework.load_targets()
            print(f"\nConfigured Targets ({len(targets)}):")
            for i, target in enumerate(targets, 1):
                print(f"{i}. {target}")
            return
        
        if args.test_framework:
            print("Running framework tests...")
            test_result = subprocess.run([sys.executable, "test_enhanced_framework.py"], 
                                       capture_output=True, text=True)
            print(test_result.stdout)
            if test_result.stderr:
                print("Errors:", test_result.stderr)
            return
        
        if args.web_scan:
            if args.target:
                print(f"Starting web security scan for: {args.target}")
                results = await framework.run_web_scan(args.target)
                if results["status"] == "completed":
                    print(f"Scan completed! Findings: {results['statistics']['total_vulnerabilities']}")
                else:
                    print(f"Scan failed: {results.get('error', 'Unknown error')}")
            else:
                print("Error: --target required for web scan")
            return
        
        # If no specific action, run interactive menu
        framework.display_interactive_menu()
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
    except Exception as e:
        print(f"Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Run the main application
    asyncio.run(main())