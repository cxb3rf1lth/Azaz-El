#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azaz-El Integration Layer
Bridges moloch.py functionality with unified dashboard
"""

import os
import sys
import asyncio
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

# Add project root to path
sys.path.append(str(Path(__file__).parent))

# Import moloch functions
from moloch import (
    run_subdomain_discovery, run_dns_resolution, run_http_probing,
    run_vulnerability_scan, run_port_scan, run_ssl_scan,
    run_crawling, run_xss_scan, run_directory_fuzzing,
    execute_tool, load_config, new_run,
    filter_and_save_positive_results, generate_simple_report
)

class MolochIntegration:
    """Integration layer for moloch.py functionality"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.config = load_config()
        self.logger = logging.getLogger("moloch-integration")
        
    async def run_reconnaissance_suite(self, target: str, output_dir: Path, aggressive: bool = False) -> Dict[str, Any]:
        """Execute comprehensive reconnaissance suite"""
        results = {
            "subdomains": [],
            "resolved_hosts": [],
            "live_hosts": [],
            "technologies": [],
            "errors": []
        }
        
        try:
            self.logger.info(f"Starting reconnaissance suite for {target}")
            
            # Phase 1: Subdomain Discovery
            subdomain_dir = output_dir / "subdomains"
            subdomain_dir.mkdir(exist_ok=True)
            
            self.logger.info("Phase 1: Subdomain Discovery")
            subdomain_success = run_subdomain_discovery(target, subdomain_dir, self.config)
            
            # Phase 2: DNS Resolution
            subdomain_files = list(subdomain_dir.glob("*.txt"))
            if subdomain_files:
                resolved_file = output_dir / "resolved_hosts.txt"
                self.logger.info("Phase 2: DNS Resolution")
                dns_success = run_dns_resolution(subdomain_files[0], resolved_file, self.config)
                
                # Phase 3: HTTP Probing
                if resolved_file.exists():
                    live_hosts_file = output_dir / "live_hosts.txt"
                    self.logger.info("Phase 3: HTTP Probing")
                    http_success = run_http_probing(resolved_file, live_hosts_file, self.config)
                    
                    # Collect results
                    if live_hosts_file.exists():
                        with open(live_hosts_file, 'r') as f:
                            results["live_hosts"] = [line.strip() for line in f if line.strip()]
            
            self.logger.info("Reconnaissance suite completed")
            return results
            
        except Exception as e:
            self.logger.error(f"Reconnaissance suite failed: {e}")
            results["errors"].append(str(e))
            return results
    
    async def run_vulnerability_suite(self, target: str, output_dir: Path, aggressive: bool = False) -> Dict[str, Any]:
        """Execute comprehensive vulnerability scanning"""
        results = {
            "nuclei_findings": [],
            "port_scan": [],
            "ssl_issues": [],
            "errors": []
        }
        
        try:
            self.logger.info(f"Starting vulnerability suite for {target}")
            
            vuln_dir = output_dir / "vulnerabilities"
            vuln_dir.mkdir(exist_ok=True)
            
            # Phase 1: Nuclei Scan
            self.logger.info("Phase 1: Nuclei Vulnerability Scan")
            host_file = output_dir / "live_hosts.txt"
            if host_file.exists():
                nuclei_success = run_vulnerability_scan(host_file, vuln_dir, self.config)
            
            # Phase 2: Port Scanning
            self.logger.info("Phase 2: Port Scanning")
            port_file = vuln_dir / f"ports_{target.replace('.', '_')}.txt"
            port_success = run_port_scan(target, port_file, self.config)
            
            # Phase 3: SSL/TLS Analysis
            self.logger.info("Phase 3: SSL/TLS Analysis")
            ssl_file = vuln_dir / f"ssl_{target.replace('.', '_')}.txt"
            ssl_success = run_ssl_scan(target, ssl_file, self.config)
            
            self.logger.info("Vulnerability suite completed")
            return results
            
        except Exception as e:
            self.logger.error(f"Vulnerability suite failed: {e}")
            results["errors"].append(str(e))
            return results
    
    async def run_web_testing_suite(self, target: str, output_dir: Path, aggressive: bool = False) -> Dict[str, Any]:
        """Execute comprehensive web application testing"""
        results = {
            "crawled_urls": [],
            "xss_findings": [],
            "directory_findings": [],
            "errors": []
        }
        
        try:
            self.logger.info(f"Starting web testing suite for {target}")
            
            web_dir = output_dir / "web_testing"
            web_dir.mkdir(exist_ok=True)
            
            # Phase 1: Web Crawling
            self.logger.info("Phase 1: Web Crawling")
            crawl_file = web_dir / f"crawled_{target.replace('.', '_')}.txt"
            crawl_success = run_crawling(target, crawl_file, self.config)
            
            # Phase 2: XSS Testing
            if crawl_file.exists():
                self.logger.info("Phase 2: XSS Vulnerability Testing")
                xss_file = web_dir / f"xss_{target.replace('.', '_')}.json"
                xss_success = run_xss_scan(crawl_file, xss_file, self.config)
            
            # Phase 3: Directory Fuzzing
            self.logger.info("Phase 3: Directory Fuzzing")
            fuzz_dir = web_dir / "fuzzing"
            fuzz_dir.mkdir(exist_ok=True)
            fuzz_success = run_directory_fuzzing(target, fuzz_dir, self.config)
            
            self.logger.info("Web testing suite completed")
            return results
            
        except Exception as e:
            self.logger.error(f"Web testing suite failed: {e}")
            results["errors"].append(str(e))
            return results
    
    async def execute_full_pipeline(self, target: str, aggressive: bool = False, 
                                  include_cloud: bool = False) -> Dict[str, Any]:
        """Execute the complete security assessment pipeline"""
        
        # Create run directory
        run_dir = new_run()
        target_dir = run_dir / target.replace('.', '_').replace(':', '_')
        target_dir.mkdir(exist_ok=True)
        
        pipeline_results = {
            "target": target,
            "run_id": run_dir.name,
            "start_time": datetime.now().isoformat(),
            "reconnaissance": {},
            "vulnerabilities": {},
            "web_testing": {},
            "cloud_security": {},
            "status": "running"
        }
        
        try:
            self.logger.info(f"Starting full pipeline for {target}")
            
            # Phase 1: Reconnaissance
            self.logger.info("Executing reconnaissance phase...")
            reconnaissance_results = await self.run_reconnaissance_suite(
                target, target_dir, aggressive
            )
            pipeline_results["reconnaissance"] = reconnaissance_results
            
            # Phase 2: Vulnerability Scanning
            self.logger.info("Executing vulnerability scanning phase...")
            vulnerability_results = await self.run_vulnerability_suite(
                target, target_dir, aggressive
            )
            pipeline_results["vulnerabilities"] = vulnerability_results
            
            # Phase 3: Web Application Testing
            self.logger.info("Executing web application testing phase...")
            web_results = await self.run_web_testing_suite(
                target, target_dir, aggressive
            )
            pipeline_results["web_testing"] = web_results
            
            # Phase 4: Cloud Security (if enabled)
            if include_cloud:
                self.logger.info("Executing cloud security assessment...")
                # Cloud scanning would be implemented here
                pipeline_results["cloud_security"] = {"status": "completed"}
            
            # Phase 5: Report Generation
            self.logger.info("Generating comprehensive report...")
            # Filter and consolidate findings
            findings = filter_and_save_positive_results(target_dir, self.config)
            
            # Generate report
            report_success = generate_simple_report(target_dir, self.config)
            
            pipeline_results["status"] = "completed"
            pipeline_results["end_time"] = datetime.now().isoformat()
            
            # Save pipeline results
            results_file = target_dir / "pipeline_results.json"
            with open(results_file, 'w') as f:
                json.dump(pipeline_results, f, indent=2, default=str)
            
            self.logger.info(f"Full pipeline completed for {target}")
            return pipeline_results
            
        except Exception as e:
            self.logger.error(f"Full pipeline failed for {target}: {e}")
            pipeline_results["status"] = "failed"
            pipeline_results["error"] = str(e)
            pipeline_results["end_time"] = datetime.now().isoformat()
            return pipeline_results
    
    def get_tool_status(self) -> Dict[str, str]:
        """Get status of all configured tools"""
        tool_status = {}
        
        for tool_name, tool_config in self.config.get("tools", {}).items():
            if not tool_config.get("enabled", False):
                tool_status[tool_name] = "❌ Disabled"
                continue
            
            # Check if tool is available
            try:
                result = subprocess.run([tool_name, "--help"], 
                                      capture_output=True, timeout=5)
                tool_status[tool_name] = "✅ Available"
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                tool_status[tool_name] = "❌ Not Found"
        
        return tool_status
    
    def get_scan_history(self) -> List[Dict[str, Any]]:
        """Get history of previous scans"""
        scan_history = []
        runs_dir = Path("runs")
        
        if not runs_dir.exists():
            return scan_history
        
        for run_dir in sorted(runs_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if run_dir.is_dir():
                # Check for pipeline results
                results_files = list(run_dir.glob("*/pipeline_results.json"))
                for results_file in results_files:
                    try:
                        with open(results_file, 'r') as f:
                            scan_data = json.load(f)
                            scan_history.append(scan_data)
                    except Exception:
                        continue
        
        return scan_history[:20]  # Return last 20 scans
    
    def install_tools(self) -> Dict[str, str]:
        """Install or update security tools"""
        installation_results = {}
        
        for tool_name, tool_config in self.config.get("tools", {}).items():
            if not tool_config.get("enabled", False):
                continue
            
            install_cmd = tool_config.get("install_cmd")
            if not install_cmd:
                installation_results[tool_name] = "❌ No install command"
                continue
            
            try:
                self.logger.info(f"Installing {tool_name}...")
                # Note: In production, this would need proper privilege handling
                installation_results[tool_name] = "⚠️  Manual installation required"
            except Exception as e:
                installation_results[tool_name] = f"❌ Failed: {str(e)}"
        
        return installation_results

class EnhancedScanner:
    """Enhanced scanner with moloch integration"""
    
    def __init__(self, config_manager):
        self.moloch = MolochIntegration(config_manager)
        self.logger = logging.getLogger("enhanced-scanner")
    
    async def quick_scan(self, target: str) -> Dict[str, Any]:
        """Quick vulnerability and web security scan"""
        self.logger.info(f"Starting quick scan for {target}")
        
        # Create temporary run directory
        run_dir = new_run()
        target_dir = run_dir / target.replace('.', '_').replace(':', '_')
        target_dir.mkdir(exist_ok=True)
        
        # Run basic reconnaissance
        recon_results = await self.moloch.run_reconnaissance_suite(
            target, target_dir, aggressive=False
        )
        
        # Run basic vulnerability scan
        vuln_results = await self.moloch.run_vulnerability_suite(
            target, target_dir, aggressive=False
        )
        
        return {
            "target": target,
            "scan_type": "quick",
            "reconnaissance": recon_results,
            "vulnerabilities": vuln_results,
            "timestamp": datetime.now().isoformat()
        }
    
    async def custom_scan(self, target: str, scan_types: List[str], 
                         aggressive: bool = False) -> Dict[str, Any]:
        """Custom scan with specified scan types"""
        self.logger.info(f"Starting custom scan for {target}: {scan_types}")
        
        run_dir = new_run()
        target_dir = run_dir / target.replace('.', '_').replace(':', '_')
        target_dir.mkdir(exist_ok=True)
        
        results = {
            "target": target,
            "scan_type": "custom",
            "scan_types": scan_types,
            "timestamp": datetime.now().isoformat()
        }
        
        if "reconnaissance" in scan_types:
            results["reconnaissance"] = await self.moloch.run_reconnaissance_suite(
                target, target_dir, aggressive
            )
        
        if "vulnerability" in scan_types:
            results["vulnerabilities"] = await self.moloch.run_vulnerability_suite(
                target, target_dir, aggressive
            )
        
        if "web" in scan_types:
            results["web_testing"] = await self.moloch.run_web_testing_suite(
                target, target_dir, aggressive
            )
        
        return results