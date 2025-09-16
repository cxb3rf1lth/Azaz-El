#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azaz-El v5.0.0-ENHANCED - Advanced Security Assessment CLI
Enhanced command-line interface with comprehensive scanning capabilities
"""

import os
import sys
import argparse
import asyncio
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from core.config import ConfigurationManager
from core.logging import get_logger
from core.reporting import AdvancedReportGenerator
from scanners.web_scanner import AdvancedWebScanner
from scanners.api_scanner import AdvancedAPIScanner
from scanners.cloud_scanner import CloudSecurityScanner
from scanners.infrastructure_scanner import InfrastructureScanner

class AzazelEnhancedCLI:
    """Enhanced command-line interface for Azaz-El framework"""
    
    def __init__(self):
        self.config_manager = ConfigurationManager("moloch.cfg.json")
        self.logger = get_logger("azaz-el-cli")
        self.report_generator = AdvancedReportGenerator(self.config_manager.load_config())
        
    def create_argument_parser(self):
        """Create enhanced argument parser"""
        parser = argparse.ArgumentParser(
            description="Azaz-El v5.0.0-ENHANCED - Advanced Security Assessment Framework",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Full comprehensive scan
  python3 azazel_enhanced.py --target example.com --scan-type all --output-dir results/

  # Web application focused scan
  python3 azazel_enhanced.py --target https://app.example.com --scan-type web --aggressive

  # API security assessment
  python3 azazel_enhanced.py --target https://api.example.com --scan-type api --format json

  # Cloud security review
  python3 azazel_enhanced.py --target https://bucket.s3.amazonaws.com --scan-type cloud

  # Infrastructure assessment
  python3 azazel_enhanced.py --target 192.168.1.0/24 --scan-type infrastructure --threads 50

  # Multiple targets from file
  python3 azazel_enhanced.py --target-file targets.txt --scan-type all --parallel

  # Compliance focused scan
  python3 azazel_enhanced.py --target example.com --compliance pci-dss,owasp --report-format pdf
            """
        )
        
        # Target specification
        target_group = parser.add_mutually_exclusive_group(required=False)
        target_group.add_argument(
            '--target', '-t',
            help='Single target URL, IP, or domain'
        )
        target_group.add_argument(
            '--target-file', '-tf',
            help='File containing list of targets (one per line)'
        )
        
        # Scan configuration
        parser.add_argument(
            '--scan-type', '-s',
            choices=['all', 'web', 'api', 'cloud', 'infrastructure', 'network'],
            default='all',
            help='Type of security scan to perform (default: all)'
        )
        
        parser.add_argument(
            '--aggressive', '-a',
            action='store_true',
            help='Enable aggressive scanning mode (more comprehensive but slower)'
        )
        
        parser.add_argument(
            '--stealth', '-st',
            action='store_true',
            help='Enable stealth mode (slower but less detectable)'
        )
        
        parser.add_argument(
            '--threads', '-th',
            type=int,
            default=10,
            help='Number of concurrent threads (default: 10)'
        )
        
        parser.add_argument(
            '--timeout', '-to',
            type=int,
            default=30,
            help='Request timeout in seconds (default: 30)'
        )
        
        # Output and reporting
        parser.add_argument(
            '--output-dir', '-o',
            default='runs',
            help='Output directory for results (default: runs)'
        )
        
        parser.add_argument(
            '--report-format', '-rf',
            choices=['html', 'json', 'csv', 'xml', 'all'],
            default='html',
            help='Report output format (default: html)'
        )
        
        parser.add_argument(
            '--no-report', '-nr',
            action='store_true',
            help='Skip report generation (faster for large scans)'
        )
        
        # Compliance and standards
        parser.add_argument(
            '--compliance', '-c',
            help='Compliance frameworks to check (comma-separated: owasp,nist,pci-dss,iso27001)'
        )
        
        # Advanced options
        parser.add_argument(
            '--exclude-paths', '-ep',
            help='Paths to exclude from scanning (comma-separated)'
        )
        
        parser.add_argument(
            '--include-only', '-io',
            help='Only scan specified paths (comma-separated)'
        )
        
        parser.add_argument(
            '--user-agent', '-ua',
            default='Azaz-El-Scanner/5.0',
            help='Custom User-Agent string'
        )
        
        parser.add_argument(
            '--headers', '-hd',
            help='Custom headers (format: "Header1:Value1,Header2:Value2")'
        )
        
        parser.add_argument(
            '--auth', '-auth',
            help='Authentication (format: "bearer:token" or "basic:user:pass")'
        )
        
        # Parallel processing
        parser.add_argument(
            '--parallel', '-p',
            action='store_true',
            help='Enable parallel scanning of multiple targets'
        )
        
        parser.add_argument(
            '--max-parallel', '-mp',
            type=int,
            default=5,
            help='Maximum parallel scans (default: 5)'
        )
        
        # Debugging and verbosity
        parser.add_argument(
            '--verbose', '-v',
            action='count',
            default=0,
            help='Increase verbosity (-v, -vv, -vvv)'
        )
        
        parser.add_argument(
            '--debug', '-d',
            action='store_true',
            help='Enable debug mode'
        )
        
        parser.add_argument(
            '--quiet', '-q',
            action='store_true',
            help='Suppress non-essential output'
        )
        
        # Configuration
        parser.add_argument(
            '--config', '-cfg',
            help='Custom configuration file path'
        )
        
        parser.add_argument(
            '--list-scanners',
            action='store_true',
            help='List available scanners and exit'
        )
        
        parser.add_argument(
            '--version',
            action='version',
            version='Azaz-El v5.0.0-ENHANCED'
        )
        
        return parser
    
    async def run_scan(self, args):
        """Execute the security scan based on arguments"""
        try:
            # Setup scan configuration
            scan_config = self._prepare_scan_config(args)
            
            # Get targets
            targets = self._get_targets(args)
            
            if not targets:
                self.logger.error("No valid targets specified")
                return False
            
            # Create output directory
            output_dir = Path(args.output_dir) / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            self.logger.info(f"Starting Azaz-El v5.0.0-ENHANCED scan")
            self.logger.info(f"Targets: {len(targets)}")
            self.logger.info(f"Scan type: {args.scan_type}")
            self.logger.info(f"Output directory: {output_dir}")
            
            # Execute scans
            all_findings = {}
            
            if args.parallel and len(targets) > 1:
                all_findings = await self._run_parallel_scans(targets, args, scan_config, output_dir)
            else:
                all_findings = await self._run_sequential_scans(targets, args, scan_config, output_dir)
            
            # Generate comprehensive report
            if not args.no_report:
                await self._generate_reports(all_findings, output_dir, args, scan_config)
            
            self.logger.info(f"Scan completed successfully. Results saved to: {output_dir}")
            return True
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
            return False
    
    def _prepare_scan_config(self, args):
        """Prepare scan configuration from arguments"""
        config = {
            'aggressive': args.aggressive,
            'stealth': args.stealth,
            'threads': args.threads,
            'timeout': args.timeout,
            'user_agent': args.user_agent,
            'verbose': args.verbose,
            'debug': args.debug
        }
        
        # Parse headers
        if args.headers:
            headers = {}
            for header in args.headers.split(','):
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
            config['custom_headers'] = headers
        
        # Parse authentication
        if args.auth:
            auth_parts = args.auth.split(':')
            if len(auth_parts) >= 2:
                auth_type = auth_parts[0].lower()
                if auth_type == 'bearer':
                    config['auth'] = {'type': 'bearer', 'token': auth_parts[1]}
                elif auth_type == 'basic' and len(auth_parts) >= 3:
                    config['auth'] = {'type': 'basic', 'username': auth_parts[1], 'password': auth_parts[2]}
        
        # Parse exclusions and inclusions
        if args.exclude_paths:
            config['exclude_paths'] = [p.strip() for p in args.exclude_paths.split(',')]
        
        if args.include_only:
            config['include_only'] = [p.strip() for p in args.include_only.split(',')]
        
        # Parse compliance requirements
        if args.compliance:
            config['compliance_frameworks'] = [f.strip().upper() for f in args.compliance.split(',')]
        
        return config
    
    def _get_targets(self, args):
        """Get list of targets from arguments"""
        targets = []
        
        if args.target:
            targets.append(args.target)
        elif args.target_file:
            try:
                with open(args.target_file, 'r') as f:
                    targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except FileNotFoundError:
                self.logger.error(f"Target file not found: {args.target_file}")
                return []
        
        # Validate targets
        valid_targets = []
        for target in targets:
            if self._validate_target(target):
                valid_targets.append(target)
            else:
                self.logger.warning(f"Invalid target skipped: {target}")
        
        return valid_targets
    
    def _validate_target(self, target):
        """Validate target format"""
        import re
        
        # URL pattern
        url_pattern = r'^https?://.+'
        # IP pattern
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$'
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        
        return (re.match(url_pattern, target) or 
                re.match(ip_pattern, target) or 
                re.match(domain_pattern, target))
    
    async def _run_parallel_scans(self, targets, args, scan_config, output_dir):
        """Run scans in parallel for multiple targets"""
        self.logger.info(f"Running parallel scans for {len(targets)} targets")
        
        semaphore = asyncio.Semaphore(args.max_parallel)
        
        async def scan_target(target):
            async with semaphore:
                return await self._scan_single_target(target, args, scan_config, output_dir)
        
        # Create tasks for all targets
        tasks = [scan_target(target) for target in targets]
        
        # Execute with progress tracking
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        all_findings = {}
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Scan failed for {targets[i]}: {result}")
            else:
                all_findings[targets[i]] = result
        
        return all_findings
    
    async def _run_sequential_scans(self, targets, args, scan_config, output_dir):
        """Run scans sequentially"""
        all_findings = {}
        
        for i, target in enumerate(targets, 1):
            self.logger.info(f"Scanning target {i}/{len(targets)}: {target}")
            
            try:
                findings = await self._scan_single_target(target, args, scan_config, output_dir)
                all_findings[target] = findings
            except Exception as e:
                self.logger.error(f"Scan failed for {target}: {e}")
                all_findings[target] = {}
        
        return all_findings
    
    async def _scan_single_target(self, target, args, scan_config, output_dir):
        """Scan a single target with specified scanners"""
        findings = {}
        
        # Determine which scanners to run
        scanners_to_run = self._get_scanners_for_target(target, args.scan_type)
        
        for scanner_name in scanners_to_run:
            try:
                self.logger.info(f"Running {scanner_name} scan on {target}")
                
                if scanner_name == 'web':
                    scanner = AdvancedWebScanner(scan_config)
                    findings['web'] = await scanner.scan_target(target, scan_config)
                
                elif scanner_name == 'api':
                    scanner = AdvancedAPIScanner(scan_config)
                    findings['api'] = await scanner.scan_target(target, scan_config)
                
                elif scanner_name == 'cloud':
                    scanner = CloudSecurityScanner(scan_config)
                    findings['cloud'] = await scanner.scan_target(target, scan_config)
                
                elif scanner_name == 'infrastructure':
                    scanner = InfrastructureScanner(scan_config)
                    findings['infrastructure'] = await scanner.scan_target(target, scan_config)
                
                self.logger.info(f"{scanner_name} scan completed: {len(findings.get(scanner_name, []))} findings")
                
            except Exception as e:
                self.logger.error(f"{scanner_name} scan failed for {target}: {e}")
                findings[scanner_name] = []
        
        return findings
    
    def _get_scanners_for_target(self, target, scan_type):
        """Determine which scanners to run based on target and scan type"""
        scanners = []
        
        if scan_type == 'all':
            scanners = ['web', 'api', 'cloud', 'infrastructure']
        elif scan_type == 'web':
            scanners = ['web']
        elif scan_type == 'api':
            scanners = ['api']
        elif scan_type == 'cloud':
            scanners = ['cloud']
        elif scan_type == 'infrastructure' or scan_type == 'network':
            scanners = ['infrastructure']
        
        # Filter based on target type
        if target.startswith('http'):
            # HTTP/HTTPS targets - good for web, api, cloud
            if scan_type == 'all':
                scanners = ['web', 'api', 'cloud']
        elif '/' in target or target.count('.') == 3:
            # Network range or IP - good for infrastructure
            if scan_type == 'all':
                scanners = ['infrastructure']
        
        return scanners
    
    async def _generate_reports(self, all_findings, output_dir, args, scan_config):
        """Generate comprehensive reports"""
        self.logger.info("Generating comprehensive security reports")
        
        # Prepare metadata
        scan_metadata = {
            'scan_type': args.scan_type,
            'start_time': datetime.now().isoformat(),
            'targets_scanned': len(all_findings),
            'scanner_version': 'v5.0.0-ENHANCED',
            'scan_config': scan_config
        }
        
        # Flatten findings from all targets
        combined_findings = {}
        for target, target_findings in all_findings.items():
            for scanner_type, findings in target_findings.items():
                if scanner_type not in combined_findings:
                    combined_findings[scanner_type] = []
                combined_findings[scanner_type].extend(findings)
        
        # Generate reports
        success = self.report_generator.generate_comprehensive_report(
            output_dir, combined_findings, scan_metadata
        )
        
        if success:
            self.logger.info(f"Reports generated successfully in {output_dir}")
        else:
            self.logger.error("Report generation failed")
    
    def list_scanners(self):
        """List available scanners"""
        scanners = {
            'web': 'Advanced Web Application Security Scanner',
            'api': 'API Security Assessment Scanner (REST/GraphQL/SOAP)',
            'cloud': 'Multi-Cloud Security Scanner (AWS/Azure/GCP)',
            'infrastructure': 'Network and Infrastructure Security Scanner'
        }
        
        print("\n🔍 Available Security Scanners:")
        print("=" * 50)
        
        for scanner_id, description in scanners.items():
            print(f"  {scanner_id:<15} - {description}")
        
        print("\nUsage examples:")
        print("  --scan-type web              # Web application focused")
        print("  --scan-type api              # API security assessment")
        print("  --scan-type cloud            # Cloud security review")
        print("  --scan-type infrastructure   # Network and system scan")
        print("  --scan-type all              # Comprehensive scan (default)")

def main():
    """Main entry point"""
    cli = AzazelEnhancedCLI()
    parser = cli.create_argument_parser()
    args = parser.parse_args()
    
    # Handle special actions
    if args.list_scanners:
        cli.list_scanners()
        return
    
    # Validate target requirement for scans
    if not args.target and not args.target_file:
        parser.error("Target is required for scanning operations. Use --target or --target-file")
    
    # Configure logging level
    log_level = "INFO"
    if args.debug:
        log_level = "DEBUG"
    elif args.verbose >= 2:
        log_level = "DEBUG"
    elif args.verbose == 1:
        log_level = "INFO"
    elif args.quiet:
        log_level = "ERROR"
    
    # Run the scan
    try:
        success = asyncio.run(cli.run_scan(args))
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()