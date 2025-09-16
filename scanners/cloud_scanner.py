"""
Cloud Security Scanner
Comprehensive AWS, Azure, GCP security assessment capabilities
"""

import json
import asyncio
import aiohttp
import re
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse
from pathlib import Path
from dataclasses import dataclass
import time

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.exceptions import ScanningError, NetworkError
from core.logging import get_logger

@dataclass
class CloudVulnerabilityFinding:
    """Structure for cloud vulnerability findings"""
    vuln_type: str
    severity: str
    confidence: str
    resource: str
    cloud_provider: str = ""
    service: str = ""
    region: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    compliance_impact: List[str] = None
    risk_score: float = 0.0
    timestamp: str = ""

class CloudSecurityScanner:
    """Advanced cloud security assessment scanner"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger("cloud-scanner")
        self.session = None
        self.findings = []
        
        # Cloud service patterns
        self.aws_patterns = {
            's3': [
                r'https?://[\w.-]+\.s3[\w.-]*\.amazonaws\.com',
                r'https?://s3[\w.-]*\.amazonaws\.com/[\w.-]+',
                r'https?://[\w.-]+\.s3-website[-\w.]*\.amazonaws\.com'
            ],
            'cloudfront': [
                r'https?://[\w.-]+\.cloudfront\.net'
            ],
            'ec2': [
                r'https?://ec2-[\d-]+\.[\w.-]+\.compute\.amazonaws\.com'
            ],
            'elb': [
                r'https?://[\w.-]+\.elb\.amazonaws\.com',
                r'https?://[\w.-]+\.[\w.-]+\.elb\.amazonaws\.com'
            ],
            'apigateway': [
                r'https?://[\w.-]+\.execute-api\.[\w.-]+\.amazonaws\.com'
            ]
        }
        
        self.azure_patterns = {
            'blob': [
                r'https?://[\w.-]+\.blob\.core\.windows\.net',
                r'https?://[\w.-]+\.blob\.core\.usgovcloudapi\.net'
            ],
            'webapp': [
                r'https?://[\w.-]+\.azurewebsites\.net',
                r'https?://[\w.-]+\.azurewebsites\.us'
            ],
            'function': [
                r'https?://[\w.-]+\.azurewebsites\.net/api',
                r'https?://[\w.-]+\.azure-api\.net'
            ]
        }
        
        self.gcp_patterns = {
            'storage': [
                r'https?://storage\.googleapis\.com/[\w.-]+',
                r'https?://[\w.-]+\.storage\.googleapis\.com'
            ],
            'appengine': [
                r'https?://[\w.-]+\.appspot\.com'
            ],
            'functions': [
                r'https?://[\w.-]+-[\w.-]+\.cloudfunctions\.net'
            ]
        }
        
        self.cloud_misconfigurations = [
            'public bucket', 'open s3', 'misconfigured cors',
            'weak ssl', 'default credentials', 'exposed admin'
        ]
    
    async def scan_target(self, target_url: str, scan_options: Dict[str, Any] = None) -> List[CloudVulnerabilityFinding]:
        """Perform comprehensive cloud security scan"""
        if scan_options is None:
            scan_options = {}
        
        self.logger.info(f"Starting cloud security scan for {target_url}")
        
        try:
            # Initialize HTTP session
            connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': 'Cloud-Scanner/5.0'}
            )
            
            # Phase 1: Cloud Service Discovery
            await self._cloud_service_discovery(target_url, scan_options)
            
            # Phase 2: AWS Security Assessment
            await self._aws_security_assessment(target_url, scan_options)
            
            # Phase 3: Azure Security Assessment  
            await self._azure_security_assessment(target_url, scan_options)
            
            # Phase 4: GCP Security Assessment
            await self._gcp_security_assessment(target_url, scan_options)
            
            # Phase 5: Multi-Cloud Misconfigurations
            await self._multi_cloud_misconfigurations(target_url, scan_options)
            
            # Phase 6: Cloud Compliance Assessment
            await self._cloud_compliance_assessment(scan_options)
            
            self.logger.info(f"Cloud security scan completed with {len(self.findings)} findings")
            return self.findings
            
        except Exception as e:
            self.logger.error(f"Cloud security scan failed: {e}")
            raise ScanningError(f"Cloud security scan failed: {e}")
        finally:
            if self.session:
                await self.session.close()
    
    async def _cloud_service_discovery(self, target_url: str, scan_options: Dict[str, Any]):
        """Discover cloud services and infrastructure"""
        self.logger.info("Phase 1: Cloud Service Discovery")
        
        try:
            # Analyze target URL for cloud patterns
            await self._analyze_url_patterns(target_url)
            
            # DNS enumeration for cloud services
            await self._enumerate_cloud_dns(target_url)
            
            # HTTP header analysis
            await self._analyze_cloud_headers(target_url)
            
        except Exception as e:
            self.logger.error(f"Cloud service discovery failed: {e}")
    
    async def _analyze_url_patterns(self, target_url: str):
        """Analyze URL patterns to identify cloud services"""
        url = target_url.lower()
        
        # Check AWS patterns
        for service, patterns in self.aws_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url):
                    finding = CloudVulnerabilityFinding(
                        vuln_type="Cloud Service Discovery",
                        severity="Info",
                        confidence="High",
                        resource=target_url,
                        cloud_provider="AWS",
                        service=service,
                        description=f"AWS {service} service detected",
                        remediation="Review security configuration of identified service"
                    )
                    self.findings.append(finding)
                    await self._detailed_aws_analysis(target_url, service)
        
        # Check Azure patterns
        for service, patterns in self.azure_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url):
                    finding = CloudVulnerabilityFinding(
                        vuln_type="Cloud Service Discovery",
                        severity="Info", 
                        confidence="High",
                        resource=target_url,
                        cloud_provider="Azure",
                        service=service,
                        description=f"Azure {service} service detected",
                        remediation="Review security configuration of identified service"
                    )
                    self.findings.append(finding)
                    await self._detailed_azure_analysis(target_url, service)
        
        # Check GCP patterns
        for service, patterns in self.gcp_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url):
                    finding = CloudVulnerabilityFinding(
                        vuln_type="Cloud Service Discovery",
                        severity="Info",
                        confidence="High", 
                        resource=target_url,
                        cloud_provider="GCP",
                        service=service,
                        description=f"GCP {service} service detected",
                        remediation="Review security configuration of identified service"
                    )
                    self.findings.append(finding)
                    await self._detailed_gcp_analysis(target_url, service)
    
    async def _enumerate_cloud_dns(self, target_url: str):
        """Enumerate DNS records for cloud service discovery"""
        try:
            domain = urlparse(target_url).netloc
            
            # Common cloud subdomains
            cloud_subdomains = [
                'api', 'app', 'admin', 'dev', 'test', 'staging', 'prod',
                's3', 'cdn', 'static', 'assets', 'files', 'backup',
                'mail', 'email', 'mx', 'www'
            ]
            
            for subdomain in cloud_subdomains:
                test_domain = f"{subdomain}.{domain}"
                await self._test_cloud_subdomain(test_domain)
                
        except Exception as e:
            self.logger.debug(f"DNS enumeration failed: {e}")
    
    async def _test_cloud_subdomain(self, domain: str):
        """Test individual subdomain for cloud services"""
        try:
            test_url = f"https://{domain}"
            async with self.session.get(test_url, allow_redirects=False) as response:
                if response.status in [200, 301, 302, 403, 404]:
                    # Analyze response for cloud indicators
                    headers = dict(response.headers)
                    await self._analyze_response_for_cloud_services(test_url, headers)
                    
        except Exception as e:
            # Try HTTP if HTTPS fails
            try:
                test_url = f"http://{domain}"
                async with self.session.get(test_url, allow_redirects=False) as response:
                    if response.status in [200, 301, 302, 403, 404]:
                        headers = dict(response.headers)
                        await self._analyze_response_for_cloud_services(test_url, headers)
            except:
                pass
    
    async def _analyze_cloud_headers(self, target_url: str):
        """Analyze HTTP headers for cloud service indicators"""
        try:
            async with self.session.get(target_url) as response:
                headers = dict(response.headers)
                await self._analyze_response_for_cloud_services(target_url, headers)
                
        except Exception as e:
            self.logger.debug(f"Header analysis failed: {e}")
    
    async def _analyze_response_for_cloud_services(self, url: str, headers: Dict[str, str]):
        """Analyze response headers for cloud service indicators"""
        cloud_indicators = {
            'AWS': ['AmazonS3', 'CloudFront', 'amazonaws'],
            'Azure': ['Microsoft-Azure', 'azurewebsites', 'azure'],
            'GCP': ['Google Cloud', 'googleapis', 'appspot']
        }
        
        for provider, indicators in cloud_indicators.items():
            for header_name, header_value in headers.items():
                for indicator in indicators:
                    if indicator.lower() in header_value.lower():
                        finding = CloudVulnerabilityFinding(
                            vuln_type="Cloud Service Header Detection",
                            severity="Info",
                            confidence="Medium",
                            resource=url,
                            cloud_provider=provider,
                            evidence=f"{header_name}: {header_value}",
                            description=f"{provider} service detected via headers",
                            remediation="Review header exposure and security implications"
                        )
                        self.findings.append(finding)
    
    async def _aws_security_assessment(self, target_url: str, scan_options: Dict[str, Any]):
        """Comprehensive AWS security assessment"""
        self.logger.info("Phase 2: AWS Security Assessment")
        
        # Test for common AWS misconfigurations
        await self._test_s3_bucket_security(target_url)
        await self._test_cloudfront_security(target_url)
        await self._test_api_gateway_security(target_url)
    
    async def _detailed_aws_analysis(self, target_url: str, service: str):
        """Detailed analysis for specific AWS service"""
        if service == 's3':
            await self._test_s3_bucket_security(target_url)
        elif service == 'cloudfront':
            await self._test_cloudfront_security(target_url)
        elif service == 'apigateway':
            await self._test_api_gateway_security(target_url)
    
    async def _test_s3_bucket_security(self, target_url: str):
        """Test S3 bucket security configurations"""
        try:
            # Extract bucket name from URL
            bucket_patterns = [
                r'https?://([\w.-]+)\.s3[\w.-]*\.amazonaws\.com',
                r'https?://s3[\w.-]*\.amazonaws\.com/([\w.-]+)'
            ]
            
            bucket_name = None
            for pattern in bucket_patterns:
                match = re.search(pattern, target_url)
                if match:
                    bucket_name = match.group(1)
                    break
            
            if not bucket_name:
                return
            
            # Test bucket enumeration
            await self._test_s3_bucket_enumeration(bucket_name)
            
            # Test bucket listing
            await self._test_s3_bucket_listing(bucket_name)
            
            # Test bucket write permissions
            await self._test_s3_bucket_write(bucket_name)
            
        except Exception as e:
            self.logger.debug(f"S3 security test failed: {e}")
    
    async def _test_s3_bucket_enumeration(self, bucket_name: str):
        """Test S3 bucket enumeration"""
        try:
            # Try different bucket URL formats
            test_urls = [
                f"https://{bucket_name}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{bucket_name}",
                f"https://{bucket_name}.s3-website-us-east-1.amazonaws.com"
            ]
            
            for url in test_urls:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if bucket listing is exposed
                        if '<ListBucketResult' in content or '<Contents>' in content:
                            finding = CloudVulnerabilityFinding(
                                vuln_type="S3 Bucket Public Listing",
                                severity="High",
                                confidence="High",
                                resource=url,
                                cloud_provider="AWS",
                                service="s3",
                                evidence=content[:500],
                                description="S3 bucket allows public listing of contents",
                                remediation="Configure bucket policy to restrict public access",
                                compliance_impact=["PCI-DSS", "GDPR", "HIPAA"]
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            self.logger.debug(f"S3 enumeration test failed: {e}")
    
    async def _test_s3_bucket_listing(self, bucket_name: str):
        """Test S3 bucket listing permissions"""
        try:
            list_url = f"https://{bucket_name}.s3.amazonaws.com/?list-type=2"
            async with self.session.get(list_url) as response:
                if response.status == 200:
                    content = await response.text()
                    if 'ListBucketResult' in content:
                        finding = CloudVulnerabilityFinding(
                            vuln_type="S3 Bucket List Access",
                            severity="Medium",
                            confidence="High",
                            resource=list_url,
                            cloud_provider="AWS",
                            service="s3",
                            description="S3 bucket allows public listing via API",
                            remediation="Remove s3:ListBucket permission for public access"
                        )
                        self.findings.append(finding)
                        
        except Exception as e:
            self.logger.debug(f"S3 listing test failed: {e}")
    
    async def _test_s3_bucket_write(self, bucket_name: str):
        """Test S3 bucket write permissions"""
        try:
            # Test PUT request to upload a test file
            test_key = "security-test.txt"
            put_url = f"https://{bucket_name}.s3.amazonaws.com/{test_key}"
            
            test_content = "Security test - please delete"
            async with self.session.put(put_url, data=test_content) as response:
                if response.status in [200, 204]:
                    finding = CloudVulnerabilityFinding(
                        vuln_type="S3 Bucket Public Write Access",
                        severity="Critical",
                        confidence="High",
                        resource=put_url,
                        cloud_provider="AWS",
                        service="s3",
                        description="S3 bucket allows public write access",
                        remediation="Remove s3:PutObject permission for public access",
                        compliance_impact=["PCI-DSS", "GDPR", "HIPAA", "SOX"]
                    )
                    self.findings.append(finding)
                    
                    # Try to delete the test file
                    async with self.session.delete(put_url) as del_response:
                        pass  # Clean up test file
                        
        except Exception as e:
            self.logger.debug(f"S3 write test failed: {e}")
    
    async def _test_cloudfront_security(self, target_url: str):
        """Test CloudFront security configurations"""
        try:
            async with self.session.get(target_url) as response:
                headers = dict(response.headers)
                
                # Check for CloudFront indicators
                if 'cloudfront' in headers.get('via', '').lower():
                    # Test for missing security headers
                    security_headers = [
                        'strict-transport-security',
                        'x-content-type-options',
                        'x-frame-options',
                        'content-security-policy'
                    ]
                    
                    missing_headers = [h for h in security_headers if h not in headers]
                    
                    if missing_headers:
                        finding = CloudVulnerabilityFinding(
                            vuln_type="CloudFront Missing Security Headers",
                            severity="Medium",
                            confidence="High",
                            resource=target_url,
                            cloud_provider="AWS",
                            service="cloudfront",
                            evidence=f"Missing: {', '.join(missing_headers)}",
                            description="CloudFront distribution lacks security headers",
                            remediation="Configure security headers in CloudFront response headers policy"
                        )
                        self.findings.append(finding)
                        
        except Exception as e:
            self.logger.debug(f"CloudFront security test failed: {e}")
    
    async def _test_api_gateway_security(self, target_url: str):
        """Test API Gateway security configurations"""
        try:
            # Check if URL matches API Gateway pattern
            if 'execute-api' in target_url and 'amazonaws.com' in target_url:
                async with self.session.get(target_url) as response:
                    # Test for missing authentication
                    if response.status == 200:
                        content = await response.text()
                        
                        # Look for API content without authentication
                        api_indicators = ['{"', '[{', 'api', 'data']
                        if any(indicator in content.lower() for indicator in api_indicators):
                            finding = CloudVulnerabilityFinding(
                                vuln_type="API Gateway Unauthenticated Access",
                                severity="High",
                                confidence="Medium",
                                resource=target_url,
                                cloud_provider="AWS",
                                service="apigateway",
                                description="API Gateway endpoint accessible without authentication",
                                remediation="Configure authorizers or API keys for the API"
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            self.logger.debug(f"API Gateway security test failed: {e}")
    
    async def _azure_security_assessment(self, target_url: str, scan_options: Dict[str, Any]):
        """Comprehensive Azure security assessment"""
        self.logger.info("Phase 3: Azure Security Assessment")
        
        await self._test_azure_blob_security(target_url)
        await self._test_azure_webapp_security(target_url)
    
    async def _detailed_azure_analysis(self, target_url: str, service: str):
        """Detailed analysis for specific Azure service"""
        if service == 'blob':
            await self._test_azure_blob_security(target_url)
        elif service == 'webapp':
            await self._test_azure_webapp_security(target_url)
    
    async def _test_azure_blob_security(self, target_url: str):
        """Test Azure Blob Storage security"""
        try:
            if 'blob.core.windows.net' in target_url:
                # Test container listing
                container_url = target_url.split('?')[0]  # Remove query parameters
                if not container_url.endswith('/'):
                    container_url += '/'
                    
                list_url = f"{container_url}?restype=container&comp=list"
                async with self.session.get(list_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        if '<Blobs>' in content:
                            finding = CloudVulnerabilityFinding(
                                vuln_type="Azure Blob Container Public Listing",
                                severity="High",
                                confidence="High",
                                resource=list_url,
                                cloud_provider="Azure",
                                service="blob",
                                evidence=content[:500],
                                description="Azure Blob container allows public listing",
                                remediation="Configure container access level to private"
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            self.logger.debug(f"Azure Blob security test failed: {e}")
    
    async def _test_azure_webapp_security(self, target_url: str):
        """Test Azure Web App security"""
        try:
            if 'azurewebsites.net' in target_url:
                async with self.session.get(target_url) as response:
                    headers = dict(response.headers)
                    
                    # Check for Azure-specific headers and misconfigurations
                    if 'server' in headers and 'iis' in headers['server'].lower():
                        # Test for common Azure Web App misconfigurations
                        test_paths = [
                            '/.env',
                            '/web.config',
                            '/App_Data/',
                            '/bin/',
                            '/.git/',
                            '/debug'
                        ]
                        
                        for path in test_paths:
                            test_url = f"{target_url.rstrip('/')}{path}"
                            async with self.session.get(test_url) as test_response:
                                if test_response.status == 200:
                                    finding = CloudVulnerabilityFinding(
                                        vuln_type="Azure Web App Information Disclosure",
                                        severity="Medium",
                                        confidence="High",
                                        resource=test_url,
                                        cloud_provider="Azure",
                                        service="webapp",
                                        description=f"Sensitive path {path} accessible",
                                        remediation="Configure web.config to block access to sensitive paths"
                                    )
                                    self.findings.append(finding)
                                    
        except Exception as e:
            self.logger.debug(f"Azure Web App security test failed: {e}")
    
    async def _gcp_security_assessment(self, target_url: str, scan_options: Dict[str, Any]):
        """Comprehensive GCP security assessment"""
        self.logger.info("Phase 4: GCP Security Assessment")
        
        await self._test_gcp_storage_security(target_url)
        await self._test_gcp_appengine_security(target_url)
    
    async def _detailed_gcp_analysis(self, target_url: str, service: str):
        """Detailed analysis for specific GCP service"""
        if service == 'storage':
            await self._test_gcp_storage_security(target_url)
        elif service == 'appengine':
            await self._test_gcp_appengine_security(target_url)
    
    async def _test_gcp_storage_security(self, target_url: str):
        """Test Google Cloud Storage security"""
        try:
            if 'googleapis.com' in target_url or 'storage.googleapis.com' in target_url:
                # Extract bucket name
                bucket_match = re.search(r'storage\.googleapis\.com/([\w.-]+)', target_url)
                if bucket_match:
                    bucket_name = bucket_match.group(1)
                    
                    # Test bucket listing
                    list_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"
                    async with self.session.get(list_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            try:
                                data = json.loads(content)
                                if 'items' in data:
                                    finding = CloudVulnerabilityFinding(
                                        vuln_type="GCP Storage Bucket Public Listing",
                                        severity="High",
                                        confidence="High",
                                        resource=list_url,
                                        cloud_provider="GCP",
                                        service="storage",
                                        description="GCP Storage bucket allows public listing",
                                        remediation="Configure bucket IAM to restrict public access"
                                    )
                                    self.findings.append(finding)
                            except json.JSONDecodeError:
                                pass
                                
        except Exception as e:
            self.logger.debug(f"GCP Storage security test failed: {e}")
    
    async def _test_gcp_appengine_security(self, target_url: str):
        """Test Google App Engine security"""
        try:
            if 'appspot.com' in target_url:
                # Test for common App Engine misconfigurations
                test_paths = [
                    '/_ah/admin',
                    '/_ah/stats',
                    '/admin',
                    '/.env',
                    '/app.yaml'
                ]
                
                for path in test_paths:
                    test_url = f"{target_url.rstrip('/')}{path}"
                    async with self.session.get(test_url) as response:
                        if response.status == 200:
                            finding = CloudVulnerabilityFinding(
                                vuln_type="GCP App Engine Information Disclosure",
                                severity="Medium",
                                confidence="High",
                                resource=test_url,
                                cloud_provider="GCP",
                                service="appengine",
                                description=f"Sensitive App Engine path {path} accessible",
                                remediation="Configure app.yaml to restrict access to admin paths"
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            self.logger.debug(f"GCP App Engine security test failed: {e}")
    
    async def _multi_cloud_misconfigurations(self, target_url: str, scan_options: Dict[str, Any]):
        """Test for common multi-cloud misconfigurations"""
        self.logger.info("Phase 5: Multi-Cloud Misconfigurations")
        
        await self._test_cors_misconfigurations(target_url)
        await self._test_ssl_tls_configuration(target_url)
        await self._test_cloud_metadata_exposure(target_url)
    
    async def _test_cors_misconfigurations(self, target_url: str):
        """Test for CORS misconfigurations"""
        try:
            headers = {'Origin': 'https://evil.com'}
            async with self.session.get(target_url, headers=headers) as response:
                cors_headers = {
                    'access-control-allow-origin': response.headers.get('access-control-allow-origin'),
                    'access-control-allow-credentials': response.headers.get('access-control-allow-credentials')
                }
                
                if cors_headers['access-control-allow-origin'] == '*' and cors_headers['access-control-allow-credentials'] == 'true':
                    finding = CloudVulnerabilityFinding(
                        vuln_type="CORS Misconfiguration",
                        severity="High",
                        confidence="High",
                        resource=target_url,
                        evidence=str(cors_headers),
                        description="Dangerous CORS configuration allows any origin with credentials",
                        remediation="Configure specific allowed origins and avoid wildcards with credentials"
                    )
                    self.findings.append(finding)
                    
        except Exception as e:
            self.logger.debug(f"CORS test failed: {e}")
    
    async def _test_ssl_tls_configuration(self, target_url: str):
        """Test SSL/TLS configuration for cloud services"""
        try:
            async with self.session.get(target_url) as response:
                # Check for HSTS header
                if 'strict-transport-security' not in response.headers:
                    finding = CloudVulnerabilityFinding(
                        vuln_type="Missing HSTS Header",
                        severity="Medium",
                        confidence="High",
                        resource=target_url,
                        description="Cloud service lacks HTTP Strict Transport Security",
                        remediation="Configure HSTS header on the cloud service"
                    )
                    self.findings.append(finding)
                    
        except Exception as e:
            self.logger.debug(f"SSL/TLS test failed: {e}")
    
    async def _test_cloud_metadata_exposure(self, target_url: str):
        """Test for cloud metadata service exposure"""
        metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://169.254.169.254/metadata/instance',   # Azure
            'http://metadata.google.internal/computeMetadata/v1/'  # GCP
        ]
        
        for metadata_url in metadata_urls:
            try:
                async with self.session.get(metadata_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        finding = CloudVulnerabilityFinding(
                            vuln_type="Cloud Metadata Service Exposure",
                            severity="Critical",
                            confidence="High",
                            resource=metadata_url,
                            description="Cloud metadata service accessible from application",
                            remediation="Implement proper network segmentation and metadata service restrictions"
                        )
                        self.findings.append(finding)
                        
            except Exception:
                # Expected to fail in most cases
                pass
    
    async def _cloud_compliance_assessment(self, scan_options: Dict[str, Any]):
        """Assess cloud configuration for compliance requirements"""
        self.logger.info("Phase 6: Cloud Compliance Assessment")
        
        # Analyze findings for compliance impacts
        compliance_frameworks = {
            'PCI-DSS': ['public access', 'weak encryption', 'missing logs'],
            'GDPR': ['data exposure', 'public bucket', 'missing encryption'],
            'HIPAA': ['public access', 'data breach', 'insufficient access controls'],
            'SOX': ['financial data exposure', 'weak access controls']
        }
        
        for finding in self.findings:
            for framework, keywords in compliance_frameworks.items():
                if any(keyword in finding.description.lower() for keyword in keywords):
                    if finding.compliance_impact is None:
                        finding.compliance_impact = []
                    if framework not in finding.compliance_impact:
                        finding.compliance_impact.append(framework)