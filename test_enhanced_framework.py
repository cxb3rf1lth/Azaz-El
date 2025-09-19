#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Framework Test Suite
Comprehensive testing of enhanced database, filtering, and reporting features
"""

import asyncio
import json
import logging
import sys
import tempfile
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

# Add project root to path
sys.path.append(str(Path(__file__).parent))

@dataclass
class MockFinding:
    """Mock finding for testing"""
    id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    confidence: float
    category: str = "general"
    url: str = ""
    evidence: str = ""
    remediation: str = ""
    false_positive: bool = False
    verified: bool = False
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass 
class MockScanResult:
    """Mock scan result for testing"""
    scan_id: str
    target: Any = None
    start_time: datetime = None
    end_time: datetime = None
    status: str = "completed"
    findings: List[MockFinding] = None
    metadata: Dict[str, Any] = None
    artifacts: Dict[str, str] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.metadata is None:
            self.metadata = {}
        if self.artifacts is None:
            self.artifacts = {}
        if self.start_time is None:
            self.start_time = datetime.now()

def create_test_findings() -> List[MockFinding]:
    """Create diverse test findings for comprehensive testing"""
    
    findings = [
        # High-value findings that should be enhanced
        MockFinding(
            id="finding_001",
            title="SQL Injection Vulnerability",
            description="SQL injection vulnerability detected in login form",
            severity="critical",
            cvss_score=9.1,
            confidence=0.9,
            category="injection",
            url="https://example.com/login",
            evidence="' OR '1'='1' -- payload successful",
            remediation="Use parameterized queries"
        ),
        MockFinding(
            id="finding_002", 
            title="Cross-Site Scripting (XSS)",
            description="Reflected XSS vulnerability in search parameter",
            severity="high",
            cvss_score=7.2,
            confidence=0.8,
            category="injection",
            url="https://example.com/search?q=<script>alert(1)</script>",
            evidence="Script executed successfully",
            remediation="Implement proper output encoding"
        ),
        MockFinding(
            id="finding_003",
            title="Remote Code Execution",
            description="Command injection allowing remote code execution",
            severity="critical",
            cvss_score=9.8,
            confidence=0.95,
            category="injection",
            url="https://example.com/upload",
            evidence="System command executed: id",
            remediation="Validate and sanitize all input"
        ),
        
        # Potential false positives
        MockFinding(
            id="finding_004",
            title="Server returned error 404 for non-existent page",
            description="404 error page found for invalid URL",
            severity="info",
            cvss_score=0.0,
            confidence=0.3,
            category="information_disclosure",
            url="https://example.com/nonexistent",
            evidence="404 Not Found response",
            remediation="N/A"
        ),
        MockFinding(
            id="finding_005",
            title="Missing X-Frame-Options header",
            description="X-Frame-Options security header not present",
            severity="low",
            cvss_score=2.1,
            confidence=0.7,
            category="security_headers",
            url="https://example.com/",
            evidence="Header not found in response",
            remediation="Add X-Frame-Options: DENY header"
        ),
        MockFinding(
            id="finding_006",
            title="Directory listing enabled on localhost",
            description="Apache directory listing enabled",
            severity="medium",
            cvss_score=4.3,
            confidence=0.6,
            category="configuration",
            url="http://localhost/test/",
            evidence="Directory index displayed",
            remediation="Disable directory listing"
        ),
        
        # Medium findings
        MockFinding(
            id="finding_007",
            title="Weak SSL/TLS Configuration",
            description="Server supports weak cipher suites",
            severity="medium",
            cvss_score=5.3,
            confidence=0.8,
            category="ssl_tls",
            url="https://example.com",
            evidence="TLSv1.0 supported",
            remediation="Update SSL/TLS configuration"
        ),
        MockFinding(
            id="finding_008",
            title="Admin panel accessible",
            description="Administrative interface found without authentication",
            severity="high",
            cvss_score=8.1,
            confidence=0.9,
            category="authentication",
            url="https://example.com/admin",
            evidence="Admin panel login page accessible",
            remediation="Implement proper access controls"
        ),
        
        # Low confidence findings
        MockFinding(
            id="finding_009",
            title="Potential backup file detected",
            description="Possible backup file found",
            severity="medium",
            cvss_score=4.0,
            confidence=0.2,  # Low confidence - might be filtered
            category="information_disclosure",
            url="https://example.com/backup.zip",
            evidence="File accessible but content unknown",
            remediation="Remove backup files from web root"
        ),
        
        # Duplicate finding (should be removed)
        MockFinding(
            id="finding_010",
            title="SQL Injection Vulnerability",  # Same as finding_001
            description="SQL injection vulnerability detected in login form",
            severity="critical",
            cvss_score=9.1,
            confidence=0.85,  # Slightly different confidence
            category="injection",
            url="https://example.com/login",
            evidence="' OR '1'='1' -- payload successful",
            remediation="Use parameterized queries"
        )
    ]
    
    return findings

async def test_enhanced_database_manager():
    """Test enhanced database manager functionality"""
    print("\n🧪 Testing Enhanced Database Manager...")
    
    try:
        from core.database_manager import EnhancedDatabaseManager
        
        # Use temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            test_db_path = tmp.name
        
        # Setup logging
        logger = logging.getLogger('test_db')
        logger.setLevel(logging.INFO)
        
        # Initialize database manager
        db_manager = EnhancedDatabaseManager(test_db_path, logger)
        
        # Create test scan result
        findings = create_test_findings()
        scan_result = MockScanResult(
            scan_id="test_scan_001",
            findings=findings,
            metadata={"test": True, "framework": "enhanced_test"}
        )
        
        # Test save with all export formats
        export_formats = ["json", "csv", "xml", "html"]
        success = db_manager.save_scan_result(scan_result, export_formats)
        
        print(f"✅ Database save and export: {'SUCCESS' if success else 'FAILED'}")
        
        # Test retrieval
        retrieved = db_manager.get_scan_results("test_scan_001")
        if retrieved:
            print(f"✅ Data retrieval: SUCCESS ({len(retrieved['findings'])} findings)")
        else:
            print("❌ Data retrieval: FAILED")
        
        # Test scan listing
        scans = db_manager.list_scans(10)
        print(f"✅ Scan listing: SUCCESS ({len(scans)} scans)")
        
        # Check generated files
        results_dir = Path(f"results/test_scan_001")
        if results_dir.exists():
            files = list(results_dir.glob("*"))
            print(f"✅ File generation: SUCCESS ({len(files)} files generated)")
            for file_path in files:
                print(f"   📄 {file_path.name} ({file_path.stat().st_size} bytes)")
        else:
            print("❌ File generation: No results directory found")
        
        # Cleanup
        db_manager.close()
        Path(test_db_path).unlink(missing_ok=True)
        
        return True
        
    except Exception as e:
        print(f"❌ Database Manager test failed: {e}")
        return False

async def test_enhanced_results_filter():
    """Test enhanced results filter functionality"""
    print("\n🧪 Testing Enhanced Results Filter...")
    
    try:
        from core.results_filter import EnhancedResultsFilter, FilterContext
        
        # Setup logging
        logger = logging.getLogger('test_filter')
        logger.setLevel(logging.INFO)
        
        # Initialize filter
        results_filter = EnhancedResultsFilter({}, logger)
        
        # Create test findings
        findings = create_test_findings()
        original_count = len(findings)
        print(f"📊 Original findings: {original_count}")
        
        # Test different filter contexts
        test_contexts = [
            {
                "name": "Production Environment",
                "context": FilterContext(
                    environment='production',
                    target_type='web',
                    min_confidence=0.3,
                    auto_exclude_fps=True
                )
            },
            {
                "name": "Development Environment",
                "context": FilterContext(
                    environment='development',
                    target_type='web',
                    min_confidence=0.5,
                    exclude_severities=['info'],
                    auto_exclude_fps=True
                )
            },
            {
                "name": "High Confidence Only",
                "context": FilterContext(
                    environment='production',
                    target_type='web',
                    min_confidence=0.7,
                    auto_exclude_fps=True
                )
            }
        ]
        
        for test_case in test_contexts:
            print(f"\n🔍 Testing: {test_case['name']}")
            
            # Apply filtering
            filtered_findings = results_filter.filter_findings(findings.copy(), test_case['context'])
            filtered_count = len(filtered_findings)
            
            print(f"   📊 Results: {original_count} → {filtered_count} findings")
            
            # Check for enhanced findings
            enhanced_count = sum(1 for f in filtered_findings if getattr(f, 'verified', False))
            print(f"   ⭐ Enhanced findings: {enhanced_count}")
            
            # Check for false positives
            fp_count = sum(1 for f in filtered_findings if getattr(f, 'false_positive', False))
            print(f"   🚫 False positives marked: {fp_count}")
            
            # Show severity distribution
            severities = {}
            for f in filtered_findings:
                severities[f.severity] = severities.get(f.severity, 0) + 1
            print(f"   📈 Severity distribution: {severities}")
        
        # Test filter statistics
        stats = results_filter.get_filter_statistics()
        print(f"\n📊 Filter Statistics:")
        for key, value in stats.items():
            print(f"   {key}: {value}")
        
        return True
        
    except Exception as e:
        print(f"❌ Results Filter test failed: {e}")
        return False

async def test_integration():
    """Test integration of all enhanced components"""
    print("\n🧪 Testing Component Integration...")
    
    try:
        from core.database_manager import EnhancedDatabaseManager
        from core.results_filter import EnhancedResultsFilter, FilterContext
        
        # Use temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            test_db_path = tmp.name
        
        # Setup logging
        logger = logging.getLogger('test_integration')
        logger.setLevel(logging.INFO)
        
        # Initialize components
        db_manager = EnhancedDatabaseManager(test_db_path, logger)
        results_filter = EnhancedResultsFilter({}, logger)
        
        # Create realistic scan scenario
        findings = create_test_findings()
        scan_result = MockScanResult(
            scan_id="integration_test_001",
            findings=findings,
            metadata={
                "framework": "integration_test",
                "scan_type": "comprehensive",
                "target_count": 1
            }
        )
        
        print(f"📊 Starting with {len(findings)} findings")
        
        # Apply filtering pipeline
        filter_context = FilterContext(
            environment='production',
            target_type='web',
            min_confidence=0.4,
            auto_exclude_fps=True
        )
        
        # Filter findings
        original_count = len(scan_result.findings)
        scan_result.findings = results_filter.filter_findings(scan_result.findings, filter_context)
        filtered_count = len(scan_result.findings)
        
        print(f"🔍 After filtering: {original_count} → {filtered_count} findings")
        
        # Save to database with full export
        export_formats = ["json", "csv", "xml", "html"]
        success = db_manager.save_scan_result(scan_result, export_formats)
        
        print(f"💾 Database save: {'SUCCESS' if success else 'FAILED'}")
        
        # Verify files were created
        results_dir = Path(f"results/integration_test_001")
        if results_dir.exists():
            files = list(results_dir.glob("*"))
            print(f"📁 Generated {len(files)} result files:")
            
            for file_path in files:
                size = file_path.stat().st_size
                print(f"   📄 {file_path.name} ({size} bytes)")
                
                # Quick validation of file content
                if file_path.suffix == '.json':
                    try:
                        with open(file_path) as f:
                            data = json.load(f)
                        print(f"      ✅ Valid JSON with {len(data.get('findings', []))} findings")
                    except:
                        print(f"      ❌ Invalid JSON file")
                
                elif file_path.suffix == '.html':
                    content = file_path.read_text()
                    if 'Security Scan Report' in content:
                        print(f"      ✅ Valid HTML report")
                    else:
                        print(f"      ❌ Invalid HTML report")
        
        # Test database queries
        retrieved = db_manager.get_scan_results("integration_test_001")
        if retrieved:
            db_findings_count = len(retrieved['findings'])
            print(f"🔍 Database verification: {db_findings_count} findings stored")
            
            # Check if filtering info was preserved
            scan_data = retrieved['scan']
            if 'filtering_applied' in json.loads(scan_data.get('metadata', '{}')):
                print(f"✅ Filtering metadata preserved")
        
        # Cleanup
        db_manager.close()
        Path(test_db_path).unlink(missing_ok=True)
        
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

async def test_cli_integration():
    """Test command-line integration"""
    print("\n🧪 Testing CLI Integration...")
    
    try:
        # Test help output for new options
        import subprocess
        
        # Test z3muth help
        result = subprocess.run([
            sys.executable, 'z3muth.py', '--help'
        ], capture_output=True, text=True, timeout=10)
        
        if 'Filtering Options' in result.stdout:
            print("✅ Z3MUTH CLI filtering options added")
        else:
            print("❌ Z3MUTH CLI filtering options missing")
        
        # Test azaz_el_ultimate help  
        result = subprocess.run([
            sys.executable, 'azaz_el_ultimate.py', '--help'
        ], capture_output=True, text=True, timeout=10)
        
        if '--min-confidence' in result.stdout:
            print("✅ Azaz-El Ultimate CLI filtering options added")
        else:
            print("❌ Azaz-El Ultimate CLI filtering options missing")
        
        return True
        
    except Exception as e:
        print(f"❌ CLI integration test failed: {e}")
        return False

async def main():
    """Run comprehensive test suite"""
    print("🚀 Enhanced Framework Test Suite")
    print("=" * 50)
    
    test_results = []
    
    # Run all tests
    tests = [
        ("Enhanced Database Manager", test_enhanced_database_manager),
        ("Enhanced Results Filter", test_enhanced_results_filter), 
        ("Component Integration", test_integration),
        ("CLI Integration", test_cli_integration)
    ]
    
    for test_name, test_func in tests:
        try:
            result = await test_func()
            test_results.append((test_name, result))
            print(f"\n{'✅' if result else '❌'} {test_name}: {'PASSED' if result else 'FAILED'}")
        except Exception as e:
            test_results.append((test_name, False))
            print(f"\n❌ {test_name}: FAILED - {e}")
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status} - {test_name}")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Enhanced framework is working correctly.")
    else:
        print("⚠️  Some tests failed. Please review the output above.")
    
    return passed == total

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run tests
    success = asyncio.run(main())
    sys.exit(0 if success else 1)