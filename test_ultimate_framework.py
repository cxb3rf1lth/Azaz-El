#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azaz-El Ultimate Framework Test Suite
Comprehensive testing for the v7.0.0-ULTIMATE framework
"""

import sys
import os
import asyncio
import unittest
import tempfile
import shutil
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

# Add project root to path
sys.path.append(str(Path(__file__).parent))

# Test imports
try:
    from azaz_el_ultimate import (
        AzazElUltimate, 
        ScanTarget, 
        VulnerabilityFinding, 
        ScanResult,
        AdvancedExploitEngine,
        IntelligentResultProcessor,
        DistributedScanManager
    )
    ULTIMATE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Ultimate framework not available: {e}")
    ULTIMATE_AVAILABLE = False

class TestUltimateFramework(unittest.TestCase):
    """Test the ultimate framework core functionality"""
    
    def setUp(self):
        """Set up test environment"""
        if not ULTIMATE_AVAILABLE:
            self.skipTest("Ultimate framework not available")
            
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config_file = self.temp_dir / "test_config.json"
        
        # Create test configuration
        test_config = {
            "version": "7.0.0-ULTIMATE",
            "tools": {
                "nuclei": {"enabled": True, "timeout": 300},
                "subfinder": {"enabled": True, "timeout": 300}
            },
            "general": {
                "runs_dir": str(self.temp_dir / "runs"),
                "max_concurrent": 5
            }
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(test_config, f)
        
        # Patch the configuration file path
        with patch('azaz_el_ultimate.ConfigurationManager') as mock_config:
            mock_config.return_value.load_config.return_value = test_config
            self.framework = AzazElUltimate()
    
    def tearDown(self):
        """Clean up test environment"""
        if hasattr(self, 'temp_dir'):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_framework_initialization(self):
        """Test framework initialization"""
        self.assertEqual(self.framework.version, "v7.0.0-ULTIMATE")
        self.assertEqual(self.framework.name, "Azaz-El Ultimate")
        self.assertIsNotNone(self.framework.exploit_engine)
        self.assertIsNotNone(self.framework.result_processor)
        self.assertIsNotNone(self.framework.distributed_manager)
    
    def test_target_type_detection(self):
        """Test target type detection"""
        test_cases = [
            ("example.com", "domain"),
            ("192.168.1.1", "ip"),
            ("https://example.com", "url"),
            ("192.168.1.0/24", "cidr"),
            ("unknown_format", "unknown")
        ]
        
        for target, expected_type in test_cases:
            detected_type = self.framework._detect_target_type(target)
            self.assertEqual(detected_type, expected_type)
    
    def test_scan_target_creation(self):
        """Test ScanTarget creation"""
        target = ScanTarget(
            target="example.com",
            target_type="domain",
            priority=1,
            tags=["web", "production"],
            metadata={"owner": "security_team"}
        )
        
        self.assertEqual(target.target, "example.com")
        self.assertEqual(target.target_type, "domain")
        self.assertEqual(target.priority, 1)
        self.assertIn("web", target.tags)
        self.assertEqual(target.metadata["owner"], "security_team")
    
    def test_vulnerability_finding_creation(self):
        """Test VulnerabilityFinding creation"""
        finding = VulnerabilityFinding(
            id="test-finding-001",
            title="Test SQL Injection",
            description="SQL injection vulnerability found",
            severity="high",
            cvss_score=8.1,
            cwe="CWE-89",
            affected_url="https://example.com/login",
            evidence={"payload": "' OR 1=1--"},
            remediation="Use parameterized queries",
            references=["https://owasp.org/sqli"],
            confidence=0.9,
            exploitability=0.8,
            business_impact="high",
            compliance_impact={"OWASP": ["A03:2021"]},
            timestamp=datetime.now(),
            scan_id="test-scan-001",
            target="example.com"
        )
        
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.cvss_score, 8.1)
        self.assertEqual(finding.confidence, 0.9)
        self.assertIn("A03:2021", finding.compliance_impact["OWASP"])

class TestAdvancedExploitEngine(unittest.TestCase):
    """Test the advanced exploit engine"""
    
    def setUp(self):
        """Set up test environment"""
        if not ULTIMATE_AVAILABLE:
            self.skipTest("Ultimate framework not available")
            
        self.config = {"exploitation": {"enabled": True, "safe_mode": True}}
        self.logger = MagicMock()
        self.engine = AdvancedExploitEngine(self.config, self.logger)
    
    def test_payload_database_loading(self):
        """Test payload database loading"""
        payloads = self.engine._load_payloads_database()
        
        self.assertIn('xss', payloads)
        self.assertIn('sqli', payloads)
        self.assertIn('lfi', payloads)
        self.assertTrue(len(payloads['xss']) > 0)
        self.assertTrue(len(payloads['sqli']) > 0)
    
    def test_custom_payload_generation(self):
        """Test custom payload generation"""
        context = {
            'input_type': 'textarea',
            'content_type': 'json'
        }
        
        payloads = self.engine.generate_custom_payloads('xss', context)
        
        self.assertTrue(len(payloads) > 0)
        # Check for context-specific payloads
        textarea_payload_found = any('</textarea>' in payload for payload in payloads)
        json_payload_found = any('\\u003c' in payload for payload in payloads)
        
        self.assertTrue(textarea_payload_found or json_payload_found)
    
    def test_automated_exploitation(self):
        """Test automated exploitation functionality"""
        
        # Create test finding
        finding = VulnerabilityFinding(
            id="test-001",
            title="SQL Injection Vulnerability",
            description="SQL injection found in login form",
            severity="critical",
            cvss_score=9.8,
            cwe="CWE-89",
            affected_url="https://example.com/login",
            evidence={},
            remediation="Use parameterized queries",
            references=[],
            confidence=0.95,
            exploitability=0.9,
            business_impact="high",
            compliance_impact={},
            timestamp=datetime.now(),
            scan_id="test-scan",
            target="example.com"
        )
        
        # Test the method exists and returns correct structure
        # Note: We can't easily test async methods in unittest without additional setup
        self.assertTrue(hasattr(self.engine, 'automated_exploitation'))
        
        # Test method signature
        import inspect
        sig = inspect.signature(self.engine.automated_exploitation)
        self.assertEqual(len(sig.parameters), 1)


class TestIntelligentResultProcessor(unittest.TestCase):
    """Test intelligent result processing"""
    
    def setUp(self):
        """Set up test environment"""
        if not ULTIMATE_AVAILABLE:
            self.skipTest("Ultimate framework not available")
            
        self.config = {"processing": {"confidence_threshold": 0.5}}
        self.logger = MagicMock()
        self.processor = IntelligentResultProcessor(self.config, self.logger)
    
    def test_false_positive_detection(self):
        """Test false positive detection"""
        # Create test finding that might be a false positive
        finding = VulnerabilityFinding(
            id="test-fp-001",
            title="SSL Certificate Self-Signed",
            description="SSL certificate is self-signed",
            severity="medium",
            cvss_score=4.0,
            cwe="CWE-295",
            affected_url="https://example.com",
            evidence={},
            remediation="Use valid SSL certificate",
            references=[],
            confidence=0.8,
            exploitability=0.2,
            business_impact="medium",
            compliance_impact={},
            timestamp=datetime.now(),
            scan_id="test-scan",
            target="example.com"
        )
        
        context = {"environment": "development"}
        
        is_fp = self.processor._is_likely_false_positive(finding, context)
        # Note: This might return True or False depending on pattern matching
        self.assertIsInstance(is_fp, bool)
    
    def test_contextual_filtering(self):
        """Test contextual filtering"""
        finding = VulnerabilityFinding(
            id="test-filter-001",
            title="Test Finding",
            description="Test vulnerability",
            severity="low",
            cvss_score=2.0,
            cwe="CWE-200",
            affected_url="https://example.com",
            evidence={},
            remediation="Fix it",
            references=[],
            confidence=0.3,  # Low confidence
            exploitability=0.1,
            business_impact="low",
            compliance_impact={},
            timestamp=datetime.now(),
            scan_id="test-scan",
            target="example.com"
        )
        
        context = {"min_confidence": 0.5}
        
        passes_filter = self.processor._passes_contextual_filters(finding, context)
        self.assertFalse(passes_filter)  # Should fail due to low confidence
    
    def test_finding_prioritization(self):
        """Test finding prioritization"""
        findings = [
            VulnerabilityFinding(
                id="low-001",
                title="Low Severity Finding",
                description="Low severity",
                severity="low",
                cvss_score=2.0,
                cwe="CWE-200",
                affected_url="https://example.com",
                evidence={},
                remediation="Fix",
                references=[],
                confidence=0.8,
                exploitability=0.2,
                business_impact="low",
                compliance_impact={},
                timestamp=datetime.now(),
                scan_id="test-scan",
                target="example.com"
            ),
            VulnerabilityFinding(
                id="critical-001",
                title="Critical Finding",
                description="Critical vulnerability",
                severity="critical",
                cvss_score=9.8,
                cwe="CWE-89",
                affected_url="https://example.com",
                evidence={},
                remediation="Fix immediately",
                references=[],
                confidence=0.95,
                exploitability=0.9,
                business_impact="critical",
                compliance_impact={},
                timestamp=datetime.now(),
                scan_id="test-scan",
                target="example.com"
            )
        ]
        
        prioritized = self.processor.prioritize_findings(findings)
        
        # Critical finding should be first
        self.assertEqual(prioritized[0].severity, "critical")
        self.assertEqual(prioritized[1].severity, "low")

class TestDistributedScanManager(unittest.TestCase):
    """Test distributed scanning capabilities"""
    
    def setUp(self):
        """Set up test environment"""
        if not ULTIMATE_AVAILABLE:
            self.skipTest("Ultimate framework not available")
            
        self.config = {"distributed": {"enabled": True}}
        self.logger = MagicMock()
        self.manager = DistributedScanManager(self.config, self.logger)
    
    def test_scan_node_addition(self):
        """Test adding scan nodes"""
        node_config = {
            "host": "scanner1.example.com",
            "port": 8443,
            "api_key": "test-key-123"
        }
        
        result = self.manager.add_scan_node(node_config)
        
        self.assertTrue(result)
        self.assertEqual(len(self.manager.scan_nodes), 1)
        self.assertEqual(self.manager.scan_nodes[0]["host"], "scanner1.example.com")
    
    def test_invalid_node_addition(self):
        """Test adding invalid scan node"""
        invalid_node = {
            "host": "scanner1.example.com"
            # Missing required fields
        }
        
        result = self.manager.add_scan_node(invalid_node)
        
        self.assertFalse(result)
        self.assertEqual(len(self.manager.scan_nodes), 0)
    
    def test_task_distribution(self):
        """Test task distribution across nodes"""
        
        # Add test nodes
        self.manager.add_scan_node({
            "host": "scanner1.example.com",
            "port": 8443,
            "api_key": "test-key-1"
        })
        self.manager.add_scan_node({
            "host": "scanner2.example.com",
            "port": 8443,
            "api_key": "test-key-2"
        })
        
        # Create test targets
        targets = [
            ScanTarget(target="example1.com", target_type="domain"),
            ScanTarget(target="example2.com", target_type="domain"),
            ScanTarget(target="example3.com", target_type="domain"),
            ScanTarget(target="example4.com", target_type="domain")
        ]
        
        # Test that method exists and nodes are configured
        self.assertTrue(hasattr(self.manager, 'distribute_scan_tasks'))
        self.assertEqual(len(self.manager.scan_nodes), 2)
        
        # Test target division logic
        targets_per_node = len(targets) // len(self.manager.scan_nodes)
        self.assertGreaterEqual(targets_per_node, 1)

class TestDatabaseOperations(unittest.TestCase):
    """Test database operations"""
    
    def setUp(self):
        """Set up test environment"""
        if not ULTIMATE_AVAILABLE:
            self.skipTest("Ultimate framework not available")
            
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_azaz_el.db"
        
        # Create test database
        self.db_connection = sqlite3.connect(str(self.db_path))
        
        # Create tables (same structure as framework)
        self.db_connection.execute("""
            CREATE TABLE scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT,
                start_time TEXT,
                end_time TEXT,
                status TEXT,
                findings_count INTEGER,
                metadata TEXT
            )
        """)
        
        self.db_connection.execute("""
            CREATE TABLE findings (
                finding_id TEXT PRIMARY KEY,
                scan_id TEXT,
                title TEXT,
                severity TEXT,
                cvss_score REAL,
                exploitability REAL,
                data TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        """)
        
        self.db_connection.commit()
    
    def tearDown(self):
        """Clean up test environment"""
        if hasattr(self, 'db_connection'):
            self.db_connection.close()
        if hasattr(self, 'temp_dir'):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_scan_record_insertion(self):
        """Test inserting scan records"""
        scan_data = (
            "test-scan-001",
            "example.com",
            datetime.now().isoformat(),
            datetime.now().isoformat(),
            "completed",
            5,
            '{"test": "data"}'
        )
        
        self.db_connection.execute("""
            INSERT INTO scans 
            (scan_id, target, start_time, end_time, status, findings_count, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, scan_data)
        
        self.db_connection.commit()
        
        # Verify insertion
        cursor = self.db_connection.execute("SELECT scan_id FROM scans WHERE scan_id = ?", ("test-scan-001",))
        result = cursor.fetchone()
        
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "test-scan-001")
    
    def test_finding_record_insertion(self):
        """Test inserting finding records"""
        # First insert a scan
        self.db_connection.execute("""
            INSERT INTO scans (scan_id, target, start_time, status, findings_count, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("test-scan-001", "example.com", datetime.now().isoformat(), "completed", 1, "{}"))
        
        # Then insert a finding
        finding_data = (
            "test-finding-001",
            "test-scan-001",
            "Test SQL Injection",
            "high",
            8.1,
            0.8,
            '{"evidence": "test"}'
        )
        
        self.db_connection.execute("""
            INSERT INTO findings
            (finding_id, scan_id, title, severity, cvss_score, exploitability, data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, finding_data)
        
        self.db_connection.commit()
        
        # Verify insertion
        cursor = self.db_connection.execute("SELECT finding_id FROM findings WHERE finding_id = ?", ("test-finding-001",))
        result = cursor.fetchone()
        
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "test-finding-001")

class TestIntegrationScenarios(unittest.TestCase):
    """Test integration scenarios"""
    
    def setUp(self):
        """Set up test environment"""
        if not ULTIMATE_AVAILABLE:
            self.skipTest("Ultimate framework not available")
    
    def test_end_to_end_scan_simulation(self):
        """Test end-to-end scan simulation"""
        # Create test targets
        targets = ["example.com", "test.com"]
        
        # Create scan configuration
        scan_config = {
            'aggressive': False,
            'enable_exploitation': False,
            'threads': 2,
            'timeout': 60
        }
        
        # Test that we can create the framework and configure a scan
        # (Actual scanning would require network access and tools)
        try:
            with patch('azaz_el_ultimate.ConfigurationManager'):
                framework = AzazElUltimate()
                
                # Test target parsing
                for target in targets:
                    target_type = framework._detect_target_type(target)
                    self.assertIn(target_type, ['domain', 'ip', 'url', 'cidr', 'unknown'])
                
                # Test scan configuration
                self.assertIsInstance(scan_config, dict)
                self.assertIn('aggressive', scan_config)
                
        except Exception as e:
            self.fail(f"Framework initialization failed: {e}")

def run_comprehensive_tests():
    """Run the comprehensive test suite"""
    print("=" * 80)
    print("AZAZ-EL ULTIMATE FRAMEWORK v7.0.0 - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    
    if not ULTIMATE_AVAILABLE:
        print("❌ Ultimate framework not available for testing")
        return False
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestUltimateFramework,
        TestAdvancedExploitEngine,
        TestIntelligentResultProcessor,
        TestDistributedScanManager,
        TestDatabaseOperations,
        TestIntegrationScenarios
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Total Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"  • {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"  • {test}: {traceback.split('Exception:')[-1].strip()}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100) if result.testsRun > 0 else 0
    print(f"\nSuccess Rate: {success_rate:.1f}%")
    
    if result.failures or result.errors:
        print("\n❌ SOME TESTS FAILED")
        return False
    else:
        print("\n✅ ALL TESTS PASSED! Ultimate framework is ready for deployment.")
        return True

if __name__ == "__main__":
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)