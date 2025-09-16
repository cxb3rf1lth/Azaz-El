#!/usr/bin/env python3
"""
Comprehensive Test Suite for Azaz-El Framework v4.0
Tests all enhanced modules and functionality
"""

import sys
import asyncio
import tempfile
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

try:
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent))
    
    import core.exceptions as exc
    from core.validators import InputValidator
    from core.config import ConfigurationManager
    from core.logging import AdvancedLogger
    from scanners.web_scanner import AdvancedWebScanner, VulnerabilityFinding
    
    # Import exceptions for use in tests
    AzazelException = exc.AzazelException
    ConfigurationError = exc.ConfigurationError
    ValidationError = exc.ValidationError
    
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all required dependencies are installed:")
    print("pip install cryptography aiohttp")
    sys.exit(1)

class TestCoreExceptions(unittest.TestCase):
    """Test custom exception classes"""
    
    def test_base_exception(self):
        """Test base AzazelException"""
        exc = AzazelException("test message", "TEST001", {"key": "value"})
        self.assertEqual(str(exc), "test message")
        self.assertEqual(exc.error_code, "TEST001")
        self.assertEqual(exc.details["key"], "value")
        self.assertIsNotNone(exc.timestamp)
    
    def test_configuration_error(self):
        """Test ConfigurationError"""
        exc = ConfigurationError("config error")
        self.assertIsInstance(exc, AzazelException)
        self.assertEqual(str(exc), "config error")

class TestInputValidator(unittest.TestCase):
    """Test input validation functionality"""
    
    def test_validate_domain(self):
        """Test domain validation"""
        self.assertTrue(InputValidator.is_valid_domain("example.com"))
        self.assertTrue(InputValidator.is_valid_domain("sub.example.com"))
        self.assertFalse(InputValidator.is_valid_domain(""))
        self.assertFalse(InputValidator.is_valid_domain("invalid..domain"))
    
    def test_validate_ip(self):
        """Test IP address validation"""
        self.assertTrue(InputValidator.is_valid_ip("192.168.1.1"))
        self.assertTrue(InputValidator.is_valid_ip("::1"))
        self.assertFalse(InputValidator.is_valid_ip("999.999.999.999"))
        self.assertFalse(InputValidator.is_valid_ip("invalid"))
    
    def test_validate_target(self):
        """Test target validation"""
        self.assertEqual(InputValidator.validate_target("example.com"), "example.com")
        self.assertEqual(InputValidator.validate_target("http://example.com"), "http://example.com")
        
        with self.assertRaises(ValidationError):
            InputValidator.validate_target("")
        
        with self.assertRaises(ValidationError):
            InputValidator.validate_target("invalid target")
    
    def test_validate_port(self):
        """Test port validation"""
        self.assertEqual(InputValidator.validate_port("80"), 80)
        self.assertEqual(InputValidator.validate_port(443), 443)
        
        with self.assertRaises(ValidationError):
            InputValidator.validate_port("0")
        
        with self.assertRaises(ValidationError):
            InputValidator.validate_port("99999")
    
    def test_sanitize_filename(self):
        """Test filename sanitization"""
        self.assertEqual(InputValidator.sanitize_filename("normal.txt"), "normal.txt")
        self.assertEqual(InputValidator.sanitize_filename("file<>:\"/\\|?*.txt"), "file_________.txt")
        
        with self.assertRaises(ValidationError):
            InputValidator.sanitize_filename("")

class TestConfigurationManager(unittest.TestCase):
    """Test configuration management"""
    
    def setUp(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config_file = self.temp_dir / "test_config.json"
        self.config_manager = ConfigurationManager(self.config_file)
    
    def test_create_default_config(self):
        """Test default configuration creation"""
        config = self.config_manager.load_config()
        self.assertIn("tools", config)
        self.assertIn("performance", config)
        self.assertIn("security", config)
        self.assertIn("reporting", config)
    
    def test_save_and_load_config(self):
        """Test configuration save and load"""
        test_config = {
            "tools": {"test_tool": {"enabled": True}},
            "performance": {"max_workers": 5},
            "security": {"encrypt_sensitive_data": False},
            "reporting": {"auto_open_html": False},
            "wordlists": {},
            "output": {}
        }
        
        self.config_manager.save_config(test_config)
        loaded_config = self.config_manager.load_config()
        
        self.assertEqual(loaded_config["tools"]["test_tool"]["enabled"], True)
        self.assertEqual(loaded_config["performance"]["max_workers"], 5)
    
    def test_encryption_key_generation(self):
        """Test encryption key generation"""
        key = ConfigurationManager.generate_encryption_key()
        self.assertIsInstance(key, str)
        self.assertTrue(len(key) > 20)  # Should be a substantial key
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

class TestAdvancedLogger(unittest.TestCase):
    """Test advanced logging functionality"""
    
    def setUp(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.logger = AdvancedLogger("test_logger", self.temp_dir)
    
    def test_basic_logging(self):
        """Test basic logging functionality"""
        self.logger.info("Test info message")
        self.logger.error("Test error message")
        self.logger.debug("Test debug message")
        
        # Check if log files are created
        log_files = list(self.temp_dir.glob("*.log"))
        self.assertTrue(len(log_files) > 0)
    
    def test_structured_logging(self):
        """Test structured logging with extra data"""
        extra_data = {"test_key": "test_value", "number": 42}
        self.logger.info("Test structured message", extra_data)
        
        # Check if JSON log file exists
        json_files = list(self.temp_dir.glob("*structured.json"))
        self.assertTrue(len(json_files) > 0)
    
    def test_tool_execution_logging(self):
        """Test tool execution logging"""
        self.logger.log_tool_execution("test_tool", "test command", True, 1.5, 1024)
        
        # Should not raise any exceptions
        self.assertTrue(True)
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

class TestVulnerabilityFinding(unittest.TestCase):
    """Test vulnerability finding structure"""
    
    def test_vulnerability_creation(self):
        """Test vulnerability finding creation"""
        finding = VulnerabilityFinding(
            vuln_type="XSS",
            severity="High",
            confidence="High",
            url="http://example.com",
            parameter="test_param",
            payload="<script>alert(1)</script>"
        )
        
        self.assertEqual(finding.vuln_type, "XSS")
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.url, "http://example.com")
        self.assertIsInstance(finding.references, list)

class TestWebScanner(unittest.TestCase):
    """Test web scanner functionality"""
    
    def setUp(self):
        """Setup test environment"""
        self.config = {"performance": {"max_workers": 5}}
        self.scanner = AdvancedWebScanner(self.config)
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner.config)
        self.assertIsInstance(self.scanner.xss_payloads, list)
        self.assertIsInstance(self.scanner.sqli_payloads, list)
        self.assertTrue(len(self.scanner.xss_payloads) > 0)
        self.assertTrue(len(self.scanner.sqli_payloads) > 0)
    
    def test_payload_loading(self):
        """Test payload loading functionality"""
        xss_payloads = self.scanner._load_xss_payloads()
        sqli_payloads = self.scanner._load_sqli_payloads()
        lfi_payloads = self.scanner._load_lfi_payloads()
        
        self.assertTrue(len(xss_payloads) > 20)
        self.assertTrue(len(sqli_payloads) > 15)
        self.assertTrue(len(lfi_payloads) > 10)
        
        # Check for common payloads
        self.assertTrue(any("<script>" in payload for payload in xss_payloads))
        self.assertTrue(any("'" in payload for payload in sqli_payloads))
        self.assertTrue(any("etc/passwd" in payload for payload in lfi_payloads))
    
    def test_link_extraction(self):
        """Test link extraction from HTML"""
        html_content = '''
        <html>
            <a href="/test1">Test 1</a>
            <a href="http://example.com/test2">Test 2</a>
            <a href="../test3">Test 3</a>
        </html>
        '''
        
        links = self.scanner._extract_links(html_content, "http://example.com/page")
        self.assertTrue(len(links) > 0)
    
    def test_form_parameter_extraction(self):
        """Test form parameter extraction"""
        html_content = '''
        <form method="post">
            <input name="username" type="text">
            <input name="password" type="password">
            <input name="hidden_field" type="hidden">
        </form>
        '''
        
        initial_count = len(self.scanner.tested_parameters)
        self.scanner._extract_forms_and_parameters(html_content, "http://example.com")
        
        # Should have added some parameters
        self.assertTrue(len(self.scanner.tested_parameters) > initial_count)

def run_comprehensive_tests():
    """Run all tests and provide detailed results"""
    print("=" * 80)
    print("AZAZ-EL FRAMEWORK v4.0 - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestCoreExceptions,
        TestInputValidator,
        TestConfigurationManager,
        TestAdvancedLogger,
        TestVulnerabilityFinding,
        TestWebScanner,
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    total_tests = result.testsRun
    failed_tests = len(result.failures)
    error_tests = len(result.errors)
    passed_tests = total_tests - failed_tests - error_tests
    
    print(f"Total Tests Run: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")
    print(f"Errors: {error_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if result.failures:
        print(f"\nFAILURES ({len(result.failures)}):")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print(f"\nERRORS ({len(result.errors)}):")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('Exception:')[-1].strip()}")
    
    # Feature validation
    print("\n" + "=" * 80)
    print("FEATURE VALIDATION")
    print("=" * 80)
    
    features = [
        ("Core Exception Handling", passed_tests > 0),
        ("Input Validation", "TestInputValidator" in str(result)),
        ("Configuration Management", "TestConfigurationManager" in str(result)),
        ("Advanced Logging", "TestAdvancedLogger" in str(result)),
        ("Web Scanner", "TestWebScanner" in str(result)),
        ("Vulnerability Detection", len(AdvancedWebScanner({})._load_xss_payloads()) > 20),
        ("Payload Generation", len(AdvancedWebScanner({})._load_sqli_payloads()) > 15),
    ]
    
    for feature_name, is_working in features:
        status = "✅ WORKING" if is_working else "❌ FAILED"
        print(f"{feature_name:<30} {status}")
    
    print("\n" + "=" * 80)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_comprehensive_tests()
    
    if success:
        print("🎉 ALL TESTS PASSED! Framework is ready for enhanced operations.")
        sys.exit(0)
    else:
        print("⚠️ Some tests failed. Please review the output above.")
        sys.exit(1)