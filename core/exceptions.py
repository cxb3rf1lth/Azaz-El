"""
Custom Exception Classes for Azaz-El Framework
Provides structured error handling and better debugging capabilities
"""

class AzazelException(Exception):
    """Base exception for all Azaz-El framework errors"""
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = __import__('datetime').datetime.now().isoformat()

class ConfigurationError(AzazelException):
    """Raised when configuration is invalid or missing"""
    pass

class DependencyError(AzazelException):
    """Raised when required dependencies are missing or invalid"""
    pass

class ToolExecutionError(AzazelException):
    """Raised when tool execution fails"""
    pass

class ValidationError(AzazelException):
    """Raised when input validation fails"""
    pass

class NetworkError(AzazelException):
    """Raised when network operations fail"""
    pass

class FileSystemError(AzazelException):
    """Raised when file system operations fail"""
    pass

class ScanningError(AzazelException):
    """Raised when scanning operations fail"""
    pass

class ReportGenerationError(AzazelException):
    """Raised when report generation fails"""
    pass