"""
Input Validation and Sanitization Module
Provides comprehensive validation for all user inputs and data
"""

import re
import ipaddress
from typing import Union, List, Dict, Any, Optional
from urllib.parse import urlparse
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.exceptions import ValidationError

class InputValidator:
    """Comprehensive input validation class"""
    
    # Regex patterns for common validations
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
    
    @staticmethod
    def validate_target(target: str) -> str:
        """Validate and normalize target input"""
        if not target or not isinstance(target, str):
            raise ValidationError("Target must be a non-empty string")
        
        target = target.strip().lower()
        
        # Remove protocol if present for validation
        clean_target = target
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            clean_target = parsed.netloc
        
        # Validate as domain or IP
        if not (InputValidator.is_valid_domain(clean_target) or InputValidator.is_valid_ip(clean_target)):
            raise ValidationError(f"Invalid target format: {target}")
        
        return target
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if string is a valid domain name"""
        if not domain or len(domain) > 253:
            return False
        return bool(InputValidator.DOMAIN_PATTERN.match(domain))
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """Check if string is a valid CIDR notation"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> int:
        """Validate port number"""
        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValidationError(f"Port must be between 1 and 65535, got: {port}")
            return port_num
        except ValueError:
            raise ValidationError(f"Invalid port format: {port}")
    
    @staticmethod
    def validate_file_path(path: str, must_exist: bool = False) -> str:
        """Validate file path"""
        if not path or not isinstance(path, str):
            raise ValidationError("File path must be a non-empty string")
        
        from pathlib import Path
        path_obj = Path(path)
        
        if must_exist and not path_obj.exists():
            raise ValidationError(f"File does not exist: {path}")
        
        # Check for directory traversal attempts
        if '..' in path or path.startswith('/'):
            if not path.startswith(('/home', '/tmp', '/var/tmp')):
                raise ValidationError(f"Potentially unsafe file path: {path}")
        
        return str(path_obj.resolve())
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent security issues"""
        if not filename:
            raise ValidationError("Filename cannot be empty")
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        sanitized = re.sub(r'\.{2,}', '.', sanitized)  # Remove multiple dots
        sanitized = sanitized.strip('. ')  # Remove leading/trailing dots and spaces
        
        if not sanitized:
            raise ValidationError("Filename becomes empty after sanitization")
        
        # Ensure reasonable length
        if len(sanitized) > 255:
            sanitized = sanitized[:255]
        
        return sanitized
    
    @staticmethod
    def validate_config_schema(config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate configuration schema"""
        required_sections = ['tools', 'wordlists', 'output', 'performance']
        
        for section in required_sections:
            if section not in config:
                raise ValidationError(f"Missing required configuration section: {section}")
        
        # Validate performance settings
        performance = config.get('performance', {})
        if 'max_workers' in performance:
            workers = performance['max_workers']
            if not isinstance(workers, int) or workers < 1 or workers > 100:
                raise ValidationError("max_workers must be between 1 and 100")
        
        if 'tool_timeout' in performance:
            timeout = performance['tool_timeout']
            if not isinstance(timeout, int) or timeout < 30 or timeout > 3600:
                raise ValidationError("tool_timeout must be between 30 and 3600 seconds")
        
        return config
    
    @staticmethod
    def validate_wordlist_content(content: List[str], max_size: int = 1000000) -> List[str]:
        """Validate wordlist content"""
        if not isinstance(content, list):
            raise ValidationError("Wordlist content must be a list")
        
        if len(content) > max_size:
            raise ValidationError(f"Wordlist too large: {len(content)} entries (max: {max_size})")
        
        # Filter out potentially malicious entries
        clean_content = []
        for entry in content:
            if isinstance(entry, str) and len(entry.strip()) > 0:
                # Remove entries with potential shell injection
                if not re.search(r'[;&|`$(){}]', entry):
                    clean_content.append(entry.strip())
        
        return clean_content
    
    @staticmethod
    def validate_command_args(args: List[str]) -> List[str]:
        """Validate command line arguments for security"""
        if not isinstance(args, list):
            raise ValidationError("Command arguments must be a list")
        
        dangerous_patterns = [
            r'[;&|`]',  # Command injection
            r'\$\(',    # Command substitution
            r'\.\./',   # Directory traversal
            r'rm\s',    # Dangerous commands
            r'dd\s',
            r'mkfs',
            r'format',
        ]
        
        for arg in args:
            if not isinstance(arg, str):
                raise ValidationError(f"All arguments must be strings, got: {type(arg)}")
            
            for pattern in dangerous_patterns:
                if re.search(pattern, arg, re.IGNORECASE):
                    raise ValidationError(f"Potentially dangerous argument detected: {arg}")
        
        return args