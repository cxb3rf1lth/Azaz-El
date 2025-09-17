"""
Configuration Management System
Advanced configuration handling with schema validation and encryption support
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
import base64
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.exceptions import ConfigurationError, ValidationError
from core.validators import InputValidator

@dataclass
class ToolConfig:
    """Configuration for individual tools"""
    enabled: bool = True
    flags: List[str] = None
    install_cmd: str = ""
    timeout: int = 600
    max_retries: int = 3
    priority: int = 1
    requires_auth: bool = False
    
    def __post_init__(self):
        if self.flags is None:
            self.flags = []

@dataclass
class PerformanceConfig:
    """Performance and resource configuration"""
    max_workers: int = 10
    tool_timeout: int = 600
    rate_limit: int = 1000
    memory_limit_mb: int = 2048
    disk_space_check: bool = True
    
@dataclass
class SecurityConfig:
    """Security-related configuration"""
    encrypt_sensitive_data: bool = True
    log_sensitive_commands: bool = False
    validate_all_inputs: bool = True
    sandbox_mode: bool = False
    allowed_networks: List[str] = None
    
    def __post_init__(self):
        if self.allowed_networks is None:
            self.allowed_networks = []

@dataclass
class ReportConfig:
    """Reporting configuration"""
    auto_open_html: bool = True
    report_format: str = "html"
    include_screenshots: bool = True
    export_formats: List[str] = None
    template_dir: str = ""
    
    def __post_init__(self):
        if self.export_formats is None:
            self.export_formats = ["html", "json"]

class ConfigurationManager:
    """Advanced configuration management with encryption and validation"""
    
    def __init__(self, config_file: Path, encryption_key: Optional[str] = None):
        self.config_file = Path(config_file)
        self.encryption_key = encryption_key
        self._cipher_suite = None
        
        if encryption_key:
            try:
                key = base64.urlsafe_b64decode(encryption_key.encode())
                self._cipher_suite = Fernet(key)
            except Exception as e:
                raise ConfigurationError(f"Invalid encryption key: {e}")
        
        self._config_cache = None
        self._schema_validators = {
            'tools': self._validate_tools_config,
            'performance': self._validate_performance_config,
            'security': self._validate_security_config,
            'reporting': self._validate_reporting_config,
        }
    
    @staticmethod
    def generate_encryption_key() -> str:
        """Generate a new encryption key for sensitive data"""
        key = Fernet.generate_key()
        return base64.urlsafe_b64encode(key).decode()
    
    def load_config(self) -> Dict[str, Any]:
        """Load and validate configuration from file"""
        if self._config_cache is not None:
            return self._config_cache
        
        try:
            if not self.config_file.exists():
                self._config_cache = self._create_default_config()
                self.save_config(self._config_cache)
                return self._config_cache
            
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Decrypt sensitive sections if encryption is enabled
            if self._cipher_suite and 'encrypted_sections' in config_data:
                config_data = self._decrypt_config_sections(config_data)
            
            # Validate configuration
            validated_config = self._validate_full_config(config_data)
            self._config_cache = validated_config
            return validated_config
            
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in config file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def save_config(self, config: Dict[str, Any]):
        """Save configuration to file with optional encryption"""
        try:
            # Validate before saving
            validated_config = self._validate_full_config(config)
            
            # Encrypt sensitive sections if encryption is enabled
            if self._cipher_suite:
                validated_config = self._encrypt_config_sections(validated_config)
            
            # Ensure parent directory exists
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to temporary file first, then move to prevent corruption
            temp_file = self.config_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(validated_config, f, indent=2, ensure_ascii=False)
            
            temp_file.replace(self.config_file)
            self._config_cache = config  # Update cache with original (unencrypted) config
            
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def get_tool_config(self, tool_name: str) -> ToolConfig:
        """Get configuration for a specific tool"""
        config = self.load_config()
        tool_data = config.get('tools', {}).get(tool_name, {})
        
        # Convert dict to ToolConfig with defaults
        return ToolConfig(
            enabled=tool_data.get('enabled', True),
            flags=tool_data.get('flags', []),
            install_cmd=tool_data.get('install_cmd', ''),
            timeout=tool_data.get('timeout', 600),
            max_retries=tool_data.get('max_retries', 3),
            priority=tool_data.get('priority', 1),
            requires_auth=tool_data.get('requires_auth', False)
        )
    
    def update_tool_config(self, tool_name: str, tool_config: ToolConfig):
        """Update configuration for a specific tool"""
        config = self.load_config()
        if 'tools' not in config:
            config['tools'] = {}
        
        config['tools'][tool_name] = asdict(tool_config)
        self.save_config(config)
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default configuration"""
        return {
            "version": "5.0.0",
            "tools": {
                "subfinder": {
                    "enabled": True,
                    "flags": ["-all", "-recursive"],
                    "install_cmd": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                    "timeout": 600,
                    "priority": 1
                },
                "nuclei": {
                    "enabled": True,
                    "flags": ["-silent", "-severity", "low,medium,high,critical", "-c", "100"],
                    "install_cmd": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                    "timeout": 1200,
                    "priority": 1
                },
                "httpx": {
                    "enabled": True,
                    "flags": ["-silent", "-title", "-tech-detect", "-status-code"],
                    "install_cmd": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                    "timeout": 300,
                    "priority": 1
                },
                # New Advanced Tools
                "gf": {
                    "enabled": True,
                    "flags": ["-save"],
                    "install_cmd": "go install github.com/tomnomnom/gf@latest",
                    "timeout": 180,
                    "priority": 2
                },
                "unfurl": {
                    "enabled": True,
                    "flags": ["domains"],
                    "install_cmd": "go install github.com/tomnomnom/unfurl@latest",
                    "timeout": 120,
                    "priority": 2
                },
                "anew": {
                    "enabled": True,
                    "flags": [],
                    "install_cmd": "go install github.com/tomnomnom/anew@latest",
                    "timeout": 60,
                    "priority": 3
                },
                "notify": {
                    "enabled": False,
                    "flags": ["-silent"],
                    "install_cmd": "go install -v github.com/projectdiscovery/notify/cmd/notify@latest",
                    "timeout": 60,
                    "priority": 3
                },
                "interactsh-client": {
                    "enabled": True,
                    "flags": ["-json"],
                    "install_cmd": "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
                    "timeout": 300,
                    "priority": 2
                },
                "alterx": {
                    "enabled": True,
                    "flags": ["-silent"],
                    "install_cmd": "go install github.com/projectdiscovery/alterx/cmd/alterx@latest",
                    "timeout": 180,
                    "priority": 2
                },
                "tlsx": {
                    "enabled": True,
                    "flags": ["-silent", "-json"],
                    "install_cmd": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
                    "timeout": 300,
                    "priority": 2
                },
                "cdncheck": {
                    "enabled": True,
                    "flags": ["-silent"],
                    "install_cmd": "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
                    "timeout": 120,
                    "priority": 2
                },
                "mapcidr": {
                    "enabled": True,
                    "flags": ["-silent"],
                    "install_cmd": "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
                    "timeout": 120,
                    "priority": 2
                },
                "asnmap": {
                    "enabled": True,
                    "flags": ["-silent"],
                    "install_cmd": "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
                    "timeout": 180,
                    "priority": 2
                }
            },
            "wordlists": {
                "subdomains": "subdomains-top1million-5000.txt",
                "directories": "raft-medium-directories.txt",
                "parameters": "param-miner.txt",
                "api_endpoints": "api-endpoints.txt"
            },
            "performance": asdict(PerformanceConfig()),
            "security": asdict(SecurityConfig()),
            "reporting": asdict(ReportConfig()),
            "output": {
                "base_dir": "runs",
                "keep_raw_output": True,
                "compress_old_runs": True
            }
        }
    
    def _validate_full_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate entire configuration structure"""
        # Basic structure validation
        config = InputValidator.validate_config_schema(config)
        
        # Validate individual sections
        for section_name, validator in self._schema_validators.items():
            if section_name in config:
                config[section_name] = validator(config[section_name])
        
        return config
    
    def _validate_tools_config(self, tools_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate tools configuration section"""
        for tool_name, tool_data in tools_config.items():
            if not isinstance(tool_data, dict):
                raise ConfigurationError(f"Tool {tool_name} configuration must be a dictionary")
            
            # Validate flags
            if 'flags' in tool_data and not isinstance(tool_data['flags'], list):
                raise ConfigurationError(f"Tool {tool_name} flags must be a list")
            
            # Validate timeout
            if 'timeout' in tool_data:
                timeout = tool_data['timeout']
                if not isinstance(timeout, int) or timeout < 10 or timeout > 3600:
                    raise ConfigurationError(f"Tool {tool_name} timeout must be between 10 and 3600 seconds")
        
        return tools_config
    
    def _validate_performance_config(self, perf_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate performance configuration section"""
        # Validate max_workers
        if 'max_workers' in perf_config:
            workers = perf_config['max_workers']
            if not isinstance(workers, int) or workers < 1 or workers > 100:
                raise ConfigurationError("max_workers must be between 1 and 100")
        
        # Validate memory_limit_mb
        if 'memory_limit_mb' in perf_config:
            memory = perf_config['memory_limit_mb']
            if not isinstance(memory, int) or memory < 512:
                raise ConfigurationError("memory_limit_mb must be at least 512 MB")
        
        return perf_config
    
    def _validate_security_config(self, sec_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate security configuration section"""
        # Validate allowed_networks
        if 'allowed_networks' in sec_config:
            networks = sec_config['allowed_networks']
            if not isinstance(networks, list):
                raise ConfigurationError("allowed_networks must be a list")
            
            for network in networks:
                if not InputValidator.is_valid_cidr(network) and not InputValidator.is_valid_ip(network):
                    raise ConfigurationError(f"Invalid network specification: {network}")
        
        return sec_config
    
    def _validate_reporting_config(self, report_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate reporting configuration section"""
        # Validate export_formats
        if 'export_formats' in report_config:
            formats = report_config['export_formats']
            if not isinstance(formats, list):
                raise ConfigurationError("export_formats must be a list")
            
            valid_formats = ['html', 'json', 'xml', 'pdf', 'csv']
            for fmt in formats:
                if fmt not in valid_formats:
                    raise ConfigurationError(f"Invalid export format: {fmt}")
        
        return report_config
    
    def _encrypt_config_sections(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive configuration sections"""
        if not self._cipher_suite:
            return config
        
        sensitive_sections = ['auth', 'api_keys', 'credentials']
        encrypted_config = config.copy()
        encrypted_sections = {}
        
        for section in sensitive_sections:
            if section in config:
                section_data = json.dumps(config[section])
                encrypted_data = self._cipher_suite.encrypt(section_data.encode())
                encrypted_sections[section] = base64.urlsafe_b64encode(encrypted_data).decode()
                del encrypted_config[section]
        
        if encrypted_sections:
            encrypted_config['encrypted_sections'] = encrypted_sections
        
        return encrypted_config
    
    def _decrypt_config_sections(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive configuration sections"""
        if not self._cipher_suite or 'encrypted_sections' not in config:
            return config
        
        decrypted_config = config.copy()
        encrypted_sections = config['encrypted_sections']
        
        for section_name, encrypted_data in encrypted_sections.items():
            try:
                decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
                decrypted_data = self._cipher_suite.decrypt(decoded_data)
                section_data = json.loads(decrypted_data.decode())
                decrypted_config[section_name] = section_data
            except Exception as e:
                raise ConfigurationError(f"Failed to decrypt section {section_name}: {e}")
        
        del decrypted_config['encrypted_sections']
        return decrypted_config
    
    def validate_tool_configuration(self, tool_name: str, tool_config: Dict[str, Any]) -> bool:
        """Validate individual tool configuration"""
        try:
            # Check required fields
            if 'enabled' not in tool_config:
                tool_config['enabled'] = True
            
            if 'timeout' in tool_config:
                timeout = tool_config['timeout']
                if not isinstance(timeout, int) or timeout < 10 or timeout > 3600:
                    raise ValidationError(f"Tool {tool_name} timeout must be between 10 and 3600 seconds")
            
            if 'priority' in tool_config:
                priority = tool_config['priority']
                if not isinstance(priority, int) or priority < 1 or priority > 10:
                    raise ValidationError(f"Tool {tool_name} priority must be between 1 and 10")
            
            if 'flags' in tool_config:
                flags = tool_config['flags']
                if not isinstance(flags, list):
                    raise ValidationError(f"Tool {tool_name} flags must be a list")
                
                # Validate individual flags for security
                InputValidator.validate_command_args(flags)
            
            return True
        except Exception as e:
            raise ConfigurationError(f"Invalid configuration for tool {tool_name}: {e}")
    
    def optimize_performance_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize performance configuration based on system resources"""
        try:
            import psutil
            
            performance = config.get('performance', {})
            
            # Auto-adjust max_workers based on CPU cores
            cpu_count = psutil.cpu_count()
            if 'max_workers' not in performance or performance['max_workers'] > cpu_count * 2:
                performance['max_workers'] = min(cpu_count * 2, 20)
            
            # Adjust memory limit based on available RAM
            memory = psutil.virtual_memory()
            available_mb = memory.available // (1024 * 1024)
            if 'memory_limit_mb' not in performance or performance['memory_limit_mb'] > available_mb * 0.5:
                performance['memory_limit_mb'] = int(available_mb * 0.3)  # Use 30% of available memory
            
            config['performance'] = performance
            return config
        except ImportError:
            # If psutil not available, use conservative defaults
            return config
        except Exception as e:
            raise ConfigurationError(f"Failed to optimize performance configuration: {e}")
    
    def backup_configuration(self, backup_path: Optional[Path] = None) -> Path:
        """Create a backup of current configuration"""
        if backup_path is None:
            backup_path = self.config_path.with_suffix('.backup.json')
        
        try:
            if self.config_path.exists():
                import shutil
                shutil.copy2(self.config_path, backup_path)
                return backup_path
            else:
                raise ConfigurationError("No configuration file exists to backup")
        except Exception as e:
            raise ConfigurationError(f"Failed to backup configuration: {e}")
    
    def restore_configuration(self, backup_path: Path) -> bool:
        """Restore configuration from backup"""
        try:
            if not backup_path.exists():
                raise ConfigurationError(f"Backup file does not exist: {backup_path}")
            
            # Validate backup before restoring
            with open(backup_path, 'r') as f:
                backup_config = json.load(f)
            
            validated_config = InputValidator.validate_config_schema(backup_config)
            
            # Save current config as emergency backup
            if self.config_path.exists():
                emergency_backup = self.config_path.with_suffix('.emergency.json')
                self.backup_configuration(emergency_backup)
            
            # Restore from backup
            import shutil
            shutil.copy2(backup_path, self.config_path)
            
            # Reload configuration
            self.load_config()
            return True
        except Exception as e:
            raise ConfigurationError(f"Failed to restore configuration: {e}")
    
    def get_tool_statistics(self) -> Dict[str, Any]:
        """Get statistics about configured tools"""
        config = self.get_config()
        tools = config.get('tools', {})
        
        stats = {
            'total_tools': len(tools),
            'enabled_tools': sum(1 for tool in tools.values() if tool.get('enabled', True)),
            'disabled_tools': sum(1 for tool in tools.values() if not tool.get('enabled', True)),
            'tools_with_install_cmd': sum(1 for tool in tools.values() if tool.get('install_cmd')),
            'high_priority_tools': sum(1 for tool in tools.values() if tool.get('priority', 1) <= 2),
            'tools_requiring_auth': sum(1 for tool in tools.values() if tool.get('requires_auth', False))
        }
        
        return stats