"""
Advanced Logging System for Azaz-El Framework
Provides structured logging with JSON output and multiple handlers
"""

import json
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import sys

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
            "thread": record.thread,
            "process": record.process,
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'extra_data'):
            log_entry["extra"] = record.extra_data
        
        return json.dumps(log_entry, ensure_ascii=False)

class AdvancedLogger:
    """Advanced logging system with multiple handlers and structured output"""
    
    def __init__(self, name: str, log_dir: Path, log_level: str = "INFO"):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create main logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # Setup handlers
        self._setup_console_handler()
        self._setup_file_handler()
        self._setup_json_handler()
        self._setup_error_handler()
        
        # Prevent propagation to root logger
        self.logger.propagate = False
    
    def _setup_console_handler(self):
        """Setup colored console output handler"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Custom formatter with colors
        class ColoredFormatter(logging.Formatter):
            COLORS = {
                'DEBUG': '\033[36m',    # Cyan
                'INFO': '\033[32m',     # Green
                'WARNING': '\033[33m',  # Yellow
                'ERROR': '\033[31m',    # Red
                'CRITICAL': '\033[35m', # Magenta
            }
            RESET = '\033[0m'
            
            def format(self, record):
                log_color = self.COLORS.get(record.levelname, '')
                record.levelname = f"{log_color}{record.levelname}{self.RESET}"
                return super().format(record)
        
        formatter = ColoredFormatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def _setup_file_handler(self):
        """Setup rotating file handler for general logs"""
        log_file = self.log_dir / f"{self.name}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def _setup_json_handler(self):
        """Setup JSON handler for structured logging"""
        json_file = self.log_dir / f"{self.name}_structured.json"
        json_handler = logging.handlers.RotatingFileHandler(
            json_file, maxBytes=50*1024*1024, backupCount=3
        )
        json_handler.setLevel(logging.DEBUG)
        json_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(json_handler)
    
    def _setup_error_handler(self):
        """Setup separate handler for errors and above"""
        error_file = self.log_dir / f"{self.name}_errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_file, maxBytes=5*1024*1024, backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        error_handler.setFormatter(formatter)
        self.logger.addHandler(error_handler)
    
    def debug(self, message: str, extra_data: Dict[str, Any] = None):
        """Log debug message with optional extra data"""
        self._log_with_extra(logging.DEBUG, message, extra_data)
    
    def info(self, message: str, extra_data: Dict[str, Any] = None):
        """Log info message with optional extra data"""
        self._log_with_extra(logging.INFO, message, extra_data)
    
    def warning(self, message: str, extra_data: Dict[str, Any] = None):
        """Log warning message with optional extra data"""
        self._log_with_extra(logging.WARNING, message, extra_data)
    
    def error(self, message: str, extra_data: Dict[str, Any] = None):
        """Log error message with optional extra data"""
        self._log_with_extra(logging.ERROR, message, extra_data)
    
    def critical(self, message: str, extra_data: Dict[str, Any] = None):
        """Log critical message with optional extra data"""
        self._log_with_extra(logging.CRITICAL, message, extra_data)
    
    def _log_with_extra(self, level: int, message: str, extra_data: Dict[str, Any] = None):
        """Internal method to log with extra data"""
        if extra_data:
            # Create a custom LogRecord with extra data
            record = self.logger.makeRecord(
                self.logger.name, level, __file__, 0, message, (), None
            )
            record.extra_data = extra_data
            self.logger.handle(record)
        else:
            self.logger.log(level, message)
    
    def log_tool_execution(self, tool_name: str, command: str, success: bool, 
                          execution_time: float, output_size: int = 0):
        """Log tool execution with structured data"""
        extra_data = {
            "tool_name": tool_name,
            "command": command,
            "success": success,
            "execution_time": execution_time,
            "output_size": output_size,
            "category": "tool_execution"
        }
        
        level = logging.INFO if success else logging.ERROR
        message = f"Tool {tool_name} {'succeeded' if success else 'failed'} in {execution_time:.2f}s"
        self._log_with_extra(level, message, extra_data)
    
    def log_scan_progress(self, target: str, phase: str, progress: float, 
                         findings_count: int = 0):
        """Log scanning progress with structured data"""
        extra_data = {
            "target": target,
            "phase": phase,
            "progress": progress,
            "findings_count": findings_count,
            "category": "scan_progress"
        }
        
        message = f"Scan progress for {target}: {phase} - {progress:.1f}% ({findings_count} findings)"
        self._log_with_extra(logging.INFO, message, extra_data)
    
    def log_vulnerability_found(self, target: str, vuln_type: str, severity: str, 
                               details: Dict[str, Any]):
        """Log vulnerability discovery with structured data"""
        extra_data = {
            "target": target,
            "vulnerability_type": vuln_type,
            "severity": severity,
            "details": details,
            "category": "vulnerability_found"
        }
        
        message = f"Vulnerability found on {target}: {vuln_type} ({severity})"
        self._log_with_extra(logging.WARNING, message, extra_data)

# Global logger instance
_global_logger: Optional[AdvancedLogger] = None

def get_logger(name: str = "azaz-el", log_dir: Path = None, log_level: str = "INFO") -> AdvancedLogger:
    """Get or create global logger instance"""
    global _global_logger
    
    if _global_logger is None:
        if log_dir is None:
            log_dir = Path.cwd() / "logs"
        _global_logger = AdvancedLogger(name, log_dir, log_level)
    
    return _global_logger

def setup_logging(log_dir: Path, log_level: str = "INFO") -> AdvancedLogger:
    """Setup and return configured logger"""
    return get_logger("azaz-el", log_dir, log_level)