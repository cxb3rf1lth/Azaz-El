# Azaz-El - Advanced Automated Penetration Testing Framework

![Version](https://img.shields.io/badge/version-v3.5.0-blue)
![Python](https://img.shields.io/badge/python-3.6+-green)
![License](https://img.shields.io/badge/license-Educational-red)

## Overview

Azaz-El (Moloch Framework) is a comprehensive automated penetration testing toolkit designed for security professionals. This enhanced version includes extensive bug fixes, performance optimizations, and massive wordlist/payload integrations.

## Features

### 🎯 Core Capabilities
- **Automated Reconnaissance**: Subdomain discovery, DNS resolution, HTTP probing
- **Vulnerability Scanning**: Nuclei templates, SSL/TLS testing, port scanning
- **Web Application Testing**: XSS detection, crawling, parameter discovery
- **Directory Fuzzing**: Advanced directory and file discovery
- **Comprehensive Reporting**: HTML reports with consolidated findings

### 🔧 Recent Improvements (V2 Fixed)
- ✅ **All Critical Bugs Fixed**: Function signatures, command execution, indentation
- ✅ **Massive Wordlist Integration**: 6 comprehensive wordlists with 50K+ entries
- ✅ **Advanced Payload Libraries**: 4 payload sets with 15K+ attack vectors
- ✅ **Enhanced Error Handling**: Robust exception handling and timeout management
- ✅ **Performance Optimizations**: Concurrent execution and smart tool detection
- ✅ **Interactive Installation**: User-controlled dependency installation

### 📚 Integrated Wordlists & Payloads

#### Wordlists (50K+ entries)
- **Subdomains**: Top 1M subdomain variations
- **Directories**: RAFT medium directories + custom paths
- **Parameters**: Comprehensive parameter mining wordlist
- **API Endpoints**: Modern API path discovery
- **Extensions**: Common file extensions
- **Sensitive Files**: Configuration and backup files

#### Payloads (15K+ entries)
- **XSS Payloads**: Context-aware XSS vectors including WAF bypasses
- **SQL Injection**: Boolean, time-based, error-based, and union-based SQLi
- **Advanced XSS**: HTML5, SVG, MathML, template literals, polyglots
- **Advanced SQLi**: NoSQL, LDAP, XPath, OS command injection

## Installation

### Prerequisites
```bash
# Essential system tools (install manually)
sudo apt update
sudo apt install git wget curl golang python3 python3-pip

# Or on macOS
brew install git wget curl go python3
```

### Quick Start
```bash
# Clone repository
git clone https://github.com/cxb3rf1lth/Azaz-El.git
cd Azaz-El

# Initialize environment (creates wordlists, installs tools)
python3 Azazel_V2_Fixed.py --init

# Add target and run
python3 Azazel_V2_Fixed.py -t example.com
```

## Usage

### Command Line Options
```bash
# Show help
python3 Azazel_V2_Fixed.py --help

# Initialize environment only
python3 Azazel_V2_Fixed.py --init

# Add target and run interactive menu
python3 Azazel_V2_Fixed.py -t target.com

# Add target and run full automation
python3 Azazel_V2_Fixed.py -t target.com --run-full

# Use custom config
python3 Azazel_V2_Fixed.py -c custom-config.json
```

### Interactive Menu
The script provides an intuitive menu system:

1. **Full Automation Pipeline** - Complete recon → scan → web → fuzz → report
2. **Target Management** - Add/remove/view targets
3. **Reconnaissance** - Subdomain discovery, DNS resolution, HTTP probing
4. **Vulnerability Scanning** - Nuclei, port scans, SSL/TLS testing
5. **Web Application Testing** - Crawling, XSS detection
6. **Fuzzing** - Directory and file discovery
7. **Configuration** - Settings and tool status
8. **Generate Report** - HTML report generation

## Tools Integration

### Reconnaissance Tools
- **Subfinder**: Subdomain discovery
- **Amass**: Advanced subdomain enumeration
- **Assetfinder**: Additional subdomain discovery
- **Findomain**: Fast subdomain finder
- **DNSx**: DNS resolution and validation
- **HTTPx**: HTTP/HTTPS probing

### Scanning Tools
- **Nuclei**: Vulnerability scanner with templates
- **Nmap**: Network discovery and port scanning
- **Naabu**: Fast port scanner
- **testssl.sh**: SSL/TLS configuration testing

### Web Application Tools
- **Katana**: Web crawler
- **Gau**: URL gathering from various sources
- **Waybackurls**: Wayback Machine URL extraction
- **Dalfox**: XSS scanner
- **FFuF**: Fast web fuzzer
- **Gobuster**: Directory/file brute-forcer

## Configuration

The framework uses `moloch.cfg.json` for configuration:

```json
{
  "tools": {
    "nuclei": {
      "enabled": true,
      "flags": ["-silent", "-severity", "low,medium,high,critical"]
    }
  },
  "wordlists": {
    "subdomains": "subdomains-top1million-5000.txt",
    "fuzzing": "raft-medium-directories.txt"
  },
  "performance": {
    "max_workers": 10,
    "tool_timeout": 600
  }
}
```

## Output Structure

```
runs/
├── moloch_20231201_120000_abc123def/
│   ├── subdomains/
│   │   ├── subfinder.txt
│   │   ├── amass.txt
│   │   └── subdomains_target.txt
│   ├── hosts/
│   │   ├── resolved_target.txt
│   │   ├── live_target.txt
│   │   └── port_scan_target.nmap
│   ├── vulns/
│   │   ├── nuclei_results.json
│   │   └── ssl_target.json
│   ├── crawling/
│   │   ├── urls_target.txt
│   │   └── xss_target.txt
│   ├── fuzzing/
│   │   └── ffuf_target.json
│   └── report/
│       ├── report.html
│       └── moloch_findings.json
```

## Security Considerations

⚠️ **Important**: This tool is for authorized security testing only.

- Always obtain proper authorization before testing
- Use responsibly on systems you own or have permission to test
- Be mindful of rate limits and server resources
- Review and understand all payloads before use

## Troubleshooting

### Common Issues

1. **Tool not found errors**
   ```bash
   # Run initialization to install missing tools
   python3 Azazel_V2_Fixed.py --init
   ```

2. **Permission errors**
   ```bash
   # Ensure proper Go environment
   export GOPATH=$HOME/go
   export PATH=$PATH:$GOPATH/bin
   ```

3. **Timeout issues**
   ```bash
   # Adjust timeout in moloch.cfg.json
   "performance": {"tool_timeout": 1200}
   ```

### Debug Mode
Enable debug logging by modifying the logging level in the script or checking log files in the `logs/` directory.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## Changelog

### V2 Fixed (Current)
- 🐛 Fixed all critical bugs identified in analysis
- 📚 Integrated massive wordlists and payloads (65K+ entries)
- ⚡ Performance optimizations and timeout management
- 🛡️ Enhanced error handling and user experience
- 🎯 Interactive tool installation with user confirmation

### V1 (Buggy)
- Initial framework with basic functionality
- Multiple critical bugs preventing proper execution
- Limited wordlists and payloads

## License

This project is for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations.

## Disclaimer

The authors are not responsible for misuse of this tool. Use only on systems you own or have explicit permission to test.

---

**Made for security professionals, by security professionals** 🛡️