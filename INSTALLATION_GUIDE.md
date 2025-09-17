# Azaz-El v6.0.0-ENHANCED-SECURITY Installation Guide

## 🚀 Quick Start Installation

### Prerequisites
- **Operating System**: Linux (Ubuntu/Debian/Kali), macOS, or WSL2
- **Python**: 3.8+ (Python 3.12+ recommended)
- **Go**: 1.19+ (for security tools)
- **Git**: Latest version
- **Internet Connection**: For tool downloads and updates

### One-Line Installation
```bash
curl -sSL https://raw.githubusercontent.com/cxb3rf1lth/Azaz-El/main/install.sh | bash
```

### Manual Installation

#### 1. Clone Repository
```bash
git clone https://github.com/cxb3rf1lth/Azaz-El.git
cd Azaz-El
```

#### 2. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

#### 3. Install Security Tools (Interactive)
```bash
python3 moloch.py --init
```

#### 4. Install Security Tools (Automated)
```bash
python3 moloch.py --install-tools --auto
```

## 🔧 Advanced Installation Options

### Custom Configuration
```bash
# Copy default configuration
cp moloch.cfg.json moloch.cfg.json.backup

# Edit configuration
nano moloch.cfg.json

# Validate configuration
python3 verify_installation.py
```

### Installing Specific Tool Categories

#### Reconnaissance Tools
```bash
python3 moloch.py --install-category recon
```

#### Web Application Testing Tools
```bash
python3 moloch.py --install-category web
```

#### Infrastructure Testing Tools
```bash
python3 moloch.py --install-category infrastructure
```

## 🛡️ Enhanced Security Features

### Input Validation
The framework now includes comprehensive input validation:
- Target validation (domains, IPs, URLs)
- Path traversal protection
- Command injection prevention
- File extension validation

### Async HTTP Client
High-performance concurrent operations:
- Connection pooling
- SSL/TLS security
- Rate limiting
- Timeout management

### Configuration Security
- Auto-validation and correction
- Security-focused defaults
- Encrypted sensitive data storage
- Configuration backup and restore

## 📊 Verification and Testing

### System Health Check
```bash
python3 verify_installation.py
```

### Run Test Suite
```bash
python3 test_enhanced_framework.py
python3 test_fixes.py
```

### Validate Enhancements
```bash
python3 validate_enhancements.py
```

## 🎯 Usage Examples

### Basic Reconnaissance
```bash
python3 moloch.py --target example.com --recon
```

### Full Security Assessment
```bash
python3 moloch.py --target example.com --full-scan
```

### Web Application Testing
```bash
python3 moloch.py --target https://example.com --web-scan
```

### Unified Dashboard
```bash
python3 azaz_el_unified.py
```

### Master Interface
```bash
python3 master_azaz_el.py
```

## 🔧 Tool Installation Details

### Automatic Installation
The framework automatically installs these categories of tools:

#### Subdomain Discovery (7 tools)
- subfinder, amass, assetfinder, findomain, chaos, shuffledns, alterx

#### Web Application Testing (8 tools)
- httpx, nuclei, ffuf, gobuster, katana, gau, waybackurls, dalfox

#### Infrastructure Testing (6 tools)
- nmap, naabu, dnsx, testssl, nikto, tlsx

#### Advanced Analysis (9 tools)
- cdncheck, asnmap, mapcidr, gf, unfurl, anew, notify, interactsh-client, arjun

### Manual Tool Installation
If automatic installation fails, you can install tools manually:

```bash
# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install system tools (Ubuntu/Debian)
sudo apt update && sudo apt install -y nmap nikto

# Install Python tools
pip3 install arjun
```

## 🚨 Troubleshooting

### Common Issues

#### "Tool not found in PATH"
```bash
# Add Go bin to PATH
export PATH=$PATH:~/go/bin

# Make permanent
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### "Permission denied"
```bash
# Fix permissions
sudo chmod +x /usr/local/bin/tool_name

# Or install to user directory
go install tool_name@latest
```

#### "Configuration validation failed"
```bash
# Reset configuration to defaults
rm moloch.cfg.json
python3 moloch.py --init
```

### Performance Optimization

#### For Large Targets
```bash
# Increase worker count (in moloch.cfg.json)
"max_workers": 20

# Increase timeout
"tool_timeout": 1200
```

#### For Rate-Limited Targets
```bash
# Decrease rate limit
"rate_limit": 500

# Add delays
"request_delay": 1
```

## 🔐 Security Considerations

### Safe Usage
- Always obtain proper authorization before testing
- Use rate limiting to avoid overwhelming targets
- Review and sanitize all inputs
- Enable logging for audit trails

### API Keys and Credentials
- Store API keys securely in moloch.cfg.json
- Use environment variables for sensitive data
- Regularly rotate credentials
- Never commit credentials to version control

### Network Security
- Use VPN for external assessments
- Configure firewall rules appropriately
- Monitor network traffic during scans
- Implement egress filtering for safety

## 📞 Support and Updates

### Getting Help
```bash
# Framework help
python3 moloch.py --help
python3 azaz_el_unified.py --help

# Tool-specific help
python3 moloch.py --tool-help nuclei
```

### Updates
```bash
# Update framework
git pull origin main

# Update tools
python3 moloch.py --update-tools

# Update wordlists
python3 moloch.py --update-wordlists
```

### Community
- **GitHub Issues**: Bug reports and feature requests
- **Documentation**: Comprehensive guides and tutorials
- **Security Research**: Responsible disclosure program

---

**For more information, see the main README.md and CHANGELOG.md files.**