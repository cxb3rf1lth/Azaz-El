# Azaz-El v5.0.0-UNIFIED Professional Security Assessment Framework

🔱 **Advanced Unified Security Assessment Dashboard** 🔱

## 🚀 Quick Start

```bash
# Launch interactive dashboard
python3 azaz_el_unified.py

# Quick security scan
python3 azaz_el_unified.py --target example.com --quick-scan

# Complete security assessment
python3 azaz_el_unified.py --target example.com --full-pipeline

# System status check
python3 azaz_el_unified.py --status
```

## ✨ What's New in v5.0.0-UNIFIED

The Azaz-El framework has been completely redesigned with a **unified professional dashboard** that integrates all security scanning capabilities into a single, powerful interface:

### 🎛️ Professional Dashboard Interface
- **Interactive Navigation**: Multi-level menu system with professional UI
- **Real-time Monitoring**: Live system status and scan progress tracking
- **Dual Interface Modes**: Both interactive dashboard and CLI operations
- **Advanced Configuration**: Comprehensive settings and tool management

### 🔧 Complete Integration
- **Unified Security Engine**: All moloch.py functionality integrated into dashboard
- **20+ Security Tools**: Comprehensive tool integration and status monitoring
- **Advanced Workflows**: Complete automation pipelines for all assessment types
- **Professional Reporting**: Enhanced reporting with multiple formats

### 📊 Enhanced Capabilities
- **Multi-target Scanning**: Parallel processing of multiple targets
- **Cloud Security Assessment**: Comprehensive multi-cloud security analysis
- **Advanced Web Testing**: Complete web application security suite
- **Compliance Tracking**: Security standard compliance monitoring

## 🎯 Core Features

### Security Assessment Capabilities
- **🔍 Reconnaissance Suite**: Subdomain discovery, DNS analysis, HTTP probing
- **🛡️ Vulnerability Scanning**: Nuclei templates, port scanning, SSL analysis  
- **🌐 Web Application Testing**: Crawling, XSS detection, directory fuzzing
- **☁️ Cloud Security Assessment**: Multi-cloud security analysis
- **📊 Professional Reporting**: HTML, JSON, and executive summary reports

### Interface Modes
- **Interactive Dashboard**: Full-featured menu-driven interface
- **Command-Line Interface**: Streamlined CLI for automation
- **Monitoring Mode**: Real-time system monitoring
- **Hybrid Operations**: Seamless mode switching

## 📋 Installation & Usage

### Prerequisites
```bash
# Python 3.8+ required
pip3 install cryptography aiohttp
```

### Dashboard Operations
```bash
# Interactive Dashboard (recommended)
python3 azaz_el_unified.py

# Quick Operations
python3 azaz_el_unified.py --target example.com --quick-scan
python3 azaz_el_unified.py --target-file targets.txt --reconnaissance
python3 azaz_el_unified.py --target example.com --full-pipeline --aggressive

# System Management
python3 azaz_el_unified.py --status
python3 azaz_el_unified.py --config-check
python3 azaz_el_unified.py --list-scans
```

## 🎛️ Dashboard Features

### Main Operations
1. **🚀 Full Automated Pipeline** - Complete security assessment
2. **🎯 Target Management** - Configure and manage targets
3. **🔍 Reconnaissance Suite** - Intelligence gathering
4. **🛡️ Vulnerability Scanning** - Security assessment modules
5. **🌐 Web Application Testing** - Advanced web security
6. **☁️ Cloud Security Assessment** - Multi-cloud analysis
7. **🔧 System Configuration** - Settings management
8. **📊 Reporting & Analytics** - Professional reports
9. **🎛️ System Dashboard** - Real-time monitoring

### Advanced Features
- **Multi-target Processing**: Batch scanning capabilities
- **Async Operations**: High-performance scanning engine  
- **Professional UI**: Color-coded status and progress tracking
- **Comprehensive Logging**: Detailed audit trails
- **Tool Integration**: 20+ security tools seamlessly integrated

## 🔧 Configuration

The unified dashboard uses comprehensive configuration management through `moloch.cfg.json`:

```json
{
  "version": "5.0.0",
  "tools": {
    "subfinder": {"enabled": true, "timeout": 600},
    "nuclei": {"enabled": true, "timeout": 1200},
    "httpx": {"enabled": true, "timeout": 300}
  },
  "performance": {
    "max_concurrent": 10,
    "timeout_default": 300
  }
}
```

## 🧪 Testing & Validation

```bash
# Run comprehensive test suite
python3 test_enhanced_framework.py

# Run unified dashboard demo
python3 demo_unified_dashboard.py

# Test specific functionality
python3 azaz_el_unified.py --target demo.testfire.net --quick-scan
```

**Test Results**: ✅ 18/18 tests passing (100% success rate)

## 📊 Security Tools Integration

The framework integrates with 20+ professional security tools:

### Reconnaissance
- **subfinder**: Subdomain discovery
- **amass**: Advanced subdomain enumeration  
- **httpx**: HTTP service probing
- **assetfinder**: Additional subdomain discovery

### Vulnerability Assessment
- **nuclei**: 5000+ vulnerability templates
- **nmap**: Network service discovery
- **testssl**: SSL/TLS security analysis

### Web Application Testing  
- **katana**: Advanced web crawling
- **dalfox**: XSS vulnerability detection
- **ffuf**: Directory and parameter fuzzing
- **gobuster**: Additional directory discovery

## 🔒 Security Considerations

### Responsible Usage
- ⚠️ **Only test systems you own or have explicit permission to test**
- 📋 **Comply with all applicable laws and regulations**
- 🎯 **Use in designated testing environments only**

### Framework Security
- 🔒 **Encrypted configuration storage**
- 🛡️ **Input validation and sanitization**  
- 📊 **Audit logging and compliance tracking**
- 🔐 **Secure credential management**

## 📚 Documentation

### Command Reference
```bash
# Show all available options
python3 azaz_el_unified.py --help

# System status and configuration
python3 azaz_el_unified.py --status
python3 azaz_el_unified.py --config-check

# Scanning operations
python3 azaz_el_unified.py --target example.com --quick-scan
python3 azaz_el_unified.py --target example.com --full-pipeline
python3 azaz_el_unified.py --target example.com --reconnaissance
python3 azaz_el_unified.py --target example.com --vuln-scan
python3 azaz_el_unified.py --target example.com --web-scan
```

### Additional Documentation
- **📖 [Complete Documentation](README_UNIFIED.md)** - Comprehensive feature guide
- **🎯 [Demo Script](demo_unified_dashboard.py)** - Interactive demonstration
- **🧪 [Test Suite](test_enhanced_framework.py)** - Validation and testing

## 🚀 Advanced Usage

### Multi-target Operations
```bash
# Multiple targets
python3 azaz_el_unified.py --target-list site1.com site2.com site3.com --reconnaissance

# Target file
python3 azaz_el_unified.py --target-file targets.txt --full-pipeline

# Advanced options
python3 azaz_el_unified.py --target example.com --web-scan --aggressive --output-dir results/
```

### Monitoring & Management
```bash
# Real-time monitoring
python3 azaz_el_unified.py --monitor

# Scan history
python3 azaz_el_unified.py --list-scans

# Report generation
python3 azaz_el_unified.py --generate-report --scan-id scan_20250101_120000
```

## 🎉 Migration from Previous Versions

The v5.0.0-UNIFIED release represents a complete redesign:

- **✅ All moloch.py functionality preserved and enhanced**
- **✅ Professional dashboard interface added**
- **✅ Enhanced CLI with comprehensive argument support**  
- **✅ Real-time monitoring and status tracking**
- **✅ Improved performance and reliability**

### Quick Migration
```bash
# Old usage (still works)
python3 moloch.py

# New unified approach (recommended)
python3 azaz_el_unified.py
```

## 📞 Support & Contributing

- **🐛 Issues**: Report issues via GitHub Issues
- **💡 Features**: Request features via GitHub Discussions
- **🤝 Contributing**: See contributing guidelines for development

## ⚖️ License & Disclaimer

This tool is intended for authorized security testing only. Users are responsible for complying with all applicable laws and regulations.

---

🔱 **Azaz-El v5.0.0-UNIFIED - Professional Security Assessment Framework** 🔱

*The complete security assessment platform with unified dashboard interface*