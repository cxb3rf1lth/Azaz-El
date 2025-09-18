#!/bin/bash
# Enhanced Azaz-El Ultimate Framework Installation Script
# Version: 7.0.0-ULTIMATE

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Framework information
FRAMEWORK_NAME="Azaz-El Ultimate"
FRAMEWORK_VERSION="v7.0.0-ULTIMATE"
GITHUB_REPO="https://github.com/cxb3rf1lth/Azaz-El.git"

# Installation directories
INSTALL_DIR="/opt/azaz-el-ultimate"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="$HOME/.azaz-el"
TOOLS_DIR="$INSTALL_DIR/tools"

# Log file
LOG_FILE="/tmp/azaz-el-ultimate-install.log"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

print_section() {
    echo -e "\n${CYAN}==== $1 ====${NC}" | tee -a "$LOG_FILE"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check system requirements
check_system_requirements() {
    print_section "Checking System Requirements"
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        print_status "Operating System: Linux ✓"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        print_status "Operating System: macOS ✓"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    # Check Python version
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d'.' -f1)
        PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d'.' -f2)
        
        if [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 8 ]]; then
            print_status "Python version: $PYTHON_VERSION ✓"
        else
            print_error "Python 3.8+ required, found: $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
    
    # Check available memory
    if command_exists free; then
        TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
        if [[ $TOTAL_RAM -ge 4 ]]; then
            print_status "Available RAM: ${TOTAL_RAM}GB ✓"
        else
            print_warning "Recommended 4GB+ RAM, found: ${TOTAL_RAM}GB"
        fi
    fi
    
    # Check disk space
    AVAILABLE_SPACE=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ $AVAILABLE_SPACE -ge 10 ]]; then
        print_status "Available disk space: ${AVAILABLE_SPACE}GB ✓"
    else
        print_warning "Recommended 10GB+ disk space, found: ${AVAILABLE_SPACE}GB"
    fi
}

# Function to install system dependencies
install_system_dependencies() {
    print_section "Installing System Dependencies"
    
    if command_exists apt-get; then
        # Debian/Ubuntu
        print_status "Detected Debian/Ubuntu system"
        sudo apt-get update
        sudo apt-get install -y \
            curl wget git unzip \
            python3-pip python3-venv \
            build-essential \
            nmap nikto \
            sqlite3 \
            golang-go
            
    elif command_exists yum; then
        # RHEL/CentOS
        print_status "Detected RHEL/CentOS system"
        sudo yum update -y
        sudo yum install -y \
            curl wget git unzip \
            python3-pip \
            gcc gcc-c++ make \
            nmap nikto \
            sqlite \
            golang
            
    elif command_exists pacman; then
        # Arch Linux
        print_status "Detected Arch Linux system"
        sudo pacman -Syu --noconfirm \
            curl wget git unzip \
            python-pip \
            base-devel \
            nmap nikto \
            sqlite \
            go
            
    elif command_exists brew; then
        # macOS
        print_status "Detected macOS system"
        brew update
        brew install \
            curl wget git \
            python3 \
            nmap nikto \
            sqlite \
            go
    else
        print_warning "Unknown package manager. Please install dependencies manually."
    fi
}

# Function to install Go security tools
install_go_tools() {
    print_section "Installing Go Security Tools"
    
    # Ensure Go is in PATH
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    
    # Create tools directory
    mkdir -p "$TOOLS_DIR"
    
    # List of Go tools to install
    declare -A GO_TOOLS=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["amass"]="github.com/owasp-amass/amass/v4/...@master"
        ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["tlsx"]="github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
        ["cdncheck"]="github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
        ["asnmap"]="github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
        ["mapcidr"]="github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
        ["arjun"]="github.com/s0md3v/Arjun@latest"
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["gobuster"]="github.com/OJ/gobuster/v3@latest"
        ["gf"]="github.com/tomnomnom/gf@latest"
        ["unfurl"]="github.com/tomnomnom/unfurl@latest"
        ["anew"]="github.com/tomnomnom/anew@latest"
        ["notify"]="github.com/projectdiscovery/notify/cmd/notify@latest"
        ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        ["alterx"]="github.com/projectdiscovery/alterx/cmd/alterx@latest"
        ["shuffledns"]="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
        ["chaos"]="github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    )
    
    for tool in "${!GO_TOOLS[@]}"; do
        print_status "Installing $tool..."
        if go install -v "${GO_TOOLS[$tool]}" >> "$LOG_FILE" 2>&1; then
            print_status "$tool installed successfully ✓"
        else
            print_warning "$tool installation failed"
        fi
    done
    
    # Install findomain separately (binary download)
    print_status "Installing findomain..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        wget -q https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O "$TOOLS_DIR/findomain"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        wget -q https://github.com/findomain/findomain/releases/latest/download/findomain-osx -O "$TOOLS_DIR/findomain"
    fi
    chmod +x "$TOOLS_DIR/findomain"
    sudo ln -sf "$TOOLS_DIR/findomain" "$BIN_DIR/findomain"
}

# Function to install Python dependencies
install_python_dependencies() {
    print_section "Installing Python Dependencies"
    
    # Create virtual environment
    python3 -m venv "$INSTALL_DIR/venv"
    source "$INSTALL_DIR/venv/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install required packages
    pip install \
        aiohttp>=3.8.0 \
        cryptography>=3.4.0 \
        requests>=2.25.0 \
        pyyaml>=5.4.0 \
        colorama>=0.4.4 \
        psutil>=5.8.0 \
        pycryptodome>=3.15.0 \
        python-nmap>=0.7.1 \
        jinja2>=3.0.0 \
        asyncio \
        aiofiles \
        click \
        rich \
        tabulate \
        selenium \
        beautifulsoup4 \
        lxml \
        dnspython \
        shodan \
        censys
        
    print_status "Python dependencies installed successfully ✓"
}

# Function to setup configuration
setup_configuration() {
    print_section "Setting Up Configuration"
    
    # Create configuration directory
    mkdir -p "$CONFIG_DIR"
    
    # Create enhanced configuration file
    cat > "$CONFIG_DIR/azaz-el-ultimate.json" << 'EOF'
{
    "version": "7.0.0-ULTIMATE",
    "framework": {
        "name": "Azaz-El Ultimate",
        "concurrent_scans": 50,
        "max_memory_usage": 0.8,
        "max_cpu_usage": 0.9,
        "default_timeout": 300
    },
    "tools": {
        "subfinder": {"enabled": true, "timeout": 600, "priority": 1},
        "amass": {"enabled": true, "timeout": 900, "priority": 1},
        "assetfinder": {"enabled": true, "timeout": 300, "priority": 2},
        "httpx": {"enabled": true, "timeout": 300, "priority": 1},
        "nuclei": {"enabled": true, "timeout": 1200, "priority": 1},
        "katana": {"enabled": true, "timeout": 600, "priority": 2},
        "dnsx": {"enabled": true, "timeout": 180, "priority": 2},
        "naabu": {"enabled": true, "timeout": 300, "priority": 1},
        "nmap": {"enabled": true, "timeout": 900, "priority": 1},
        "nikto": {"enabled": true, "timeout": 600, "priority": 2},
        "ffuf": {"enabled": true, "timeout": 800, "priority": 2},
        "gobuster": {"enabled": true, "timeout": 600, "priority": 2},
        "dalfox": {"enabled": true, "timeout": 400, "priority": 2},
        "gau": {"enabled": true, "timeout": 300, "priority": 3},
        "waybackurls": {"enabled": true, "timeout": 180, "priority": 3}
    },
    "scanning": {
        "intelligence_gathering": true,
        "network_discovery": true,
        "vulnerability_assessment": true,
        "web_security_testing": true,
        "automated_exploitation": false,
        "compliance_checking": true
    },
    "reporting": {
        "formats": ["html", "json", "pdf"],
        "include_screenshots": true,
        "include_evidence": true,
        "compliance_frameworks": ["OWASP", "NIST", "PCI-DSS"]
    },
    "api_keys": {
        "shodan": "",
        "censys": "",
        "securitytrails": "",
        "chaos": "",
        "github": ""
    }
}
EOF
    
    print_status "Configuration file created: $CONFIG_DIR/azaz-el-ultimate.json"
}

# Function to create directory structure
create_directory_structure() {
    print_section "Creating Directory Structure"
    
    # Create main directories
    sudo mkdir -p "$INSTALL_DIR"/{core,scanners,reports,wordlists,payloads,plugins}
    sudo mkdir -p "$INSTALL_DIR"/logs
    sudo mkdir -p "$INSTALL_DIR"/runs
    
    # Create symlinks
    sudo ln -sf "$INSTALL_DIR/azaz_el_ultimate.py" "$BIN_DIR/azaz-el"
    sudo ln -sf "$INSTALL_DIR/azaz_el_ultimate.py" "$BIN_DIR/azaz-el-ultimate"
    
    print_status "Directory structure created successfully ✓"
}

# Function to download wordlists and payloads
download_resources() {
    print_section "Downloading Wordlists and Payloads"
    
    WORDLIST_DIR="$INSTALL_DIR/wordlists"
    PAYLOAD_DIR="$INSTALL_DIR/payloads"
    
    # Download SecLists
    if [[ ! -d "$WORDLIST_DIR/SecLists" ]]; then
        print_status "Downloading SecLists..."
        git clone https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists" >> "$LOG_FILE" 2>&1
    fi
    
    # Download common wordlists
    cd "$WORDLIST_DIR"
    
    # Download dirbuster wordlists
    if [[ ! -f "common.txt" ]]; then
        wget -q https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt
    fi
    
    # Download subdomain wordlists
    if [[ ! -f "subdomains-top1million-5000.txt" ]]; then
        wget -q https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-1000.txt -O subdomains-top1000.txt
    fi
    
    # Create custom payload database
    cat > "$PAYLOAD_DIR/xss_payloads.txt" << 'EOF'
<script>alert('XSS')</script>
"><script>alert(document.domain)</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
'><script>alert(String.fromCharCode(88,83,83))</script>
<iframe src="javascript:alert('XSS')"></iframe>
<body onload=alert('XSS')>
EOF
    
    cat > "$PAYLOAD_DIR/sqli_payloads.txt" << 'EOF'
' OR '1'='1
' UNION SELECT null,version(),user()--
'; DROP TABLE users;--
' OR 1=1--
admin'/*
' UNION SELECT 1,2,3,4,5,6,7,8,9,10--
' AND (SELECT COUNT(*) FROM information_schema.tables)>0--
EOF
    
    print_status "Resources downloaded successfully ✓"
}

# Function to run tests
run_tests() {
    print_section "Running Framework Tests"
    
    cd "$INSTALL_DIR"
    
    # Activate virtual environment
    source "$INSTALL_DIR/venv/bin/activate"
    
    # Run existing tests
    if [[ -f "test_enhanced_framework.py" ]]; then
        print_status "Running enhanced framework tests..."
        python3 test_enhanced_framework.py >> "$LOG_FILE" 2>&1
        if [[ $? -eq 0 ]]; then
            print_status "Framework tests passed ✓"
        else
            print_warning "Some framework tests failed"
        fi
    fi
    
    # Test ultimate framework
    print_status "Testing ultimate framework..."
    python3 azaz_el_ultimate.py --help >> "$LOG_FILE" 2>&1
    if [[ $? -eq 0 ]]; then
        print_status "Ultimate framework test passed ✓"
    else
        print_error "Ultimate framework test failed"
    fi
}

# Function to create startup script
create_startup_script() {
    print_section "Creating Startup Script"
    
    cat > "$BIN_DIR/azaz-el-ultimate" << EOF
#!/bin/bash
# Azaz-El Ultimate Framework Startup Script

# Activate virtual environment
source "$INSTALL_DIR/venv/bin/activate"

# Set environment variables
export AZAZ_EL_HOME="$INSTALL_DIR"
export AZAZ_EL_CONFIG="$CONFIG_DIR"
export PATH="\$PATH:$HOME/go/bin:$TOOLS_DIR"

# Run the framework
cd "$INSTALL_DIR"
python3 azaz_el_ultimate.py "\$@"
EOF
    
    chmod +x "$BIN_DIR/azaz-el-ultimate"
    print_status "Startup script created: $BIN_DIR/azaz-el-ultimate"
}

# Function to display completion message
display_completion() {
    print_section "Installation Complete"
    
    echo -e "${GREEN}"
    cat << 'EOF'
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║  ██████╗ ███████╗██████╗ ███████╗     ███████╗██╗                          ║
    ║  ██╔══██╗██╔════╝██╔══██╗██╔════╝     ██╔════╝██║                          ║
    ║  ██████╔╝█████╗  ██████╔╝█████╗       █████╗  ██║                          ║
    ║  ██╔══██╗██╔══╝  ██╔══██╗██╔══╝       ██╔══╝  ██║                          ║
    ║  ██║  ██║███████╗██████╔╝███████╗     ███████╗███████╗                     ║
    ║  ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝     ╚══════╝╚══════╝                     ║
    ║                                                                              ║
    ║                     🎉 INSTALLATION COMPLETE! 🎉                           ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    print_status "${FRAMEWORK_NAME} ${FRAMEWORK_VERSION} installed successfully!"
    echo
    print_status "📁 Installation Directory: $INSTALL_DIR"
    print_status "⚙️  Configuration Directory: $CONFIG_DIR"
    print_status "📋 Log File: $LOG_FILE"
    echo
    print_status "🚀 Quick Start Commands:"
    echo -e "   ${CYAN}azaz-el-ultimate --help${NC}                    # Show help"
    echo -e "   ${CYAN}azaz-el-ultimate --target example.com -u${NC}  # Ultimate scan"
    echo -e "   ${CYAN}azaz-el-ultimate --list-scans${NC}              # List active scans"
    echo
    print_status "📚 Next Steps:"
    echo "   1. Configure API keys in: $CONFIG_DIR/azaz-el-ultimate.json"
    echo "   2. Review configuration settings"
    echo "   3. Run your first scan"
    echo
    print_warning "⚠️  Remember to use this tool responsibly and only on systems you own or have permission to test!"
}

# Main installation function
main() {
    echo -e "${PURPLE}"
    cat << 'EOF'
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║  ██████╗ ███████╗██████╗ ███████╗     ███████╗██╗                          ║
    ║  ██╔══██╗██╔════╝██╔══██╗██╔════╝     ██╔════╝██║                          ║
    ║  ██████╔╝█████╗  ██████╔╝█████╗       █████╗  ██║                          ║
    ║  ██╔══██╗██╔══╝  ██╔══██╗██╔══╝       ██╔══╝  ██║                          ║
    ║  ██║  ██║███████╗██████╔╝███████╗     ███████╗███████╗                     ║
    ║  ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝     ╚══════╝╚══════╝                     ║
    ║                                                                              ║
    ║                      ULTIMATE FRAMEWORK INSTALLER                           ║
    ║                         Version 7.0.0-ULTIMATE                             ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    print_status "Starting installation of ${FRAMEWORK_NAME} ${FRAMEWORK_VERSION}"
    echo "Installation log: $LOG_FILE"
    echo
    
    # Check if running as root for certain operations
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some operations may require sudo anyway."
    fi
    
    # Run installation steps
    check_system_requirements
    install_system_dependencies
    create_directory_structure
    install_go_tools
    install_python_dependencies
    setup_configuration
    download_resources
    create_startup_script
    run_tests
    display_completion
}

# Trap for cleanup on exit
trap 'echo -e "\n${RED}Installation interrupted!${NC}"; exit 1' INT

# Check for help argument
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Azaz-El Ultimate Framework Installer"
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --help, -h     Show this help message"
    echo "  --no-go        Skip Go tools installation"
    echo "  --no-resources Skip wordlists/payloads download"
    echo "  --no-tests     Skip running tests"
    echo
    exit 0
fi

# Run main installation
main "$@"