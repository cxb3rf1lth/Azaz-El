#!/bin/bash
# Azaz-El Security Framework - Enhanced Auto Installation Script
# Professional security assessment framework setup automation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
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
                                                                      
EOF
echo -e "${NC}"

echo -e "${WHITE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${WHITE}║${GREEN}                    🔱 AZAZ-EL INSTALLATION WIZARD 🔱${WHITE}                    ║${NC}"
echo -e "${WHITE}║${CYAN}                Advanced Security Assessment Framework${WHITE}                   ║${NC}"
echo -e "${WHITE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"

echo ""
echo -e "${GREEN}🚀 Starting Azaz-El Security Framework Installation...${NC}"
echo ""

# Check if running as root for system-wide tool installation
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}⚠️  Running as root - will install system-wide tools${NC}"
    INSTALL_PREFIX="sudo"
else
    echo -e "${BLUE}ℹ️  Running as user - will install user-level tools${NC}"
    INSTALL_PREFIX=""
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Python packages
install_python_deps() {
    echo -e "${CYAN}📦 Installing Python dependencies...${NC}"
    
    if ! command_exists pip3; then
        echo -e "${RED}❌ pip3 not found. Installing pip...${NC}"
        $INSTALL_PREFIX apt-get update && $INSTALL_PREFIX apt-get install -y python3-pip
    fi
    
    pip3 install -r requirements.txt
    echo -e "${GREEN}✅ Python dependencies installed successfully${NC}"
}

# Function to install Go tools
install_go_tools() {
    echo -e "${CYAN}🔧 Installing Go-based security tools...${NC}"
    
    if ! command_exists go; then
        echo -e "${YELLOW}⚠️  Go not found. Please install Go manually or via package manager${NC}"
        echo -e "${BLUE}💡 Ubuntu/Debian: sudo apt install golang-go${NC}"
        return 1
    fi
    
    # Install nuclei
    if ! command_exists nuclei; then
        echo -e "${BLUE}🔬 Installing Nuclei vulnerability scanner...${NC}"
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    else
        echo -e "${GREEN}✅ Nuclei already installed${NC}"
    fi
    
    # Install subfinder
    if ! command_exists subfinder; then
        echo -e "${BLUE}🔍 Installing Subfinder subdomain discovery tool...${NC}"
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    else
        echo -e "${GREEN}✅ Subfinder already installed${NC}"
    fi
    
    # Install httpx
    if ! command_exists httpx; then
        echo -e "${BLUE}🌐 Installing HTTPx HTTP toolkit...${NC}"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    else
        echo -e "${GREEN}✅ HTTPx already installed${NC}"
    fi
    
    # Install katana
    if ! command_exists katana; then
        echo -e "${BLUE}🕷️  Installing Katana web crawler...${NC}"
        go install github.com/projectdiscovery/katana/cmd/katana@latest
    else
        echo -e "${GREEN}✅ Katana already installed${NC}"
    fi
    
    echo -e "${GREEN}✅ Go tools installation completed${NC}"
}

# Function to install system tools
install_system_tools() {
    echo -e "${CYAN}🛠️  Installing system security tools...${NC}"
    
    # Update package list
    $INSTALL_PREFIX apt-get update
    
    # Install nmap
    if ! command_exists nmap; then
        echo -e "${BLUE}🔌 Installing Nmap network scanner...${NC}"
        $INSTALL_PREFIX apt-get install -y nmap
    else
        echo -e "${GREEN}✅ Nmap already installed${NC}"
    fi
    
    # Install curl and wget
    $INSTALL_PREFIX apt-get install -y curl wget git unzip
    
    # Install ffuf
    if ! command_exists ffuf; then
        echo -e "${BLUE}💥 Installing FFuF web fuzzer...${NC}"
        $INSTALL_PREFIX apt-get install -y ffuf || {
            echo -e "${YELLOW}⚠️  FFuF not available via apt, installing from GitHub...${NC}"
            wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz
            tar -xzf ffuf_2.1.0_linux_amd64.tar.gz
            $INSTALL_PREFIX mv ffuf /usr/local/bin/
            rm ffuf_2.1.0_linux_amd64.tar.gz
        }
    else
        echo -e "${GREEN}✅ FFuF already installed${NC}"
    fi
    
    echo -e "${GREEN}✅ System tools installation completed${NC}"
}

# Function to setup directories and configuration
setup_framework() {
    echo -e "${CYAN}📁 Setting up framework directories and configuration...${NC}"
    
    # Create necessary directories
    mkdir -p runs logs wordlists payloads
    
    # Initialize configuration if not exists
    if [ ! -f "moloch.cfg.json" ]; then
        echo -e "${BLUE}📝 Creating default configuration...${NC}"
        python3 moloch.py --init
    fi
    
    # Set executable permissions
    chmod +x moloch.py azaz_el_unified.py
    
    echo -e "${GREEN}✅ Framework setup completed${NC}"
}

# Function to validate installation
validate_installation() {
    echo -e "${CYAN}🔍 Validating installation...${NC}"
    
    # Test Python imports
    echo -e "${BLUE}🐍 Testing Python dependencies...${NC}"
    python3 -c "import aiohttp, cryptography; print('✅ Core dependencies OK')" || {
        echo -e "${RED}❌ Python dependencies validation failed${NC}"
        return 1
    }
    
    # Test framework compilation
    echo -e "${BLUE}🧪 Testing framework compilation...${NC}"
    python3 -m py_compile moloch.py azaz_el_unified.py || {
        echo -e "${RED}❌ Framework compilation failed${NC}"
        return 1
    }
    
    # Test tool availability
    echo -e "${BLUE}🔧 Checking tool availability...${NC}"
    missing_tools=()
    required_tools=("nmap" "python3" "curl" "wget")
    
    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -eq 0 ]; then
        echo -e "${GREEN}✅ All required tools are available${NC}"
    else
        echo -e "${YELLOW}⚠️  Missing tools: ${missing_tools[*]}${NC}"
    fi
    
    echo -e "${GREEN}✅ Installation validation completed${NC}"
}

# Main installation flow
main() {
    echo -e "${WHITE}🎯 Installation Options:${NC}"
    echo -e "${GREEN}  1. Full Installation (Recommended)${NC}"
    echo -e "${BLUE}  2. Python Dependencies Only${NC}"
    echo -e "${YELLOW}  3. System Tools Only${NC}"
    echo -e "${CYAN}  4. Framework Setup Only${NC}"
    echo ""
    
    read -p "Select installation type (1-4): " choice
    
    case $choice in
        1)
            echo -e "${GREEN}🚀 Starting full installation...${NC}"
            install_python_deps
            install_system_tools
            install_go_tools
            setup_framework
            validate_installation
            ;;
        2)
            install_python_deps
            ;;
        3)
            install_system_tools
            install_go_tools
            ;;
        4)
            setup_framework
            ;;
        *)
            echo -e "${RED}❌ Invalid choice. Exiting.${NC}"
            exit 1
            ;;
    esac
    
    echo ""
    echo -e "${WHITE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║${GREEN}                        🎉 INSTALLATION COMPLETED! 🎉${WHITE}                        ║${NC}"
    echo -e "${WHITE}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${CYAN}  Get Started:${WHITE}                                                            ║${NC}"
    echo -e "${WHITE}║${BLUE}    Interactive Dashboard: python3 azaz_el_unified.py${WHITE}                      ║${NC}"
    echo -e "${WHITE}║${BLUE}    Core Framework: python3 moloch.py${WHITE}                                      ║${NC}"
    echo -e "${WHITE}║${BLUE}    Quick Scan: python3 azaz_el_unified.py --target example.com --quick-scan${WHITE} ║${NC}"
    echo -e "${WHITE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}🔱 Azaz-El Security Framework is ready for professional security assessments!${NC}"
}

# Run main function
main "$@"