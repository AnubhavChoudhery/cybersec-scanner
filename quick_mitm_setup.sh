#!/bin/bash
# Quick MITM Setup Script for Windows (Git Bash)

echo "==========================================="
echo "MITM PROXY - QUICK SETUP"
echo "==========================================="

# Check if running on Windows
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "Platform: Windows"
    
    # Check for admin privileges
    echo ""
    echo "⚠ IMPORTANT: You need to run this with Administrator privileges"
    echo "   Right-click Git Bash and select 'Run as Administrator'"
    echo ""
    read -p "Are you running as Administrator? (y/n) " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Please restart as Administrator and try again"
        exit 1
    fi
else
    # Linux/Mac - check for sudo
    if [ "$EUID" -ne 0 ]; then
        echo "Please run with sudo:"
        echo "  sudo bash quick_mitm_setup.sh"
        exit 1
    fi
fi

# Get target URL
read -p "Enter your application URL (default: http://localhost:8501): " target
target=${target:-http://localhost:8501}

# Get port
read -p "Enter MITM proxy port (default: 8082): " port
port=${port:-8082}

# Get root directory
read -p "Enter project root directory (default: .): " root
root=${root:-.}

echo ""
echo "Configuration:"
echo "  Target: $target"
echo "  Port: $port"
echo "  Root: $root"
echo ""
read -p "Start scan? (y/n) " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Starting scan with auto-certificate installation..."
    echo "==========================================="
    
    python local_check.py \
        --target "$target" \
        --root "$root" \
        --enable-mitm \
        --auto-install-cert \
        --mitm-port "$port" \
        --mitm-timeout 0 \
        -vv
else
    echo "Cancelled"
fi
