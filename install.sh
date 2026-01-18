#!/bin/bash

# Arch Load Manager - Installation Script v2.1.0
# Maintainer: Porker Roland <gitporker@gmail.com>

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored message
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. Installation will be system-wide."
        return 0
    else
        print_info "Not running as root. Daemon service will require sudo."
        return 1
    fi
}

# Detect package manager
detect_package_manager() {
    if command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v apt &> /dev/null; then
        echo "apt"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v yum &> /dev/null; then
        echo "yum"
    else
        echo "unknown"
    fi
}

# Check for required dependencies
check_dependencies() {
    print_info "Checking dependencies..."

    local missing_deps=()

    # Check for build tools
    if ! command -v gcc &> /dev/null; then
        missing_deps+=("gcc")
    fi

    if ! command -v make &> /dev/null; then
        missing_deps+=("make")
    fi

    if ! command -v pkg-config &> /dev/null; then
        missing_deps+=("pkg-config")
    fi

    # Check for GTK3
    if ! pkg-config --exists gtk+-3.0; then
        missing_deps+=("gtk3")
    fi

    # Check for json-c
    if ! pkg-config --exists json-c; then
        missing_deps+=("json-c")
    fi

    # Check for uthash (header-only library)
    if ! echo '#include <uthash.h>' | gcc -E - &> /dev/null; then
        missing_deps+=("uthash")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_info "Please install them first:"

        local pm=$(detect_package_manager)
        case $pm in
            pacman)
                echo "  sudo pacman -S base-devel gtk3 json-c uthash"
                ;;
            apt)
                echo "  sudo apt install build-essential libgtk-3-dev libjson-c-dev uthash-dev"
                ;;
            dnf|yum)
                echo "  sudo $pm install gcc make pkg-config gtk3-devel json-c-devel uthash-devel"
                ;;
            *)
                echo "  Install: gcc, make, pkg-config, gtk3, json-c, uthash"
                ;;
        esac
        return 1
    fi

    print_success "All dependencies are installed"
    return 0
}

# Build the project
build_project() {
    print_info "Building Arch Load Manager..."

    # Clean previous builds
    make clean &> /dev/null || true

    # Build
    if make all; then
        print_success "Build completed successfully"
        return 0
    else
        print_error "Build failed"
        return 1
    fi
}

# Install binaries and files via Makefile
install_files() {
    print_info "Installing files..."
    if sudo make install; then
        print_success "Files installed successfully"
    else
        print_error "Installation failed"
        return 1
    fi
}

# Install icons (extra step for resizing)
install_icons() {
    print_info "Installing application icons (resized)..."

    if [ ! -f "Arch Load Manager.png" ]; then
        print_warning "Icon file 'Arch Load Manager.png' not found, skipping..."
        return
    fi

    # Install to hicolor theme at multiple sizes for all DEs
    local sizes=(16 24 32 48 64 128 256)
    local icon_base="/usr/share/icons/hicolor"

    for size in "${sizes[@]}"; do
        local dest_dir="${icon_base}/${size}x${size}/apps"
        sudo mkdir -p "$dest_dir"

        # Use ImageMagick if available
        if command -v magick &> /dev/null; then
            sudo magick "Arch Load Manager.png" -resize "${size}x${size}" \
                "$dest_dir/arch-load-manager.png"
        elif command -v convert &> /dev/null; then
            sudo convert "Arch Load Manager.png" -resize "${size}x${size}" \
                "$dest_dir/arch-load-manager.png" 2>/dev/null
        fi
    done

    # Update icon cache
    if command -v gtk-update-icon-cache &> /dev/null; then
        sudo gtk-update-icon-cache -f -t "$icon_base" 2>/dev/null || true
    fi

    print_success "Icons installed and cache updated"
}

# Setup and start the daemon
setup_daemon() {
    print_info "Setting up daemon service..."
    
    if command -v systemctl &> /dev/null; then
        sudo systemctl daemon-reload
        sudo systemctl enable --now arch-load-daemon
        print_success "Daemon service enabled and started"
    else
        print_warning "systemctl not found. Please start the daemon manually."
    fi
}

# Main installation flow
main() {
    echo ""
    echo "======================================"
    echo "  Arch Load Manager - Installation"
    echo "======================================"
    echo ""

    check_root || true

    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi

    # Build
    if ! build_project; then
        exit 1
    fi

    # Install
    install_files
    install_icons

    # Setup daemon
    setup_daemon

    echo ""
    print_success "Installation complete!"
    echo ""
    echo "To launch the GUI:"
    echo "  - From application menu: Search for 'Arch Load Manager'"
    echo "  - From terminal: arch-load-manager"
    echo ""
    echo "To check daemon status:"
    echo "  sudo systemctl status arch-load-daemon"
    echo ""
    echo "Configuration file location:"
    echo "  ~/.config/arch-load-manager.json"
    echo ""
}

# Run main installation
main "$@"
