#!/bin/bash

# Arch Load Manager - Installation Script
# This script installs the Arch Load Manager application and daemon

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
                echo "  sudo pacman -S base-devel gtk3 json-c uthash libdbusmenu-gtk3"
                ;;
            apt)
                echo "  sudo apt install build-essential libgtk-3-dev libjson-c-dev uthash-dev appmenu-gtk3-module"
                ;;
            dnf|yum)
                echo "  sudo $pm install gcc make pkg-config gtk3-devel json-c-devel uthash-devel appmenu-gtk3-module"
                ;;
            *)
                echo "  Install: gcc, make, pkg-config, gtk3, json-c, uthash, appmenu-gtk-module"
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

# Install binaries
install_binaries() {
    print_info "Installing binaries..."

    sudo install -Dm755 arch-load-manager /usr/local/bin/arch-load-manager
    sudo install -Dm755 arch-load-daemon /usr/local/bin/arch-load-daemon

    print_success "Binaries installed to /usr/local/bin/"
}

# Install icon to hicolor theme (works on KDE, GNOME, XFCE, etc.)
install_icons() {
    print_info "Installing application icons..."

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

        # Use ImageMagick if available, otherwise just copy the original
        if command -v magick &> /dev/null; then
            sudo magick "Arch Load Manager.png" -resize "${size}x${size}" \
                "$dest_dir/arch-load-manager.png"
        elif command -v convert &> /dev/null; then
            sudo convert "Arch Load Manager.png" -resize "${size}x${size}" \
                "$dest_dir/arch-load-manager.png" 2>/dev/null
        else
            # Fallback: copy original (GTK will scale it)
            sudo install -Dm644 "Arch Load Manager.png" "$dest_dir/arch-load-manager.png"
        fi
    done

    # Also install to pixmaps as fallback for legacy apps
    sudo install -Dm644 "Arch Load Manager.png" /usr/share/pixmaps/arch-load-manager.png

    # Update icon cache
    if command -v gtk-update-icon-cache &> /dev/null; then
        sudo gtk-update-icon-cache -f -t "$icon_base" 2>/dev/null || true
    fi

    print_success "Icons installed to hicolor theme"
}

# Create systemd service
install_daemon_service() {
    print_info "Creating systemd service..."

    local service_file="/etc/systemd/system/arch-load-daemon.service"

    sudo tee "$service_file" > /dev/null << 'EOF'
[Unit]
Description=Arch Load Manager - Process Affinity Daemon
Documentation=https://github.com/yourusername/arch-load-manager
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/bin/arch-load-daemon
Restart=on-failure
RestartSec=5s

# Run as root to manage process priorities/affinities
User=root

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/proc /tmp

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    print_success "Systemd service created"
}

# Install desktop entry
install_desktop_entry() {
    print_info "Installing desktop entry..."

    local desktop_file="/usr/share/applications/arch-load-manager.desktop"

    sudo tee "$desktop_file" > /dev/null << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Arch Load Manager
Comment=Manage CPU affinity and process priorities
Exec=arch-load-manager
Icon=arch-load-manager
Terminal=false
Categories=System;Monitor;
Keywords=cpu;affinity;priority;process;performance;
StartupNotify=true
StartupWMClass=arch-load-manager
EOF

    sudo chmod 644 "$desktop_file"
    print_success "Desktop entry installed"
}

# Ask user if they want to enable the daemon
setup_daemon() {
    echo ""
    read -p "Do you want to enable and start the daemon service? (y/n) " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Enabling and starting daemon..."
        sudo systemctl enable arch-load-daemon
        sudo systemctl start arch-load-daemon

        if sudo systemctl is-active --quiet arch-load-daemon; then
            print_success "Daemon is running"
        else
            print_warning "Daemon failed to start. Check: sudo journalctl -u arch-load-daemon"
        fi
    else
        print_info "Daemon not started. You can enable it later with:"
        echo "  sudo systemctl enable --now arch-load-daemon"
    fi
}

# Main installation flow
main() {
    echo ""
    echo "======================================"
    echo "  Arch Load Manager - Installation"
    echo "======================================"
    echo ""

    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi

    # Build
    if ! build_project; then
        exit 1
    fi

    # Install
    install_binaries
    install_icons
    install_daemon_service
    install_desktop_entry

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
    echo "  ~/.config/cpu_affinity_manager.json"
    echo ""
}

# Run main installation
main "$@"
