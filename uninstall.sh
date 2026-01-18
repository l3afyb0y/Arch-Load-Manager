#!/bin/bash

# Arch Load Manager - Uninstallation Script v2.1.0
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

# Stop and disable daemon
stop_daemon() {
    print_info "Stopping daemon service..."

    if systemctl is-active --quiet arch-load-daemon 2>/dev/null; then
        sudo systemctl stop arch-load-daemon
        print_success "Daemon stopped"
    else
        print_info "Daemon is not running"
    fi

    if systemctl is-enabled --quiet arch-load-daemon 2>/dev/null; then
        sudo systemctl disable arch-load-daemon
        print_success "Daemon disabled"
    else
        print_info "Daemon is not enabled"
    fi
}

# Remove installed files via Makefile
remove_files() {
    print_info "Removing installed files..."

    if sudo make uninstall; then
        print_success "Files removed"
    else
        print_warning "Make uninstall failed, manual cleanup may be needed"
    fi
}

# Ask about removing config
remove_config() {
    echo ""
    read -p "Do you want to remove user configuration files? (y/n) " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local config_file="$HOME/.config/arch-load-manager.json"

        if [ -f "$config_file" ]; then
            rm "$config_file"
            print_success "Configuration file removed"
        else
            print_info "No configuration file found"
        fi
    else
        print_info "Configuration file preserved at: ~/.config/arch-load-manager.json"
    fi
}

# Main uninstallation flow
main() {
    echo ""
    echo "========================================"
    echo "  Arch Load Manager - Uninstallation"
    echo "========================================"
    echo ""

    # Confirm uninstallation
    read -p "Are you sure you want to uninstall Arch Load Manager? (y/n) " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Uninstallation cancelled"
        exit 0
    fi

    # Stop and remove daemon
    stop_daemon

    # Remove installed files
    remove_files

    # Ask about config
    remove_config

    echo ""
    print_success "Arch Load Manager has been uninstalled"
    echo ""
}

# Run main uninstallation
main "$@"