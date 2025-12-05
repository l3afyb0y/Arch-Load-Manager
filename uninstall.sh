#!/bin/bash

# Arch Load Manager - Uninstallation Script
# This script removes all installed components of Arch Load Manager

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

# Remove systemd service
remove_service() {
    print_info "Removing systemd service..."

    local service_file="/etc/systemd/system/arch-load-daemon.service"

    if [ -f "$service_file" ]; then
        sudo rm "$service_file"
        sudo systemctl daemon-reload
        print_success "Service file removed"
    else
        print_info "Service file not found"
    fi
}

# Remove binaries
remove_binaries() {
    print_info "Removing installed binaries..."

    local removed=0

    if [ -f "/usr/local/bin/arch-load-manager" ]; then
        sudo rm "/usr/local/bin/arch-load-manager"
        print_success "Removed arch-load-manager"
        removed=1
    fi

    if [ -f "/usr/local/bin/arch-load-daemon" ]; then
        sudo rm "/usr/local/bin/arch-load-daemon"
        print_success "Removed arch-load-daemon"
        removed=1
    fi

    if [ $removed -eq 0 ]; then
        print_info "No binaries found to remove"
    fi
}

# Remove desktop entry
remove_desktop_entry() {
    print_info "Removing desktop entry..."

    local desktop_file="/usr/share/applications/arch-load-manager.desktop"

    if [ -f "$desktop_file" ]; then
        sudo rm "$desktop_file"
        print_success "Desktop entry removed"
    else
        print_info "Desktop entry not found"
    fi
}

# Ask about removing config
remove_config() {
    echo ""
    read -p "Do you want to remove user configuration files? (y/n) " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local config_file="$HOME/.config/cpu_affinity_manager.json"

        if [ -f "$config_file" ]; then
            rm "$config_file"
            print_success "Configuration file removed"
        else
            print_info "No configuration file found"
        fi
    else
        print_info "Configuration file preserved at: ~/.config/cpu_affinity_manager.json"
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
    remove_service

    # Remove installed files
    remove_binaries
    remove_desktop_entry

    # Ask about config
    remove_config

    echo ""
    print_success "Arch Load Manager has been uninstalled"
    echo ""
}

# Run main uninstallation
main "$@"
