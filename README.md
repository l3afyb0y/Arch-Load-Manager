# Arch Load Manager

A lightweight, native Linux process manager for controlling CPU affinity and process priorities. Built in C with GTK3 for the GUI and an event-driven daemon for automatic rule application.

---

> **Disclaimer**: This application was entirely **"Vibe-Coded"** - developed through AI-assisted programming. While functional and tested, there may be edge cases or improvements that could be made. If you encounter any issues, have suggestions, or want to contribute improvements, please feel free to open an issue or pull request. Your feedback is welcome!

---

## Warnings

### Functional Risks

This application modifies low-level process scheduling parameters. Improper use can cause:

- **System instability**: Pinning critical system processes to too few CPUs can cause freezes or lag
- **Application crashes**: Some applications expect access to all CPU cores
- **Priority inversion**: Setting inappropriate priorities can starve important processes
- **Real-time priority dangers**: Real-time priority (nice -20) can lock up your system if a process runs away

**Recommendations**:
- Use **Test Mode** first to verify settings before saving
- Avoid modifying system processes (PID < 1000) unless you know what you're doing
- Don't set Real-time priority on untrusted or unstable applications
- Keep at least 2 CPU cores unassigned as a safety margin

### Vibe-Coded Software Risks

This software was developed with AI assistance ("vibe-coded"). This means:

- **Limited real-world testing**: Edge cases may not have been thoroughly tested
- **Potential for subtle bugs**: AI-generated code can have non-obvious issues
- **No warranty**: Use at your own risk

**Recommendations**:
- Review the config file (`~/.config/arch-load-manager.json`) before enabling the daemon
- Monitor system behavior after applying new rules
- Keep backups of working configurations
- Report any issues you encounter

---

## Overview

Arch Load Manager lets you:
- **Pin processes to specific CPU cores** to optimize performance or isolate workloads
- **Set process priorities** from background (nice 19) to real-time (nice -20)
- **Automatically apply rules** to new processes via the background daemon
- **Save rules** by executable path or process name for persistent configuration

## Features

- **Process Management**: View all running processes with real-time CPU and memory usage
- **CPU Affinity Control**: Pin processes to specific CPU cores
- **Priority Management**: Set process priorities from Lowest to Real-time
- **Automatic Rule Application**: Background daemon automatically applies saved rules
- **Rule Persistence**: Rules saved by executable path or process name
- **Test Mode**: Try settings without saving
- **Apply to Process Family**: Apply settings to related processes with the same executable
- **Ultra-Lightweight**: Daemon uses <0.05% CPU idle, ~2-5MB RAM
- **Sortable Columns**: Sort by PID, Name, CPU%, or Memory%
- **Color-Coded Processes**: Green (low), Yellow (medium), Red (high CPU usage)

## Limitations

- **Root required for negative nice values**: High, Highest, and Real-time priorities require the daemon to be running as root
- **Daemon config scope**: The systemd service runs as root by default and reads `/root/.config/arch-load-manager.json`. To use a user config, you can use the `--config` flag, run the daemon as that user, or set `Environment=HOME=/home/USER` in the service.
- **Linux only**: Uses Linux-specific APIs (`/proc`, `sched_setaffinity`, `inotify`)
- **Process matching**: Rules match exact executable paths or process names; no wildcard/regex support


### Components

1. **arch-load-manager** (GTK3 GUI)
   - Visual process management interface
   - Create and edit rules
   - Manual rule application
   - Memory: ~20-30MB
   - Startup: <100ms

2. **arch-load-daemon** (Background Service)
   - Event-driven with inotify/epoll
   - Monitors for new processes
   - Auto-applies matching rules
   - Hot-reloads configuration
   - CPU: <0.05% idle, <0.2% active
   - Memory: ~2-5MB

### Configuration

Rules are stored in: `~/.config/arch-load-manager.json`

Format:
```json
{
  "exe": {
    "/usr/bin/firefox": {
      "cpus": [0, 1, 2],
      "priority": "High",
      "mode": "active"
    }
  },
  "name": {
    "python3": {
      "cpus": [4, 5, 6, 7],
      "priority": "Normal",
      "mode": "active"
    }
  }
}
```

## Installation

### 🚀 Easy Installation (Any Distribution)

The easiest way to install Arch Load Manager on any Linux distribution is using the provided installation script. This script will check for dependencies, build the project, and install all necessary files.

```bash
git clone https://github.com/gitporker/Arch-Load-Manager.git
cd Arch-Load-Manager
chmod +x install.sh
./install.sh
```

### 🏔️ Arch Linux (Official Installer)

For Arch Linux and its derivatives (Manjaro, EndeavourOS, etc.), you can use the `PKGBUILD` to install it as a native package:

```bash
git clone https://github.com/gitporker/Arch-Load-Manager.git
cd Arch-Load-Manager
makepkg -si
```

### 🛠️ Manual Installation

If you prefer to install manually:

1. **Install dependencies:**
   - GTK3 (e.g., `libgtk-3-dev` on Debian/Ubuntu, `gtk3` on Arch)
   - JSON-C (e.g., `libjson-c-dev` on Debian/Ubuntu, `json-c` on Arch)
   - UThash (e.g., `uthash-dev` on Debian/Ubuntu, `uthash` on Arch)
   - Build tools: `gcc`, `make`, `pkg-config`

2. **Build and Install:**
```bash
make
sudo make install
```

3. **Start the daemon:**
```bash
sudo systemctl enable --now arch-load-daemon
```

## Maintainer

**Porker Roland** - [gitporker@gmail.com](mailto:gitporker@gmail.com)

### Dependencies

**Build-time:**
- gcc
- make
- pkg-config
- gtk3 development headers
- json-c development headers
- uthash headers

**Runtime:**
- gtk3
- json-c

**Arch Linux:**
```bash
sudo pacman -S base-devel gtk3 json-c uthash libdbusmenu-gtk3
```

**Ubuntu/Debian:**
```bash
sudo apt install build-essential libgtk-3-dev libjson-c-dev uthash-dev appmenu-gtk3-module
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc make pkg-config gtk3-devel json-c-devel uthash-devel appmenu-gtk3-module
```

## Usage

### GUI Application

Launch from:
- Application menu: Search for "Arch Load Manager"
- Terminal: `arch-load-manager`

#### Creating Rules

1. Select a process from the list
2. Choose CPU cores by checking/unchecking boxes
3. Select priority level from dropdown
4. Choose rule type:
   - **Executable path**: Rule applies to specific binary
   - **Process name**: Rule applies to any process with that name
5. Click "Apply"

#### Options

- **Test Mode**: Apply settings without saving; the daemon skips those PIDs while the GUI is open
- **Apply to process family**: Also apply to related processes with the same executable

### Daemon Service (enable or rules won't auto-apply)

```bash
# Start daemon
sudo systemctl start arch-load-daemon

# Enable on boot
sudo systemctl enable arch-load-daemon

# Run manually with custom config
arch-load-daemon --config /path/to/config.json
```

### Configuration File

Edit `~/.config/cpu_affinity_manager.json` manually or use the GUI. The systemd
daemon runs as root by default and reads `/root/.config/cpu_affinity_manager.json`
unless you override `HOME` in the service or run the daemon as your user.

The daemon automatically reloads when the file changes. The `mode` field is
currently always saved as `active` and ignored by the daemon.

## Priority Levels

| Priority | Nice Value | Use Case |
|----------|-----------|----------|
| **Lowest** | 19 | Background tasks |
| **Low** | 10 | Non-critical processes |
| **Normal** | 0 | Default priority |
| **High** | -5 | Important applications |
| **Highest** | -10 | Critical processes |
| **Real-time** | -20 | Time-sensitive tasks |

> **Note**: Negative nice values require root privileges

## UI Features


### Color-Coded Process Names

- 🟢 **Green**: CPU usage 0-30% (low)
- 🟡 **Yellow**: CPU usage 30-70% (medium)
- 🔴 **Red**: CPU usage 70%+ (high)

### Sortable Columns

Click column headers to sort by:
- **PID**: Process ID
- **Process Name**: Alphabetically
- **CPU %**: Percentage of total CPU (all processes sum to ~100%)
- **Memory %**: Percentage of total RAM

Default: Sorted by CPU% (descending)

## Performance

### GUI (arch-load-manager)
- Memory: ~20-30MB
- Startup: <100ms
- Update interval: 500ms
- Updates pause when minimized

### Daemon (arch-load-daemon)
- CPU: <0.05% idle (event-driven)
- CPU: <0.2% when applying rules
- Memory: ~2-5MB resident
- Response time: <100ms for new processes

## Troubleshooting

### Daemon Not Starting

```bash
# Check logs
sudo journalctl -u arch-load-daemon

# Check permissions
ls -l /usr/local/bin/arch-load-daemon

# Verify config
cat ~/.config/cpu_affinity_manager.json | jq
sudo cat /root/.config/cpu_affinity_manager.json | jq
```

### Permission Denied

Setting negative nice values (High, Highest, Real-time) requires root:
- Daemon must run as root (systemd service handles this)
- GUI can only apply these priorities with sudo/pkexec

### Rules Not Applying

1. Check daemon is running: `systemctl status arch-load-daemon`
2. Verify config file exists and is valid JSON
3. Check daemon logs: `journalctl -u arch-load-daemon -f`
4. Ensure process names/paths match exactly

### GUI Not Showing Some Processes

Some processes may not be accessible due to permissions. Run GUI with sudo to see all:
```bash
sudo arch-load-manager
```

## Uninstallation

```bash
# Using uninstall script
chmod +x uninstall.sh
./uninstall.sh

# Or manually
sudo make uninstall
```

This removes:
- Binaries from `/usr/local/bin/`
- Systemd service
- Desktop entry
- Optionally, user configuration

## Building from Source

```bash
# Clone repository
git clone https://github.com/yourusername/arch-load-manager.git
cd arch-load-manager

# Build
make all

# Build only GUI
make gui

# Build only daemon
make daemon

# Clean build artifacts
make clean

# View help
make help
```

## Development

### Project Structure

```
arch-load-manager/
├── common.h               # Shared definitions
├── config.h               # Config management header
├── config.c               # Config implementation (json-c)
├── arch-load-manager.c    # GTK3 GUI application
├── arch-load-daemon.c     # Background daemon
├── Makefile               # Build system
├── install.sh             # Installation script
├── uninstall.sh           # Removal script
└── README.md              # This file
```

### Code Style

- C11 standard
- Optimized with `-O3 -march=native`
- Wall, Wextra enabled
- Event-driven architecture
- Zero-copy where possible

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Credits

- **Development**: AI-assisted "Vibe-Coded" with Claude
- **UI Design**: Dark theme inspired by modern desktop aesthetics
- **Libraries**: GTK3, json-c, uthash
- **System**: Linux kernel process management APIs (`sched_setaffinity`, `setpriority`, `inotify`, `epoll`)

## Version

Current version: 1.0.0

## Feedback & Contributions

This project is open to improvements! If you find bugs, have feature requests, or want to contribute:
- Open an issue to report problems or suggest features
- Submit a pull request with your improvements
- Share your feedback - it helps make the app better for everyone
