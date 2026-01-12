# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Arch Load Manager is a native C application for Linux process management with two components:
- **arch-load-manager**: GTK3 GUI for managing CPU affinity and process priorities
- **arch-load-daemon**: Event-driven background daemon using inotify/epoll

Both share common code (config.c, common.h) for JSON configuration management.

## Build Commands

```bash
# Build everything
make all

# Build individual components
make gui      # Build only GUI
make daemon   # Build only daemon

# Clean
make clean

# Install (creates systemd service, desktop entry)
./install.sh  # Recommended - handles dependencies and setup
# OR
sudo make install  # Manual install
```

## Running and Testing

```bash
# Run GUI directly (useful for debugging)
./arch-load-manager

# Run daemon in foreground (for testing)
sudo ./arch-load-daemon

# View daemon logs
sudo journalctl -t arch-load-daemon -f

# Test with systemd
sudo systemctl start arch-load-daemon
sudo systemctl status arch-load-daemon
```

## Architecture

x86_64bit CPU's
Arch Linux is the expected operating system for this program.

### Shared Components

**common.h**: Defines core data structures used by both GUI and daemon
- `Rule` struct: Holds CPU affinity (list of CPU IDs) and priority level
- `Priority` enum: Maps to nice values (-20 to 19)
- Config location: `~/.config/cpu_affinity_manager.json`

**config.c/config.h**: JSON configuration management using json-c and uthash
- Two hash tables: `exe_rules` (keyed by full executable path) and `name_rules` (keyed by process name)
- Hot-reload support via mtime checking
- Rules can specify either/both: CPU affinity list, Priority level

### GUI (arch-load-manager.c)

- GTK3 application with custom CSS ("Liquid Glass" theme)
- Updates process list every 1 second
- **Important**: Preserves scroll position and sort order during updates (lines 311-373)
- Stores only basename of executable in tree view (not full path)
- Color-codes process names by CPU usage: green (<30%), yellow (30-70%), red (>70%)

### Daemon (arch-load-daemon.c)

- Uses inotify to watch `/proc` for new process directories (IN_CREATE events)
- Uses epoll for zero-CPU event waiting
- Applies rules by matching against exe path first, then process name
- Watches config file for changes and hot-reloads
- Logs to syslog (view with `journalctl -t arch-load-daemon`)

## Critical Design Decisions

Processess should maintain low load on the system (low memory usage, low cpu usage, etc.)
End result should be an "install.sh" file which compiles the program and installs all dependencies required for it to function as intended.
Multiple coding languages can, and should be used in places where it would be more effective or efficent to use one over another (i.e. C++ over Python).

### CPU Percentage Calculation

**Requirement**: CPU % represents percentage of TOTAL system CPU.

The calculation in `get_process_cpu_usage()` (arch-load-manager.c):
```c
CPU % = (delta_process_cpu / delta_total_cpu) × 100
```

This means:
- All process percentages sum to approximately 100% of total system CPU
- On a 12-core system, a process using 1 full core ≈ 8%
- On a 4-core system, a process using 1 full core = 25%
- First two updates return 0% (initialization period)
- Subsequent updates show real-time deltas every 500ms

**Implementation**:
- Global CPU snapshot taken once per update cycle to ensure consistency
- Per-PID static arrays cache previous utime/stime values (up to 32768 PIDs)
- First update initializes global snapshot
- Second update initializes per-PID values
- Third+ updates show actual CPU percentages

### Display Format

- CPU and Memory percentages are **integers only** (no decimals)
- GtkListStore columns use G_TYPE_INT, not G_TYPE_DOUBLE
- Executable column shows basename only, not full path

### Scroll Position Preservation

When updating the process list (every 1 second):
1. Save vertical scroll position before clearing list
2. Rebuild entire list from /proc scan
3. Restore scroll position after rebuild

This prevents the annoying "jump to top" behavior during updates.

### Default Sort

The GUI sorts by **CPU % descending** by default, showing the highest CPU usage processes at the top. Users can click column headers to change the sort order, and their choice persists across updates.

## Configuration File Format

`~/.config/cpu_affinity_manager.json`:
```json
{
  "exe": {
    "/full/path/to/binary": {
      "cpus": [0, 1, 2],
      "priority": "High",
      "mode": "active"
    }
  },
  "name": {
    "process-name": {
      "cpus": [4, 5],
      "priority": "Normal",
      "mode": "active"
    }
  }
}
```

Priority values: "Lowest", "Low", "Normal", "High", "Highest", "Real-time"

## Common Issues
The program was originally written by ChatGPT in Python, as a result, some of the GUI functions don't work or were faked by ChatGPT in order to appear as if they did. Check program functions to ensure all intended outcomes occur, especially Test Mode, as that is a "safety feature" implimented in to prevent users from bricking their computers by accident.

### GUI Segfaults
- Ensure GTK callback functions don't have recursive calls
- Verify tree view column data types match what's stored in GtkListStore
- Check that cell data functions use correct types (gint vs gdouble)

### Daemon Not Applying Rules
- Verify daemon is running: `systemctl status arch-load-daemon`
- Check logs: `journalctl -t arch-load-daemon`
- Ensure config file is valid JSON
- Remember: Negative nice values (High/Highest/Real-time) require root

### Everything Shows 0% CPU
- First update uses full values (average since boot)
- Subsequent updates use deltas - if still 0%, check the static cache initialization
- Verify prev_total_cpu and prev_proc_cpu arrays are being updated

## Dependencies

**Build**: gcc, make, pkg-config, gtk3-devel, json-c-devel, uthash
**Runtime**: gtk3, json-c

Install on Arch: `sudo pacman -S base-devel gtk3 json-c uthash`
