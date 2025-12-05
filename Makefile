CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -std=c11
LDFLAGS =

# Dependencies
GTK_CFLAGS = $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS = $(shell pkg-config --libs gtk+-3.0)
JSON_CFLAGS = $(shell pkg-config --cflags json-c)
JSON_LIBS = $(shell pkg-config --libs json-c)

# Targets
GUI_TARGET = arch-load-manager
DAEMON_TARGET = arch-load-daemon

# Source files
GUI_SOURCES = arch-load-manager.c config.c
DAEMON_SOURCES = arch-load-daemon.c config.c
COMMON_HEADERS = common.h config.h

# Object files
GUI_OBJECTS = $(GUI_SOURCES:.c=.o)
DAEMON_OBJECTS = $(DAEMON_SOURCES:.c=.o)

# Default target
all: $(GUI_TARGET) $(DAEMON_TARGET)

# Build GUI
$(GUI_TARGET): $(GUI_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(GTK_LIBS) $(JSON_LIBS)

# Build daemon
$(DAEMON_TARGET): $(DAEMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(JSON_LIBS)

# Pattern rule for GUI objects
arch-load-manager.o: arch-load-manager.c $(COMMON_HEADERS)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) $(JSON_CFLAGS) -c $< -o $@

# Pattern rule for daemon objects
arch-load-daemon.o: arch-load-daemon.c $(COMMON_HEADERS)
	$(CC) $(CFLAGS) $(JSON_CFLAGS) -c $< -o $@

# Config object (used by both)
config.o: config.c $(COMMON_HEADERS)
	$(CC) $(CFLAGS) $(JSON_CFLAGS) -c $< -o $@

# Individual targets
gui: $(GUI_TARGET)

daemon: $(DAEMON_TARGET)

# Clean build artifacts
clean:
	rm -f $(GUI_TARGET) $(DAEMON_TARGET) *.o

# Install (requires root for daemon and desktop file)
install: all
	@echo "Installing Arch Load Manager..."
	install -Dm755 $(GUI_TARGET) $(DESTDIR)/usr/local/bin/$(GUI_TARGET)
	install -Dm755 $(DAEMON_TARGET) $(DESTDIR)/usr/local/bin/$(DAEMON_TARGET)
	install -Dm644 arch-load-manager.desktop $(DESTDIR)/usr/share/applications/arch-load-manager.desktop
	@echo "Installation complete!"
	@echo "To enable the daemon: sudo systemctl enable --now arch-load-daemon"

# Uninstall
uninstall:
	@echo "Uninstalling Arch Load Manager..."
	rm -f /usr/local/bin/$(GUI_TARGET)
	rm -f /usr/local/bin/$(DAEMON_TARGET)
	rm -f /usr/share/applications/arch-load-manager.desktop
	systemctl disable arch-load-daemon 2>/dev/null || true
	systemctl stop arch-load-daemon 2>/dev/null || true
	rm -f /etc/systemd/system/arch-load-daemon.service
	@echo "Uninstall complete!"

# Help
help:
	@echo "Arch Load Manager - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build both GUI and daemon (default)"
	@echo "  gui        - Build only the GUI application"
	@echo "  daemon     - Build only the daemon"
	@echo "  clean      - Remove all build artifacts"
	@echo "  install    - Install binaries and desktop file (requires root)"
	@echo "  uninstall  - Remove installed files (requires root)"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Dependencies:"
	@echo "  - gtk3 (libgtk-3-dev or gtk3-devel)"
	@echo "  - json-c (libjson-c-dev or json-c-devel)"
	@echo "  - gcc, make, pkg-config"

.PHONY: all gui daemon clean install uninstall help
