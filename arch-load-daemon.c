#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <syslog.h>
#include <errno.h>
#include <limits.h>

#define MAX_EVENTS 10
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (MAX_EVENTS * (EVENT_SIZE + 16))
#define OVERRIDE_FILE "/tmp/arch-load-manager-override"

// Global config instance
static Config *g_config = NULL;
static volatile sig_atomic_t g_running = 1;

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    (void)signum;
    g_running = 0;
}

// Get process executable path
bool get_process_exe(pid_t pid, char *exe_path, size_t size) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    ssize_t len = readlink(proc_path, exe_path, size - 1);
    if (len == -1) {
        return false;
    }

    exe_path[len] = '\0';
    return true;
}

// Get process name from /proc/[pid]/comm
bool get_process_name(pid_t pid, char *name, size_t size) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);

    FILE *f = fopen(proc_path, "r");
    if (!f) return false;

    if (fgets(name, size, f) == NULL) {
        fclose(f);
        return false;
    }

    // Remove trailing newline
    size_t len = strlen(name);
    if (len > 0 && name[len - 1] == '\n') {
        name[len - 1] = '\0';
    }

    fclose(f);
    return true;
}

// Apply CPU affinity to process
bool apply_affinity(pid_t pid, const Rule *rule) {
    if (!rule->has_cpus || rule->cpu_count == 0) {
        return true;  // Nothing to apply
    }

    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);

    for (int i = 0; i < rule->cpu_count; i++) {
        CPU_SET(rule->cpus[i], &cpu_set);
    }

    if (sched_setaffinity(pid, sizeof(cpu_set), &cpu_set) == -1) {
        syslog(LOG_WARNING, "Failed to set affinity for PID %d: %s", pid, strerror(errno));
        return false;
    }

    syslog(LOG_INFO, "Applied affinity to PID %d: %d CPUs", pid, rule->cpu_count);
    return true;
}

// Apply priority to process
bool apply_priority(pid_t pid, const Rule *rule) {
    if (!rule->has_priority) {
        return true;  // Nothing to apply
    }

    int nice_val = priority_nice(rule->priority);

    if (setpriority(PRIO_PROCESS, pid, nice_val) == -1) {
        syslog(LOG_WARNING, "Failed to set priority for PID %d: %s", pid, strerror(errno));
        return false;
    }

    syslog(LOG_INFO, "Applied priority to PID %d: %s (nice %d)",
           pid, priority_name(rule->priority), nice_val);
    return true;
}

// Check if PID is in the override file (test mode)
bool is_pid_overridden(pid_t pid) {
    FILE *f = fopen(OVERRIDE_FILE, "r");
    if (!f) {
        return false;  // No override file means no overrides
    }

    char line[32];
    bool found = false;

    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        // Check if this line matches our PID
        pid_t override_pid = (pid_t)atoi(line);
        if (override_pid == pid) {
            found = true;
            break;
        }
    }

    fclose(f);
    return found;
}

// Apply rules to a single process
void apply_rules_to_process(pid_t pid) {
    // Skip if PID is being tested in the GUI
    if (is_pid_overridden(pid)) {
        return;
    }
    char exe_path[MAX_PATH_LEN];
    char proc_name[MAX_PROC_NAME];

    // Try to get exe path first
    bool has_exe = get_process_exe(pid, exe_path, sizeof(exe_path));
    bool has_name = get_process_name(pid, proc_name, sizeof(proc_name));

    if (!has_exe && !has_name) {
        return;  // Can't identify process
    }

    const Rule *rule = NULL;

    // Check for exe-based rule first (more specific)
    if (has_exe) {
        rule = config_get_rule_by_exe(g_config, exe_path);
    }

    // Fall back to name-based rule
    if (!rule && has_name) {
        rule = config_get_rule_by_name(g_config, proc_name);
    }

    // Apply rule if found
    if (rule) {
        syslog(LOG_INFO, "Found rule for PID %d (%s)", pid,
               has_name ? proc_name : "unknown");

        apply_affinity(pid, rule);
        apply_priority(pid, rule);
    }
}

// Apply rules to all existing processes
void apply_rules_to_all_processes(void) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        syslog(LOG_ERR, "Failed to open /proc: %s", strerror(errno));
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        // Check if directory name is a number (PID)
        if (entry->d_type != DT_DIR) continue;

        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        apply_rules_to_process((pid_t)pid);
    }

    closedir(proc_dir);
    syslog(LOG_INFO, "Applied rules to all existing processes");
}

// Check if a string is a valid PID (all digits)
bool is_pid_string(const char *str) {
    if (!str || *str == '\0') return false;

    for (const char *p = str; *p; p++) {
        if (*p < '0' || *p > '9') return false;
    }

    return true;
}

// Handle new process in /proc
void handle_new_process(const char *name) {
    if (!is_pid_string(name)) return;

    pid_t pid = (pid_t)atoi(name);
    if (pid <= 0) return;

    // Small delay to ensure process is fully initialized
    usleep(10000);  // 10ms

    apply_rules_to_process(pid);
}

// Reload configuration
void reload_config(void) {
    syslog(LOG_INFO, "Reloading configuration...");

    // Clear existing rules
    config_free(g_config);
    g_config = config_init();

    if (!g_config) {
        syslog(LOG_ERR, "Failed to reinitialize config");
        return;
    }

    if (!config_load(g_config)) {
        syslog(LOG_WARNING, "Failed to load config file");
        return;
    }

    syslog(LOG_INFO, "Configuration reloaded");

    // Reapply rules to all processes
    apply_rules_to_all_processes();
}

int main(void) {
    // Open syslog
    openlog("arch-load-daemon", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Starting Arch Load Manager daemon v%s", ARCH_LOAD_VERSION);

    // Set up signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // Initialize config
    g_config = config_init();
    if (!g_config) {
        syslog(LOG_ERR, "Failed to initialize config");
        return 1;
    }

    // Load rules (it's okay if file doesn't exist yet)
    if (config_load(g_config)) {
        syslog(LOG_INFO, "Loaded configuration from %s", g_config->config_path);
    } else {
        syslog(LOG_INFO, "No configuration file found, starting with empty rules");
    }

    // Apply rules to existing processes
    apply_rules_to_all_processes();

    // Initialize inotify
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd == -1) {
        syslog(LOG_ERR, "Failed to initialize inotify: %s", strerror(errno));
        config_free(g_config);
        return 1;
    }

    // Watch /proc for new processes
    int proc_wd = inotify_add_watch(inotify_fd, "/proc", IN_CREATE);
    if (proc_wd == -1) {
        syslog(LOG_ERR, "Failed to watch /proc: %s", strerror(errno));
        close(inotify_fd);
        config_free(g_config);
        return 1;
    }

    // Watch config file for changes (if it exists)
    int config_wd = -1;
    if (g_config->config_path) {
        config_wd = inotify_add_watch(inotify_fd, g_config->config_path,
                                      IN_MODIFY | IN_CREATE);
        if (config_wd == -1) {
            syslog(LOG_WARNING, "Could not watch config file (will retry): %s",
                   strerror(errno));
        }
    }

    // Initialize epoll
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        syslog(LOG_ERR, "Failed to create epoll: %s", strerror(errno));
        close(inotify_fd);
        config_free(g_config);
        return 1;
    }

    // Add inotify fd to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = inotify_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &ev) == -1) {
        syslog(LOG_ERR, "Failed to add inotify to epoll: %s", strerror(errno));
        close(epoll_fd);
        close(inotify_fd);
        config_free(g_config);
        return 1;
    }

    syslog(LOG_INFO, "Daemon initialized, entering event loop");

    // Event loop
    char event_buf[EVENT_BUF_LEN];
    struct epoll_event events[MAX_EVENTS];

    while (g_running) {
        // Wait for events (blocks with zero CPU usage)
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);  // 1 second timeout

        if (n == -1) {
            if (errno == EINTR) continue;  // Interrupted by signal
            syslog(LOG_ERR, "epoll_wait failed: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == inotify_fd) {
                // Read inotify events
                ssize_t len = read(inotify_fd, event_buf, EVENT_BUF_LEN);
                if (len == -1) {
                    if (errno != EAGAIN) {
                        syslog(LOG_ERR, "Failed to read inotify: %s", strerror(errno));
                    }
                    continue;
                }

                // Process events
                for (char *ptr = event_buf; ptr < event_buf + len; ) {
                    struct inotify_event *event = (struct inotify_event *)ptr;

                    if (event->len > 0) {
                        if (event->wd == proc_wd) {
                            // New process in /proc
                            handle_new_process(event->name);
                        } else if (event->wd == config_wd) {
                            // Config file changed
                            reload_config();

                            // Re-add watch if needed (some editors recreate the file)
                            config_wd = inotify_add_watch(inotify_fd,
                                                         g_config->config_path,
                                                         IN_MODIFY | IN_CREATE);
                        }
                    }

                    ptr += EVENT_SIZE + event->len;
                }
            }
        }

        // Periodically check if config file was created (if we couldn't watch it initially)
        if (config_wd == -1 && g_config->config_path) {
            config_wd = inotify_add_watch(inotify_fd, g_config->config_path,
                                         IN_MODIFY | IN_CREATE);
        }
    }

    // Cleanup
    syslog(LOG_INFO, "Shutting down daemon");

    close(epoll_fd);
    close(inotify_fd);
    config_free(g_config);
    closelog();

    return 0;
}
