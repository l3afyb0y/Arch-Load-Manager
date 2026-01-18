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
#include <sys/syscall.h>

#define MAX_EVENTS 64
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (MAX_EVENTS * (EVENT_SIZE + 16))

// Global config instance
static Config *g_config = NULL;
static char *g_config_path_override = NULL;
static volatile sig_atomic_t g_running = 1;

// ProBalance tracking
typedef struct {
    pid_t pid;
    uint64_t start_time_ms;
    bool suppressed;
    int original_nice;
    UT_hash_handle hh;
} ProBalanceEntry;

static ProBalanceEntry *g_pb_tracker = NULL;

// Helper to get current time in ms
static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Apply CPU affinity to IRQ
bool apply_irq_affinity(int irq_id, const IrqRule *rule) {
    if (!rule->has_affinity || rule->cpu_count == 0) return true;

    char path[256];
    snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity_list", irq_id);

    FILE *f = fopen(path, "w");
    if (!f) {
        syslog(LOG_WARNING, "Failed to open %s: %s", path, strerror(errno));
        return false;
    }

    for (int i = 0; i < rule->cpu_count; i++) {
        fprintf(f, "%d%s", rule->cpus[i], (i == rule->cpu_count - 1) ? "" : ",");
    }

    fclose(f);
    syslog(LOG_INFO, "Applied affinity to IRQ %d: %s", irq_id, rule->device_name);
    return true;
}

// Apply all configured IRQ rules
void apply_all_irq_rules(void) {
    IrqRuleEntry *entry, *tmp;
    HASH_ITER(hh, g_config->irq_rules, entry, tmp) {
        apply_irq_affinity(entry->irq_id, &entry->rule);
    }
}

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
    if (len <= 0 || (size_t)len >= size - 1) {
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

    // Apply scheduler policy if specified
    if (rule->has_sched_policy) {
        struct sched_param param = {0};
        int policy = SCHED_OTHER;
        switch (rule->sched_policy) {
            case SCHED_POL_BATCH: policy = SCHED_BATCH; break;
            case SCHED_POL_IDLE: policy = SCHED_IDLE; break;
            case SCHED_POL_FIFO: policy = SCHED_FIFO; param.sched_priority = 1; break;
            case SCHED_POL_RR: policy = SCHED_RR; param.sched_priority = 1; break;
            default: policy = SCHED_OTHER; break;
        }
        if (sched_setscheduler(pid, policy, &param) == -1) {
            syslog(LOG_WARNING, "Failed to set scheduler for PID %d: %s", pid, strerror(errno));
        }
    }

    // Apply IO priority if specified
    if (rule->has_ioprio) {
        int p = IOPRIO_PRIO_VALUE(rule->ioprio_class, rule->ioprio_level);
        if (ioprio_set(IOPRIO_WHO_PROCESS, pid, p) == -1) {
            syslog(LOG_WARNING, "Failed to set IO priority for PID %d: %s", pid, strerror(errno));
        }
    }

    syslog(LOG_INFO, "Applied priority/policy to PID %d: %s (nice %d)",
           pid, priority_name(rule->priority), nice_val);
    return true;
}

#include <sys/stat.h>
#include <fcntl.h>

// Check if PID is in the override file (test mode)
bool is_pid_overridden(pid_t pid) {
    int fd = open(OVERRIDE_FILE, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) {
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) {
        close(fd);
        return false;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return false;
    }

    char line[32];
    bool found = false;

    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        if (line[0] == '\0') continue;

        // Check if this line matches our PID
        pid_t override_pid = (pid_t)atoi(line);
        if (override_pid == pid) {
            found = true;
            break;
        }
    }

    fclose(f); // Also closes fd
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

// Structure to track CPU deltas for ProBalance
typedef struct {
    pid_t pid;
    unsigned long prev_proc_time;
    UT_hash_handle hh;
} CpuDelta;

static CpuDelta *g_cpu_deltas = NULL;
static unsigned long g_prev_total_time = 0;

// Structure to hold process info from /proc/[pid]/stat
typedef struct {
    int ppid;
    int pgid;
    int tpgid;
    unsigned long utime;
    unsigned long stime;
} ProcStat;

static bool get_proc_stat(pid_t pid, ProcStat *ps) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return false;

    // The comm field is in parens and can contain spaces/parens.
    // We skip it by finding the last ')'.
    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return false;
    }
    fclose(f);

    char *p = strrchr(line, ')');
    if (!p) return false;
    
    // After ')', fields are: state ppid pgid sid tty_nr tpgid ... utime stime
    //                       0     1    2    3   4      5         11    12
    if (sscanf(p + 2, "%*c %d %d %*d %*d %d %*u %*u %*u %*u %*u %lu %lu",
               &ps->ppid, &ps->pgid, &ps->tpgid, &ps->utime, &ps->stime) != 5) {
        return false;
    }
    return true;
}

// Calculate process CPU usage %
static int get_cpu_usage_optimized(pid_t pid, unsigned long total_delta, unsigned long proc_time) {
    if (total_delta == 0) return 0;

    CpuDelta *d = NULL;
    HASH_FIND_INT(g_cpu_deltas, &pid, d);
    if (!d) {
        d = calloc(1, sizeof(CpuDelta));
        d->pid = pid;
        d->prev_proc_time = proc_time;
        HASH_ADD_INT(g_cpu_deltas, pid, d);
        return 0;
    }

    unsigned long proc_delta = proc_time - d->prev_proc_time;
    d->prev_proc_time = proc_time;

    return (int)((proc_delta * 100) / total_delta);
}

// Check and handle ProBalance for all processes
void handle_probalance(void) {
    if (!g_config->probalance.enabled) return;

    // Get total system time delta
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return;
    unsigned long u, n, s, i, io, irq, sirq, steal;
    if (fscanf(f, "cpu %lu %lu %lu %lu %lu %lu %lu %lu", &u, &n, &s, &i, &io, &irq, &sirq, &steal) != 8) {
        fclose(f);
        return;
    }
    fclose(f);
    unsigned long total_time = u + n + s + i + io + irq + sirq + steal;
    unsigned long total_delta = total_time - g_prev_total_time;
    g_prev_total_time = total_time;

    if (total_delta == 0) return;

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;

    uint64_t now = get_time_ms();
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        pid_t pid = (pid_t)atoi(entry->d_name);
        if (pid <= 0) continue;

        ProcStat ps;
        if (!get_proc_stat(pid, &ps)) continue;

        // Skip kernel threads
        if (ps.ppid == 2) continue;

        // Check foreground if enabled
        if (g_config->probalance.ignore_foreground && ps.pgid == ps.tpgid && ps.tpgid != -1) {
            continue;
        }

        int usage = get_cpu_usage_optimized(pid, total_delta, ps.utime + ps.stime);
        bool above_threshold = usage >= g_config->probalance.cpu_threshold;

        ProBalanceEntry *pb = NULL;
        HASH_FIND_INT(g_pb_tracker, &pid, pb);

        if (above_threshold) {
            if (!pb) {
                pb = calloc(1, sizeof(ProBalanceEntry));
                pb->pid = pid;
                pb->start_time_ms = now;
                pb->original_nice = getpriority(PRIO_PROCESS, pid);
                HASH_ADD_INT(g_pb_tracker, pid, pb);
            } else if (!pb->suppressed && (now - pb->start_time_ms >= (uint64_t)g_config->probalance.duration_ms)) {
                // Check if excluded by rule
                const Rule *rule = NULL;
                char exe[MAX_PATH_LEN], name[MAX_PROC_NAME];
                if (get_process_exe(pid, exe, sizeof(exe))) rule = config_get_rule_by_exe(g_config, exe);
                if (!rule && get_process_name(pid, name, sizeof(name))) rule = config_get_rule_by_name(g_config, name);
                
                if (rule && rule->exclude_probalance) {
                    HASH_DEL(g_pb_tracker, pb);
                    free(pb);
                    continue;
                }

                // Suppress!
                int new_nice = pb->original_nice + g_config->probalance.suppression_nice;
                if (new_nice > 19) new_nice = 19;
                if (setpriority(PRIO_PROCESS, pid, new_nice) == 0) {
                    pb->suppressed = true;
                    syslog(LOG_INFO, "ProBalance: Suppressed PID %d (%d%% CPU) to nice %d", pid, usage, new_nice);
                }
            }
        } else if (pb) {
            if (pb->suppressed) {
                setpriority(PRIO_PROCESS, pid, pb->original_nice);
                syslog(LOG_INFO, "ProBalance: Restored PID %d to original nice %d", pid, pb->original_nice);
            }
            HASH_DEL(g_pb_tracker, pb);
            free(pb);
        }
    }
    closedir(proc_dir);

    // Cleanup dead processes from trackers
    CpuDelta *cd, *cd_tmp;
    HASH_ITER(hh, g_cpu_deltas, cd, cd_tmp) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d", cd->pid);
        if (access(path, F_OK) != 0) {
            HASH_DEL(g_cpu_deltas, cd);
            free(cd);
        }
    }

    ProBalanceEntry *pb_entry, *pb_tmp;
    HASH_ITER(hh, g_pb_tracker, pb_entry, pb_tmp) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d", pb_entry->pid);
        if (access(path, F_OK) != 0) {
            HASH_DEL(g_pb_tracker, pb_entry);
            free(pb_entry);
        }
    }
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
    g_config = config_init(g_config_path_override);

    if (!g_config) {
        syslog(LOG_ERR, "Failed to reinitialize config");
        return;
    }

    if (!config_load(g_config)) {
        syslog(LOG_WARNING, "Failed to load config file");
        return;
    }

    syslog(LOG_INFO, "Configuration reloaded");

    // Reapply rules to all processes and IRQs
    apply_rules_to_all_processes();
    apply_all_irq_rules();
}

int main(int argc, char *argv[]) {
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            g_config_path_override = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("Arch Load Manager Daemon v%s\n", ARCH_LOAD_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -c, --config PATH  Path to configuration file\n");
            printf("  -v, --version      Show version\n");
            printf("  -h, --help         Show this help\n");
            return 0;
        }
    }

    // Open syslog
    openlog("arch-load-daemon", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Starting Arch Load Manager daemon v%s", ARCH_LOAD_VERSION);

    // Set up signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // Initialize config
    g_config = config_init(g_config_path_override);
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

    // Apply rules to existing processes and IRQs
    apply_rules_to_all_processes();
    apply_all_irq_rules();

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
    uint64_t last_pb_time = 0;

    while (g_running) {
        // Wait for events (blocks with zero CPU usage)
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 500);

        uint64_t now = get_time_ms();
        if (now - last_pb_time >= 500) {
            handle_probalance();
            last_pb_time = now;
        }
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
