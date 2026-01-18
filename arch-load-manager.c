#define _GNU_SOURCE
#include "config.h"
#include <gtk/gtk.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include <signal.h>

// Column indices for tree view
enum {
    COL_PID = 0,
    COL_NAME,
    COL_EXE,
    COL_CPU,
    COL_MEM,
    NUM_COLS
};

// PID to row reference mapping for in-place updates
typedef struct {
    int pid;
    GtkTreeRowReference *row_ref;
    bool seen_this_scan;
    UT_hash_handle hh;
} PidRowMap;

// Application data
typedef struct {
    GtkWidget *window;
    GtkWidget *stack;
    GtkWidget *tree_view;
    GtkWidget *irq_tree_view;
    GtkWidget *filter_entry;
    GtkWidget *status_label;
    GtkWidget *priority_combo;
    GtkWidget *sched_policy_combo;
    GtkWidget *ioprio_class_combo;
    GtkWidget *ioprio_level_spin;
    GtkWidget *test_mode_check;
    GtkWidget *apply_children_check;
    GtkWidget *exclude_pb_check;
    GtkWidget *exe_radio;
    GtkWidget *name_radio;
    GtkListStore *process_store;
    GtkListStore *irq_store;
    GtkTreeModelFilter *filter_model;
    GtkCheckButton **cpu_checks;
    GtkCheckButton **irq_cpu_checks;
    GtkWidget *scrolled_window;
    PidRowMap *pid_row_map;
    Config *config;
    int selected_pid;
    int selected_irq;
    char selected_exe[MAX_PATH_LEN];      // Full path for rule saving
    char selected_name[MAX_PROC_NAME];
    int ncpus;
    guint update_timer;
    
    // ProBalance settings widgets
    GtkWidget *pb_enabled_switch;
    GtkWidget *pb_threshold_spin;
    GtkWidget *pb_suppression_spin;
    GtkWidget *pb_duration_spin;
    GtkWidget *pb_ignore_fg_check;
} AppData;

// UI Styling
static const char *css_style =
    "window {"
    "    background: #1e1e2e;"
    "    color: #cdd6f4;"
    "}"
    "headerbar {"
    "    background: #181825;"
    "    border-bottom: 1px solid #313244;"
    "    padding: 6px;"
    "}"
    "stackswitcher button {"
    "    padding: 4px 12px;"
    "    margin: 0 4px;"
    "    border-radius: 6px;"
    "    background: transparent;"
    "    border: none;"
    "    color: #bac2de;"
    "}"
    "stackswitcher button:checked {"
    "    background: #45475a;"
    "    color: #89b4fa;"
    "    font-weight: bold;"
    "}"
    "stackswitcher button:hover {"
    "    background: #313244;"
    "}"
    "entry {"
    "    background: #313244;"
    "    border: 1px solid #45475a;"
    "    border-radius: 8px;"
    "    padding: 8px;"
    "    color: #cdd6f4;"
    "}"
    "entry:focus {"
    "    border-color: #89b4fa;"
    "    box-shadow: 0 0 0 2px rgba(137, 180, 250, 0.2);"
    "}"
    "treeview {"
    "    background: #1e1e2e;"
    "    color: #cdd6f4;"
    "    border: 1px solid #313244;"
    "    border-radius: 6px;"
    "}"
    "treeview:selected {"
    "    background: #45475a;"
    "    color: #89b4fa;"
    "}"
    "treeview header button {"
    "    background: #181825;"
    "    color: #a6adc8;"
    "    border: none;"
    "    padding: 8px;"
    "}"
    "button.suggested-action {"
    "    background: #89b4fa;"
    "    color: #11111b;"
    "    border-radius: 8px;"
    "    font-weight: bold;"
    "    padding: 8px 16px;"
    "}"
    "button.destructive-action {"
    "    background: #f38ba8;"
    "    color: #11111b;"
    "    border-radius: 8px;"
    "    font-weight: bold;"
    "}"
    "frame {"
    "    border: 1px solid #313244;"
    "    border-radius: 12px;"
    "    padding: 10px;"
    "    margin: 5px;"
    "}"
    "label.title {"
    "    font-weight: bold;"
    "    font-size: 1.1em;"
    "    color: #89b4fa;"
    "}"
    "scrolledwindow {"
    "    border: 1px solid #313244;"
    "    border-radius: 8px;"
    "}";

// Global CPU time tracking (updated once per cycle, not per process)
static unsigned long g_prev_total_cpu = 0;
static unsigned long g_curr_total_cpu = 0;
static bool g_cpu_snapshot_taken = false;
static unsigned long long g_total_mem_kb = 0;

// Per-process CPU tracking using hash table (no PID limit)
typedef struct {
    pid_t pid;
    unsigned long prev_cpu;
    UT_hash_handle hh;
} ProcessCpuTracker;

static ProcessCpuTracker *cpu_tracker_map = NULL;

#define UPDATE_INTERVAL_MS 500

#include <fcntl.h>

// Add PID to override file (test mode)
void add_pid_to_override(pid_t pid) {
    // Read existing PIDs safely
    int fd_read = open(OVERRIDE_FILE, O_RDONLY | O_NOFOLLOW);
    pid_t existing_pids[1024];
    int count = 0;

    if (fd_read != -1) {
        FILE *f = fdopen(fd_read, "r");
        if (f) {
            char line[32];
            while (fgets(line, sizeof(line), f) && count < 1024) {
                pid_t existing = (pid_t)atoi(line);
                if (existing > 0 && existing != pid) {
                    existing_pids[count++] = existing;
                }
            }
            fclose(f);
        } else {
            close(fd_read);
        }
    }

    // Write all PIDs including the new one safely
    int fd_write = open(OVERRIDE_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd_write == -1) return;

    FILE *f = fdopen(fd_write, "w");
    if (!f) {
        close(fd_write);
        return;
    }

    fprintf(f, "%d\n", pid);
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d\n", existing_pids[i]);
    }

    fclose(f);
}

// Remove PID from override file
void remove_pid_from_override(pid_t pid) {
    int fd_read = open(OVERRIDE_FILE, O_RDONLY | O_NOFOLLOW);
    if (fd_read == -1) return;

    pid_t pids[1024];
    int count = 0;

    FILE *f_read = fdopen(fd_read, "r");
    if (f_read) {
        char line[32];
        while (fgets(line, sizeof(line), f_read) && count < 1024) {
            pid_t existing = (pid_t)atoi(line);
            if (existing > 0 && existing != pid) {
                pids[count++] = existing;
            }
        }
        fclose(f_read);
    } else {
        close(fd_read);
    }

    // Rewrite file without this PID safely
    if (count == 0) {
        unlink(OVERRIDE_FILE);
    } else {
        int fd_write = open(OVERRIDE_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
        if (fd_write == -1) return;

        FILE *f_write = fdopen(fd_write, "w");
        if (!f_write) {
            close(fd_write);
            return;
        }

        for (int i = 0; i < count; i++) {
            fprintf(f_write, "%d\n", pids[i]);
        }
        fclose(f_write);
    }
}

// Clear all overrides
void clear_all_overrides(void) {
    unlink(OVERRIDE_FILE);
}

// Forward declaration for cleanup callback
void on_window_destroy(GtkWidget *widget, gpointer data);

// Read total system CPU time - call once per update cycle
void update_cpu_snapshot(void) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return;

    unsigned long user, nice, system, idle, iowait, irq, softirq, steal;
    if (fscanf(f, "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) == 8) {
        unsigned long new_total = user + nice + system + idle + iowait + irq + softirq + steal;

        // Only update prev if curr is non-zero (skip first call)
        if (g_curr_total_cpu > 0) {
            g_prev_total_cpu = g_curr_total_cpu;
        }
        g_curr_total_cpu = new_total;
        g_cpu_snapshot_taken = true;
    }
    fclose(f);
}

static unsigned long long get_total_mem_kb(void) {
    if (g_total_mem_kb > 0) {
        return g_total_mem_kb;
    }

    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        return 0;
    }

    g_total_mem_kb = (unsigned long long)si.totalram * si.mem_unit / 1024ULL;
    return g_total_mem_kb;
}

// Get process CPU usage using pre-calculated system CPU snapshot
// Returns percentage of total system CPU (all processes sum to ~100%)
int get_process_cpu_usage(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    // Read the entire line - process names can contain spaces like "(Web Content)"
    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    // Find the closing ')' - use strrchr to handle names with nested parens
    char *p = strrchr(line, ')');
    if (!p) return 0;
    p += 2; // Skip ") "

    // Parse fields after comm: state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime
    // Fields:                   0    1    2    3       4   5     6     7      8       9      10      11    12
    unsigned long utime, stime;
    char state;
    long ppid, pgrp, session, tty_nr, tpgid;
    unsigned long flags, minflt, cminflt, majflt, cmajflt;
    if (sscanf(p, "%c %ld %ld %ld %ld %ld %lu %lu %lu %lu %lu %lu %lu",
               &state, &ppid, &pgrp, &session, &tty_nr, &tpgid,
               &flags, &minflt, &cminflt, &majflt, &cmajflt,
               &utime, &stime) != 13) {
        return 0;
    }

    unsigned long proc_cpu = utime + stime;

    // First call initialization - need at least one snapshot
    if (!g_cpu_snapshot_taken || g_prev_total_cpu == 0) {
        // Initialize this PID in the tracker
        ProcessCpuTracker *tracker = NULL;
        HASH_FIND_INT(cpu_tracker_map, &pid, tracker);
        if (!tracker) {
            tracker = malloc(sizeof(ProcessCpuTracker));
            tracker->pid = pid;
            tracker->prev_cpu = proc_cpu;
            HASH_ADD_INT(cpu_tracker_map, pid, tracker);
        }
        return 0;
    }

    // Find or create tracker for this PID
    ProcessCpuTracker *tracker = NULL;
    HASH_FIND_INT(cpu_tracker_map, &pid, tracker);

    if (!tracker) {
        // First time seeing this PID - initialize and return 0
        tracker = malloc(sizeof(ProcessCpuTracker));
        tracker->pid = pid;
        tracker->prev_cpu = proc_cpu;
        HASH_ADD_INT(cpu_tracker_map, pid, tracker);
        return 0;
    }

    // Calculate deltas
    unsigned long delta_total = g_curr_total_cpu - g_prev_total_cpu;
    unsigned long delta_proc = proc_cpu - tracker->prev_cpu;
    tracker->prev_cpu = proc_cpu;

    // Calculate CPU usage as percentage of TOTAL system CPU
    // On a 12-core system, a process using 1 full core = ~8%
    // All processes should sum to approximately 100%
    if (delta_total == 0) return 0;

    // Simple percentage: (delta_proc / delta_total) * 100
    int cpu_pct = (int)((delta_proc * 100) / delta_total);
    return cpu_pct >= 0 ? cpu_pct : 0;
}

// Structure for IRQ info
typedef struct {
    int id;
    char device[128];
    char type[64];
    uint64_t total_count;
} IrqInfo;

// Get list of IRQs from /proc/interrupts
static IrqInfo* get_irq_list(int *count) {
    FILE *f = fopen("/proc/interrupts", "r");
    if (!f) return NULL;

    IrqInfo *list = malloc(sizeof(IrqInfo) * MAX_IRQS);
    *count = 0;

    char line[4096];
    // Skip header
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        free(list);
        return NULL;
    }

    // Number of CPUs is determined by the number of columns in the header
    int ncpus = 0;
    char *p = line;
    while ((p = strstr(p, "CPU")) != NULL) {
        ncpus++;
        p += 3;
    }

    while (fgets(line, sizeof(line), f) && *count < MAX_IRQS) {
        char *ptr = line;
        // Skip leading spaces
        while (*ptr == ' ') ptr++;

        // Get IRQ ID (can be numeric or string like 'NMI')
        char id_str[16];
        int n = 0;
        while (*ptr != ':' && *ptr != '\0' && n < 15) id_str[n++] = *ptr++;
        id_str[n] = '\0';
        if (*ptr != ':') continue;
        ptr++;

        // Only handle numeric IRQs for affinity usually
        char *endptr;
        int id = (int)strtol(id_str, &endptr, 10);
        if (*endptr != '\0') continue;

        IrqInfo *info = &list[*count];
        info->id = id;
        info->total_count = 0;

        // Skip CPU counts
        for (int i = 0; i < ncpus; i++) {
            while (*ptr == ' ') ptr++;
            info->total_count += strtoull(ptr, &ptr, 10);
        }

        // Get Type and Device
        while (*ptr == ' ') ptr++;
        char *type_end = strstr(ptr, "  ");
        if (type_end) {
            int type_len = type_end - ptr;
            if (type_len > 63) type_len = 63;
            strncpy(info->type, ptr, type_len);
            info->type[type_len] = '\0';
            ptr = type_end;
            while (*ptr == ' ') ptr++;
        } else {
            strcpy(info->type, "Unknown");
        }

        strncpy(info->device, ptr, sizeof(info->device) - 1);
        info->device[sizeof(info->device) - 1] = '\0';
        // Remove newline
        size_t len = strlen(info->device);
        if (len > 0 && info->device[len - 1] == '\n') info->device[len - 1] = '\0';

        (*count)++;
    }

    fclose(f);
    return list;
}

// Get process memory usage percentage (as integer)
int get_process_mem_usage(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    unsigned long vm_rss = 0;
    char line[256];

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "VmRSS: %lu", &vm_rss) == 1) {
            break;
        }
    }
    fclose(f);

    // Get total system memory (cached)
    unsigned long long total_mem_kb = get_total_mem_kb();
    if (total_mem_kb == 0) return 0;

    // vm_rss is already in KB, calculate percentage
    int mem_pct = (int)((vm_rss * 100ULL) / total_mem_kb);
    return mem_pct >= 0 ? mem_pct : 0;
}

// Get process executable path
bool get_process_exe(pid_t pid, char *exe_path, size_t size) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    ssize_t len = readlink(proc_path, exe_path, size - 1);
    if (len <= 0 || (size_t)len >= size - 1) {
        exe_path[0] = '\0';
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

// Custom cell data function for colored process names
void cell_data_func_name(GtkTreeViewColumn *col, GtkCellRenderer *renderer,
                         GtkTreeModel *model, GtkTreeIter *iter, gpointer user_data) {
    (void)col;
    AppData *app = (AppData *)user_data;

    gchar *name;
    gint cpu_pct;
    gtk_tree_model_get(model, iter, COL_NAME, &name, COL_CPU, &cpu_pct, -1);

    // Determine color based on CPU load relative to one core
    // High: > 80% of one core, Medium: > 30% of one core
    const char *color;
    int one_core_pct = 100 / app->ncpus;
    if (one_core_pct == 0) one_core_pct = 1;

    if (cpu_pct >= (one_core_pct * 80 / 100) || cpu_pct >= 50) {
        color = "#ff4444";  // Red (high)
    } else if (cpu_pct >= (one_core_pct * 30 / 100)) {
        color = "#ffaa00";  // Yellow (medium)
    } else {
        color = "#44ff44";  // Green (low)
    }

    // Apply color with Pango markup
    gchar *markup = g_markup_printf_escaped(
        "<span foreground='%s' weight='bold'>%s</span>",
        color, name
    );

    g_object_set(renderer, "markup", markup, NULL);
    g_free(name);
    g_free(markup);
}

// Filter function for search entry
gboolean filter_func(GtkTreeModel *model, GtkTreeIter *iter, gpointer data) {
    AppData *app = (AppData *)data;
    const char *filter_text = gtk_entry_get_text(GTK_ENTRY(app->filter_entry));

    if (!filter_text || strlen(filter_text) == 0) {
        return TRUE;  // Show all if no filter
    }

    gchar *name, *exe;
    gint pid;
    gtk_tree_model_get(model, iter, COL_PID, &pid, COL_NAME, &name,
                      COL_EXE, &exe, -1);

    // Check if filter matches PID, name, or exe
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    gboolean match = (strstr(pid_str, filter_text) != NULL) ||
                     (name && strcasestr(name, filter_text) != NULL) ||
                     (exe && strcasestr(exe, filter_text) != NULL);

    g_free(name);
    g_free(exe);

    return match;
}

// Update process list (in-place updates preserve scroll position)
gboolean update_process_list(gpointer data) {
    AppData *app = (AppData *)data;

    // Phase 0: Update CPU snapshot ONCE per cycle (not per process)
    update_cpu_snapshot();

    // Phase 1: Mark all existing entries as not seen
    PidRowMap *entry, *tmp;
    HASH_ITER(hh, app->pid_row_map, entry, tmp) {
        entry->seen_this_scan = false;
    }

    // Phase 2: Scan /proc and update/insert
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return TRUE;

    struct dirent *dir_entry;
    while ((dir_entry = readdir(proc_dir)) != NULL) {
        if (dir_entry->d_type != DT_DIR) continue;

        // Check if directory name is a number (PID)
        char *endptr;
        long pid = strtol(dir_entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        int pid_int = (int)pid;
        PidRowMap *pid_entry = NULL;
        HASH_FIND_INT(app->pid_row_map, &pid_int, pid_entry);

        if (pid_entry && !gtk_tree_row_reference_valid(pid_entry->row_ref)) {
            gtk_tree_row_reference_free(pid_entry->row_ref);
            HASH_DEL(app->pid_row_map, pid_entry);
            free(pid_entry);
            pid_entry = NULL;
        }

        if (pid_entry) {
            int cpu_pct = get_process_cpu_usage((pid_t)pid);
            int mem_pct = get_process_mem_usage((pid_t)pid);

            // UPDATE existing row in place
            GtkTreePath *path = gtk_tree_row_reference_get_path(pid_entry->row_ref);
            GtkTreeIter iter;
            if (gtk_tree_model_get_iter(GTK_TREE_MODEL(app->process_store), &iter, path)) {
                gtk_list_store_set(app->process_store, &iter,
                                  COL_CPU, cpu_pct,
                                  COL_MEM, mem_pct,
                                  -1);
            }
            gtk_tree_path_free(path);
            pid_entry->seen_this_scan = true;
            continue;
        } else {
            // Get process info for new rows only
            char name[MAX_PROC_NAME];
            char exe_path[MAX_PATH_LEN];

            if (!get_process_name((pid_t)pid, name, sizeof(name))) continue;
            get_process_exe((pid_t)pid, exe_path, sizeof(exe_path));

            // Get basename of executable
            const char *exe_basename = strrchr(exe_path, '/');
            exe_basename = exe_basename ? exe_basename + 1 : exe_path;

            int cpu_pct = get_process_cpu_usage((pid_t)pid);
            int mem_pct = get_process_mem_usage((pid_t)pid);

            // INSERT new row
            GtkTreeIter iter;
            gtk_list_store_append(app->process_store, &iter);
            gtk_list_store_set(app->process_store, &iter,
                              COL_PID, pid_int,
                              COL_NAME, name,
                              COL_EXE, exe_basename,
                              COL_CPU, cpu_pct,
                              COL_MEM, mem_pct,
                              -1);

            // Create row reference and add to hash map
            GtkTreePath *path = gtk_tree_model_get_path(
                GTK_TREE_MODEL(app->process_store), &iter);
            GtkTreeRowReference *row_ref = gtk_tree_row_reference_new(
                GTK_TREE_MODEL(app->process_store), path);
            gtk_tree_path_free(path);

            PidRowMap *new_entry = malloc(sizeof(PidRowMap));
            new_entry->pid = pid_int;
            new_entry->row_ref = row_ref;
            new_entry->seen_this_scan = true;
            HASH_ADD_INT(app->pid_row_map, pid, new_entry);
        }
    }

    closedir(proc_dir);

    // Phase 3: Remove processes that no longer exist
    HASH_ITER(hh, app->pid_row_map, entry, tmp) {
        if (!entry->seen_this_scan) {
            if (gtk_tree_row_reference_valid(entry->row_ref)) {
                GtkTreePath *path = gtk_tree_row_reference_get_path(entry->row_ref);
                GtkTreeIter iter;
                if (gtk_tree_model_get_iter(GTK_TREE_MODEL(app->process_store), &iter, path)) {
                    gtk_list_store_remove(app->process_store, &iter);
                }
                gtk_tree_path_free(path);
            }

            // Also clean up CPU tracker entry to prevent memory leak
            ProcessCpuTracker *cpu_entry = NULL;
            HASH_FIND_INT(cpu_tracker_map, &entry->pid, cpu_entry);
            if (cpu_entry) {
                HASH_DEL(cpu_tracker_map, cpu_entry);
                free(cpu_entry);
            }

            gtk_tree_row_reference_free(entry->row_ref);
            HASH_DEL(app->pid_row_map, entry);
            free(entry);
        }
    }

    // Update status label
    int process_count = HASH_COUNT(app->pid_row_map);
    char status[128];
    snprintf(status, sizeof(status), "%d processes", process_count);
    gtk_label_set_text(GTK_LABEL(app->status_label), status);

    return TRUE;  // Continue timer
}

static void free_cpu_tracker_map(void) {
    ProcessCpuTracker *entry, *tmp;
    HASH_ITER(hh, cpu_tracker_map, entry, tmp) {
        HASH_DEL(cpu_tracker_map, entry);
        free(entry);
    }
    cpu_tracker_map = NULL;
}

// Update IRQ list
void update_irq_list(AppData *app) {
    int count = 0;
    IrqInfo *irqs = get_irq_list(&count);
    if (!irqs) return;

    gtk_list_store_clear(app->irq_store);
    for (int i = 0; i < count; i++) {
        GtkTreeIter iter;
        gtk_list_store_append(app->irq_store, &iter);
        gtk_list_store_set(app->irq_store, &iter,
                          0, irqs[i].id,
                          1, irqs[i].device,
                          2, irqs[i].type,
                          3, (int)irqs[i].total_count,
                          -1);
    }
    free(irqs);
}

// Handle IRQ selection
void on_irq_selection_changed(GtkTreeSelection *selection, gpointer data) {
    AppData *app = (AppData *)data;
    GtkTreeIter iter;
    GtkTreeModel *model;

    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gint irq_id;
        gtk_tree_model_get(model, &iter, 0, &irq_id, -1);
        app->selected_irq = irq_id;

        // Clear all checks first
        for (int i = 0; i < app->ncpus; i++) {
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->irq_cpu_checks[i]), FALSE);
        }

        // Get current affinity
        char path[256];
        snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity_list", irq_id);
        FILE *f = fopen(path, "r");
        if (f) {
            char line[256];
            if (fgets(line, sizeof(line), f)) {
                // Parse affinity list (e.g. "0-3,5")
                char *token = strtok(line, ", \n");
                while (token) {
                    int start, end;
                    if (sscanf(token, "%d-%d", &start, &end) == 2) {
                        for (int i = start; i <= end && i < app->ncpus; i++)
                            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->irq_cpu_checks[i]), TRUE);
                    } else {
                        int cpu = atoi(token);
                        if (cpu >= 0 && cpu < app->ncpus)
                            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->irq_cpu_checks[cpu]), TRUE);
                    }
                    token = strtok(NULL, ", \n");
                }
            }
            fclose(f);
        }
    }
}

// Apply IRQ affinity
void on_apply_irq_clicked(GtkButton *button, gpointer data) {
    (void)button;
    AppData *app = (AppData *)data;
    if (app->selected_irq < 0) return;

    IrqRule rule = {0};
    rule.irq_id = app->selected_irq;
    rule.has_affinity = true;
    rule.cpu_count = 0;

    for (int i = 0; i < app->ncpus; i++) {
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->irq_cpu_checks[i]))) {
            rule.cpus[rule.cpu_count++] = i;
        }
    }

    // Get device name from selection
    GtkTreeIter iter;
    GtkTreeModel *model;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->irq_tree_view));
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gchar *dev;
        gtk_tree_model_get(model, &iter, 1, &dev, -1);
        strncpy(rule.device_name, dev, sizeof(rule.device_name)-1);
        g_free(dev);
    }

    config_set_irq_rule(app->config, rule.irq_id, &rule);
    config_save(app->config);
    
    // Attempt to apply immediately
    char path[256];
    snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity_list", app->selected_irq);
    FILE *f = fopen(path, "w");
    if (f) {
        for (int i = 0; i < rule.cpu_count; i++) {
            fprintf(f, "%d%s", rule.cpus[i], (i == rule.cpu_count - 1) ? "" : ",");
        }
        fclose(f);
        gtk_label_set_text(GTK_LABEL(app->status_label), "Applied and saved IRQ affinity");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Saved rule (run as root to apply immediately)");
    }
}

// Handle process selection
void on_selection_changed(GtkTreeSelection *selection, gpointer data) {
    AppData *app = (AppData *)data;
    GtkTreeIter iter;
    GtkTreeModel *model;

    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gint pid;
        gchar *name, *exe;

        gtk_tree_model_get(model, &iter,
                          COL_PID, &pid,
                          COL_NAME, &name,
                          COL_EXE, &exe,
                          -1);

        app->selected_pid = pid;
        g_strlcpy(app->selected_name, name, sizeof(app->selected_name));

        // Get the FULL exe path for rule saving (not just basename)
        char full_exe_path[MAX_PATH_LEN];
        if (get_process_exe(pid, full_exe_path, sizeof(full_exe_path))) {
            g_strlcpy(app->selected_exe, full_exe_path, sizeof(app->selected_exe));
        } else {
            // Fallback to basename if we can't read the full path
            g_strlcpy(app->selected_exe, exe, sizeof(app->selected_exe));
        }

        // Get current affinity and update checkboxes
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);

        if (sched_getaffinity(pid, sizeof(cpu_set), &cpu_set) == 0) {
            for (int i = 0; i < app->ncpus; i++) {
                gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->cpu_checks[i]),
                                            CPU_ISSET(i, &cpu_set));
            }
        }

        // Check for existing rules and update UI
        const Rule *rule = config_get_rule_by_exe(app->config, app->selected_exe);
        if (rule) {
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->exe_radio), TRUE);
        } else {
            rule = config_get_rule_by_name(app->config, app->selected_name);
            if (rule) {
                gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->name_radio), TRUE);
            }
        }

        if (rule) {
            if (rule->has_priority) gtk_combo_box_set_active(GTK_COMBO_BOX(app->priority_combo), rule->priority);
            if (rule->has_sched_policy) gtk_combo_box_set_active(GTK_COMBO_BOX(app->sched_policy_combo), rule->sched_policy);
            if (rule->has_ioprio) {
                gtk_combo_box_set_active(GTK_COMBO_BOX(app->ioprio_class_combo), rule->ioprio_class);
                gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->ioprio_level_spin), rule->ioprio_level);
            }
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->exclude_pb_check), rule->exclude_probalance);
        } else {
            // Reset to defaults if no rule
            gtk_combo_box_set_active(GTK_COMBO_BOX(app->priority_combo), PRIORITY_NORMAL);
            gtk_combo_box_set_active(GTK_COMBO_BOX(app->sched_policy_combo), 0);
            gtk_combo_box_set_active(GTK_COMBO_BOX(app->ioprio_class_combo), 0);
            gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->ioprio_level_spin), 4);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->exclude_pb_check), FALSE);
        }

        // Update status
        char status[512];
        snprintf(status, sizeof(status), "Selected: PID %d - %s", pid, name);
        gtk_label_set_text(GTK_LABEL(app->status_label), status);

        g_free(name);
        g_free(exe);
    } else {
        app->selected_pid = 0;
    }
}

// Get parent PID from /proc/[pid]/stat
static pid_t get_parent_pid(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char stat_line[512];
    if (!fgets(stat_line, sizeof(stat_line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    char *p = strrchr(stat_line, ')');
    if (!p) return -1;

    char state;
    int ppid;
    if (sscanf(p + 1, " %c %d", &state, &ppid) == 2) {
        return ppid;
    }
    return -1;
}

// Find the root of the process family (topmost process with same executable)
static pid_t find_process_family_root(pid_t pid, const char *target_exe) {
    pid_t current = pid;
    pid_t root = pid;

    while (current > 1) {
        pid_t parent = get_parent_pid(current);
        if (parent <= 1) break;  // Don't go past init/systemd

        char parent_exe[MAX_PATH_LEN];
        if (!get_process_exe(parent, parent_exe, sizeof(parent_exe))) break;

        // If parent has different executable, we found the root
        if (strcmp(parent_exe, target_exe) != 0) break;

        root = parent;
        current = parent;
    }

    return root;
}

// Apply settings to all descendants with matching executable (recursive)
static void apply_to_family_recursive(pid_t pid, const char *target_exe, const Rule *rule, int *count) {
    char exe_path[MAX_PATH_LEN];
    if (!get_process_exe(pid, exe_path, sizeof(exe_path))) return;

    // Only apply if executable matches
    if (strcmp(exe_path, target_exe) != 0) return;

    // Apply affinity
    if (rule->has_cpus) {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        for (int i = 0; i < rule->cpu_count; i++) {
            CPU_SET(rule->cpus[i], &cpu_set);
        }
        if (sched_setaffinity(pid, sizeof(cpu_set), &cpu_set) == 0) {
            (*count)++;
        }
    }

    // Apply priority
    if (rule->has_priority) {
        setpriority(PRIO_PROCESS, pid, priority_nice(rule->priority));
    }

    // Find and recurse into children
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;

        char *endptr;
        long child_pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || child_pid <= 0) continue;

        if (get_parent_pid((pid_t)child_pid) == pid) {
            apply_to_family_recursive((pid_t)child_pid, target_exe, rule, count);
        }
    }
    closedir(proc_dir);
}

// Check if a process is a "system boundary" - something we should never kill
// when trying to kill an application (init, systemd, shells, session managers, etc.)

// Check if a PID is in our own ancestry (would kill ourselves)
static bool would_kill_ourselves(pid_t target_pid) {
    pid_t our_pid = getpid();
    
    // Direct check: is target us?
    if (target_pid == our_pid) return true;
    
    // Check if target is one of our ancestors
    pid_t current = our_pid;
    while (current > 1) {
        pid_t parent = get_parent_pid(current);
        if (parent <= 1) break;
        if (parent == target_pid) return true;
        current = parent;
    }
    
    // Check if we are a descendant of the target (target is our ancestor)
    // This is already covered above, but also check if target's descendants include us
    // by checking if target is in our ancestry chain
    return false;
}

static bool is_system_boundary(pid_t pid) {
    if (pid <= 1) return true;  // init/systemd

    char comm[256];
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return true;  // Can't read = assume system

    if (!fgets(comm, sizeof(comm), f)) {
        fclose(f);
        return true;
    }
    fclose(f);
    comm[strcspn(comm, "\n")] = '\0';

    // List of system boundary processes - these should never be killed as "parents"
    static const char *system_procs[] = {
        "systemd", "init", "bash", "zsh", "sh", "fish", "ksh", "tcsh", "csh",
        "login", "sshd", "gdm", "sddm", "lightdm", "xdm",
        "gnome-session", "plasma", "xfce4-session", "mate-session",
        "dbus-daemon", "dbus-broker", "polkitd", "upowerd",
        "Xorg", "Xwayland", "kwin", "mutter", "weston", "sway", "hyprland",
        "tmux", "screen", "sudo", "su", "pkexec", "doas",
        NULL
    };

    for (int i = 0; system_procs[i] != NULL; i++) {
        if (strcmp(comm, system_procs[i]) == 0) return true;
    }
    return false;
}

// Find the application root - go UP the tree until we hit a system boundary
static pid_t find_application_root(pid_t pid) {
    pid_t current = pid;
    pid_t root = pid;

    while (current > 1) {
        pid_t parent = get_parent_pid(current);
        if (parent <= 1) break;
        if (is_system_boundary(parent)) break;

        root = parent;
        current = parent;
    }
    return root;
}

// Collect all descendant PIDs efficiently
static void collect_descendants_efficient(pid_t root_pid, pid_t *descendants, int *count, int max_pids) {
    typedef struct {
        pid_t pid;
        pid_t ppid;
    } ProcInfo;

    int proc_capacity = 1024;
    ProcInfo *procs = malloc(sizeof(ProcInfo) * proc_capacity);
    int proc_count = 0;

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        free(procs);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;

        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        if (proc_count >= proc_capacity) {
            int new_capacity = proc_capacity * 2;
            ProcInfo *new_procs = realloc(procs, sizeof(ProcInfo) * new_capacity);
            if (!new_procs) {
                closedir(proc_dir);
                free(procs);
                return;
            }
            procs = new_procs;
            proc_capacity = new_capacity;
        }

        procs[proc_count].pid = (pid_t)pid;
        procs[proc_count].ppid = get_parent_pid((pid_t)pid);
        proc_count++;
    }
    closedir(proc_dir);

    // Iteratively find all descendants
    bool added;
    do {
        added = false;
        for (int i = 0; i < proc_count; i++) {
            // Check if this process's parent is root_pid or one of the already found descendants
            bool is_descendant = (procs[i].ppid == root_pid);
            if (!is_descendant) {
                for (int j = 0; j < *count; j++) {
                    if (procs[i].ppid == descendants[j]) {
                        is_descendant = true;
                        break;
                    }
                }
            }

            if (is_descendant) {
                // Check if already in our list
                bool already_added = false;
                for (int j = 0; j < *count; j++) {
                    if (descendants[j] == procs[i].pid) {
                        already_added = true;
                        break;
                    }
                }

                if (!already_added && *count < max_pids) {
                    descendants[(*count)++] = procs[i].pid;
                    added = true;
                }
            }
        }
    } while (added && *count < max_pids);

    free(procs);
}

// Kill a process and all its descendants
static int kill_process_tree(pid_t root_pid) {
    #define MAX_KILL_PIDS 2048
    pid_t pids[MAX_KILL_PIDS];
    int count = 0;
    int killed = 0;

    collect_descendants_efficient(root_pid, pids, &count, MAX_KILL_PIDS);

    // Kill descendants first
    for (int i = 0; i < count; i++) {
        if (kill(pids[i], SIGTERM) == 0) {
            killed++;
        }
    }

    // Kill the root process
    if (kill(root_pid, SIGTERM) == 0) {
        killed++;
    }

    // Wait a bit and SIGKILL survivors
    usleep(100000); // 100ms

    for (int i = 0; i < count; i++) {
        if (kill(pids[i], 0) == 0) kill(pids[i], SIGKILL);
    }
    if (kill(root_pid, 0) == 0) kill(root_pid, SIGKILL);

    return killed > 0 ? killed : -1;
    #undef MAX_KILL_PIDS
}

// Apply affinity and priority to selected process
void on_apply_clicked(GtkButton *button, gpointer data) {
    (void)button;
    AppData *app = (AppData *)data;

    if (app->selected_pid == 0) {
        gtk_label_set_text(GTK_LABEL(app->status_label),
                          "Error: No process selected");
        return;
    }

    Rule rule = {0};

    // Build CPU affinity list
    rule.has_cpus = false;
    rule.cpu_count = 0;

    for (int i = 0; i < app->ncpus; i++) {
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->cpu_checks[i]))) {
            rule.cpus[rule.cpu_count++] = i;
            rule.has_cpus = true;
        }
    }

    // Get priority selection
    int priority_idx = gtk_combo_box_get_active(GTK_COMBO_BOX(app->priority_combo));
    if (priority_idx >= 0 && priority_idx <= PRIORITY_REALTIME) {
        rule.has_priority = true;
        rule.priority = (Priority)priority_idx;
    }

    // Get scheduler policy
    int policy_idx = gtk_combo_box_get_active(GTK_COMBO_BOX(app->sched_policy_combo));
    if (policy_idx > 0) {
        rule.has_sched_policy = true;
        rule.sched_policy = (SchedPolicy)policy_idx;
    }

    // Get IO priority
    int ioprio_class = gtk_combo_box_get_active(GTK_COMBO_BOX(app->ioprio_class_combo));
    if (ioprio_class > 0) {
        rule.has_ioprio = true;
        rule.ioprio_class = (IOPrioClass)ioprio_class;
        rule.ioprio_level = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(app->ioprio_level_spin));
    }

    // ProBalance exclusion
    rule.exclude_probalance = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->exclude_pb_check));

    // Apply immediately to process
    if (rule.has_cpus) {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);

        for (int i = 0; i < rule.cpu_count; i++) {
            CPU_SET(rule.cpus[i], &cpu_set);
        }

        if (sched_setaffinity(app->selected_pid, sizeof(cpu_set), &cpu_set) == -1) {
            gtk_label_set_text(GTK_LABEL(app->status_label),
                              "Error: Failed to set CPU affinity");
            return;
        }
    }

    if (rule.has_priority) {
        int nice_val = priority_nice(rule.priority);
        if (setpriority(PRIO_PROCESS, app->selected_pid, nice_val) == -1) {
            gtk_label_set_text(GTK_LABEL(app->status_label),
                              "Error: Failed to set priority");
            return;
        }
    }

    // Apply scheduler policy immediately
    if (rule.has_sched_policy) {
        struct sched_param param = {0};
        int policy = SCHED_OTHER;
        switch (rule.sched_policy) {
            case SCHED_POL_BATCH: policy = SCHED_BATCH; break;
            case SCHED_POL_IDLE: policy = SCHED_IDLE; break;
            case SCHED_POL_FIFO: policy = SCHED_FIFO; param.sched_priority = 1; break;
            case SCHED_POL_RR: policy = SCHED_RR; param.sched_priority = 1; break;
            default: policy = SCHED_OTHER; break;
        }
        if (sched_setscheduler(app->selected_pid, policy, &param) == -1) {
            gtk_label_set_text(GTK_LABEL(app->status_label), "Error: Failed to set scheduler policy");
        }
    }

    // Apply IO priority immediately
    if (rule.has_ioprio) {
        int p = IOPRIO_PRIO_VALUE(rule.ioprio_class, rule.ioprio_level);
        if (ioprio_set(IOPRIO_WHO_PROCESS, app->selected_pid, p) == -1) {
            gtk_label_set_text(GTK_LABEL(app->status_label), "Error: Failed to set IO priority");
        }
    }

    // Save rule if not in test mode
    gboolean test_mode = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(app->test_mode_check));

    if (!test_mode) {
        gboolean use_exe = gtk_toggle_button_get_active(
            GTK_TOGGLE_BUTTON(app->exe_radio));

        const char *key = use_exe ? app->selected_exe : app->selected_name;
        config_set_rule(app->config, key, use_exe, &rule);
        config_save(app->config);

        // Remove from override file so daemon can manage it
        remove_pid_from_override(app->selected_pid);

        gtk_label_set_text(GTK_LABEL(app->status_label),
                          "Applied and saved rule");
    } else {
        // Test mode: add PID to override file to prevent daemon from managing it
        add_pid_to_override(app->selected_pid);

        gtk_label_set_text(GTK_LABEL(app->status_label),
                          "Applied (test mode - not saved)");
    }

    // Apply to process family if requested
    gboolean apply_children = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(app->apply_children_check));

    if (apply_children) {
        char target_exe[MAX_PATH_LEN];
        if (get_process_exe(app->selected_pid, target_exe, sizeof(target_exe))) {
            // Find the root of the process family
            pid_t root = find_process_family_root(app->selected_pid, target_exe);

            // Apply to entire family recursively
            int family_count = 0;
            apply_to_family_recursive(root, target_exe, &rule, &family_count);

            if (family_count > 0) {
                char status[256];
                snprintf(status, sizeof(status), "Applied to %d process(es) in family", family_count);
                gtk_label_set_text(GTK_LABEL(app->status_label), status);
            }
        }
    }
}

void on_delete_rule_clicked(GtkButton *button, gpointer data) {
    (void)button;
    AppData *app = (AppData *)data;

    if (app->selected_pid == 0) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Error: No process selected");
        return;
    }

    gboolean use_exe = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->exe_radio));
    const char *key = use_exe ? app->selected_exe : app->selected_name;

    config_remove_rule(app->config, key, use_exe);
    if (config_save(app->config)) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Rule deleted and config saved");
        // Trigger a re-selection to update UI controls to defaults
        GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->tree_view));
        on_selection_changed(sel, app);
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Error saving config after deleting rule");
    }
}

// Kill selected process and its entire application tree
// Finds the application root (going UP past child workers) then kills DOWN
void on_kill_clicked(GtkButton *button, gpointer data) {
    (void)button;
    AppData *app = (AppData *)data;

    if (app->selected_pid == 0) {
        gtk_label_set_text(GTK_LABEL(app->status_label),
                          "Error: No process selected");
        return;
    }

    // SAFETY: Don't allow selecting ourselves directly
    if (app->selected_pid == getpid()) {
        gtk_label_set_text(GTK_LABEL(app->status_label),
                          "Error: Cannot kill the Load Manager itself!");
        return;
    }

    // Find the application root - this handles the case where user clicks
    // on a child process (like Discord's "Web Content") but wants to kill
    // the whole application
    pid_t root_pid = find_application_root(app->selected_pid);

    // SAFETY: Don't allow killing ourselves or our parent processes
    if (would_kill_ourselves(root_pid)) {
        gtk_label_set_text(GTK_LABEL(app->status_label),
                          "Error: Cannot kill the Load Manager itself!");
        return;
    }

    // Get the root process name for status message
    char root_name[MAX_PROC_NAME] = "unknown";
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/comm", root_pid);
    FILE *f = fopen(stat_path, "r");
    if (f) {
        if (fgets(root_name, sizeof(root_name), f)) {
            root_name[strcspn(root_name, "\n")] = '\0';
        }
        fclose(f);
    }

    // Kill from the application root down
    int result = kill_process_tree(root_pid);

    if (result > 0) {
        char status[256];
        if (root_pid != app->selected_pid) {
            // We went up the tree - let user know
            snprintf(status, sizeof(status),
                     "Killed %s (PID %d) + %d child(ren) [root of selected process]",
                     root_name, root_pid, result - 1);
        } else {
            snprintf(status, sizeof(status),
                     "Killed %s (PID %d) + %d child(ren)",
                     root_name, root_pid, result - 1);
        }
        gtk_label_set_text(GTK_LABEL(app->status_label), status);

        // Clear selection since process is gone
        app->selected_pid = 0;
        app->selected_exe[0] = '\0';
        app->selected_name[0] = '\0';

        // Refresh the list to show updated state
        update_process_list(app);
    } else {
        char status[256];
        snprintf(status, sizeof(status), "Failed to kill %s (PID %d) - permission denied?",
                 root_name, root_pid);
        gtk_label_set_text(GTK_LABEL(app->status_label), status);
    }
}

// Save ProBalance settings
void on_save_settings_clicked(GtkButton *button, gpointer data) {
    (void)button;
    AppData *app = (AppData *)data;

    app->config->probalance.enabled = gtk_switch_get_active(GTK_SWITCH(app->pb_enabled_switch));
    app->config->probalance.cpu_threshold = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(app->pb_threshold_spin));
    app->config->probalance.suppression_nice = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(app->pb_suppression_spin));
    app->config->probalance.duration_ms = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(app->pb_duration_spin));
    app->config->probalance.ignore_foreground = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->pb_ignore_fg_check));

    if (config_save(app->config)) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Settings saved successfully");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Error saving settings");
    }
}

// Filter entry changed
void on_filter_changed(GtkEditable *editable, gpointer data) {
    (void)editable;
    AppData *app = (AppData *)data;
    gtk_tree_model_filter_refilter(app->filter_model);
}

gboolean on_window_state_event(GtkWidget *widget, GdkEventWindowState *event, gpointer data) {
    (void)widget;
    AppData *app = (AppData *)data;

    if ((event->changed_mask & GDK_WINDOW_STATE_ICONIFIED) == 0) {
        return FALSE;
    }

    if (event->new_window_state & GDK_WINDOW_STATE_ICONIFIED) {
        if (app->update_timer != 0) {
            g_source_remove(app->update_timer);
            app->update_timer = 0;
        }
    } else {
        if (app->update_timer == 0) {
            app->update_timer = g_timeout_add(UPDATE_INTERVAL_MS, update_process_list, app);
            update_process_list(app);
        }
    }

    return FALSE;
}

// Create main window with tabs
GtkWidget* create_main_window(AppData *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Arch Load Manager");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1000, 700);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "arch-load-manager");

    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "Arch Load Manager");
    gtk_window_set_titlebar(GTK_WINDOW(app->window), header);

    GtkWidget *main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(app->window), main_vbox);

    app->stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(app->stack), GTK_STACK_TRANSITION_TYPE_SLIDE_LEFT_RIGHT);
    gtk_stack_set_transition_duration(GTK_STACK(app->stack), 300);

    GtkWidget *switcher = gtk_stack_switcher_new();
    gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(switcher), GTK_STACK(app->stack));
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(header), switcher);

    // --- Tab 1: Processes (Task Manager) ---
    GtkWidget *proc_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(proc_vbox), 12);
    
    app->filter_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->filter_entry), "Search processes...");
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(app->filter_entry), GTK_ENTRY_ICON_PRIMARY, "system-search-symbolic");
    g_signal_connect(app->filter_entry, "changed", G_CALLBACK(on_filter_changed), app);
    gtk_box_pack_start(GTK_BOX(proc_vbox), app->filter_entry, FALSE, FALSE, 0);

    app->process_store = gtk_list_store_new(NUM_COLS, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT);
    app->filter_model = GTK_TREE_MODEL_FILTER(gtk_tree_model_filter_new(GTK_TREE_MODEL(app->process_store), NULL));
    gtk_tree_model_filter_set_visible_func(app->filter_model, filter_func, app, NULL);
    GtkTreeModel *sort_model = gtk_tree_model_sort_new_with_model(GTK_TREE_MODEL(app->filter_model));
    app->tree_view = gtk_tree_view_new_with_model(sort_model);
    
    // (Add columns - shortened for brevity in this replacement)
    const char *titles[] = {"PID", "Process Name", "Executable", "CPU %", "Mem %"};
    for (int i = 0; i < NUM_COLS; i++) {
        GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(titles[i], renderer, "text", i, NULL);
        if (i == COL_NAME) gtk_tree_view_column_set_cell_data_func(col, renderer, cell_data_func_name, app, NULL);
        gtk_tree_view_column_set_sort_column_id(col, i);
        gtk_tree_view_append_column(GTK_TREE_VIEW(app->tree_view), col);
    }
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(sort_model), COL_CPU, GTK_SORT_DESCENDING);
    
    app->scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(app->scrolled_window), app->tree_view);
    gtk_box_pack_start(GTK_BOX(proc_vbox), app->scrolled_window, TRUE, TRUE, 0);

    // Process controls
    GtkWidget *proc_ctrls = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *cpu_frame = gtk_frame_new("CPU Affinity");
    GtkWidget *cpu_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_container_add(GTK_CONTAINER(cpu_frame), cpu_box);
    app->cpu_checks = g_new0(GtkCheckButton*, app->ncpus);
    for (int i = 0; i < app->ncpus; i++) {
        char l[16]; snprintf(l, sizeof(l), "%d", i);
        app->cpu_checks[i] = GTK_CHECK_BUTTON(gtk_check_button_new_with_label(l));
        gtk_box_pack_start(GTK_BOX(cpu_box), GTK_WIDGET(app->cpu_checks[i]), FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(proc_ctrls), cpu_frame, TRUE, TRUE, 0);

    GtkWidget *prio_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    app->priority_combo = gtk_combo_box_text_new();
    for(int i=0; i<=PRIORITY_REALTIME; i++) gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->priority_combo), priority_name(i));
    gtk_combo_box_set_active(GTK_COMBO_BOX(app->priority_combo), PRIORITY_NORMAL);
    gtk_box_pack_start(GTK_BOX(prio_vbox), gtk_label_new("Priority:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(prio_vbox), app->priority_combo, FALSE, FALSE, 0);

    app->sched_policy_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->sched_policy_combo), "Default");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->sched_policy_combo), "Batch");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->sched_policy_combo), "Idle");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->sched_policy_combo), "FIFO (RT)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->sched_policy_combo), "RR (RT)");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app->sched_policy_combo), 0);
    gtk_box_pack_start(GTK_BOX(prio_vbox), gtk_label_new("Sched Policy:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(prio_vbox), app->sched_policy_combo, FALSE, FALSE, 0);

    GtkWidget *ioprio_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    app->ioprio_class_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->ioprio_class_combo), "None");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->ioprio_class_combo), "Real-time");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->ioprio_class_combo), "Best-effort");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->ioprio_class_combo), "Idle");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app->ioprio_class_combo), 0);
    app->ioprio_level_spin = gtk_spin_button_new_with_range(0, 7, 1);
    gtk_box_pack_start(GTK_BOX(ioprio_hbox), app->ioprio_class_combo, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(ioprio_hbox), app->ioprio_level_spin, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(prio_vbox), gtk_label_new("IO Priority:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(prio_vbox), ioprio_hbox, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(proc_ctrls), prio_vbox, FALSE, FALSE, 0);

    GtkWidget *options_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    app->exclude_pb_check = gtk_check_button_new_with_label("Exclude from ProBalance");
    app->apply_children_check = gtk_check_button_new_with_label("Apply to children");
    app->test_mode_check = gtk_check_button_new_with_label("Test Mode (no save)");
    gtk_box_pack_start(GTK_BOX(options_vbox), app->exclude_pb_check, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(options_vbox), app->apply_children_check, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(options_vbox), app->test_mode_check, FALSE, FALSE, 0);
    
    GtkWidget *type_frame = gtk_frame_new("Rule Type");
    GtkWidget *type_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    app->exe_radio = gtk_radio_button_new_with_label(NULL, "By Executable Path");
    app->name_radio = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(app->exe_radio), "By Process Name");
    gtk_box_pack_start(GTK_BOX(type_vbox), app->exe_radio, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(type_vbox), app->name_radio, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(type_frame), type_vbox);
    
    gtk_box_pack_start(GTK_BOX(options_vbox), type_frame, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(proc_ctrls), options_vbox, FALSE, FALSE, 0);

    GtkWidget *proc_btns = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *apply_btn = gtk_button_new_with_label("Apply Rule");
    gtk_style_context_add_class(gtk_widget_get_style_context(apply_btn), "suggested-action");
    g_signal_connect(apply_btn, "clicked", G_CALLBACK(on_apply_clicked), app);
    GtkWidget *kill_btn = gtk_button_new_with_label("End Task");
    gtk_style_context_add_class(gtk_widget_get_style_context(kill_btn), "destructive-action");
    g_signal_connect(kill_btn, "clicked", G_CALLBACK(on_kill_clicked), app);
    
    GtkWidget *delete_btn = gtk_button_new_with_label("Delete Rule");
    g_signal_connect(delete_btn, "clicked", G_CALLBACK(on_delete_rule_clicked), app);
    
    gtk_box_pack_start(GTK_BOX(proc_btns), apply_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(proc_btns), delete_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(proc_btns), kill_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(proc_ctrls), proc_btns, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(proc_vbox), proc_ctrls, FALSE, FALSE, 0);
    gtk_stack_add_titled(GTK_STACK(app->stack), proc_vbox, "processes", "Processes");

    // --- Tab 2: Interrupts (MSI/IRQ) ---
    GtkWidget *irq_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(irq_vbox), 12);
    app->irq_store = gtk_list_store_new(4, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT);
    app->irq_tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(app->irq_store));
    const char *irq_titles[] = {"IRQ", "Device", "Type", "Total Events"};
    for (int i = 0; i < 4; i++) {
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(irq_titles[i], gtk_cell_renderer_text_new(), "text", i, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(app->irq_tree_view), col);
    }
    GtkWidget *irq_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(irq_scroll), app->irq_tree_view);
    gtk_box_pack_start(GTK_BOX(irq_vbox), irq_scroll, TRUE, TRUE, 0);
    
    GtkWidget *irq_ctrls = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *irq_cpu_frame = gtk_frame_new("Interrupt Affinity (MSI)");
    GtkWidget *irq_cpu_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_container_add(GTK_CONTAINER(irq_cpu_frame), irq_cpu_box);
    app->irq_cpu_checks = g_new0(GtkCheckButton*, app->ncpus);
    for (int i = 0; i < app->ncpus; i++) {
        char l[16]; snprintf(l, sizeof(l), "%d", i);
        app->irq_cpu_checks[i] = GTK_CHECK_BUTTON(gtk_check_button_new_with_label(l));
        gtk_box_pack_start(GTK_BOX(irq_cpu_box), GTK_WIDGET(app->irq_cpu_checks[i]), FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(irq_ctrls), irq_cpu_frame, TRUE, TRUE, 0);
    GtkWidget *irq_apply = gtk_button_new_with_label("Set Affinity");
    g_signal_connect(irq_apply, "clicked", G_CALLBACK(on_apply_irq_clicked), app);
    gtk_box_pack_start(GTK_BOX(irq_ctrls), irq_apply, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(irq_vbox), irq_ctrls, FALSE, FALSE, 0);
    
    gtk_stack_add_titled(GTK_STACK(app->stack), irq_vbox, "interrupts", "Interrupts (MSI)");

    // --- Tab 3: ProBalance & Settings ---
    GtkWidget *set_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_container_set_border_width(GTK_CONTAINER(set_vbox), 30);
    
    GtkWidget *pb_frame = gtk_frame_new(NULL);
    GtkWidget *pb_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_container_set_border_width(GTK_CONTAINER(pb_box), 15);
    gtk_container_add(GTK_CONTAINER(pb_frame), pb_box);
    
    GtkWidget *pb_head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *pb_title = gtk_label_new("ProBalance Dynamic Optimization");
    gtk_style_context_add_class(gtk_widget_get_style_context(pb_title), "title");
    gtk_box_pack_start(GTK_BOX(pb_head), pb_title, FALSE, FALSE, 0);
    app->pb_enabled_switch = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(app->pb_enabled_switch), app->config->probalance.enabled);
    gtk_box_pack_end(GTK_BOX(pb_head), app->pb_enabled_switch, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(pb_box), pb_head, FALSE, FALSE, 0);
    
    GtkWidget *pb_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(pb_grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(pb_grid), 20);
    
    gtk_grid_attach(GTK_GRID(pb_grid), gtk_label_new("CPU Usage Threshold (%):"), 0, 0, 1, 1);
    app->pb_threshold_spin = gtk_spin_button_new_with_range(1, 100, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->pb_threshold_spin), app->config->probalance.cpu_threshold);
    gtk_grid_attach(GTK_GRID(pb_grid), app->pb_threshold_spin, 1, 0, 1, 1);
    
    gtk_grid_attach(GTK_GRID(pb_grid), gtk_label_new("Suppression Nice (add):"), 0, 1, 1, 1);
    app->pb_suppression_spin = gtk_spin_button_new_with_range(1, 20, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->pb_suppression_spin), app->config->probalance.suppression_nice);
    gtk_grid_attach(GTK_GRID(pb_grid), app->pb_suppression_spin, 1, 1, 1, 1);
    
    gtk_grid_attach(GTK_GRID(pb_grid), gtk_label_new("Duration (ms):"), 0, 2, 1, 1);
    app->pb_duration_spin = gtk_spin_button_new_with_range(100, 10000, 100);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->pb_duration_spin), app->config->probalance.duration_ms);
    gtk_grid_attach(GTK_GRID(pb_grid), app->pb_duration_spin, 1, 2, 1, 1);
    
    app->pb_ignore_fg_check = gtk_check_button_new_with_label("Ignore Foreground Applications");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->pb_ignore_fg_check), app->config->probalance.ignore_foreground);
    gtk_grid_attach(GTK_GRID(pb_grid), app->pb_ignore_fg_check, 0, 3, 2, 1);
    
    gtk_box_pack_start(GTK_BOX(pb_box), pb_grid, FALSE, FALSE, 0);
    
    GtkWidget *save_pb = gtk_button_new_with_label("Save ProBalance Settings");
    g_signal_connect(save_pb, "clicked", G_CALLBACK(on_save_settings_clicked), app);
    gtk_box_pack_start(GTK_BOX(pb_box), save_pb, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(set_vbox), pb_frame, FALSE, FALSE, 0);
    gtk_stack_add_titled(GTK_STACK(app->stack), set_vbox, "settings", "Settings");

    gtk_box_pack_start(GTK_BOX(main_vbox), app->stack, TRUE, TRUE, 0);

    // Status label at the very bottom
    app->status_label = gtk_label_new("Ready");
    gtk_widget_set_name(app->status_label, "status-label");
    gtk_label_set_xalign(GTK_LABEL(app->status_label), 0.0);
    gtk_box_pack_start(GTK_BOX(main_vbox), app->status_label, FALSE, FALSE, 0);

    g_signal_connect(app->window, "destroy", G_CALLBACK(on_window_destroy), NULL);
    
    // Connect IRQ selection
    GtkTreeSelection *irq_sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->irq_tree_view));
    g_signal_connect(irq_sel, "changed", G_CALLBACK(on_irq_selection_changed), app);
    
    // Initial data
    update_irq_list(app);

    return app->window;
}

// Cleanup callback when window is destroyed
void on_window_destroy(GtkWidget *widget, gpointer data) {
    (void)widget;
    (void)data;

    // Clear all test mode overrides
    clear_all_overrides();

    gtk_main_quit();
}

int main(int argc, char *argv[]) {
    // Set application ID for Wayland compositors (must be before gtk_init)
    g_set_prgname("arch-load-manager");

    gtk_init(&argc, &argv);

    // Set window class for X11 and additional Wayland hints
    gdk_set_program_class("arch-load-manager");

    // Initialize app data
    AppData app = {0};
    app.ncpus = get_nprocs();
    if (app.ncpus > MAX_CPUS) {
        g_warning("System has %d CPUs, but we only support %d. Capping.", app.ncpus, MAX_CPUS);
        app.ncpus = MAX_CPUS;
    }
    app.selected_pid = 0;
    app.selected_irq = -1;
    app.pid_row_map = NULL;

    // Initialize config
    app.config = config_init(NULL);
    if (!app.config) {
        g_printerr("Failed to initialize config\n");
        return 1;
    }

    // Load existing config
    config_load(app.config);

    // Apply CSS styling
    GtkCssProvider *css_provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css_provider, css_style, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css_provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    // Create main window
    create_main_window(&app);

    // Initial process list update
    update_process_list(&app);

    // Set up timer for automatic updates
    app.update_timer = g_timeout_add(UPDATE_INTERVAL_MS, update_process_list, &app);

    // Show window and run
    gtk_widget_show_all(app.window);
    gtk_main();

    // Cleanup
    if (app.update_timer != 0) {
        g_source_remove(app.update_timer);
    }
    config_free(app.config);
    g_free(app.cpu_checks);
    g_free(app.irq_cpu_checks);

    // Cleanup pid row map
    PidRowMap *entry, *tmp;
    HASH_ITER(hh, app.pid_row_map, entry, tmp) {
        if (entry->row_ref) {
            gtk_tree_row_reference_free(entry->row_ref);
        }
        HASH_DEL(app.pid_row_map, entry);
        free(entry);
    }

    free_cpu_tracker_map();

    return 0;
}
