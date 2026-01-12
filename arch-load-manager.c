#define _GNU_SOURCE
#include "config.h"
#include <gtk/gtk.h>
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
    GtkWidget *tree_view;
    GtkWidget *filter_entry;
    GtkWidget *status_label;
    GtkWidget *priority_combo;
    GtkWidget *test_mode_check;
    GtkWidget *apply_children_check;
    GtkWidget *exe_radio;
    GtkWidget *name_radio;
    GtkListStore *process_store;
    GtkTreeModelFilter *filter_model;
    GtkCheckButton **cpu_checks;
    GtkWidget *scrolled_window;
    PidRowMap *pid_row_map;
    Config *config;
    int selected_pid;
    char selected_exe[MAX_PATH_LEN];      // Full path for rule saving
    char selected_exe_base[MAX_PATH_LEN]; // Basename for display
    char selected_name[MAX_PROC_NAME];
    int ncpus;
    guint update_timer;
} AppData;

// UI Styling
static const char *css_style =
    "window {"
    "    background: linear-gradient(135deg, #1a1a1a, #2b2b2b);"
    "}"
    ""
    "#search-entry {"
    "    background: rgba(74, 144, 226, 0.15);"
    "    border: 1px solid rgba(74, 144, 226, 0.4);"
    "    border-radius: 8px;"
    "    padding: 8px 12px;"
    "    color: #e0e0e0;"
    "    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);"
    "    font-size: 12px;"
    "}"
    "#search-entry:focus {"
    "    background: rgba(74, 144, 226, 0.25);"
    "    border-color: #4a90e2;"
    "    box-shadow: 0 0 12px rgba(74, 144, 226, 0.5);"
    "}"
    ""
    "treeview {"
    "    background: rgba(30, 30, 30, 0.85);"
    "    color: #e0e0e0;"
    "    border-radius: 6px;"
    "}"
    "treeview header button {"
    "    background: rgba(50, 50, 50, 0.9);"
    "    border: 1px solid rgba(74, 144, 226, 0.3);"
    "    border-radius: 4px;"
    "    padding: 6px;"
    "    color: #e0e0e0;"
    "}"
    "treeview header button:hover {"
    "    background: rgba(74, 144, 226, 0.3);"
    "    box-shadow: 0 0 8px rgba(74, 144, 226, 0.4);"
    "}"
    "treeview:selected {"
    "    background: rgba(74, 144, 226, 0.4);"
    "}"
    ""
    "button {"
    "    background: linear-gradient(135deg, #3a3a3a, #4a4a4a);"
    "    border: 1px solid rgba(74, 144, 226, 0.4);"
    "    border-radius: 6px;"
    "    padding: 6px 16px;"
    "    color: #e0e0e0;"
    "    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.3);"
    "}"
    "button:hover {"
    "    background: linear-gradient(135deg, #4a90e2, #5aa0f2);"
    "    border-color: #4a90e2;"
    "    box-shadow: 0 0 12px rgba(74, 144, 226, 0.6);"
    "}"
    ""
    "checkbutton {"
    "    color: #e0e0e0;"
    "}"
    "checkbutton:checked {"
    "    color: #4a90e2;"
    "}"
    ""
    "combobox button {"
    "    background: rgba(50, 50, 50, 0.8);"
    "    border: 1px solid rgba(74, 144, 226, 0.3);"
    "    color: #e0e0e0;"
    "}"
    ""
    "label {"
    "    color: #e0e0e0;"
    "}"
    ""
    "#status-label {"
    "    background: rgba(30, 30, 30, 0.9);"
    "    padding: 6px;"
    "    border-radius: 4px;"
    "}";

// Global CPU time tracking (updated once per cycle, not per process)
static unsigned long g_prev_total_cpu = 0;
static unsigned long g_curr_total_cpu = 0;
static bool g_cpu_snapshot_taken = false;

// Per-process CPU tracking using hash table (no PID limit)
typedef struct {
    pid_t pid;
    unsigned long prev_cpu;
    UT_hash_handle hh;
} ProcessCpuTracker;

static ProcessCpuTracker *cpu_tracker_map = NULL;

// Override file for test mode
#define OVERRIDE_FILE "/tmp/arch-load-manager-override"

// Add PID to override file (test mode)
void add_pid_to_override(pid_t pid) {
    // Read existing PIDs
    FILE *f = fopen(OVERRIDE_FILE, "r");
    pid_t existing_pids[1024];
    int count = 0;

    if (f) {
        char line[32];
        while (fgets(line, sizeof(line), f) && count < 1024) {
            pid_t existing = (pid_t)atoi(line);
            if (existing > 0 && existing != pid) {
                existing_pids[count++] = existing;
            }
        }
        fclose(f);
    }

    // Write all PIDs including the new one
    f = fopen(OVERRIDE_FILE, "w");
    if (!f) return;

    fprintf(f, "%d\n", pid);
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d\n", existing_pids[i]);
    }

    fclose(f);
}

// Remove PID from override file
void remove_pid_from_override(pid_t pid) {
    FILE *f = fopen(OVERRIDE_FILE, "r");
    if (!f) return;

    pid_t pids[1024];
    int count = 0;

    char line[32];
    while (fgets(line, sizeof(line), f) && count < 1024) {
        pid_t existing = (pid_t)atoi(line);
        if (existing > 0 && existing != pid) {
            pids[count++] = existing;
        }
    }
    fclose(f);

    // Rewrite file without this PID
    if (count == 0) {
        // No PIDs left, remove file
        unlink(OVERRIDE_FILE);
    } else {
        f = fopen(OVERRIDE_FILE, "w");
        if (!f) return;

        for (int i = 0; i < count; i++) {
            fprintf(f, "%d\n", pids[i]);
        }
        fclose(f);
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

    // Get total system memory
    struct sysinfo si;
    if (sysinfo(&si) != 0) return 0;

    // totalram is in units of mem_unit, convert to KB
    double total_mem_kb = (si.totalram * si.mem_unit) / 1024.0;

    // vm_rss is already in KB, calculate percentage
    double mem_pct_d = (vm_rss / total_mem_kb) * 100.0;
    int mem_pct = (int)mem_pct_d;

    return mem_pct >= 0 ? mem_pct : 0;
}

// Get process executable path
bool get_process_exe(pid_t pid, char *exe_path, size_t size) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    ssize_t len = readlink(proc_path, exe_path, size - 1);
    if (len == -1) {
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
    (void)user_data;

    gchar *name;
    gint cpu_pct;
    gtk_tree_model_get(model, iter, COL_NAME, &name, COL_CPU, &cpu_pct, -1);

    // Determine color based on CPU load
    const char *color;
    if (cpu_pct >= 70) {
        color = "#ff4444";  // Red (high)
    } else if (cpu_pct >= 30) {
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

        // Get process info
        char name[MAX_PROC_NAME];
        char exe_path[MAX_PATH_LEN];

        if (!get_process_name((pid_t)pid, name, sizeof(name))) continue;
        get_process_exe((pid_t)pid, exe_path, sizeof(exe_path));

        // Get basename of executable
        const char *exe_basename = strrchr(exe_path, '/');
        exe_basename = exe_basename ? exe_basename + 1 : exe_path;

        int cpu_pct = get_process_cpu_usage((pid_t)pid);
        int mem_pct = get_process_mem_usage((pid_t)pid);

        // Find existing entry in hash map
        int pid_int = (int)pid;
        PidRowMap *pid_entry = NULL;
        HASH_FIND_INT(app->pid_row_map, &pid_int, pid_entry);

        if (pid_entry && gtk_tree_row_reference_valid(pid_entry->row_ref)) {
            // UPDATE existing row in place
            GtkTreePath *path = gtk_tree_row_reference_get_path(pid_entry->row_ref);
            GtkTreeIter iter;
            if (gtk_tree_model_get_iter(GTK_TREE_MODEL(app->process_store), &iter, path)) {
                gtk_list_store_set(app->process_store, &iter,
                                  COL_NAME, name,
                                  COL_EXE, exe_basename,
                                  COL_CPU, cpu_pct,
                                  COL_MEM, mem_pct,
                                  -1);
            }
            gtk_tree_path_free(path);
            pid_entry->seen_this_scan = true;
        } else {
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
        strncpy(app->selected_name, name, MAX_PROC_NAME - 1);
        strncpy(app->selected_exe_base, exe, MAX_PATH_LEN - 1);

        // Get the FULL exe path for rule saving (not just basename)
        char full_exe_path[MAX_PATH_LEN];
        if (get_process_exe(pid, full_exe_path, sizeof(full_exe_path))) {
            strncpy(app->selected_exe, full_exe_path, MAX_PATH_LEN - 1);
        } else {
            // Fallback to basename if we can't read the full path
            strncpy(app->selected_exe, exe, MAX_PATH_LEN - 1);
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

// Refresh process list manually
void on_refresh_clicked(GtkButton *button, gpointer data) {
    (void)button;
    update_process_list(data);

    AppData *app = (AppData *)data;
    gtk_label_set_text(GTK_LABEL(app->status_label), "Process list refreshed");
}

// Filter entry changed
void on_filter_changed(GtkEditable *editable, gpointer data) {
    (void)editable;
    AppData *app = (AppData *)data;
    gtk_tree_model_filter_refilter(app->filter_model);
}

// Create main window
GtkWidget* create_main_window(AppData *app) {
    // Main window
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Arch Load Manager");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 900, 600);

    // Set application icon - use icon name for theme integration (works on all DEs)
    // KDE/Wayland looks up icon via app ID matching .desktop file
    // X11/GNOME uses the icon name or falls back to icon list
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "arch-load-manager");

    // For development/uninstalled: load icon directly if theme lookup fails
    if (!gtk_window_get_icon(GTK_WINDOW(app->window))) {
        GError *error = NULL;
        char exe_dir[MAX_PATH_LEN];
        ssize_t len = readlink("/proc/self/exe", exe_dir, sizeof(exe_dir) - 1);

        if (len > 0) {
            exe_dir[len] = '\0';
            char *slash = strrchr(exe_dir, '/');
            if (slash) *slash = '\0';

            char icon_path[MAX_PATH_LEN];
            snprintf(icon_path, sizeof(icon_path), "%s/Arch Load Manager.png", exe_dir);

            GdkPixbuf *icon = gdk_pixbuf_new_from_file(icon_path, &error);
            if (icon) {
                gtk_window_set_icon(GTK_WINDOW(app->window), icon);
                g_object_unref(icon);
            }
            if (error) g_clear_error(&error);
        }
    }

    g_signal_connect(app->window, "destroy", G_CALLBACK(on_window_destroy), NULL);

    // Main vertical box
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    // Search entry
    app->filter_entry = gtk_entry_new();
    gtk_widget_set_name(app->filter_entry, "search-entry");
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->filter_entry),
                                   "Search processes (PID, name, or path)...");
    g_signal_connect(app->filter_entry, "changed",
                    G_CALLBACK(on_filter_changed), app);
    gtk_box_pack_start(GTK_BOX(vbox), app->filter_entry, FALSE, FALSE, 0);

    // Process list (tree view)
    app->process_store = gtk_list_store_new(NUM_COLS,
                                           G_TYPE_INT,     // PID
                                           G_TYPE_STRING,  // Name
                                           G_TYPE_STRING,  // Exe
                                           G_TYPE_INT,     // CPU %
                                           G_TYPE_INT);    // Mem %

    // Create filter model wrapped in a sort model for proper sorting
    GtkTreeModel *base_model = GTK_TREE_MODEL(app->process_store);
    app->filter_model = GTK_TREE_MODEL_FILTER(
        gtk_tree_model_filter_new(base_model, NULL));
    gtk_tree_model_filter_set_visible_func(app->filter_model, filter_func, app, NULL);

    // Wrap filter in sort model to enable column sorting
    GtkTreeModel *sort_model = gtk_tree_model_sort_new_with_model(GTK_TREE_MODEL(app->filter_model));

    app->tree_view = gtk_tree_view_new_with_model(sort_model);

    // Add columns
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;

    // PID column
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("PID", renderer,
                                                       "text", COL_PID, NULL);
    gtk_tree_view_column_set_sort_column_id(column, COL_PID);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->tree_view), column);

    // Name column (with color coding)
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Process Name", renderer,
                                                       "text", COL_NAME, NULL);
    gtk_tree_view_column_set_cell_data_func(column, renderer, cell_data_func_name, app, NULL);
    gtk_tree_view_column_set_sort_column_id(column, COL_NAME);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->tree_view), column);

    // Exe column
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Executable", renderer,
                                                       "text", COL_EXE, NULL);
    gtk_tree_view_column_set_sort_column_id(column, COL_EXE);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->tree_view), column);

    // CPU % column
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("CPU %", renderer,
                                                       "text", COL_CPU, NULL);
    gtk_tree_view_column_set_sort_column_id(column, COL_CPU);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->tree_view), column);

    // Mem % column
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Memory %", renderer,
                                                       "text", COL_MEM, NULL);
    gtk_tree_view_column_set_sort_column_id(column, COL_MEM);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->tree_view), column);

    // Set default sort: CPU % descending (highest CPU usage at top)
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(sort_model),
                                         COL_CPU, GTK_SORT_DESCENDING);

    // Selection signal
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->tree_view));
    gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
    g_signal_connect(selection, "changed", G_CALLBACK(on_selection_changed), app);

    // Scrolled window for tree view
    app->scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(app->scrolled_window),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(app->scrolled_window), app->tree_view);
    gtk_box_pack_start(GTK_BOX(vbox), app->scrolled_window, TRUE, TRUE, 0);

    // Bottom controls
    GtkWidget *controls_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_box_pack_start(GTK_BOX(vbox), controls_box, FALSE, FALSE, 0);

    // CPU affinity checkboxes
    GtkWidget *cpu_frame = gtk_frame_new("CPU Affinity");
    GtkWidget *cpu_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(cpu_box), 8);
    gtk_container_add(GTK_CONTAINER(cpu_frame), cpu_box);

    app->cpu_checks = malloc(sizeof(GtkCheckButton*) * app->ncpus);
    for (int i = 0; i < app->ncpus; i++) {
        char label[16];
        snprintf(label, sizeof(label), "CPU %d", i);
        app->cpu_checks[i] = GTK_CHECK_BUTTON(gtk_check_button_new_with_label(label));
        gtk_box_pack_start(GTK_BOX(cpu_box), GTK_WIDGET(app->cpu_checks[i]),
                          FALSE, FALSE, 0);
    }

    gtk_box_pack_start(GTK_BOX(controls_box), cpu_frame, FALSE, FALSE, 0);

    // Options row
    GtkWidget *options_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    // Priority selection
    GtkWidget *priority_label = gtk_label_new("Priority:");
    gtk_box_pack_start(GTK_BOX(options_box), priority_label, FALSE, FALSE, 0);

    app->priority_combo = gtk_combo_box_text_new();
    for (int i = 0; i <= PRIORITY_REALTIME; i++) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->priority_combo),
                                       priority_name((Priority)i));
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(app->priority_combo), PRIORITY_NORMAL);
    gtk_box_pack_start(GTK_BOX(options_box), app->priority_combo, FALSE, FALSE, 0);

    // Test mode checkbox
    app->test_mode_check = gtk_check_button_new_with_label("Test Mode (don't save)");
    gtk_box_pack_start(GTK_BOX(options_box), app->test_mode_check, FALSE, FALSE, 0);

    // Apply to process family checkbox
    app->apply_children_check = gtk_check_button_new_with_label("Apply to process family");
    gtk_box_pack_start(GTK_BOX(options_box), app->apply_children_check, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(controls_box), options_box, FALSE, FALSE, 0);

    // Rule type selection
    GtkWidget *rule_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *rule_label = gtk_label_new("Save rule by:");
    gtk_box_pack_start(GTK_BOX(rule_box), rule_label, FALSE, FALSE, 0);

    app->exe_radio = gtk_radio_button_new_with_label(NULL, "Executable path");
    gtk_box_pack_start(GTK_BOX(rule_box), app->exe_radio, FALSE, FALSE, 0);

    app->name_radio = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(app->exe_radio), "Process name");
    gtk_box_pack_start(GTK_BOX(rule_box), app->name_radio, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(controls_box), rule_box, FALSE, FALSE, 0);

    // Buttons
    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    GtkWidget *apply_btn = gtk_button_new_with_label("Apply");
    g_signal_connect(apply_btn, "clicked", G_CALLBACK(on_apply_clicked), app);
    gtk_box_pack_start(GTK_BOX(button_box), apply_btn, TRUE, TRUE, 0);

    GtkWidget *refresh_btn = gtk_button_new_with_label("Refresh");
    g_signal_connect(refresh_btn, "clicked", G_CALLBACK(on_refresh_clicked), app);
    gtk_box_pack_start(GTK_BOX(button_box), refresh_btn, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(controls_box), button_box, FALSE, FALSE, 0);

    // Status label
    app->status_label = gtk_label_new("Ready");
    gtk_widget_set_name(app->status_label, "status-label");
    gtk_label_set_xalign(GTK_LABEL(app->status_label), 0.0);
    gtk_box_pack_start(GTK_BOX(vbox), app->status_label, FALSE, FALSE, 0);

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

    // Initialize config
    app.config = config_init();
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

    // Set up timer for automatic updates (every 500ms for faster refresh)
    app.update_timer = g_timeout_add(500, update_process_list, &app);

    // Show window and run
    gtk_widget_show_all(app.window);
    gtk_main();

    // Cleanup
    g_source_remove(app.update_timer);
    config_free(app.config);
    free(app.cpu_checks);

    // Cleanup pid row map
    PidRowMap *entry, *tmp;
    HASH_ITER(hh, app.pid_row_map, entry, tmp) {
        if (entry->row_ref) {
            gtk_tree_row_reference_free(entry->row_ref);
        }
        HASH_DEL(app.pid_row_map, entry);
        free(entry);
    }

    return 0;
}
