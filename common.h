#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

// Version
#define ARCH_LOAD_VERSION "1.0.0"

// Config file location
#define CONFIG_DIR ".config"
#define CONFIG_FILE "cpu_affinity_manager.json"

// Maximum values
#define MAX_CPUS 256
#define MAX_PATH_LEN 4096
#define MAX_PROC_NAME 256

// Priority levels
typedef enum {
    PRIORITY_LOWEST = 0,
    PRIORITY_LOW,
    PRIORITY_NORMAL,
    PRIORITY_HIGH,
    PRIORITY_HIGHEST,
    PRIORITY_REALTIME
} Priority;

// Priority to nice value mapping
static const int priority_to_nice[] = {
    [PRIORITY_LOWEST] = 19,
    [PRIORITY_LOW] = 10,
    [PRIORITY_NORMAL] = 0,
    [PRIORITY_HIGH] = -5,
    [PRIORITY_HIGHEST] = -10,
    [PRIORITY_REALTIME] = -20
};

// Priority names
static const char *priority_names[] = {
    [PRIORITY_LOWEST] = "Lowest",
    [PRIORITY_LOW] = "Low",
    [PRIORITY_NORMAL] = "Normal",
    [PRIORITY_HIGH] = "High",
    [PRIORITY_HIGHEST] = "Highest",
    [PRIORITY_REALTIME] = "Real-time"
};

// Affinity/Priority rule
typedef struct {
    bool has_cpus;           // Whether CPU affinity is set
    uint8_t cpu_count;       // Number of CPUs in affinity
    int cpus[MAX_CPUS];      // CPU affinity list
    bool has_priority;       // Whether priority is set
    Priority priority;       // Priority level
} Rule;

// Process info (for GUI)
typedef struct {
    pid_t pid;
    char name[MAX_PROC_NAME];
    char exe_path[MAX_PATH_LEN];
    double cpu_percent;
    double mem_percent;
} ProcessInfo;

// Helper functions
static inline Priority nice_to_priority(int nice_val) {
    if (nice_val >= 15) return PRIORITY_LOWEST;
    if (nice_val >= 5) return PRIORITY_LOW;
    if (nice_val >= -4) return PRIORITY_NORMAL;
    if (nice_val >= -9) return PRIORITY_HIGH;
    if (nice_val >= -19) return PRIORITY_HIGHEST;
    return PRIORITY_REALTIME;
}

static inline const char* priority_name(Priority p) {
    if (p < 0 || p > PRIORITY_REALTIME) return "Unknown";
    return priority_names[p];
}

static inline int priority_nice(Priority p) {
    if (p < 0 || p > PRIORITY_REALTIME) return 0;
    return priority_to_nice[p];
}

// Get config file path (caller must free)
char* get_config_path(void);

#endif // COMMON_H
