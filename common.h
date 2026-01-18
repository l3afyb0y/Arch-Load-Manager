#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#include <sys/syscall.h>
#include <unistd.h>

// IO Priority definitions
#define IOPRIO_CLASS_SHIFT 13
#define IOPRIO_PRIO_VALUE(class, data) (((class) << IOPRIO_CLASS_SHIFT) | (data))
#define IOPRIO_WHO_PROCESS 1

static inline int ioprio_set(int which, int who, int ioprio) {
    return syscall(SYS_ioprio_set, which, who, ioprio);
}

// Version
#define ARCH_LOAD_VERSION "2.1.0"

// Config file location
#define CONFIG_DIR ".config"
#define CONFIG_FILE "arch-load-manager.json"

// Maximum values
#define MAX_CPUS 1024
#define MAX_PATH_LEN 4096
#define MAX_PROC_NAME 256
#define MAX_IRQS 1024

// Priority levels
typedef enum {
    PRIORITY_LOWEST = 0,
    PRIORITY_LOW,
    PRIORITY_NORMAL,
    PRIORITY_HIGH,
    PRIORITY_HIGHEST,
    PRIORITY_REALTIME
} Priority;

// Scheduler policies
typedef enum {
    SCHED_POL_DEFAULT = 0,
    SCHED_POL_BATCH,
    SCHED_POL_IDLE,
    SCHED_POL_FIFO,
    SCHED_POL_RR
} SchedPolicy;

// IO Priorities
typedef enum {
    IOPRIO_CLASS_NONE = 0,
    IOPRIO_CLASS_RT,
    IOPRIO_CLASS_BE,
    IOPRIO_CLASS_IDLE
} IOPrioClass;

// Priority names
extern const char *priority_names[];

// Priority to nice value mapping
extern const int priority_to_nice[];

// ProBalance Settings
typedef struct {
    bool enabled;
    int cpu_threshold;      // CPU % to trigger suppression
    int suppression_nice;   // Nice value to add when suppressed
    int duration_ms;        // How long above threshold before acting
    bool ignore_foreground; // Don't suppress foreground apps (if detectable)
} ProBalanceSettings;

// IRQ Rule
typedef struct {
    int irq_id;
    char device_name[128];
    bool has_affinity;
    uint16_t cpu_count;
    int cpus[MAX_CPUS];
} IrqRule;

// Affinity/Priority rule for processes
typedef struct {
    bool has_cpus;           // Whether CPU affinity is set
    uint16_t cpu_count;      // Number of CPUs in affinity
    int cpus[MAX_CPUS];      // CPU affinity list
    bool has_priority;       // Whether priority is set
    Priority priority;       // Priority level
    bool has_sched_policy;
    SchedPolicy sched_policy;
    bool has_ioprio;
    IOPrioClass ioprio_class;
    int ioprio_level;        // 0-7
    bool exclude_probalance; // Don't let ProBalance touch this process
} Rule;

// Helper functions
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

// Override file for test mode
#define OVERRIDE_FILE "/tmp/.arch-load-manager-override"

#endif // COMMON_H
