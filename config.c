#define _GNU_SOURCE
#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <json-c/json.h>

// Priority names
const char *priority_names[] = {
    [PRIORITY_LOWEST] = "Lowest",
    [PRIORITY_LOW] = "Low",
    [PRIORITY_NORMAL] = "Normal",
    [PRIORITY_HIGH] = "High",
    [PRIORITY_HIGHEST] = "Highest",
    [PRIORITY_REALTIME] = "Real-time"
};

// Priority to nice value mapping
const int priority_to_nice[] = {
    [PRIORITY_LOWEST] = 19,
    [PRIORITY_LOW] = 10,
    [PRIORITY_NORMAL] = 0,
    [PRIORITY_HIGH] = -5,
    [PRIORITY_HIGHEST] = -10,
    [PRIORITY_REALTIME] = -20
};

// Get config file path
char* get_config_path(void) {
    // Check if system-wide config exists first if we are root
    if (getuid() == 0) {
        const char *etc_path = "/etc/arch-load-manager.json";
        if (access(etc_path, F_OK) == 0) {
            return strdup(etc_path);
        }
    }

    const char *home = getenv("HOME");
    const char *xdg_config = getenv("XDG_CONFIG_HOME");
    
    char *path = malloc(MAX_PATH_LEN);
    if (!path) return NULL;

    if (xdg_config && xdg_config[0] != '\0') {
        snprintf(path, MAX_PATH_LEN, "%s/%s", xdg_config, CONFIG_FILE);
    } else if (home) {
        snprintf(path, MAX_PATH_LEN, "%s/%s/%s", home, CONFIG_DIR, CONFIG_FILE);
    } else {
        free(path);
        return NULL;
    }
    
    // If user config doesn't exist but etc does, use etc as fallback
    if (access(path, F_OK) != 0) {
        const char *etc_path = "/etc/arch-load-manager.json";
        if (access(etc_path, F_OK) == 0) {
            free(path);
            return strdup(etc_path);
        }
    }

    return path;
}

// Initialize config
Config* config_init(const char *override_path) {
    Config *cfg = calloc(1, sizeof(Config));
    if (!cfg) return NULL;

    if (override_path) {
        cfg->config_path = strdup(override_path);
    } else {
        cfg->config_path = get_config_path();
    }

    if (!cfg->config_path) {
        free(cfg);
        return NULL;
    }

    cfg->exe_rules = NULL;
    cfg->name_rules = NULL;
    cfg->irq_rules = NULL;
    cfg->last_mtime = 0;

    // Default ProBalance settings
    cfg->probalance.enabled = true;
    cfg->probalance.cpu_threshold = 20;
    cfg->probalance.suppression_nice = 5;
    cfg->probalance.duration_ms = 3000;
    cfg->probalance.ignore_foreground = true;

    return cfg;
}

// Free config
void config_free(Config *cfg) {
    if (!cfg) return;

    // Free exe rules
    RuleEntry *entry, *tmp;
    HASH_ITER(hh, cfg->exe_rules, entry, tmp) {
        HASH_DEL(cfg->exe_rules, entry);
        free(entry);
    }

    // Free name rules
    HASH_ITER(hh, cfg->name_rules, entry, tmp) {
        HASH_DEL(cfg->name_rules, entry);
        free(entry);
    }

    // Free IRQ rules
    IrqRuleEntry *irq_entry, *irq_tmp;
    HASH_ITER(hh, cfg->irq_rules, irq_entry, irq_tmp) {
        HASH_DEL(cfg->irq_rules, irq_entry);
        free(irq_entry);
    }

    free(cfg->config_path);
    free(cfg);
}

// Parse rule from JSON object
static bool parse_rule(struct json_object *json, Rule *rule) {
    memset(rule, 0, sizeof(Rule));

    // Parse CPUs
    struct json_object *cpus = NULL;
    if (json_object_object_get_ex(json, "cpus", &cpus) &&
        json_object_is_type(cpus, json_type_array)) {
        rule->has_cpus = true;
        rule->cpu_count = 0;

        int array_len = json_object_array_length(cpus);
        for (int i = 0; i < array_len && rule->cpu_count < MAX_CPUS; i++) {
            struct json_object *cpu_obj = json_object_array_get_idx(cpus, i);
            if (json_object_is_type(cpu_obj, json_type_int)) {
                int cpu_id = json_object_get_int(cpu_obj);
                if (cpu_id >= 0 && cpu_id < MAX_CPUS) {
                    rule->cpus[rule->cpu_count++] = cpu_id;
                }
            }
        }
    }

    // Parse priority
    struct json_object *priority = NULL;
    if (json_object_object_get_ex(json, "priority", &priority) &&
        json_object_is_type(priority, json_type_string)) {
        const char *prio_str = json_object_get_string(priority);
        rule->has_priority = true;

        // Match priority string
        for (int i = 0; i <= PRIORITY_REALTIME; i++) {
            if (strcmp(prio_str, priority_names[i]) == 0) {
                rule->priority = i;
                break;
            }
        }
    }

    // Parse scheduler policy
    struct json_object *sched = NULL;
    if (json_object_object_get_ex(json, "sched_policy", &sched) &&
        json_object_is_type(sched, json_type_string)) {
        const char *s = json_object_get_string(sched);
        rule->has_sched_policy = true;
        if (strcmp(s, "batch") == 0) rule->sched_policy = SCHED_POL_BATCH;
        else if (strcmp(s, "idle") == 0) rule->sched_policy = SCHED_POL_IDLE;
        else if (strcmp(s, "fifo") == 0) rule->sched_policy = SCHED_POL_FIFO;
        else if (strcmp(s, "rr") == 0) rule->sched_policy = SCHED_POL_RR;
        else rule->sched_policy = SCHED_POL_DEFAULT;
    }

    // Parse IO priority
    struct json_object *ioprio = NULL;
    if (json_object_object_get_ex(json, "ioprio", &ioprio) &&
        json_object_is_type(ioprio, json_type_object)) {
        rule->has_ioprio = true;
        struct json_object *class_obj, *level_obj;
        if (json_object_object_get_ex(ioprio, "class", &class_obj)) {
            const char *c = json_object_get_string(class_obj);
            if (strcmp(c, "rt") == 0) rule->ioprio_class = IOPRIO_CLASS_RT;
            else if (strcmp(c, "be") == 0) rule->ioprio_class = IOPRIO_CLASS_BE;
            else if (strcmp(c, "idle") == 0) rule->ioprio_class = IOPRIO_CLASS_IDLE;
            else rule->ioprio_class = IOPRIO_CLASS_NONE;
        }
        if (json_object_object_get_ex(ioprio, "level", &level_obj)) {
            rule->ioprio_level = json_object_get_int(level_obj);
        }
    }

    // Parse ProBalance exclusion
    struct json_object *exclude = NULL;
    if (json_object_object_get_ex(json, "exclude_probalance", &exclude)) {
        rule->exclude_probalance = json_object_get_boolean(exclude);
    }

    return rule->has_cpus || rule->has_priority || rule->has_sched_policy || rule->has_ioprio;
}

// Parse IRQ rule from JSON object
static bool parse_irq_rule(struct json_object *json, IrqRule *rule) {
    memset(rule, 0, sizeof(IrqRule));

    struct json_object *cpus = NULL;
    if (json_object_object_get_ex(json, "cpus", &cpus) &&
        json_object_is_type(cpus, json_type_array)) {
        rule->has_affinity = true;
        rule->cpu_count = 0;

        int array_len = json_object_array_length(cpus);
        for (int i = 0; i < array_len && rule->cpu_count < MAX_CPUS; i++) {
            struct json_object *cpu_obj = json_object_array_get_idx(cpus, i);
            if (json_object_is_type(cpu_obj, json_type_int)) {
                int cpu_id = json_object_get_int(cpu_obj);
                if (cpu_id >= 0 && cpu_id < MAX_CPUS) {
                    rule->cpus[rule->cpu_count++] = cpu_id;
                }
            }
        }
    }

    struct json_object *dev = NULL;
    if (json_object_object_get_ex(json, "device", &dev)) {
        strncpy(rule->device_name, json_object_get_string(dev), sizeof(rule->device_name) - 1);
    }

    return rule->has_affinity;
}

static const char* sched_policy_to_string(SchedPolicy policy) {
    switch (policy) {
        case SCHED_POL_BATCH: return "batch";
        case SCHED_POL_IDLE: return "idle";
        case SCHED_POL_FIFO: return "fifo";
        case SCHED_POL_RR: return "rr";
        default: return "default";
    }
}

static struct json_object* serialize_rule(const Rule *rule) {
    struct json_object *rule_obj = json_object_new_object();
    if (!rule_obj) {
        return NULL;
    }

    if (rule->has_cpus) {
        struct json_object *cpus_arr = json_object_new_array();
        for (int i = 0; i < rule->cpu_count; i++) {
            json_object_array_add(cpus_arr, json_object_new_int(rule->cpus[i]));
        }
        json_object_object_add(rule_obj, "cpus", cpus_arr);
    }

    if (rule->has_priority) {
        json_object_object_add(rule_obj, "priority",
                               json_object_new_string(priority_name(rule->priority)));
    }

    if (rule->has_sched_policy) {
        json_object_object_add(rule_obj, "sched_policy",
                               json_object_new_string(sched_policy_to_string(rule->sched_policy)));
    }

    if (rule->has_ioprio) {
        struct json_object *io_obj = json_object_new_object();
        const char *c = "none";
        if (rule->ioprio_class == IOPRIO_CLASS_RT) c = "rt";
        else if (rule->ioprio_class == IOPRIO_CLASS_BE) c = "be";
        else if (rule->ioprio_class == IOPRIO_CLASS_IDLE) c = "idle";
        json_object_object_add(io_obj, "class", json_object_new_string(c));
        json_object_object_add(io_obj, "level", json_object_new_int(rule->ioprio_level));
        json_object_object_add(rule_obj, "ioprio", io_obj);
    }

    if (rule->exclude_probalance) {
        json_object_object_add(rule_obj, "exclude_probalance", json_object_new_boolean(true));
    }

    return rule_obj;
}

// Load rules from JSON file
bool config_load(Config *cfg) {
    if (!cfg || !cfg->config_path) return false;

    // Check if file exists
    struct stat st;
    if (stat(cfg->config_path, &st) != 0) {
        return false;  // File doesn't exist yet
    }

    cfg->last_mtime = st.st_mtime;

    // Parse JSON
    struct json_object *root = json_object_from_file(cfg->config_path);
    if (!root) return false;

    // Parse ProBalance settings
    struct json_object *pb_obj = NULL;
    if (json_object_object_get_ex(root, "probalance", &pb_obj)) {
        struct json_object *enabled, *threshold, *suppression, *duration, *ignore_fg;
        if (json_object_object_get_ex(pb_obj, "enabled", &enabled))
            cfg->probalance.enabled = json_object_get_boolean(enabled);
        if (json_object_object_get_ex(pb_obj, "cpu_threshold", &threshold))
            cfg->probalance.cpu_threshold = json_object_get_int(threshold);
        if (json_object_object_get_ex(pb_obj, "suppression_nice", &suppression))
            cfg->probalance.suppression_nice = json_object_get_int(suppression);
        if (json_object_object_get_ex(pb_obj, "duration_ms", &duration))
            cfg->probalance.duration_ms = json_object_get_int(duration);
        if (json_object_object_get_ex(pb_obj, "ignore_foreground", &ignore_fg))
            cfg->probalance.ignore_foreground = json_object_get_boolean(ignore_fg);
    }

    // Parse exe rules
    struct json_object *exe_obj = NULL;
    if (json_object_object_get_ex(root, "exe", &exe_obj) &&
        json_object_is_type(exe_obj, json_type_object)) {

        json_object_object_foreach(exe_obj, key, val) {
            if (json_object_is_type(val, json_type_object)) {
                Rule rule;
                if (parse_rule(val, &rule)) {
                    config_set_rule(cfg, key, true, &rule);
                }
            }
        }
    }

    // Parse name rules
    struct json_object *name_obj = NULL;
    if (json_object_object_get_ex(root, "name", &name_obj) &&
        json_object_is_type(name_obj, json_type_object)) {

        json_object_object_foreach(name_obj, key, val) {
            if (json_object_is_type(val, json_type_object)) {
                Rule rule;
                if (parse_rule(val, &rule)) {
                    config_set_rule(cfg, key, false, &rule);
                }
            }
        }
    }

    // Parse IRQ rules
    struct json_object *irqs_obj = NULL;
    if (json_object_object_get_ex(root, "irqs", &irqs_obj) &&
        json_object_is_type(irqs_obj, json_type_object)) {

        json_object_object_foreach(irqs_obj, irq_key, val) {
            if (json_object_is_type(val, json_type_object)) {
                IrqRule rule;
                if (parse_irq_rule(val, &rule)) {
                    rule.irq_id = atoi(irq_key);
                    config_set_irq_rule(cfg, rule.irq_id, &rule);
                }
            }
        }
    }

    json_object_put(root);
    return true;
}

// Add or update an IRQ rule
void config_set_irq_rule(Config *cfg, int irq_id, const IrqRule *rule) {
    if (!cfg || !rule) return;

    IrqRuleEntry *entry = NULL;
    HASH_FIND_INT(cfg->irq_rules, &irq_id, entry);

    if (entry) {
        entry->rule = *rule;
    } else {
        entry = malloc(sizeof(IrqRuleEntry));
        if (!entry) return;
        entry->irq_id = irq_id;
        entry->rule = *rule;
        HASH_ADD_INT(cfg->irq_rules, irq_id, entry);
    }
}

// Get IRQ rule
const IrqRule* config_get_irq_rule(Config *cfg, int irq_id) {
    if (!cfg) return NULL;
    IrqRuleEntry *entry = NULL;
    HASH_FIND_INT(cfg->irq_rules, &irq_id, entry);
    return entry ? &entry->rule : NULL;
}

// Save rules to JSON file
bool config_save(Config *cfg) {
    if (!cfg || !cfg->config_path) return false;

    // Create config directory if needed
    const char *home = getenv("HOME");
    if (!home) return false;

    char dir_path[MAX_PATH_LEN];
    snprintf(dir_path, MAX_PATH_LEN, "%s/%s", home, CONFIG_DIR);
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
        return false;
    }

    // Create JSON
    struct json_object *root = json_object_new_object();
    
    // ProBalance settings
    struct json_object *pb_obj = json_object_new_object();
    json_object_object_add(pb_obj, "enabled", json_object_new_boolean(cfg->probalance.enabled));
    json_object_object_add(pb_obj, "cpu_threshold", json_object_new_int(cfg->probalance.cpu_threshold));
    json_object_object_add(pb_obj, "suppression_nice", json_object_new_int(cfg->probalance.suppression_nice));
    json_object_object_add(pb_obj, "duration_ms", json_object_new_int(cfg->probalance.duration_ms));
    json_object_object_add(pb_obj, "ignore_foreground", json_object_new_boolean(cfg->probalance.ignore_foreground));
    json_object_object_add(root, "probalance", pb_obj);

    struct json_object *exe_obj = json_object_new_object();
    struct json_object *name_obj = json_object_new_object();

    // Add exe rules
    RuleEntry *entry;
    for (entry = cfg->exe_rules; entry != NULL; entry = entry->hh.next) {
        struct json_object *rule_obj = serialize_rule(&entry->rule);
        if (rule_obj) {
            json_object_object_add(exe_obj, entry->key, rule_obj);
        }
    }

    // Add name rules
    for (entry = cfg->name_rules; entry != NULL; entry = entry->hh.next) {
        struct json_object *rule_obj = serialize_rule(&entry->rule);
        if (rule_obj) {
            json_object_object_add(name_obj, entry->key, rule_obj);
        }
    }

    json_object_object_add(root, "exe", exe_obj);
    json_object_object_add(root, "name", name_obj);

    // Add IRQ rules
    struct json_object *irqs_obj = json_object_new_object();
    IrqRuleEntry *irq_entry;
    for (irq_entry = cfg->irq_rules; irq_entry != NULL; irq_entry = irq_entry->hh.next) {
        struct json_object *rule_obj = json_object_new_object();
        if (irq_entry->rule.has_affinity) {
            struct json_object *cpus_arr = json_object_new_array();
            for (int i = 0; i < irq_entry->rule.cpu_count; i++) {
                json_object_array_add(cpus_arr, json_object_new_int(irq_entry->rule.cpus[i]));
            }
            json_object_object_add(rule_obj, "cpus", cpus_arr);
        }
        json_object_object_add(rule_obj, "device", json_object_new_string(irq_entry->rule.device_name));
        char irq_id_str[16];
        snprintf(irq_id_str, sizeof(irq_id_str), "%d", irq_entry->irq_id);
        json_object_object_add(irqs_obj, irq_id_str, rule_obj);
    }
    json_object_object_add(root, "irqs", irqs_obj);

    // Write to file
    if (json_object_to_file_ext(cfg->config_path, root,
        JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED) != 0) {
        json_object_put(root);
        return false;
    }

    json_object_put(root);

    // Update mtime
    struct stat st;
    if (stat(cfg->config_path, &st) == 0) {
        cfg->last_mtime = st.st_mtime;
    }

    return true;
}

// Add or update a rule
void config_set_rule(Config *cfg, const char *key, bool is_exe, const Rule *rule) {
    if (!cfg || !key || !rule) return;

    RuleEntry **table = is_exe ? &cfg->exe_rules : &cfg->name_rules;

    // Find existing entry
    RuleEntry *entry = NULL;
    HASH_FIND_STR(*table, key, entry);

    if (entry) {
        // Update existing
        entry->rule = *rule;
    } else {
        // Create new
        entry = malloc(sizeof(RuleEntry));
        if (!entry) return;

        strncpy(entry->key, key, MAX_PATH_LEN - 1);
        entry->key[MAX_PATH_LEN - 1] = 0;
        entry->rule = *rule;

        HASH_ADD_STR(*table, key, entry);
    }
}

// Remove a rule
void config_remove_rule(Config *cfg, const char *key, bool is_exe) {
    if (!cfg || !key) return;

    RuleEntry **table = is_exe ? &cfg->exe_rules : &cfg->name_rules;
    RuleEntry *entry = NULL;
    HASH_FIND_STR(*table, key, entry);

    if (entry) {
        HASH_DEL(*table, entry);
        free(entry);
    }
}

// Get rule by exe path
const Rule* config_get_rule_by_exe(Config *cfg, const char *exe_path) {
    if (!cfg || !exe_path) return NULL;

    RuleEntry *entry = NULL;
    HASH_FIND_STR(cfg->exe_rules, exe_path, entry);

    return entry ? &entry->rule : NULL;
}

// Get rule by process name
const Rule* config_get_rule_by_name(Config *cfg, const char *name) {
    if (!cfg || !name) return NULL;

    RuleEntry *entry = NULL;
    HASH_FIND_STR(cfg->name_rules, name, entry);

    return entry ? &entry->rule : NULL;
}
