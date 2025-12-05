#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <json-c/json.h>

// Get config file path
char* get_config_path(void) {
    const char *home = getenv("HOME");
    if (!home) return NULL;

    char *path = malloc(MAX_PATH_LEN);
    if (!path) return NULL;

    snprintf(path, MAX_PATH_LEN, "%s/%s/%s", home, CONFIG_DIR, CONFIG_FILE);
    return path;
}

// Initialize config
Config* config_init(void) {
    Config *cfg = calloc(1, sizeof(Config));
    if (!cfg) return NULL;

    cfg->config_path = get_config_path();
    if (!cfg->config_path) {
        free(cfg);
        return NULL;
    }

    cfg->exe_rules = NULL;
    cfg->name_rules = NULL;
    cfg->last_mtime = 0;

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

    return rule->has_cpus || rule->has_priority;
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

    // Read file
    FILE *f = fopen(cfg->config_path, "r");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *json_str = malloc(fsize + 1);
    if (!json_str) {
        fclose(f);
        return false;
    }

    fread(json_str, 1, fsize, f);
    fclose(f);
    json_str[fsize] = 0;

    // Parse JSON
    struct json_object *root = json_tokener_parse(json_str);
    free(json_str);

    if (!root) return false;

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

    json_object_put(root);
    return true;
}

// Save rules to JSON file
bool config_save(Config *cfg) {
    if (!cfg || !cfg->config_path) return false;

    // Create config directory if needed
    const char *home = getenv("HOME");
    if (!home) return false;

    char dir_path[MAX_PATH_LEN];
    snprintf(dir_path, MAX_PATH_LEN, "%s/%s", home, CONFIG_DIR);
    mkdir(dir_path, 0755);

    // Create JSON
    struct json_object *root = json_object_new_object();
    struct json_object *exe_obj = json_object_new_object();
    struct json_object *name_obj = json_object_new_object();

    // Add exe rules
    RuleEntry *entry;
    for (entry = cfg->exe_rules; entry != NULL; entry = entry->hh.next) {
        struct json_object *rule_obj = json_object_new_object();

        if (entry->rule.has_cpus) {
            struct json_object *cpus_arr = json_object_new_array();
            for (int i = 0; i < entry->rule.cpu_count; i++) {
                json_object_array_add(cpus_arr,
                    json_object_new_int(entry->rule.cpus[i]));
            }
            json_object_object_add(rule_obj, "cpus", cpus_arr);
        }

        if (entry->rule.has_priority) {
            json_object_object_add(rule_obj, "priority",
                json_object_new_string(priority_name(entry->rule.priority)));
        }

        json_object_object_add(rule_obj, "mode",
            json_object_new_string("active"));
        json_object_object_add(exe_obj, entry->key, rule_obj);
    }

    // Add name rules
    for (entry = cfg->name_rules; entry != NULL; entry = entry->hh.next) {
        struct json_object *rule_obj = json_object_new_object();

        if (entry->rule.has_cpus) {
            struct json_object *cpus_arr = json_object_new_array();
            for (int i = 0; i < entry->rule.cpu_count; i++) {
                json_object_array_add(cpus_arr,
                    json_object_new_int(entry->rule.cpus[i]));
            }
            json_object_object_add(rule_obj, "cpus", cpus_arr);
        }

        if (entry->rule.has_priority) {
            json_object_object_add(rule_obj, "priority",
                json_object_new_string(priority_name(entry->rule.priority)));
        }

        json_object_object_add(rule_obj, "mode",
            json_object_new_string("active"));
        json_object_object_add(name_obj, entry->key, rule_obj);
    }

    json_object_object_add(root, "exe", exe_obj);
    json_object_object_add(root, "name", name_obj);

    // Write to file
    const char *json_str = json_object_to_json_string_ext(root,
        JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);

    if (!json_str) {
        json_object_put(root);
        return false;
    }

    FILE *f = fopen(cfg->config_path, "w");
    if (!f) {
        json_object_put(root);
        return false;
    }

    fputs(json_str, f);
    fclose(f);
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

// Check if config file has been modified
bool config_has_changed(Config *cfg) {
    if (!cfg || !cfg->config_path) return false;

    struct stat st;
    if (stat(cfg->config_path, &st) != 0) {
        return false;
    }

    return st.st_mtime > cfg->last_mtime;
}
