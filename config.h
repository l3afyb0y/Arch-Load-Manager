#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include <uthash.h>  // For hash table

// Hash table entry for rules
typedef struct RuleEntry {
    char key[MAX_PATH_LEN];  // exe path or process name
    Rule rule;
    UT_hash_handle hh;       // Makes this hashable
} RuleEntry;

// Config manager
typedef struct {
    RuleEntry *exe_rules;    // Rules by exe path
    RuleEntry *name_rules;   // Rules by process name
    char *config_path;       // Path to config file
    time_t last_mtime;       // Last modification time
} Config;

// Initialize config
Config* config_init(void);

// Free config
void config_free(Config *cfg);

// Load rules from JSON file
bool config_load(Config *cfg);

// Save rules to JSON file
bool config_save(Config *cfg);

// Add or update a rule
void config_set_rule(Config *cfg, const char *key, bool is_exe, const Rule *rule);

// Get rule by exe path
const Rule* config_get_rule_by_exe(Config *cfg, const char *exe_path);

// Get rule by process name
const Rule* config_get_rule_by_name(Config *cfg, const char *name);

// Remove a rule
void config_remove_rule(Config *cfg, const char *key, bool is_exe);

// Check if config file has been modified
bool config_has_changed(Config *cfg);

#endif // CONFIG_H
