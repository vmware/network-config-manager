/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdbool.h>

#pragma once

#include "macros.h"
#include "string-util.h"

typedef struct Config {
        const char *ctl_name;
        const char *config;
} Config;

typedef struct ConfigManager {
        GHashTable *ctl_to_config_table;
} ConfigManager;

int config_manager_new(const Config *configs, ConfigManager **ret);
void config_manager_unref(ConfigManager *m);
const char *ctl_to_config(const ConfigManager *m, const char *name);

int set_config_file_string(const char *path, const char *section, const char *k, const char *v);
int set_config_file_bool(const char *path, const char *section, const char *k, bool b);
int set_config_file_integer(const char *path, const char *section, const char *k, int v);

int remove_key_from_config_file(const char *path, const char *section, const char *k);
int remove_section_from_config_file(const char *path, const char *section);
int remove_config_files_glob(const char *path, const char *section, const char *k, const char *v);
int remove_config_files_section_glob(const char *path, const char *section, const char *k, const char *v);

int write_to_conf_file_file(const char *path, const GString *s);
int append_to_conf_file(const char *path, const GString *s);
int write_to_proxy_conf_file(GHashTable *table);

int read_conf_file(const char *path, char **s);

int write_to_resolv_conf_file(char **dns, char **domains);
