/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <glib.h>

#include "macros.h"
#include "string-util.h"

typedef struct Config {
        const char *ctl_name;
        const char *config;
} Config;

typedef struct ConfigManager {
        GHashTable *ctl_to_config_table;
} ConfigManager;

typedef struct Key {
        char *name;
        char *v;
} Key;

typedef struct Section {
        char *name;

        GList *keys;
} Section;

typedef struct KeyFile {
        size_t nsections;
        char *name;

        GList *sections;
} KeyFile;

int key_new(const char *key, const char *value, Key **ret);
void key_free(void *k);
DEFINE_CLEANUP(Key*, key_free);

int section_new(const char *name, Section **ret);
void section_free(void *s);
DEFINE_CLEANUP(Section*, section_free);

int key_file_new(const char *file_name, KeyFile **ret);
void key_file_free(KeyFile *k);
DEFINE_CLEANUP(KeyFile*, key_file_free);

int config_manager_new(const Config *configs, ConfigManager **ret);
void config_manager_free(ConfigManager *m);
DEFINE_CLEANUP(ConfigManager*, config_manager_free);

int set_config(KeyFile *key_file, const char *section, const char *k, const char *v);
int set_config_uint(KeyFile *key_file, const char *section, const char *k, uint v);

int add_key_to_section(Section *s, const char *k, const char *v);
int add_key_to_section_int(Section *s, const char *k, int v);
int add_key_to_section_uint(Section *s, const char *k, uint v);

int add_section_to_key_file(KeyFile *k, Section *s);

const char *ctl_to_config(const ConfigManager *m, const char *name);

int set_config_file_str(const char *path, const char *section, const char *k, const char *v);
int set_config_file_bool(const char *path, const char *section, const char *k, bool b);
int set_config_file_int(const char *path, const char *section, const char *k, int v);

int add_config_file_str(const char *path, const char *section, const char *k, const char *v);

int key_file_set_str(KeyFile *key_file, const char *section, const char *k, const char *v);
int key_file_set_uint(KeyFile *key_file, const char *section, const char *k, const uint v);
int key_file_set_bool(KeyFile *key_file, const char *section, const char *k, const bool b);

int key_file_parse_str(KeyFile *key_file, const char *section, const char *k, char **v);
int key_file_parse_int(KeyFile *key_file, const char *section, const char *k, unsigned *v);

int key_file_add_str(KeyFile *key_file, const char *section, const char *k, const char *v);
int add_key_to_section_str(const char *path, const char *section, const char *k, const char *v);

int remove_key_from_config_file(const char *path, const char *section, const char *k);
int remove_key_value_from_config_file(const char *path, const char *section, const char *k, const char *v);

int remove_section_from_config_file(const char *path, const char *section);
int remove_section_from_config_file_key(const char *path, const char *section, const char *k, const char *v);

int remove_config_files_glob(const char *path, const char *section, const char *k, const char *v);
int remove_config_files_section_glob(const char *path, const char *section, const char *k, const char *v);

int write_to_conf_file_file(const char *path, const GString *s);
int append_to_conf_file(const char *path, const GString *s);
int write_to_proxy_conf_file(GHashTable *table);

int read_conf_file(const char *path, char **s);

int write_to_resolv_conf_file(char **dns, char **domains);

int key_file_save(KeyFile *k);

int determine_conf_file_name(const char *ifname, char **ret);
