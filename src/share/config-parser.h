/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <glib.h>

#include "config-file.h"

static inline void gkey_file_freep(GKeyFile **f) {
        if (f && *f)
                g_key_file_free(*f);
}

int load_config_file(const char *path, KeyFile **ret);

int parse_line(const char *line, char **key, char **value);
int parse_state_file(const char *path, const char *key, char **v, GHashTable **table);

int parse_key_file(const char *path, KeyFile **ret);
int display_key_file(const KeyFile *k);

bool config_exists(const char *path, const char *section, const char *k, const char *v);
bool config_contains(const char *path, const char *section, const char *k, const char *v);
bool key_file_config_exists(const KeyFile *kf, const char *s, const char *k, const char *v);
bool key_file_config_contains(const KeyFile *kf, const char *s, const char *k, const char *v);
char *key_file_config_get(const KeyFile *key_file, const char *section, const char *k);

int parse_config_file(const char *path, const char *section, const char *key, char **ret);
int parse_config_file_integer(const char *path, const char *section, const char *k, unsigned *ret);
int parse_resolv_conf(char ***dns, char ***domains);

int key_file_parse_strv(const char *path, const char *section, const char *key, char ***ret);

int key_file_network_parse_dns(const char *path, char ***ret);
int key_file_network_parse_search_domains(const char *path, char ***ret);
int key_file_network_parse_ntp(const char *path, char ***ret);
