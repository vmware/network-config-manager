/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include <glib.h>

int load_config_file(const char *path, GKeyFile **ret);

int parse_line(const char *line, char **key, char **value);
int parse_state_file(const char *path, const char *key, char **ret);
int parse_config_file(const char *path, const char *section, const char *key, char **ret);
int parse_config_file_integer(const char *path, const char *section, const char *k, unsigned *ret);
int parse_resolv_conf(char ***dns, char ***domains);

static inline void key_file_free(GKeyFile **f) {
        if (f && *f)
                g_key_file_free(*f);
}
