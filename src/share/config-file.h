/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <stdbool.h>

#pragma once

int set_config_file_string(const char *path, const char *section, const char *k, const char *v);
int set_config_file_bool(const char *path, const char *section, const char *k, bool b);
int set_config_file_integer(const char *path, const char *section, const char *k, int v);

int remove_key_from_config_file(const char *path, const char *section, const char *k);
int remove_section_from_config_file(const char *path, const char *section);

int write_to_conf_file_file(const char *path, const GString *s);
int append_to_conf_file(const char *path, const GString *s);
int read_conf_file(const char *path, char **s);

int write_to_resolv_conf_file(char **dns, char **domains);
