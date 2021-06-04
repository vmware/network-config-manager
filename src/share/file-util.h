/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <glob.h>

int safe_mkdir_p_dir(const char* file_path) ;

int set_file_permisssion(const char *path, const char *user);
int create_conf_file(const char *path, const char *ifname, const char *extension, char **ret);
int write_to_conf_file(const char *path, const GString *s);

int read_one_line(const char *path, char **v);
int write_one_line(const char *path, const char *v);

int glob_files(const char *path, int flags, glob_t *ret);
