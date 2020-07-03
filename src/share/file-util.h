/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

int safe_mkdir_p_dir(const char* file_path) ;

int set_file_permisssion(const char *path, const char *user);
int create_conf_file(const char *path, const char *ifname, const char *extension, char **ret);

int read_one_line(const char *path, char **v);
int write_one_line(const char *path, const char *v);
