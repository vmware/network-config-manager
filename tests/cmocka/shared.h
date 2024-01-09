/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

int link_add(const char *s);
int link_remove (const char *s);

int reload_networkd (const char *s);

int apply_yaml_file(const char *y);
