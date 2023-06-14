/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

void set_json(bool k);
void set_beautify(bool k);
void set_log(bool k, int size);

bool json_enabled(void);
bool beautify_enabled(void);
bool log_enabled(void);

int get_log_line(void);
