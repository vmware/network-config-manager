/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include <stdint.h>

int parse_integer(const char *c, int *val);
int parse_uint32(const char *c, unsigned *val);
int parse_uint16(const char *c, uint16_t *val);
int parse_boolean(const char *v);
