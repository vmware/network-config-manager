/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "netdev-link.h"

int parse_yaml_link_file(const char *yaml_file, NetDevLink **ret);
