/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <json-c/json.h>

#include "network-util.h"

DEFINE_CLEANUP(json_object*, json_object_put);

int json_system_status(char **ret);
int json_list_one_link(IfNameIndex *p, char **ret);

int json_show_dns_server(const IfNameIndex *p, char *dns_config);
int json_show_dns_server_domains(void);
