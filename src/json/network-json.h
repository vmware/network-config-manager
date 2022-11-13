/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "network-util.h"

int json_system_status(char **ret);
int json_list_one_link(IfNameIndex *p, char **ret);

int json_show_dns_server(void);
int json_show_dns_server_domains(void);
