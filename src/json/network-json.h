/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <json-c/json.h>

#include "network-util.h"
#include "network-address.h"
#include "network-route.h"

DEFINE_CLEANUP(json_object*, json_object_put);

int json_fill_system_status(char **ret);
int json_fill_one_link(IfNameIndex *p, bool ipv4, json_object **ret);

int json_fill_dns_server(const IfNameIndex *p, char *dns_config, int ifindex);
int json_fill_dns_server_domains(void);

int address_flags_to_string(Address *a, json_object *jobj, uint32_t flags);
int routes_flags_to_string(Route *rt, json_object *jobj, uint32_t flags);
