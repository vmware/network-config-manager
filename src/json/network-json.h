/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <json-c/json.h>

#include "network.h"
#include "network-util.h"
#include "network-address.h"
#include "network-route.h"

DEFINE_CLEANUP(json_object*, json_object_put);

int json_fill_system_status(char **ret);
int json_fill_one_link(IfNameIndex *p, bool ipv4, json_object **ret);

int json_fill_dns_server(const IfNameIndex *p, char **dns_config, int ifindex);
int json_fill_dns_server_domains(void);

int address_flags_to_string(Address *a, json_object *jobj, uint32_t flags);
int routes_flags_to_string(Route *rt, json_object *jobj, uint32_t flags);

int json_get_dns_mode(DHCPClient mode, bool dhcpv4, bool dhcpv6, bool static_dns);

int json_acquire_and_parse_network_data(json_object **ret);
int json_parse_address_config_source(const json_object *jobj,
                                     const char *link,
                                     const char *address,
                                     char **config_source,
                                     char **config_provider);
