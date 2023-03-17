/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <yaml.h>

#include "alloc-util.h"

typedef struct Networks {
    GHashTable *networks;
} Networks;

int networks_new(Networks **ret);
void networks_free(Networks *n);
DEFINE_CLEANUP(Networks*, networks_free);

typedef struct YAMLManager {
        GHashTable *match_config;
        GHashTable *network_config;
        GHashTable *address_config;
        GHashTable *dhcp4_config;
        GHashTable *dhcp6_config;
        GHashTable *nameserver_config;
        GHashTable *route_config;
        GHashTable *routing_policy_rule_config;
        GHashTable *wifi_config;
        GHashTable *link_config;
} YAMLManager;

int yaml_manager_new(YAMLManager **ret);
void yaml_manager_free(YAMLManager *p);

DEFINE_CLEANUP(YAMLManager *, yaml_manager_free);

static inline const char *scalar(const yaml_node_t *node) {
        return (const char*) node->data.scalar.value;
}

int parse_yaml_file(const char *yaml_file, Networks **n);
