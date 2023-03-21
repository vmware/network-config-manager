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
        GHashTable *match;
        GHashTable *network;
        GHashTable *address;
        GHashTable *dhcp4;
        GHashTable *dhcp6;
        GHashTable *nameserver;
        GHashTable *route;
        GHashTable *routing_policy_rule;
        GHashTable *wifi_config;
        GHashTable *link;
        GHashTable *netdev_vlan;
        GHashTable *netdev_bond;
        GHashTable *netdev_bridge;
} YAMLManager;

int yaml_manager_new(YAMLManager **ret);
void yaml_manager_free(YAMLManager *p);

DEFINE_CLEANUP(YAMLManager *, yaml_manager_free);

static inline const char *scalar(const yaml_node_t *node) {
        return (const char*) node->data.scalar.value;
}

int yaml_parse_file(const char *yaml_file, Networks **n);
