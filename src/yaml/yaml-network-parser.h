/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <yaml.h>

#include "network.h"
#include "netdev-link.h"

typedef struct YAMLManager {
        GHashTable *network_config;
        GHashTable *route_config;
        GHashTable *wifi_config;
        GHashTable *link_config;

        Network *n;
        NetDevLink *l;
} YAMLManager;

int new_yaml_manager(YAMLManager **ret);
void yaml_manager_unrefp(YAMLManager **p);

static inline const char *scalar(const yaml_node_t *node) {
        return (const char*) node->data.scalar.value;
}

int parse_yaml_network_file(const char *yaml_file, Network **ret);
