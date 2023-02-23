/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <yaml.h>

#include "network.h"

typedef struct YAMLManager {
        GHashTable *match_config;
        GHashTable *network_config;
        GHashTable *address_config;
        GHashTable *dhcp4_config;
        GHashTable *dhcp6_config;
        GHashTable *nameserver_config;
        GHashTable *route_config;
        GHashTable *wifi_config;
        GHashTable *link_config;
} YAMLManager;

int new_yaml_manager(YAMLManager **ret);
void yaml_manager_freep(YAMLManager **p);

static inline const char *scalar(const yaml_node_t *node) {
        return (const char*) node->data.scalar.value;
}

int parse_yaml_file(const char *yaml_file, Networks **n);
