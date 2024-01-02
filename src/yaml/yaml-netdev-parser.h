/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <yaml.h>

#include "yaml-manager.h"

typedef enum YAMLNetDevKind {
        YAML_NETDEV_KIND_VLAN,
        YAML_NETDEV_KIND_BRIDGE,
        YAML_NETDEV_KIND_BOND,
        YAML_NETDEV_KIND_VXLAN,
        YAML_NETDEV_KIND_MACVLAN,
        YAML_NETDEV_KIND_MACVTAP,
        YAML_NETDEV_KIND_IPVLAN,
        YAML_NETDEV_KIND_IPVTAP,
        YAML_NETDEV_KIND_VRF,
        YAML_NETDEV_KIND_TUN,
        YAML_NETDEV_KIND_TAP,
        YAML_NETDEV_KIND_VETH,
        YAML_NETDEV_KIND_TUNNEL,
        YAML_NETDEV_KIND_WIREGUARD,
        _YAML_NETDEV_KIND_MAX,
        _YAML_NETDEV_KIND_INVALID = -EINVAL
} YAMLNetDevKind;

const char *yaml_netdev_kind_to_name(YAMLNetDevKind id);
int yaml_netdev_name_to_kind(const char *name);

bool is_yaml_netdev_kind(const char *s);

int yaml_register_netdev(YAMLManager *m);
int yaml_parse_netdev_config(YAMLManager *m, YAMLNetDevKind kind, yaml_document_t *dp, yaml_node_t *node, Networks *nets);
