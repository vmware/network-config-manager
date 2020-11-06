/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include "network-util.h"

typedef enum NetDevKind {
        NET_DEV_KIND_VLAN,
        NET_DEV_KIND_BRIDGE,
        NET_DEV_KIND_BOND,
        NET_DEV_KIND_VXLAN,
        _NET_DEV_KIND_MAX,
        _NET_DEV_KIND_INVALID = -1
} NetDevKind;

typedef enum BondMode {
        BOND_MODE_ROUNDROBIN,
        BOND_MODE_ACTIVEBACKUP,
        BOND_MODE_XOR,
        BOND_MODE_BROADCAST,
        BOND_MODE_8023AD,
        BOND_MODE_TLB,
        BOND_MODE_ALB,
        _BOND_MODE_MAX,
        _BOND_MODE_INVALID = -1
} BondMode;

typedef struct NetDev {
        char *ifname;
        char *mac;

        bool independent;

        IPAddress local;
        IPAddress remote;
        IPAddress group;

        uint16_t destination_port;

        uint32_t id;
        NetDevKind kind;
        BondMode bond_mode;
} NetDev;

int netdev_new(NetDev **ret);
void netdev_unrefp(NetDev **n);

int generate_netdev_config(NetDev *n, GString **ret);
int create_netdev_conf_file(const char *ifnameidx, char **ret);

const char *netdev_kind_to_name(NetDevKind id);
int netdev_kind_to_id(const char *name);

const char *bond_mode_to_name(BondMode id);
int bond_mode_to_id(const char *name);
