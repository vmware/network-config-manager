/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */
#pragma once

#include <linux/if_link.h>

#include "network-util.h"

typedef enum NetDevKind {
        NET_DEV_KIND_VLAN,
        NET_DEV_KIND_BRIDGE,
        NET_DEV_KIND_BOND,
        NET_DEV_KIND_VXLAN,
        NET_DEV_KIND_MACVLAN,
        NET_DEV_KIND_MACVTAP,
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

typedef enum MACVLanMode {
        MAC_VLAN_MODE_PRIVATE  = MACVLAN_MODE_PRIVATE,
        MAC_VLAN_MODE_VEPA     = MACVLAN_MODE_VEPA,
        MAC_VLAN_MODE_BRIDGE   = MACVLAN_MODE_BRIDGE,
        MAC_VLAN_MODE_PASSTHRU = MACVLAN_MODE_PASSTHRU,
        MAC_VLAN_MODE_SOURCE   = MACVLAN_MODE_SOURCE,
        _MAC_VLAN_MODE_MAX,
        _MAC_VLAN_MODE_INVALID = -1
} MACVLanMode;

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
        MACVLanMode macvlan_mode;
} NetDev;

int netdev_new(NetDev **ret);
void netdev_unrefp(NetDev **n);

int generate_netdev_config(NetDev *n, GString **ret);
int create_netdev_conf_file(const char *ifnameidx, char **ret);

const char *netdev_kind_to_name(NetDevKind id);
int netdev_name_to_kind(const char *name);

const char *bond_mode_to_name(BondMode id);
int bond_name_to_mode(const char *name);

const char *macvlan_mode_to_name(MACVLanMode id);
int macvlan_name_to_mode(const char *name);
