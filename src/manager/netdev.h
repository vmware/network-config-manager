/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include "network-util.h"

typedef enum NetDevKind {
        NET_DEV_KIND_VLAN,
        _NET_DEV_KIND_MAX,
        _NET_DEV_KIND_INVALID = -1
} NetDevKind;

typedef struct NetDev {
        char *ifname;
        char *mac;

        uint32_t id;
        NetDevKind kind;
} NetDev;

int netdev_new(NetDev **ret);
void netdev_unrefp(NetDev **n);

int generate_netdev_config(NetDev *n, GString **ret);
int create_netdev_conf_file(const IfNameIndex *ifnameidx, char **ret);

const char *netdev_kind_to_name(NetDevKind id);
int netdev_kind_to_id(const char *name);
