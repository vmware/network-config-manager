/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "alloc-util.h"
#include "network-util.h"
#include "config-file.h"

typedef struct SRIOV {
        ConfigManager *m;

        int family;
        int ifindex;

        char *vf;
        char *vlanid;
        char *qos;
        char *vlanproto;
        char *macaddr;
        char *linkstate;

        int macspoofck;
        int qrss;
        int trust;
} SRIOV;

int netdev_sriov_new(SRIOV **ret);

void netdev_sriov_unref(SRIOV *s);
DEFINE_CLEANUP(SRIOV*, netdev_sriov_unref);

int netdev_sriov_configure(const IfNameIndex *ifnameidx, SRIOV *s);
