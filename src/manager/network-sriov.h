/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "alloc-util.h"
#include "network-util.h"
#include "config-file.h"

typedef struct SRIOV {
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

int sriov_new(SRIOV **ret);

void sriov_free(SRIOV *s);
DEFINE_CLEANUP(SRIOV*, sriov_free);

int sriov_configure(const IfNameIndex *ifidx, SRIOV *s, bool link);
