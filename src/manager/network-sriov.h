/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "alloc-util.h"
#include "network-util.h"
#include "config-file.h"

typedef enum SRIOVLinkState {
        SR_IOV_LINK_STATE_DISABLE,
        SR_IOV_LINK_STATE_ENABLE,
        SR_IOV_LINK_STATE_AUTO,
        _SR_IOV_LINK_STATE_MAX,
        _SR_IOV_LINK_STATE_INVALID = -EINVAL,
} SRIOVLinkState;

typedef struct SRIOV {
        int family;
        int ifindex;

        uint32_t vf;   /* 0 - 2147483646 */
        uint32_t vlan; /* 0 - 4095, 0 disables VLAN filter */
        uint32_t qos;
        char *vlan_proto; /* ETH_P_8021Q or ETH_P_8021AD */
        int vf_spoof_check_setting;
        int query_rss;
        int trust;

        char *macaddr;

        SRIOVLinkState link_state;
} SRIOV;

int sriov_new(SRIOV **ret);

void sriov_free(SRIOV *s);
DEFINE_CLEANUP(SRIOV*, sriov_free);

int sriov_configure(const IfNameIndex *i, SRIOV *s, bool link);
int parse_sriov_link_state(const char *s);
int sriov_add_new_section(KeyFile *key_file, SRIOV *s);
