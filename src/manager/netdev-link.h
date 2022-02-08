/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <linux/if_link.h>

#include "alloc-util.h"
#include "config-file.h"
#include "macros.h"
#include "network-util.h"
#include "string-util.h"

typedef struct NetDevLink {
        ConfigManager *m;

        char *rx_buf;
        char *rx_mini_buf;
        char *rx_jumbo_buf;
        char *tx_buf;

        int rcv_csum_off;
        int tx_csum_off;
        int tcp_seg_off;
        int tcp6_seg_off;
        int gen_csum_off;
        int ggen_rcv_off;
        int large_rcv_off;
        int tx_flow_ctrl;
        int rx_flow_ctrl;
        int auto_flow_ctrl;

        int tx_queues;
        int rx_queues;
        int gen_seg_off_bytes;
        int gen_seg_off_seg;

        unsigned tx_queue_len;
} NetDevLink;

int netdev_link_new(NetDevLink **ret);

void netdev_link_unref(NetDevLink *n);
DEFINE_CLEANUP(NetDevLink*, netdev_link_unref);

int netdev_link_configure(const IfNameIndex *ifnameidx, NetDevLink *n);
int create_or_parse_netdev_link_conf_file(const char *ifname, char **ret);
