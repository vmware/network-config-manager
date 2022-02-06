/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

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

        int receive_checksum_offload;
        int transmit_checksum_offload;
        int tcp_segmentation_offload;
        int tcp6_segmentation_offload;
        int generic_checksum_offload;
        int generic_receive_offload;
        int large_receive_offload;
}NetDevLink;

int netdev_link_new(NetDevLink **ret);

void netdev_link_unref(NetDevLink *n);
DEFINE_CLEANUP(NetDevLink*, netdev_link_unref);

int netdev_link_configure(const IfNameIndex *ifnameidx, NetDevLink *n);
int create_or_parse_netdev_link_conf_file(const char *ifname, char **ret);
