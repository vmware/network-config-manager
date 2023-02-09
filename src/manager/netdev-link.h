/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <linux/if_link.h>

#include "alloc-util.h"
#include "config-file.h"
#include "macros.h"
#include "network-util.h"
#include "string-util.h"
#include "network.h"

typedef struct NetDevLink {
        ConfigManager *m;

        ParserType parser_type;

        char *ifname;

        char *alias;
        char *desc;
        char *macpolicy;
        char *macaddr;
        char *namepolicy;
        char *name;
        char *altnamepolicy;
        char *altname;

        char *mtu;
        char *bps;
        char *duplex;
        char *wol;
        char *wolp;
        char *port;
        char *advertise;

        char *rx_chnl;
        char *tx_chnl;
        char *otr_chnl;
        char *comb_chnl;

        char *rx_coal_sec;
        char *rx_coal_irq_sec;
        char *rx_coal_low_sec;
        char *rx_coal_high_sec;
        char *tx_coal_sec;
        char *tx_coal_irq_sec;
        char *tx_coal_low_sec;
        char *tx_coal_high_sec;

        char *rx_coald_frames;
        char *rx_coald_irq_frames;
        char *rx_coald_low_frames;
        char *rx_coald_high_frames;
        char *tx_coald_frames;
        char *tx_coald_irq_frames;
        char *tx_coald_low_frames;
        char *tx_coald_high_frames;


        char *coal_pkt_rate_low;
        char *coal_pkt_rate_high;
        char *coal_pkt_rate_smpl_itrvl;
        char *sts_blk_coal_sec;
 
        char *rx_buf;
        char *rx_mini_buf;
        char *rx_jumbo_buf;
        char *tx_buf;

        int auto_nego;
        int rx_csum_off;
        int tx_csum_off;
        int tcp_seg_off;
        int tcp6_seg_off;
        int gen_seg_off;
        int gen_rx_off;
        int gen_rx_off_hw;
        int large_rx_off;
        int rx_vlan_ctag_hw_acl;
        int tx_vlan_ctag_hw_acl;
        int rx_vlan_ctag_fltr;
        int tx_vlan_stag_hw_acl;
        int n_tpl_fltr;
        int use_adpt_rx_coal;
        int use_adpt_tx_coal;
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

int netdev_link_configure(const IfNameIndex *ifidx, NetDevLink *n);
int create_or_parse_netdev_link_conf_file(const char *ifname, char **ret);
