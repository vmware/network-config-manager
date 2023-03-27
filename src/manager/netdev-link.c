/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "netdev-link.h"
#include "network-link.h"
#include "network-util.h"
#include "parse-util.h"
#include "string-util.h"

static const Config link_ctl_to_config_table[] = {
                { "alias",           "Alias" },
                { "desc",            "Description" },
                { "macpolicy",       "MACAddressPolicy" },
                { "macaddr",         "MACAddress" },
                { "namepolicy",      "NamePolicy" },
                { "name",            "Name" },
                { "altnamepolicy",   "AlternativeNamesPolicy" },
                { "altname",         "AlternativeName" },
                { "mtu",             "MTUBytes" },
                { "bps",             "BitsPerSecond" },
                { "duplex",          "Duplex" },
                { "wol",             "WakeOnLan" },
                { "wolp",            "WakeOnLanPassword" },
                { "port",            "Port" },
                { "advertise",       "Advertise" },
                { "auton",           "AutoNegotiation" },
                { "rxcsumo",         "ReceiveChecksumOffload" },
                { "txcsumo",         "TransmitChecksumOffload" },
                { "tso",             "TCPSegmentationOffload" },
                { "t6so",            "TCP6SegmentationOffload" },
                { "gso",             "GenericSegmentationOffload"},
                { "grxo",            "GenericReceiveOffload" },
                { "grxoh",           "GenericReceiveOffloadHardware" },
                { "lrxo",            "LargeReceiveOffload" },
                { "rxvtha",          "ReceiveVLANCTAGHardwareAcceleration" },
                { "txvtha",          "TransmitVLANCTAGHardwareAcceleration" },
                { "rxvtf",           "ReceiveVLANCTAGFilter" },
                { "txvstha",         "TransmitVLANSTAGHardwareAcceleration" },
                { "ntf",             "NTupleFilter" },
                { "uarxc",           "UseAdaptiveRxCoalesce" },
                { "uatxc",           "UseAdaptiveTxCoalesce" },
                { "gsob",            "GenericSegmentOffloadMaxBytes" },
                { "gsos",            "GenericSegmentOffloadMaxSegments" },
                { "rxch",            "RxChannels" },
                { "txch",            "TxChannels" },
                { "otrch",           "OtherChannels" },
                { "combch",          "CombinedChannels" },
                { "rxbuf",           "RxBufferSize" },
                { "rxminbuf",        "RxMiniBufferSize" },
                { "rxjumbobuf",      "RxJumboBufferSize" },
                { "txbuf",           "TxBufferSize" },
                { "txq",             "TransmitQueues" },
                { "rxq",             "ReceiveQueues" },
                { "rxqlen",          "TransmitQueueLength" },
                { "rxflowctrl",      "RxFlowControl" },
                { "txflowctrl",      "TxFlowControl" },
                { "autoflowctrl",    "AutoNegotiationFlowControl" },
                { "rxcs",            "RxCoalesceSec" },
                { "rxcsirq",         "RxCoalesceIrqSec" },
                { "rxcslow",         "RxCoalesceLowSec" },
                { "rxcshigh",        "RxCoalesceHighSec" },
                { "txcs",            "TxCoalesceSec" },
                { "txcsirq",         "TxCoalesceIrqSec" },
                { "txcslow",         "TxCoalesceLowSec" },
                { "txcshigh",        "TxCoalesceHighSec" },
                { "rxmcf",           "RxMaxCoalescedFrames" },
                { "rxmcfirq",        "RxMaxCoalescedIrqFrames" },
                { "rxmcflow",        "RxMaxCoalescedLowFrames" },
                { "rxmcfhigh",       "RxMaxCoalescedHighFrames" },
                { "txmcf",           "TxMaxCoalescedFrames" },
                { "txmcfirq",        "TxMaxCoalescedIrqFrames" },
                { "txmcflow",        "TxMaxCoalescedLowFrames" },
                { "txmcfhigh",       "TxMaxCoalescedHighFrames" },
                { "cprlow",          "CoalescePacketRateLow" },
                { "cprhigh",         "CoalescePacketRateHigh" },
                { "cprsis",          "CoalescePacketRateSampleIntervalSec" },
                { "sbcs",            "StatisticsBlockCoalesceSec" },
                {},
};

int netdev_link_new(NetDevLink **ret) {
        NetDevLink *n = NULL;
        int r;

        n = new0(NetDevLink, 1);
        if (!n)
                return log_oom();

        *n = (NetDevLink) {
                .auto_nego = -1,
                .rx_csum_off = -1,
                .tx_csum_off = -1,
                .tcp_seg_off = -1,
                .tcp6_seg_off = -1,
                .gen_seg_off = -1,
                .gen_rx_off = -1,
                .gen_rx_off_hw = -1,
                .large_rx_off = -1,
                .rx_vlan_ctag_hw_acl = -1,
                .tx_vlan_ctag_hw_acl = -1,
                .rx_vlan_ctag_fltr = -1,
                .tx_vlan_stag_hw_acl = -1,
                .n_tpl_fltr = -1,
                .use_adpt_rx_coal = -1,
                .use_adpt_tx_coal = -1,
                .tx_flow_ctrl = -1,
                .rx_flow_ctrl = -1,
                .auto_flow_ctrl = -1,
        };

        r = config_manager_new(link_ctl_to_config_table, &n->m);
        if (r < 0)
                return r;

        *ret = n;
        return 0;
}

void netdev_link_free(NetDevLink *n) {
        if (!n)
                return;

        config_manager_free(n->m);

        free(n->alias);
        free(n->desc);
        free(n->macpolicy);
        free(n->macaddr);
        free(n->namepolicy);
        free(n->name);
        free(n->altnamepolicy);
        free(n->altname);

        free(n->mtu);
        free(n->bps);
        free(n->duplex);
        free(n->wol);
        free(n->wolp);
        free(n->port);
        free(n->advertise);

        free(n->rx_chnl);
        free(n->tx_chnl);
        free(n->otr_chnl);
        free(n->comb_chnl);

        free(n->rx_coal);
        free(n->rx_coal_irq);
        free(n->rx_coal_low);
        free(n->rx_coal_high);
        free(n->tx_coal);
        free(n->tx_coal_irq);
        free(n->tx_coal_low);
        free(n->tx_coal_high);

        free(n->rx_coald_frames);
        free(n->rx_coald_irq_frames);
        free(n->rx_coald_low_frames);
        free(n->rx_coald_high_frames);
        free(n->tx_coald_frames);
        free(n->tx_coald_irq_frames);
        free(n->tx_coald_low_frames);
        free(n->tx_coald_high_frames);

        free(n->coal_pkt_rate_low);
        free(n->coal_pkt_rate_high);
        free(n->coal_pkt_rate_smpl_itrvl);
        free(n->sts_blk_coal);

        free(n->rx_buf);
        free(n->rx_mini_buf);
        free(n->rx_jumbo_buf);
        free(n->tx_buf);

        free(n);
}

int create_or_parse_netdev_link_conf_file(const char *ifname, char **ret) {
        _auto_cleanup_ char *file = NULL, *path = NULL, *s = NULL, *mac = NULL;
        int r;

        assert(ifname);

        s = string_join("-", "10", ifname, NULL);
        if (!s)
                return -ENOMEM;

        file = string_join(".", s, "link", NULL);
        if (!file)
                return -ENOMEM;

        path = g_build_path("/", "/etc/systemd/network", file, NULL);
        if (!path)
                 return log_oom();

        if (g_file_test(path, G_FILE_TEST_EXISTS)) {
                  *ret = steal_pointer(path);
                   return 0;
        }

        r = link_get_mac_address(ifname, &mac);
        if (r < 0)
                return r;

        if (isempty_string(mac))
                return -ENOENT;

        r = create_conf_file("/etc/systemd/network", s, "link", &file);
        if (r < 0)
                return r;

        r = set_config_file_string(path, "Match", "MACAddress", mac);
        if (r < 0)
                return r;

        *ret = steal_pointer(path);
        return 0;
}

int netdev_link_configure(const IfNameIndex *ifidx, NetDevLink *n) {
        _auto_cleanup_ char *path = NULL;
         int r;

        r = create_or_parse_netdev_link_conf_file(ifidx->ifname, &path);
        if (r < 0)
                return r;

        if (n->alias) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "alias"), n->alias);
                if (r < 0)
                        return r;
        }

        if (n->desc) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "desc"), n->desc);
                if (r < 0)
                        return r;
        }

        if (n->macpolicy) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "macpolicy"), n->macpolicy);
                if (r < 0)
                        return r;
        }

        if(n->macaddr) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "macaddr"), n->macaddr);
                if (r < 0)
                    return r;
        }

        if (n->namepolicy) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "namepolicy"), n->namepolicy);
                if (r < 0)
                        return r;
        }

        if(n->name) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "name"), n->name);
                if (r < 0)
                    return r;
        }

        if (n->altnamepolicy) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "altnamepolicy"), n->altnamepolicy);
                if (r < 0)
                        return r;
        }

        if(n->altname) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "altname"), n->altname);
                if (r < 0)
                    return r;
        }

        if(n->mtu) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "mtu"), n->mtu);
                if (r < 0)
                    return r;
        }

        if(n->bps) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "bps"), n->bps);
                if (r < 0)
                    return r;
        }

        if(n->duplex) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "duplex"), n->duplex);
                if (r < 0)
                    return r;
        }

        if(n->wol) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "wol"), n->wol);
                if (r < 0)
                    return r;
        }

        if(n->wolp) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "wolp"), n->wolp);
                if (r < 0)
                    return r;
        }

        if(n->port) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "port"), n->port);
                if (r < 0)
                    return r;
        }

        if(n->advertise) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "advertise"), n->advertise);
                if (r < 0)
                    return r;
        }

        if (n->auto_nego >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "auton"), bool_to_string(n->auto_nego));
                 if (r < 0)
                         return r;
        }

        if (n->rx_csum_off >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxcsumo"), bool_to_string(n->rx_csum_off));
                 if (r < 0)
                         return r;
        }

        if (n->tx_csum_off >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txcsumo"), bool_to_string(n->tx_csum_off));
                 if (r < 0)
                         return r;
        }

        if (n->tcp_seg_off >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "tso"), bool_to_string(n->tcp_seg_off));
                 if (r < 0)
                         return r;
        }

        if (n->tcp6_seg_off>= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "t6so"), bool_to_string(n->tcp6_seg_off));
                 if (r < 0)
                         return r;
        }

        if (n->gen_seg_off >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "gso"), bool_to_string(n->gen_seg_off));
                 if (r < 0)
                         return r;
        }

        if (n->gen_rx_off >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "grxo"), bool_to_string(n->gen_rx_off));
                 if (r < 0)
                         return r;
        }

        if (n->gen_rx_off_hw >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "grxoh"), bool_to_string(n->gen_rx_off_hw));
                 if (r < 0)
                         return r;
        }

        if (n->large_rx_off >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "lrxo"), bool_to_string(n->large_rx_off));
                 if (r < 0)
                         return r;
        }

        if (n->rx_vlan_ctag_hw_acl >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxvtha"), bool_to_string(n->rx_vlan_ctag_hw_acl));
                 if (r < 0)
                         return r;
        }

        if (n->tx_vlan_ctag_hw_acl >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txvtha"), bool_to_string(n->tx_vlan_ctag_hw_acl));
                 if (r < 0)
                         return r;
        }

        if (n->rx_vlan_ctag_fltr >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxvtf"), bool_to_string(n->rx_vlan_ctag_fltr));
                 if (r < 0)
                         return r;
        }

        if (n->tx_vlan_stag_hw_acl >= 0) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txvstha"), bool_to_string(n->tx_vlan_stag_hw_acl));
                 if (r < 0)
                         return r;
        }

        if (n->n_tpl_fltr >= 0) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "ntf"), bool_to_string(n->n_tpl_fltr));
                if (r < 0)
                        return r;
        }

        if (n->use_adpt_rx_coal >= 0) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "uarxc"), bool_to_string(n->use_adpt_rx_coal));
                if (r < 0)
                        return r;
        }

        if (n->use_adpt_tx_coal >= 0) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "uatxc"), bool_to_string(n->use_adpt_tx_coal));
                if (r < 0)
                        return r;
        }

        if (n->tx_flow_ctrl >= 0) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txflowctrl"), bool_to_string(n->tx_flow_ctrl));
                if (r < 0)
                        return r;
        }

        if (n->rx_flow_ctrl >= 0) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxflowctrl"), bool_to_string(n->rx_flow_ctrl));
                if (r < 0)
                        return r;
        }

        if (n->auto_flow_ctrl >= 0) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "autoflowctrl"), bool_to_string(n->auto_flow_ctrl));
                if (r < 0)
                        return r;
        }

        if (n->rx_chnl) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxch"), n->rx_chnl);
                if (r < 0)
                        return r;
        }

        if (n->tx_chnl) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txch"), n->tx_chnl);
                if (r < 0)
                        return r;
        }

        if (n->otr_chnl) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "otrch"), n->otr_chnl);
                if (r < 0)
                        return r;
        }

        if (n->comb_chnl) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "combch"), n->comb_chnl);
                if (r < 0)
                        return r;
        }

        if (n->rx_buf) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxbuf"), n->rx_buf);
                if (r < 0)
                        return r;
        }

        if(n->rx_mini_buf) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxminbuf"), n->rx_mini_buf);
                if (r < 0)
                    return r;
        }

        if(n->rx_jumbo_buf) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxjumbobuf"), n->rx_jumbo_buf);
                if (r < 0)
                    return r;
        }

        if(n->tx_buf) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txbuf"), n->tx_buf);
                if (r < 0)
                    return r;
        }

        if (n->tx_queues > 0) {
                r = set_config_file_integer(path, "Link", ctl_to_config(n->m, "txq"), n->tx_queues);
                if (r < 0)
                        return r;
        }

        if (n->rx_queues > 0) {
                r = set_config_file_integer(path, "Link", ctl_to_config(n->m, "rxq"), n->rx_queues);
                if (r < 0)
                        return r;
        }

        if (n->tx_queue_len > 0) {
                r = set_config_file_integer(path, "Link", ctl_to_config(n->m, "rxqlen"), n->tx_queue_len);
                if (r < 0)
                        return r;
        }

        if (n->gen_seg_off_bytes > 0) {
                r = set_config_file_integer(path, "Link", ctl_to_config(n->m, "gsob"), n->gen_seg_off_bytes);
                if (r < 0)
                        return r;
        }
        if (n->gen_seg_off_seg > 0) {
                r = set_config_file_integer(path, "Link", ctl_to_config(n->m, "gsos"), n->gen_seg_off_seg);
                if (r < 0)
                        return r;
        }

        if (n->rx_coal) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxcs"), n->rx_coal);
                if (r < 0)
                        return r;
        }

        if (n->rx_coal_irq) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxcsirq"), n->rx_coal_irq);
                if (r < 0)
                        return r;
        }

        if (n->rx_coal_low) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxcslow"), n->rx_coal_low);
                if (r < 0)
                        return r;
        }

        if (n->rx_coal_high) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxcshigh"), n->rx_coal_high);
                if (r < 0)
                        return r;
        }

        if (n->tx_coal) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txcs"), n->tx_coal);
                if (r < 0)
                        return r;
        }

        if (n->tx_coal_irq) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txcsirq"), n->tx_coal_irq);
                if (r < 0)
                        return r;
        }

        if (n->tx_coal_low) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txcslow"), n->tx_coal_low);
                if (r < 0)
                        return r;
        }

        if (n->tx_coal_high) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txcshigh"), n->tx_coal_high);
                if (r < 0)
                        return r;
        }

        if (n->rx_coald_frames) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxmcf"), n->rx_coald_frames);
                if (r < 0)
                        return r;
        }

        if (n->rx_coald_irq_frames) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxmcfirq"), n->rx_coald_irq_frames);
                if (r < 0)
                        return r;
        }

        if (n->rx_coald_low_frames) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxmcflow"), n->rx_coald_low_frames);
                if (r < 0)
                        return r;
        }

        if (n->rx_coald_high_frames) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rxmcfhigh"), n->rx_coald_high_frames);
                if (r < 0)
                        return r;
        }

        if (n->tx_coald_frames) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txmcf"), n->tx_coald_frames);
                if (r < 0)
                        return r;
        }

        if (n->tx_coald_irq_frames) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txmcfirq"), n->tx_coald_irq_frames);
                if (r < 0)
                        return r;
        }

        if (n->tx_coald_low_frames) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txmcflow"), n->tx_coald_low_frames);
                if (r < 0)
                        return r;
        }

        if (n->tx_coald_high_frames) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "txmcfhigh"), n->tx_coald_high_frames);
                if (r < 0)
                        return r;
        }

        if (n->coal_pkt_rate_low) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "cprlow"), n->coal_pkt_rate_low);
                if (r < 0)
                        return r;
        }

        if (n->coal_pkt_rate_high) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "cprhigh"), n->coal_pkt_rate_high);
                if (r < 0)
                        return r;
        }

        if (n->coal_pkt_rate_smpl_itrvl) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "cprsis"), n->coal_pkt_rate_smpl_itrvl);
                if (r < 0)
                        return r;
        }

        if (n->sts_blk_coal) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "sbcs"), n->sts_blk_coal);
                if (r < 0)
                        return r;
        }

        return 0;
}
