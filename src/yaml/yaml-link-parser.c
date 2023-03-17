/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "file-util.h"
#include "log.h"
#include "netdev-link.h"
#include "network.h"
#include "string-util.h"
#include "yaml-parser.h"
#include "yaml-link-parser.h"
#include "yaml-manager.h"

static ParserTable parser_link_vtable[] = {
        { "ifname",                                    CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, ifname)},
        { "alias",                                     CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, alias)},
        { "description",                               CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, desc)},
        { "mtu",                                       CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, mtu)},
        { "bitspersecond",                             CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, bps)},
        { "duplex",                                    CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, duplex)},
        { "wakeonlan",                                 CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, wol)},
        { "wakeonlan-password",                        CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, wolp)},
        { "port",                                      CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, port)},
        { "advertise",                                 CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, advertise)},
        { "auto-negotiation",                          CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, auto_nego)},
        { "receive-checksum-offload",                  CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, rx_csum_off)},
        { "transmit-checksum-offload",                 CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tx_csum_off)},
        { "tcp-segmentation-offload",                  CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tcp_seg_off)},
        { "tcp6-segmentation-offload",                 CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tcp6_seg_off)},
        { "generic-segmentation-offload",              CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, gen_seg_off)},
        { "generic-receive-offload",                   CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, gen_rx_off)},
        { "generic-receive-offload-hardware",          CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, gen_rx_off_hw)},
        { "large-receive-offload",                     CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, large_rx_off)},
        { "receive-vlan-ctag-hardware-acceleration",   CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, rx_vlan_ctag_hw_acl)},
        { "transmit-vlan-ctag-hardware-acceleration",  CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tx_vlan_ctag_hw_acl)},
        { "receive-vlan-ctag-filter",                  CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, rx_vlan_ctag_fltr)},
        { "transmit-vlan-stag-hardware-acceleration",  CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tx_vlan_stag_hw_acl)},
        { "ntuple-filter",                             CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, n_tpl_fltr)},
        { "use-adaptive-rxcoalesce",                   CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, use_adpt_rx_coal)},
        { "use-adaptive-txcoalesce",                   CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, use_adpt_tx_coal)},
        { "macaddress-policy",                         CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, macpolicy)},
        { "macaddress",                                CONF_TYPE_LINK,           parse_yaml_mac_address,             offsetof(NetDevLink, macaddr)},
        { "name-policy",                               CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, namepolicy)},
        { "set-name",                                  CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, name)},
        { "alternative-namespolicy",                   CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, altnamepolicy)},
        { "alternative-name",                          CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, altname)},
        { "rx-buffer-size",                            CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_buf)},
        { "rx-mini-buffer",                            CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_mini_buf)},
        { "rx-jumbo-buffer",                           CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_jumbo_buf)},
        { "tx-buffer",                                 CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_buf)},
        { "transmit-queues",                           CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, tx_queues)},
        { "receive-queues",                            CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, rx_queues)},
        { "transmit-queue-length",                     CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, tx_queue_len)},
        { "tx-flow-control",                           CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tx_flow_ctrl)},
        { "rx-flow-control",                           CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, rx_flow_ctrl)},
        { "autonegotiation-flow-control",              CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, auto_flow_ctrl)},
        { "generic-segmentoffload-max-bytes",          CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, gen_seg_off_bytes)},
        { "generic-segmentoffload-max-segments",       CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, gen_seg_off_seg)},
        { "rx-channels",                               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_chnl)},
        { "tx-channels",                               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_chnl)},
        { "other-channels",                            CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, otr_chnl)},
        { "combined-channels",                         CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, comb_chnl)},
        { "rx-coalesce",                               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coal)},
        { "rx-coalesce-irq",                           CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coal_irq)},
        { "rx-coalesce-low",                           CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coal_low)},
        { "rx-coalesce-high",                          CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coal_high)},
        { "tx-coalesce",                               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coal)},
        { "tx-coalesce-irq",                           CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coal_irq)},
        { "tx-coalesce-low",                           CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coal_low)},
        { "tx-coalesce-high",                          CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coal_high)},
        { "rx-max-coalesced-frames",                   CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coald_frames)},
        { "rx-max-coalesced-irq-frames",               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coald_irq_frames)},
        { "rx-max-coalesced-low-frames",               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coald_low_frames)},
        { "rx-max-coalesced-high-frames",              CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coald_high_frames)},
        { "tx-max-coalesced-frames",                   CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coald_frames)},
        { "tx-max-coalesced-irq-frames",               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coald_irq_frames)},
        { "tx-max-coalesced-low-frames",               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coald_low_frames)},
        { "tx-max-coalesced-high-frames",              CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coald_high_frames)},
        { "coalesce-packetrate-low",                   CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, coal_pkt_rate_low)},
        { "coalesce-packetrate-high",                  CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, coal_pkt_rate_high)},
        { "coalesce-packetrate-sample-interval",       CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, coal_pkt_rate_smpl_itrvl)},
        { "statistics-block-coalesce",                 CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, sts_blk_coal)},
        { NULL,                                        _CONF_TYPE_INVALID,       0,                                  0}
};

int yaml_register_link(YAMLManager *m) {
        assert(m);

        for (size_t i = 0; parser_link_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->link_config, (void *) parser_link_vtable[i].key, &parser_link_vtable[i])) {
                        log_warning("Failed add key='%s' to link table", parser_link_vtable[i].key);
                        return -EINVAL;
                }
        }

        return 0;
}
