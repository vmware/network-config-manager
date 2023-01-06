/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"
#include "network.h"
#include "networkd-api.h"
#include "parse-util.h"
#include "string-util.h"
#include "yaml-network-parser.h"
#include "yaml-parser.h"

static WiFiAccessPoint *wifi_access_point;

static ParserTable parser_wifi_vtable[] = {
        { "ssid-name",           CONF_TYPE_WIFI,     parse_yaml_string,                   offsetof(WiFiAccessPoint,    ssid)},
        { "password",            CONF_TYPE_WIFI,     parse_yaml_string,                   offsetof(WIFIAuthentication, password)},
        { "key-management",      CONF_TYPE_WIFI,     parse_yaml_auth_key_management_type, offsetof(WIFIAuthentication, key_management)},
        { "psk",                 CONF_TYPE_WIFI,     parse_yaml_auth_key_management_type, offsetof(WIFIAuthentication, password)},
        { "method",              CONF_TYPE_WIFI,     parse_yaml_auth_eap_method,          offsetof(WIFIAuthentication, eap_method)},
        { "ca-certificate",      CONF_TYPE_WIFI,     parse_yaml_string,                   offsetof(WIFIAuthentication, ca_certificate)},
        { "client-certificate",  CONF_TYPE_WIFI,     parse_yaml_string,                   offsetof(WIFIAuthentication, client_certificate)},
        { "client-key",          CONF_TYPE_WIFI,     parse_yaml_string,                   offsetof(WIFIAuthentication, client_key)},
        { "client-key-password", CONF_TYPE_WIFI,     parse_yaml_string,                   offsetof(WIFIAuthentication, client_key_password)},
        { "identity",            CONF_TYPE_WIFI,     parse_yaml_string,                   offsetof(WIFIAuthentication, identity)},
        { "anonymous-identity",  CONF_TYPE_WIFI,     parse_yaml_string,                   offsetof(WIFIAuthentication, anonymous_identity)},
        { NULL,                  _CONF_TYPE_INVALID, 0,                                   0}
};

static ParserTable parser_network_vtable[] = {
        { "name",                     CONF_TYPE_NETWORK,     parse_yaml_string,                 offsetof(Network, ifname)},
        { "match-mac-address",        CONF_TYPE_NETWORK,     parse_yaml_mac_address,            offsetof(Network, match_mac)},
        { "mac-address",              CONF_TYPE_NETWORK,     parse_yaml_mac_address,            offsetof(Network, mac)},
        { "mtu",                      CONF_TYPE_NETWORK,     parse_yaml_uint32,                 offsetof(Network, mtu)},
        { "dhcp",                     CONF_TYPE_NETWORK,     parse_yaml_dhcp_type,              offsetof(Network, dhcp_type)},
        { "dhcp4-client-identifier",  CONF_TYPE_NETWORK,     parse_yaml_dhcp_client_identifier, offsetof(Network, dhcp_client_identifier_type)},
        { "unmanaged",                CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, unmanaged)},
        { "arp",                      CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, arp)},
        { "multicast",                CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, multicast)},
        { "allmulticast",             CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, all_multicast)},
        { "promiscuous",              CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, promiscuous)},
        { "requiredforonline",        CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, req_for_online)},
        { "requiredfamilyforonline",  CONF_TYPE_NETWORK,     parse_yaml_rf_online,              offsetof(Network, req_family_for_online)},
        { "dhcp4-use-dns",            CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, dhcp4_use_dns)},
        { "dhcp4-use-domain",         CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, dhcp4_use_domains)},
        { "dhcp4-use-ntp",            CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, dhcp4_use_ntp)},
        { "dhcp4-use-mtu",            CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, dhcp4_use_mtu)},
        { "dhcp6-use-dns",            CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, dhcp6_use_dns)},
        { "dhcp6-use-ntp",            CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, dhcp6_use_ntp)},
        { "gateway",                  CONF_TYPE_NETWORK,     parse_yaml_address,                offsetof(Network, gateway)},
        { "gateway-onlink",           CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, gateway_onlink)},
        { "lldp",                     CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, lldp)},
        { "ipv6-accept-ra",           CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, ipv6_accept_ra)},
        { "link-local-address",       CONF_TYPE_NETWORK,     parse_yaml_link_local_type,        offsetof(Network, link_local)},
        { "nameservers",              CONF_TYPE_NETWORK,     parse_yaml_addresses,              offsetof(Network, nameservers)},
        { "ntps",                     CONF_TYPE_NETWORK,     parse_yaml_addresses,              offsetof(Network, ntps)},
        { "addresses",                CONF_TYPE_NETWORK,     parse_yaml_addresses,              offsetof(Network, addresses)},
        { NULL,                       _CONF_TYPE_INVALID,    0,                                 0}
};

static ParserTable parser_route_vtable[] = {
        { "to",     CONF_TYPE_ROUTE,     parse_yaml_routes, offsetof(Network, routes)},
        { "via",    CONF_TYPE_ROUTE,     parse_yaml_routes, offsetof(Network, routes)},
        { "metric", CONF_TYPE_ROUTE,     parse_yaml_routes, offsetof(Network, routes)},
        { NULL,     _CONF_TYPE_INVALID,  0,            0}
};

static ParserTable parser_link_vtable[] = {
        { "ifname",                                   CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, ifname)},
        { "alias",                                    CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, alias)},
        { "description",                              CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, desc)},
        { "mtubytes",                                 CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, mtub)},
        { "bitspersecond",                            CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, bps)},
        { "duplex",                                   CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, duplex)},
        { "wakeonlan",                                CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, wol)},
        { "wakeonlanpassword",                        CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, wolp)},
        { "port",                                     CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, port)},
        { "advertise",                                CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, advertise)},
        { "autonegotiation",                          CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, auto_nego)},
        { "receivechecksumoffload",                   CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, rx_csum_off)},
        { "transmitchecksumoffload",                  CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tx_csum_off)},
        { "tcpsegmentationoffload",                   CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tcp_seg_off)},
        { "tcp6segmentationoffload",                  CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tcp6_seg_off)},
        { "genericsegmentationoffload",               CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, gen_seg_off)},
        { "genericreceiveoffload",                    CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, gen_rx_off)},
        { "genericreceiveoffloadhardware",            CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, gen_rx_off_hw)},
        { "largereceiveoffload",                      CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, large_rx_off)},
        { "receivevlanctaghardwareacceleration",      CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, rx_vlan_ctag_hw_acl)},
        { "transmitvlanctaghardwareacceleration",     CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tx_vlan_ctag_hw_acl)},
        { "receivevlanctagfilter",                    CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, rx_vlan_ctag_fltr)},
        { "transmitvlanstaghardwareacceleration",     CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tx_vlan_stag_hw_acl)},
        { "ntuplefilter",                             CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, n_tpl_fltr)},
        { "useadaptiverxcoalesce",                    CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, use_adpt_rx_coal)},
        { "useadaptivetxcoalesce",                    CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, use_adpt_tx_coal)},
        { "macaddresspolicy",                         CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, macpolicy)},
        { "macaddress",                               CONF_TYPE_LINK,           parse_yaml_mac_address,             offsetof(NetDevLink, macaddr)},
        { "namepolicy",                               CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, namepolicy)},
        { "name",                                     CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, name)},
        { "alternativenamespolicy",                   CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, altnamepolicy)},
        { "alternativename",                          CONF_TYPE_LINK,           parse_yaml_string,                  offsetof(NetDevLink, altname)},
        { "rxbuffersize",                             CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_buf)},
        { "rxminibuffersize",                         CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_mini_buf)},
        { "rxjumbobuffersize",                        CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_jumbo_buf)},
        { "txbuffersize",                             CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_buf)},
        { "transmitqueues",                           CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, tx_queues)},
        { "receivequeues",                            CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, rx_queues)},
        { "transmitqueuelength",                      CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, tx_queue_len)},
        { "txflowcontrol",                            CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, tx_flow_ctrl)},
        { "rxflowcontrol",                            CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, rx_flow_ctrl)},
        { "autonegotiationflowcontrol",               CONF_TYPE_LINK,           parse_yaml_bool,                    offsetof(NetDevLink, auto_flow_ctrl)},
        { "genericsegmentoffloadmaxbytes",            CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, gen_seg_off_bytes)},
        { "genericsegmentoffloadmaxsegments",         CONF_TYPE_LINK,           parse_yaml_uint32,                  offsetof(NetDevLink, gen_seg_off_seg)},
        { "rxchannels",                               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_chnl)},
        { "txchannels",                               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_chnl)},
        { "otherchannels",                            CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, otr_chnl)},
        { "combinedchannels",                         CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, comb_chnl)},
        { "rxcoalescesec",                            CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coal_sec)},
        { "rxcoalesceirqsec",                         CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coal_irq_sec)},
        { "rxcoalescelowsec",                         CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coal_low_sec)},
        { "rxcoalescehighsec",                        CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coal_high_sec)},
        { "txcoalescesec",                            CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coal_sec)},
        { "txcoalesceirqsec",                         CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coal_irq_sec)},
        { "txcoalescelowsec",                         CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coal_low_sec)},
        { "txcoalescehighsec",                        CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coal_high_sec)},
        { "rxmaxcoalescedframes",                     CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coald_frames)},
        { "rxmaxcoalescedirqframes",                  CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coald_irq_frames)},
        { "rxmaxcoalescedlowframes",                  CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coald_low_frames)},
        { "rxmaxcoalescedhighframes",                 CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, rx_coald_high_frames)},
        { "txmaxcoalescedframes",                     CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coald_frames)},
        { "txmaxcoalescedirqframes",                  CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coald_irq_frames)},
        { "txmaxcoalescedlowframes",                  CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coald_low_frames)},
        { "txmaxcoalescedhighframes",                 CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, tx_coald_high_frames)},
        { "coalescepacketratelow",                    CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, coal_pkt_rate_low)},
        { "coalescepacketratehigh",                   CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, coal_pkt_rate_high)},
        { "coalescepacketratesampleintervalsec",      CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, coal_pkt_rate_smpl_itrvl)},
        { "statisticsblockcoalescesec",               CONF_TYPE_LINK,           parse_yaml_uint32_or_max,           offsetof(NetDevLink, sts_blk_coal_sec)},
        { NULL,                                       _CONF_TYPE_INVALID,       0,                                  0}
};

static int parse_wifi_access_points_config(YAMLManager *m, yaml_document_t *doc, yaml_node_t *node, Network *network) {
        yaml_node_pair_t *entry;

        assert(doc);
        assert(node);

        for (entry = node->data.mapping.pairs.start; entry < node->data.mapping.pairs.top; entry++) {
                yaml_node_t *key, *value;
                ParserTable *p;
                void *v;

                key = yaml_document_get_node(doc, entry->key);
                value = yaml_document_get_node(doc, entry->value);

                if (string_equal(scalar(key), "ssid-name")) {
                        wifi_access_point = new0(WiFiAccessPoint, 1);
                        if (!wifi_access_point)
                                return log_oom();

                        wifi_access_point->auth = new0(WIFIAuthentication, 1);
                        if (!wifi_access_point->auth)
                                return log_oom();

                        wifi_access_point->ssid = g_strdup(scalar(value));
                        if (!network->access_points)
                                network->access_points = g_hash_table_new(g_str_hash, g_str_equal);

                        if (!g_hash_table_insert(network->access_points, wifi_access_point->ssid, wifi_access_point)) {
                                log_warning("Failed to add WiFi access point: %s", scalar(value));
                                return false;
                        }

                        continue;
                }

                p = g_hash_table_lookup(m->wifi_config, scalar(key));
                if (!p)
                        continue;

                v = (uint8_t *)  wifi_access_point->auth + p->offset;
                if (p->parser)
                        (void) p->parser(scalar(key), scalar(value), wifi_access_point, v, doc, value);
        }

        return true;
}

static int parse_network_config(YAMLManager *m, yaml_document_t *doc, yaml_node_t *node, Network *network) {
        yaml_node_pair_t *entry;

        assert(m);
        assert(doc);
        assert(node);

        for (entry = node->data.mapping.pairs.start; entry < node->data.mapping.pairs.top; entry++) {
                yaml_node_t *key, *value;
                ParserTable *p;
                void *v;

                key = yaml_document_get_node(doc, entry->key);
                value = yaml_document_get_node(doc, entry->value);

                p = g_hash_table_lookup(m->network_config, scalar(key));
                if (!p)
                        continue;

                v = (uint8_t *) network + p->offset;
                if (p->parser)
                        (void) p->parser(scalar(key), scalar(value), network, v, doc, value);
        }

        return true;
}

static int parse_route_config(YAMLManager *m, yaml_document_t *doc, yaml_node_t *node, Network *network) {
        yaml_node_pair_t *entry;

        assert(doc);
        assert(node);
        assert(m);

        for (entry = node->data.mapping.pairs.start; entry < node->data.mapping.pairs.top; entry++) {
                yaml_node_t *key, *value;
                ParserTable *p;
                void *v;

                key = yaml_document_get_node(doc, entry->key);
                value = yaml_document_get_node(doc, entry->value);

                p = g_hash_table_lookup(m->route_config, scalar(key));
                if (!p)
                        continue;

                v = (uint8_t *) network + p->offset;
                if (p->parser)
                        (void) p->parser(scalar(key), scalar(value), network, v, doc, value);
        }

        return true;
}

static int parse_yaml_node(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        yaml_node_item_t *i;
        yaml_node_pair_t *p;
        yaml_node_t *n;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        switch (node->type) {
        case YAML_NO_NODE:
        case YAML_SCALAR_NODE:
                break;
        case YAML_SEQUENCE_NODE: {
                for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                        n = yaml_document_get_node(dp, *i);
                        if (n)
                                (void) parse_yaml_node(m, dp, n, network);
                }
        }
                break;
        case YAML_MAPPING_NODE:
                (void) parse_network_config(m, dp, node, network);
                (void) parse_wifi_access_points_config(m, dp, node, network);
                (void) parse_route_config(m, dp, node, network);

                for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                        n = yaml_document_get_node(dp, p->key);
                        if (n)
                                (void) parse_yaml_node(m, dp, n, network);

                        n = yaml_document_get_node(dp, p->value);
                        if (n)
                                (void) parse_yaml_node(m, dp, n, network);
                }
                break;
        default:
                log_warning("Failed to parse node type: '%d'", node->type);
                break;
        }

        return 0;
}

static int parse_yaml_document(YAMLManager *m, yaml_document_t *dp, Network *network) {
        assert(m);
        assert(dp);
        assert(network);

        return parse_yaml_node(m, dp, yaml_document_get_root_node(dp), network);
}

int parse_yaml_network_file(const char *file, Network **ret) {
        _cleanup_(yaml_manager_unrefp) YAMLManager *m = NULL;
        _cleanup_(network_unrefp) Network *network = NULL;
        _auto_cleanup_fclose_ FILE *f = NULL;
        yaml_document_t document;
        yaml_parser_t parser;
        bool done = false;
        int r = 0;

        assert(file);
        assert(ret);

        r = new_yaml_manager(&m);
        if (r < 0)
                return r;

        f = fopen(file, "r");
        if (!f) {
                log_warning("Failed to open yaml config file: %s", file);
                return -errno;
        }

        assert(yaml_parser_initialize(&parser));
        yaml_parser_set_input_file(&parser, f);

        r = network_new(&network);
        if (r < 0)
                return r;

        network->parser_type = PARSER_TYPE_YAML;

        for (;!done;) {
                if (!yaml_parser_load(&parser, &document)) {
                        r = -EINVAL;
                        break;
                }

                done = !yaml_document_get_root_node(&document);
                if (!done)
                        r = parse_yaml_document(m, &document, network);

                yaml_document_delete(&document);
        }

        yaml_parser_delete(&parser);

        if (r >= 0)
                *ret = steal_pointer(network);

        return r;
}

void yaml_manager_unrefp(YAMLManager **p) {
        if (!p || !*p)
                return;

        g_hash_table_destroy((*p)->network_config);
        g_hash_table_destroy((*p)->route_config);
        g_hash_table_destroy((*p)->wifi_config);
        g_hash_table_destroy((*p)->link_config);

        free(*p);
}

int new_yaml_manager(YAMLManager **ret) {
        _cleanup_(yaml_manager_unrefp) YAMLManager *m = NULL;

        m = new0(YAMLManager, 1);
        if (!m)
                return log_oom();

        *m = (YAMLManager) {
                 .network_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .route_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .wifi_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .link_config = g_hash_table_new(g_str_hash, g_str_equal),
        };

        if (!m->network_config || !m->route_config || !m->wifi_config || !m->link_config)
                return log_oom();

        for (size_t i = 0; parser_network_vtable[i].key; i++) {
               if (!g_hash_table_insert(m->network_config, (void *) parser_network_vtable[i].key, &parser_network_vtable[i])) {
                        log_warning("Failed add key to network table");
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_wifi_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->wifi_config, (void *) parser_wifi_vtable[i].key, &parser_wifi_vtable[i])) {
                        log_warning("Failed add key to wifi table");
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_route_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->route_config, (void *) parser_route_vtable[i].key, &parser_route_vtable[i])) {
                        log_warning("Failed add key to route table");
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_link_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->link_config, (void *) parser_link_vtable[i].key, &parser_link_vtable[i])) {
                        log_warning("Failed add key to link table");
                        return -EINVAL;
                }
        }

        *ret = steal_pointer(m);
        return 0;
}
