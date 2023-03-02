/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "network-manager.h"
#include "netdev-link.h"
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

static ParserTable parser_match_vtable[] = {
        { "name",                       CONF_TYPE_NETWORK,     parse_yaml_string,                 offsetof(Network, ifname)},
        { "driver",                     CONF_TYPE_NETWORK,     parse_yaml_string,                 offsetof(Network, driver)},
        { "macaddress",                 CONF_TYPE_NETWORK,     parse_yaml_mac_address,            offsetof(Network, match_mac)},
        { NULL,                         _CONF_TYPE_INVALID,    0,                                 0}
};

static ParserTable parser_network_vtable[] = {
        { "unmanaged",                  CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, unmanaged)},
        { "mtu",                        CONF_TYPE_NETWORK,     parse_yaml_uint32,                 offsetof(Network, mtu)},
        { "arp",                        CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, arp)},
        { "multicast",                  CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, multicast)},
        { "allmulticast",               CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, all_multicast)},
        { "promiscuous",                CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, promiscuous)},
        { "required-for-online",        CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, req_for_online)},
        { "required-family-for-online", CONF_TYPE_NETWORK,     parse_yaml_rf_online,              offsetof(Network, req_family_for_online)},
        { "dhcp",                       CONF_TYPE_NETWORK,     parse_yaml_dhcp_type,              offsetof(Network, dhcp_type)},
        { "dhcp4",                      CONF_TYPE_NETWORK,     parse_yaml_dhcp_type,              offsetof(Network, dhcp4)},
        { "dhcp6",                      CONF_TYPE_NETWORK,     parse_yaml_dhcp_type,              offsetof(Network, dhcp6)},
        { "dhcp-identifier",            CONF_TYPE_NETWORK,     parse_yaml_dhcp_client_identifier, offsetof(Network, dhcp_client_identifier_type)},
        { "lldp",                       CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, lldp)},
        { "emit-lldp",                  CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, emit_lldp)},
        { "accept-ra",                  CONF_TYPE_NETWORK,     parse_yaml_bool,                   offsetof(Network, ipv6_accept_ra)},
        { "link-local",                 CONF_TYPE_NETWORK,     parse_yaml_link_local_type,        offsetof(Network, link_local)},
        { "ntps",                       CONF_TYPE_NETWORK,     parse_yaml_addresses,              offsetof(Network, ntps)},
        { NULL,                         _CONF_TYPE_INVALID,    0,                                 0}
};

static ParserTable parser_dhcp4_overrides_vtable[] = {
        { "use-dns",            CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp4_use_dns)},
        { "use-domain",         CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp4_use_domains)},
        { "use-ntp",            CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp4_use_ntp)},
        { "use-mtu",            CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp4_use_mtu)},
        { "use-routes",         CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp4_use_routes)},
        { "use-hostname",       CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp4_use_hostname)},
        { "send-hostname",      CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp4_send_hostname)},
        { "route-metric",       CONF_TYPE_NETWORK,     parse_yaml_uint32, offsetof(Network, dhcp4_route_metric)},
        { "hostname",           CONF_TYPE_NETWORK,     parse_yaml_string, offsetof(Network, dhcp4_hostname)},
        { NULL,                _CONF_TYPE_INVALID,    0,                  0}
};

static ParserTable parser_dhcp6_overrides_vtable[] = {
        { "use-dns",            CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp6_use_dns)},
        { "use-domain",         CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp6_use_domains)},
        { "use-ntp",            CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp6_use_ntp)},
        { "use-address",        CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp6_use_address)},
        { "use-hostname",       CONF_TYPE_NETWORK,     parse_yaml_bool,   offsetof(Network, dhcp6_use_hostname)},
        { NULL,                _CONF_TYPE_INVALID,    0,                  0}
};

static ParserTable parser_address_vtable[] = {
        { "label",     CONF_TYPE_NETWORK,     parse_yaml_addresses, offsetof(Network, addresses)},
        { "addresses", CONF_TYPE_NETWORK,     parse_yaml_addresses, offsetof(Network, addresses)},
        { NULL,        _CONF_TYPE_INVALID,    0,                    0}
};

static ParserTable parser_nameservers_vtable[] = {
        { "search",     CONF_TYPE_NETWORK,     parse_yaml_domains,              offsetof(Network, domains)},
        { "addresses",  CONF_TYPE_NETWORK,     parse_yaml_nameserver_addresses, offsetof(Network, nameservers)},
        { NULL,         _CONF_TYPE_INVALID,    0,                               0}
};

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

        return 0;
}

static int parse_route(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        _auto_cleanup_ Route *rt = NULL;
        yaml_node_item_t *i;
        yaml_node_pair_t *p;
        yaml_node_t *k, *v;
        yaml_node_t *n;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) parse_route(m, dp, n, network);
        }

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                if (!rt) {
                        r = route_new(&rt);
                        if (r < 0)
                                return log_oom();
                }

                if (string_equal(scalar(k), "metric")) {
                        r = parse_uint32(scalar(v), &rt->metric);
                        if (r < 0) {
                                log_warning("Failed to parse route metric='%s'\n", scalar(v));
                                return r;
                        }
                } else if (string_equal(scalar(k), "on-link")) {
                        r = parse_boolean(scalar(v));
                        if (r < 0) {
                                log_warning("Failed to parse route on-link='%s'\n", scalar(v));
                                return r;
                        }
                        rt->onlink = r;
                } else if (string_equal(scalar(k), "table")) {
                        r = parse_uint32(scalar(v), &rt->table);
                        if (r < 0) {
                                log_warning("Failed to parse route table='%s'\n", scalar(v));
                                return r;
                        }
                } else if (string_equal(scalar(k), "congestion-window")) {
                        r = parse_uint32(scalar(v), &rt->initcwnd);
                        if (r < 0) {
                                log_warning("Failed to parse route congestion-window='%s'\n", scalar(v));
                                return r;
                        }
               } else if (string_equal(scalar(k), "advertised-receive-window")) {
                        r = parse_uint32(scalar(v), &rt->initrwnd);
                        if (r < 0) {
                                log_warning("Failed to parse route advertised-receive-window='%s'\n", scalar(v));
                                return r;
                        }
                } else if (string_equal("to", scalar(k)) || string_equal("via", scalar(k))) {
                        _auto_cleanup_ IPAddress *address = NULL;
                        bool b = false;

                        r = parse_ip_from_string(scalar(v), &address);
                        if (r < 0) {
                                if (string_equal("default", scalar(v)))
                                        b = true;
                                else {
                                        log_warning("Failed to parse %s='%s'", scalar(k), scalar(v));
                                        return r;
                                }
                        }

                        if (string_equal("0.0.0.0/0", scalar(v)) || string_equal("::/0", scalar(v)))
                                b = true;

                        if (string_equal("to", scalar(k))) {
                                if (address) {
                                        rt->dst = *address;
                                        rt->family = address->family;
                                }

                                rt->to_default = b;
                        } else {
                                if (address) {
                                        rt->gw = *address;
                                        rt->family = address->family;
                                }
                        }
                }
        }

        if (rt) {
                if (!g_hash_table_insert(network->routes, rt, rt))
                        return -EINVAL;

                network->modified = true;
                steal_pointer(rt);
        }
        return 0;
}

static int parse_address(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network, IPAddress **addr) {
        _auto_cleanup_ IPAddress *a = NULL;
        yaml_node_pair_t *p;
        yaml_node_item_t *i;
        yaml_node_t *k, *v;
        yaml_node_t *n;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                n = yaml_document_get_node(dp, *i);
                if (n)
                        (void) parse_address(m, dp, n, network, addr);
        }

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                if (!k && !v)
                        continue;

                if (!a && !*addr) {
                        a = new0(IPAddress, 1);
                        if (!a)
                                return log_oom();
                }

                if (string_equal(scalar(k), "lifetime")) {
                        free(a->lifetime);
                        a->lifetime = strdup(scalar(v));
                        if (!a->lifetime)
                                return log_oom();
                } else if (string_equal(scalar(k), "label")) {
                        free(a->label);
                        a->label = strdup(scalar(v));
                        if (!a->label)
                                return log_oom();
                } else {
                        _auto_cleanup_ IPAddress *address = NULL;

                        r = parse_ip_from_string(scalar(k), &address);
                        if (r < 0)
                                return r;

                        if (*addr) {
                                if ((*addr)->label)
                                        address->label = strdup((*addr)->label);
                                if ((*addr)->lifetime)
                                        address->lifetime = (*addr)->lifetime;

                                free(*addr);
                                steal_pointer(*addr);
                        }

                        set_add(network->addresses, address);
                        steal_pointer(address);

                        network->modified = true;

                        if (v) {
                                r = parse_address_from_string_and_add(scalar(v), network->addresses);
                                if (r < 0)
                                        continue;
                        }
                }
        }

        if (a) {
                *addr = a;
                steal_pointer(a);
        }

        return 0;
}

static int parse_config(GHashTable *config, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        yaml_node_pair_t *p;
        yaml_node_t *k, *v;

        assert(dp);
        assert(node);
        assert(network);

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                table = g_hash_table_lookup(config, scalar(k));
                if (!table)
                        continue;

                t = (uint8_t *) network + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), network, t, dp, v);
                        network->modified = true;
                }
        }

        return 0;
}

static int parse_network_config(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Network *network) {
        yaml_node_pair_t *p;
        yaml_node_t *k, *v;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(network);

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                ParserTable *table, *link_table;
                void *t;

                k = yaml_document_get_node(dp, p->key);
                v = yaml_document_get_node(dp, p->value);

                table = g_hash_table_lookup(m->network_config, scalar(k));
                if (!table) {
                        if (string_equal(scalar(k), "match"))
                                parse_config(m->match_config, dp, v, network);
                        if (string_equal(scalar(k), "dhcp4-overrides"))
                                parse_config(m->dhcp4_config, dp, v, network);
                        if (string_equal(scalar(k), "dhcp6-overrides"))
                                parse_config(m->dhcp6_config, dp, v, network);
                        else if (string_equal(scalar(k), "addresses")) {
                                IPAddress *a = NULL;

                                parse_address(m, dp, v, network, &a);
                        } else if (string_equal(scalar(k), "routes"))
                                parse_route(m, dp, v, network);
                        else if (string_equal(scalar(k), "nameservers"))
                                parse_config(m->nameserver_config, dp, v, network);
                        else
                                (void) parse_network_config(m, dp, v, network);

                        /* .link  */
                        link_table = g_hash_table_lookup(m->link_config, scalar(k));
                        if (link_table) {
                                if (!network->link) {
                                        NetDevLink *l;

                                        r = netdev_link_new((NetDevLink **) &network->link);
                                        if (r < 0)
                                                return r;

                                        l = network->link;
                                        l->parser_type = PARSER_TYPE_YAML;
                                }

                                t = (uint8_t *) network->link + link_table->offset;
                                if (link_table->parser)
                                        (void) link_table->parser(scalar(k), scalar(v), link, t, dp, v);
                        }

                        continue;
                }

                t = (uint8_t *) network + table->offset;
                if (table->parser) {
                        (void) table->parser(scalar(k), scalar(v), network, t, dp, v);
                        network->modified = true;
                }
        }

        return 0;
}

static int parse_ethernet_config(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Networks *nets) {
        yaml_node_pair_t *p;
        yaml_node_t *n;
        int r;

        assert(m);
        assert(dp);
        assert(node);
        assert(nets);

        for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                _cleanup_(network_freep) Network *net = NULL;
                n = yaml_document_get_node(dp, p->key);

                r = network_new(&net);
                if (r < 0)
                        return r;

                net->parser_type = PARSER_TYPE_YAML;
                net->ifname = strdup(scalar(n));
                if (!net->ifname)
                        return log_oom();

                n = yaml_document_get_node(dp, p->value);
                if (n)
                        (void) parse_network_config(m, dp, n, net);

                if (!g_hash_table_insert(nets->networks, (gpointer *) net->ifname, (gpointer *) net))
                        return log_oom();

                steal_pointer(net);
        }

        return 0;
}

static int parse_yaml_node(YAMLManager *m, yaml_document_t *dp, yaml_node_t *node, Networks *networks) {
        yaml_node_item_t *i;
        yaml_node_pair_t *p;
        yaml_node_t *n;

        assert(m);
        assert(dp);
        assert(node);
        assert(networks);

        switch (node->type) {
        case YAML_NO_NODE:
        case YAML_SCALAR_NODE:
                break;
        case YAML_SEQUENCE_NODE: {
                for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                        n = yaml_document_get_node(dp, *i);
                        if (n)
                                (void) parse_yaml_node(m, dp, n, networks);
                }
        }
                break;
        case YAML_MAPPING_NODE:
                for (p = node->data.mapping.pairs.start; p < node->data.mapping.pairs.top; p++) {
                        n = yaml_document_get_node(dp, p->key);

                        if (string_equal(scalar(n), "ethernets")) {
                                n = yaml_document_get_node(dp, p->value);
                                if (n)
                                        (void) parse_ethernet_config(m, dp, n, networks);
                        } else {
                                n = yaml_document_get_node(dp, p->value);
                                if (n)
                                        (void) parse_yaml_node(m, dp, n, networks);
                        }
                }
                break;
                default:
                        log_warning("Failed to parse node type: '%d'", node->type);
                        break;
        }

        return 0;
}

static int parse_yaml_document(YAMLManager *m, yaml_document_t *dp, Networks *n) {
        return parse_yaml_node(m, dp, yaml_document_get_root_node(dp), n);
}

int parse_yaml_file(const char *file, Networks **n) {
        _cleanup_(yaml_manager_freep) YAMLManager *m = NULL;
        _cleanup_(networks_freep) Networks *networks = NULL;
        _auto_cleanup_fclose_ FILE *f = NULL;
        yaml_document_t document;
        yaml_parser_t parser;
        bool done = false;
        int r = 0;

        assert(file);
        assert(n);

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

        r = networks_new(&networks);
        if (r < 0)
                return r;

        for (;!done;) {
                if (!yaml_parser_load(&parser, &document)) {
                        r = -EINVAL;
                        break;
                }

                done = !yaml_document_get_root_node(&document);
                if (!done)
                        r = parse_yaml_document(m, &document, networks);

                yaml_document_delete(&document);
        }

        yaml_parser_delete(&parser);
        if (r >= 0)
                *n = steal_pointer(networks);

        return r;
}

void yaml_manager_free(YAMLManager *p) {
        if (!p)
                return;

        g_hash_table_destroy(p->match_config);
        g_hash_table_destroy(p->network_config);
        g_hash_table_destroy(p->address_config);
        g_hash_table_destroy(p->dhcp4_config);
        g_hash_table_destroy(p->dhcp6_config);
        g_hash_table_destroy(p->nameserver_config);
        g_hash_table_destroy(p->wifi_config);
        g_hash_table_destroy(p->link_config);

        free(p);
}

int new_yaml_manager(YAMLManager **ret) {
        _cleanup_(yaml_manager_freep) YAMLManager *m = NULL;

        m = new(YAMLManager, 1);
        if (!m)
                return log_oom();

        *m = (YAMLManager) {
                 .match_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .network_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .address_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .dhcp4_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .dhcp6_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .nameserver_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .wifi_config = g_hash_table_new(g_str_hash, g_str_equal),
                 .link_config = g_hash_table_new(g_str_hash, g_str_equal),
        };

        if (!m->network_config || !m->wifi_config || !m->link_config || !m->address_config || !m->dhcp4_config ||
            !m->dhcp6_config || !m->nameserver_config)
                return log_oom();

        for (size_t i = 0; parser_match_vtable[i].key; i++) {
               if (!g_hash_table_insert(m->match_config, (void *) parser_match_vtable[i].key, &parser_match_vtable[i])) {
                        log_warning("Failed add key='%s' to match table", parser_match_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_network_vtable[i].key; i++) {
               if (!g_hash_table_insert(m->network_config, (void *) parser_network_vtable[i].key, &parser_network_vtable[i])) {
                        log_warning("Failed add key='%s' to network table", parser_network_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_dhcp4_overrides_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->dhcp4_config, (void *) parser_dhcp4_overrides_vtable[i].key, &parser_dhcp4_overrides_vtable[i])) {
                        log_warning("Failed add key='%s' to dhcp4 table", parser_dhcp4_overrides_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_dhcp6_overrides_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->dhcp6_config, (void *) parser_dhcp6_overrides_vtable[i].key, &parser_dhcp6_overrides_vtable[i])) {
                        log_warning("Failed add key='%s' to dhcp6 table", parser_dhcp6_overrides_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_address_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->address_config, (void *) parser_address_vtable[i].key, &parser_address_vtable[i])) {
                        log_warning("Failed add key='%s' to address table", parser_address_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_nameservers_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->nameserver_config, (void *) parser_nameservers_vtable[i].key, &parser_nameservers_vtable[i])) {
                        log_warning("Failed add key='%s' to nameserver table", parser_nameservers_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_wifi_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->wifi_config, (void *) parser_wifi_vtable[i].key, &parser_wifi_vtable[i])) {
                        log_warning("Failed add key='%s' to wifi table", parser_wifi_vtable[i].key);
                        return -EINVAL;
                }
        }

        for (size_t i = 0; parser_link_vtable[i].key; i++) {
                if (!g_hash_table_insert(m->link_config, (void *) parser_link_vtable[i].key, &parser_link_vtable[i])) {
                        log_warning("Failed add key='%s' to link table", parser_link_vtable[i].key);
                        return -EINVAL;
                }
        }

        *ret = steal_pointer(m);
        return 0;
}
