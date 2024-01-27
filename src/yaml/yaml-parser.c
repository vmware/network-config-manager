/* Copyright 2024 VMware, Inc.
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
#include "network-sriov.h"
#include "yaml-parser.h"

static const char * const conf_type_table[_CONF_TYPE_MAX] = {
       [CONF_TYPE_MATCH]                = "match",
       [CONF_TYPE_NETWORK]              = "ethernets",
       [CONF_TYPE_DHCP4]                = "dhcp4-overrides",
       [CONF_TYPE_DHCP6]                = "dhcp6-overrides",
       [CONF_TYPE_RA]                   = "ra-overrides",
       [CONF_TYPE_ADDRESS]              = "addresses",
       [CONF_TYPE_DNS]                  = "nameservers",
       [CONF_TYPE_ROUTE]                = "routes",
       [CONF_TYPE_ROUTING_POLICY_RULE]  = "routing-policy",
       [CONF_TYPE_DHCP4_SERVER]         = "dhcp4-server",
       [CONF_TYPE_SRIOV]                = "sriovs",
       [CONF_TYPE_LINK]                 = "links",
       [CONF_TYPE_NETDEV]               = "netdev",
       [CONF_TYPE_NETDEV_VLAN]          = "vlan",
       [CONF_TYPE_NETDEV_MACVLAN]       = "macvlan",
       [CONF_TYPE_NETDEV_BRIDGE]        = "bridge",
       [CONF_TYPE_NETDEV_BOND]          = "bond",
       [CONF_TYPE_NETDEV_TUNNEL]        = "tunnel",
       [CONF_TYPE_NETDEV_VRF]           = "vrf",
       [CONF_TYPE_NETDEV_VXLAN]         = "vxlan",
       [CONF_TYPE_NETDEV_WIREGUARD]     = "wireguard",
       [CONF_TYPE_WIFI]                 = "wifi",
};

const char *conf_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(conf_type_table))
                return NULL;

        return conf_type_table[id];
}

int conf_type_to_mode(const char *name) {
        assert(name);

        for (size_t i = CONF_TYPE_MATCH; i < (size_t) ELEMENTSOF(conf_type_table); i++)
                if (streq_fold(name, conf_type_table[i]))
                        return i;

        return _CONF_TYPE_INVALID;
}

int parse_yaml_bool(const char *key,
                    const char *value,
                    void *data,
                    void *userdata,
                    yaml_document_t *doc,
                    yaml_node_t *node) {

        int *p;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = userdata;

        r = parse_bool(value);
        if (r < 0)
                return r;

        *p = r;
        return 0;
}

int parse_yaml_uint64(const char *key,
                      const char *value,
                      void *data,
                      void *userdata,
                      yaml_document_t *doc,
                      yaml_node_t *node) {

        uint64_t *p, k;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = userdata;

        r = parse_uint64(value, &k);
        if (r < 0) {
                log_warning("Failed to parse uint64: %s", value);
                return r;
        }

        *p = k;
        return 0;
}

int parse_yaml_uint32(const char *key,
                      const char *value,
                      void *data,
                      void *userdata,
                      yaml_document_t *doc,
                      yaml_node_t *node) {

        uint32_t *p, k;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = userdata;

        r = parse_uint32(value, &k);
        if (r < 0) {
                log_warning("Failed to parse uint32: %s", value);
                return r;
        }

        *p = k;
        return 0;
}

int parse_yaml_uint16(const char *key,
                      const char *value,
                      void *data,
                      void *userdata,
                      yaml_document_t *doc,
                      yaml_node_t *node) {

        uint16_t *p, k;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = userdata;

        r = parse_uint16(value, &k);
        if (r < 0) {
                log_warning("Failed to parse uint16: %s", value);
                return r;
        }

        *p = k;
        return 0;
}

int parse_yaml_uint32_or_max(const char *key,
                             const char *value,
                             void *data,
                             void *userdata,
                             yaml_document_t *doc,
                             yaml_node_t *node) {

        char **p;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = (char **) userdata;

        if (!is_uint32_or_max(value)) {
                log_warning("Failed to parse parameter='%s': %s", value, strerror(EINVAL));
                return -EINVAL;
        }

        *p = g_strdup(value);
        if (!*p)
                return log_oom();

        return 0;
}

int parse_yaml_mac_address(const char *key,
                           const char *value,
                           void *data,
                           void *userdata,
                           yaml_document_t *doc,
                           yaml_node_t *node) {

        char **mac;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        mac = (char **) userdata;

        if (!parse_ether_address(value)) {
                log_warning("Failed to parse MAC address: %s", value);
                return -EINVAL;
        }

        *mac = g_strdup(value);
        if (!*mac)
                return log_oom();

        return 0;
}

int parse_yaml_rf_online(const char *key,
                         const char *value,
                         void *data,
                         void *userdata,
                         yaml_document_t *doc,
                         yaml_node_t *node) {

        char **family;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        family = (char **) userdata;
        r = required_address_family_for_online_name_to_type(value);
        if(r < 0) {
                log_warning("Failed to parse RequiredFamilyForOnline: %s", value);
                return -EINVAL;
        }

        *family =  g_strdup(value);
        if (!*family)
                return log_oom();

        return 0;
}

int parse_yaml_activation_policy(const char *key,
                                 const char *value,
                                 void *data,
                                 void *userdata,
                                 yaml_document_t *doc,
                                 yaml_node_t *node) {

        char **activation_policy;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        activation_policy = (char **) userdata;
        r = device_activation_policy_name_to_type(value);
        if (r < 0) {
                log_warning("Failed to parse ActivationPolicy='%s': %s", value, strerror(EINVAL));
                return r;
        }

        *activation_policy = g_strdup(value);
        if (!*activation_policy)
                return log_oom();

        return 0;
}


int parse_yaml_string(const char *key,
                      const char *value,
                      void *data,
                      void *userdata,
                      yaml_document_t *doc,
                      yaml_node_t *node) {
        char **p;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = (char **) userdata;

        *p = g_strdup(value);
        if (!*p)
                return log_oom();

        return 0;
}

int parse_yaml_auth_key_management_type(const char *key,
                                        const char *value,
                                        void *data,
                                        void *userdata,
                                        yaml_document_t *doc,
                                        yaml_node_t *node) {
        WiFiAccessPoint *p;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = data;
        p->auth->eap_method = auth_key_management_type_to_mode(value);

        return 0;
}

int parse_yaml_dhcp_client_identifier(const char *key,
                                      const char *value,
                                      void *data,
                                      void *userdata,
                                      yaml_document_t *doc,
                                      yaml_node_t *node) {

        Network *n;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        r = dhcp_client_identifier_to_kind((char *) value);
        if (r < 0) {
                log_warning("Failed to parse dhcp client identifier='%s'", value);
                return r;
        }

        n->dhcp_client_identifier_type = dhcp_client_identifier_to_kind((char *) value);
        return 0;
}

int parse_yaml_dhcp_type(const char *key,
                         const char *value,
                         void *data,
                         void *userdata,
                         yaml_document_t *doc,
                         yaml_node_t *node) {
        Network *n;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        if (streq("dhcp4", key)) {
                r = parse_bool(value);
                if (r < 0)
                        return r;

                n->dhcp4 = r;

        } else if (streq("dhcp6", key)) {
                r = parse_bool(value);
                if (r < 0)
                        return r;

                n->dhcp6 = r;
        } else
                n->dhcp_type = dhcp_client_name_to_mode((char *) value);

        return 0;
}

int parse_yaml_link_local_type(const char *key,
                               const char *value,
                               void *data,
                               void *userdata,
                               yaml_document_t *doc,
                               yaml_node_t *node) {
        Network *n;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        r = link_local_address_type_to_kind((const char *) value);
        if (r < 0) {
                log_warning("Failed to parse link local address type='%s'", value);
                return r;
        }
        n->link_local = r;
        return 0;
}

int parse_yaml_keep_configuration(const char *key,
                                  const char *value,
                                  void *data,
                                  void *userdata,
                                  yaml_document_t *doc,
                                  yaml_node_t *node) {
        Network *n;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        r = keep_configuration_type_to_mode((const char *) value);
        if (r < 0) {
                log_warning("Failed to parse keep configuration mode='%s'", value);
                return r;
        }
        n->keep_configuration = r;
        return 0;
}

int parse_yaml_ipv6_address_generation_mode(const char *key,
                                            const char *value,
                                            void *data,
                                            void *userdata,
                                            yaml_document_t *doc,
                                            yaml_node_t *node) {
        Network *n;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        r = ipv6_link_local_address_gen_type_to_mode((const char *) value);
        if (r < 0) {
                log_warning("Failed to parse IPv6 link local address generation mode='%s'", value);
                return r;
        }
        n->ipv6_address_generation = r;
        return 0;
}

int parse_yaml_infiniband_mode(const char *key,
                               const char *value,
                               void *data,
                               void *userdata,
                               yaml_document_t *doc,
                               yaml_node_t *node) {
        Network *n;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        r = ipoib_name_to_mode((const char *) value);
        if (r < 0) {
                log_warning("Failed to parse ipoib mode='%s'", value);
                return r;
        }
        n->ipoib_mode = r;
        return 0;
}

int parse_yaml_dhcp6_without_ra(const char *key,
                                const char *value,
                                void *data,
                                void *userdata,
                                yaml_document_t *doc,
                                yaml_node_t *node) {
        Network *n;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        r = dhcp6_client_start_name_to_mode((const char *) value);
        if (r < 0) {
                log_warning("Failed to parse DHCP6 client start mode='%s'", value);
                return r;
        }
        n->dhcp6_client_start_mode = r;

        return 0;
}

int parse_yaml_ipv6_privacy_extensions(const char *key,
                                       const char *value,
                                       void *data,
                                       void *userdata,
                                       yaml_document_t *doc,
                                       yaml_node_t *node) {
        Network *n;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        r = ipv6_privacy_extensions_to_type((const char *) value);
        if (r < 0) {
                log_warning("Failed to parse IPv6PrivacyExtension='%s'", value);
                return r;
        }
        n->ipv6_privacy = r;
        return 0;
}

int parse_yaml_bond_mode(const char *key,
                         const char *value,
                         void *data,
                         void *userdata,
                         yaml_document_t *doc,
                         yaml_node_t *node) {
        Bond *b;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        b = data;

        r = bond_name_to_mode((const char *) value);
        if (r < 0) {
                log_warning("Failed to parse Bond mode='%s'", value);
                return r;
        }
        b->mode = r;
        return 0;
}

int parse_yaml_macvlan_mode(const char *key,
                            const char *value,
                            void *data,
                            void *userdata,
                            yaml_document_t *doc,
                            yaml_node_t *node) {
        MACVLan *m;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        m = data;

        r = macvlan_name_to_mode((const char *) value);
        if (r < 0) {
                log_warning("Failed to parse MACVLAN mode='%s'", value);
                return r;

        }
        m->mode = r;
        return 0;
}


int parse_yaml_address(const char *key,
                       const char *value,
                       void *data,
                       void *userdata,
                       yaml_document_t *doc,
                       yaml_node_t *node) {

        _auto_cleanup_ IPAddress *address = NULL;
        IPAddress **addr;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        addr = (IPAddress **) userdata;

        r = parse_ip_from_str(value, &address);
        if (r < 0) {
                log_warning("Failed to parse address='%s': %s", key, value);
                return r;
        }

        memcpy(addr, address, sizeof(IPAddress));
        return 0;
}

int parse_yaml_addresses(const char *key,
                         const char *value,
                         void *data,
                         void *userdata,
                         yaml_document_t *doc,
                         yaml_node_t *node) {

        Network *network;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        network = data;
        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                if (streq("addresses", key)) {
                        r = parse_address_from_str_and_add(scalar(entry), network->addresses);
                        if (r < 0 && r != -EEXIST)
                                return r;
                }
        }

        return 0;
}

int parse_yaml_nameserver_addresses(const char *key,
                                    const char *value,
                                    void *data,
                                    void *userdata,
                                    yaml_document_t *doc,
                                    yaml_node_t *node) {
        Network *network;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        network = data;
        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                r = parse_address_from_str_and_add(scalar(entry), network->nameservers);
                if (r < 0 && r != -EEXIST) {
                        log_warning("Failed to add DNS domains: %s", scalar(entry));
                        return r;
                }
        }

        return 0;
}

int parse_yaml_domains(const char *key,
                       const char *value,
                       void *data,
                       void *userdata,
                       yaml_document_t *doc,
                       yaml_node_t *node) {

        yaml_node_item_t *i;
        Network *network;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        network = data;
        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);
                _auto_cleanup_ char *p = NULL;

                p = strdup(scalar(entry));
                if (!p)
                        return log_oom();

                if (!set_contains(network->domains, p)) {
                        set_add(network->domains, p);
                        steal_ptr(p);
                }
        }

        return 0;
}

int parse_yaml_scalar_or_sequence(const char *key,
                                  const char *value,
                                  void *data,
                                  void *userdata,
                                  yaml_document_t *doc,
                                  yaml_node_t *node) {

        char ***s = (char ***) userdata;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        if (!isempty(key) && !isempty(value)) {
                *s = strv_new(value);
                if (!*s)
                        return -ENOMEM;
        }

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);
                _auto_cleanup_ char *c = NULL;

                c = strdup(scalar(entry));
                if (!c)
                        return log_oom();

                if (!*s)
                        r = strv_extend(s, c);
                else  if (!strv_contains((const char **)*s, c))
                        r = strv_extend(s, c);

                if (r < 0)
                        return r;
        }

        return 0;
}

int parse_yaml_sequence(const char *key,
                        const char *value,
                        void *data,
                        void *userdata,
                        yaml_document_t *doc,
                        yaml_node_t *node) {

        char ***s = (char ***) userdata;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);
                _auto_cleanup_ char *c = NULL;

                c = strdup(scalar(entry));
                if (!c)
                        return log_oom();

                if (!*s)
                        r = strv_extend(s, c);
                else  if (!strv_contains((const char **)*s, c))
                        r = strv_extend(s, c);

                if (r < 0)
                        return r;
        }

        return 0;
}

int parse_yaml_route(const char *key,
                     const char *value,
                     void *data,
                     void *userdata,
                     yaml_document_t *doc,
                     yaml_node_t *node) {

        Route *rt;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        rt = data;

        if (streq("to", key) || streq("via", key)) {
                _auto_cleanup_ IPAddress *address = NULL;
                bool b = false;

                r = parse_ip_from_str(value, &address);
                if (r < 0) {
                        if (streq("default", value))
                                b = true;
                        else {
                                log_warning("Failed to parse %s='%s'", key, value);
                                return r;
                        }
                }

                if (streq("0.0.0.0/0", value) || streq("::/0", value))
                        b = true;

                if (streq("to", key)) {
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

        return 0;
}

int parse_yaml_route_type(const char *key,
                          const char *value,
                          void *data,
                          void *userdata,
                          yaml_document_t *doc,
                          yaml_node_t *node) {

        Route *rt;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        rt = data;

        r = route_type_to_mode(value);
        if (r < 0) {
                log_warning("Failed to parse route type='%s'", value);
                return r;
        }
        rt->type = r;
        return 0;
}

int parse_yaml_route_scope(const char *key,
                           const char *value,
                           void *data,
                           void *userdata,
                           yaml_document_t *doc,
                           yaml_node_t *node) {

        Route *rt;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        rt = data;

        r = route_scope_type_to_mode(value);
        if (r < 0) {
                log_warning("Failed to parse route scope='%s'", value);
                return r;
        }
        rt->scope = r;

        return 0;
}

int parse_yaml_vxlan_notifications(const char *key,
                                   const char *value,
                                   void *data,
                                   void *userdata,
                                   yaml_document_t *doc,
                                   yaml_node_t *node) {

        VxLan *v;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                if (streq(scalar(entry), "l2-miss"))
                        v->l2miss = true;
                else if (streq(scalar(entry), "l3-miss"))
                        v->l3miss = true;
        }

        return 0;
}

int parse_yaml_vxlan_csum(const char *key,
                          const char *value,
                          void *data,
                          void *userdata,
                          yaml_document_t *doc,
                          yaml_node_t *node) {

        VxLan *v;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                if (streq(scalar(entry), "udp"))
                        v->udpcsum = true;
                else if (streq(scalar(entry), "zero-udp6-tx"))
                        v->udp6zerocsumtx = true;
                else if (streq(scalar(entry), "zero-udp6-rx"))
                        v->udp6zerocsumrx = true;
                else if (streq(scalar(entry), "zero-udp6-tx"))
                        v->udp6zerocsumtx = true;
                else if (streq(scalar(entry), "remote-tx"))
                        v->remote_csum_tx = true;
                else if (streq(scalar(entry), "remote-rx"))
                        v->remote_csum_rx = true;
        }

        return 0;
}

int parse_yaml_vxlan_extensions(const char *key,
                                const char *value,
                                void *data,
                                void *userdata,
                                yaml_document_t *doc,
                                yaml_node_t *node) {

        VxLan *v;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                if (streq(scalar(entry), "group-policy"))
                        v->group_policy = true;
                else if (streq(scalar(entry), "generic-protocol"))
                        v->generic_protocol_extension = true;
        }

        return 0;
}

int parse_yaml_vxlan_port_range(const char *key,
                                const char *value,
                                void *data,
                                void *userdata,
                                yaml_document_t *doc,
                                yaml_node_t *node) {

        bool b = false;
        VxLan *v;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);
                uint16_t k;

                r = parse_uint16(scalar(entry), &k);
                if (r < 0) {
                        log_warning("Failed to parse port range: %s", scalar(entry));
                        return r;
                }

                if (!b) {
                        v->low_port = k;
                        b = true;
                } else
                        v->high_port = k;
        }

        return 0;
}

int parse_yaml_bond_lacp_rate(const char *key,
                              const char *value,
                              void *data,
                              void *userdata,
                              yaml_document_t *doc,
                              yaml_node_t *node) {

        Bond *b;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        b = data;

        r = bond_lacp_rate_to_mode(value);
        if (r < 0) {
                log_warning("Failed to parse bond lacp rate type='%s'", value);
                return r;
        }

        b->lacp_rate = r;
        return 0;
}

int parse_yaml_bond_arp_validate(const char *key,
                                 const char *value,
                                 void *data,
                                 void *userdata,
                                 yaml_document_t *doc,
                                 yaml_node_t *node) {

        Bond *b;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        b = data;

        r = bond_arp_validate_table_name_to_mode(value);
        if (r < 0) {
                log_warning("Failed to parse bond arp validate type='%s'", value);
                return r;
        }

        b->arp_validate = r;
        return 0;
}

int parse_yaml_bond_fail_over_mac(const char *key,
                                  const char *value,
                                  void *data,
                                  void *userdata,
                                  yaml_document_t *doc,
                                  yaml_node_t *node) {

        Bond *b;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        b = data;

        r = bond_fail_over_mac_name_to_mode(value);
        if (r < 0) {
                log_warning("Failed to parse bond fail over mac type='%s'", value);
                return r;
        }

        b->fail_over_mac = r;
        return 0;
}

int parse_yaml_bond_ad_select(const char *key,
                              const char *value,
                              void *data,
                              void *userdata,
                              yaml_document_t *doc,
                              yaml_node_t *node) {

        Bond *b;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        b = data;

        r = bond_ad_select_name_to_mode(value);
        if (r < 0) {
                log_warning("Failed to parse bond fail over mac type='%s'", value);
                return r;
        }

        b->ad_select = r;
        return 0;
}

int parse_yaml_bond_primary_reselect(const char *key,
                                     const char *value,
                                     void *data,
                                     void *userdata,
                                     yaml_document_t *doc,
                                     yaml_node_t *node) {

        Bond *b;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        b = data;

        r = bond_primary_reselect_name_to_mode(value);
        if (r < 0) {
                log_warning("Failed to parse bond primary reselect type='%s'", value);
                return r;
        }

        b->primary_reselect = r;
        return 0;
}

int parse_yaml_bond_xmit_hash_policy(const char *key,
                                     const char *value,
                                     void *data,
                                     void *userdata,
                                     yaml_document_t *doc,
                                     yaml_node_t *node) {

        Bond *b;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        b = data;

        r = bond_xmit_hash_policy_name_to_mode(value);
        if (r < 0) {
                log_warning("Failed to parse bond xmit hash policy type='%s'", value);
                return r;
        }

        b->xmit_hash_policy = r;
        return 0;
}

int parse_yaml_wireguard_key_or_path(const char *key,
                                     const char *value,
                                     void *data,
                                     void *userdata,
                                     yaml_document_t *doc,
                                     yaml_node_t *node) {
        WireGuard *w;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        w = (WireGuard *) data;

        if (streq(key, "key")) {
                if (string_has_prefix(value, "/")) {
                        w->private_key_file = strdup(value);
                        if (!w->private_key_file)
                                return log_oom();
                } else {
                        w->private_key = strdup(value);
                        if (!w->private_key)
                                return log_oom();
                }
        }

        return 0;
}

int parse_yaml_sequence_wireguard_peer_shared_key_or_path(const char *key,
                                                          const char *value,
                                                          void *data,
                                                          void *userdata,
                                                          yaml_document_t *doc,
                                                          yaml_node_t *node) {

        WireGuardPeer *w;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        w = (WireGuardPeer *) data;

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *k, *v;

                k = yaml_document_get_node(doc, *i++);
                v = yaml_document_get_node(doc, *i);

                if (streq(scalar(k), "shared")) {
                        if (string_has_prefix(value, "/")) {
                                w->preshared_key_file = strdup(scalar(v));
                                if (!w->preshared_key_file)
                                        return log_oom();
                        } else {
                                w->preshared_key = strdup(scalar(v));
                                if (!w->preshared_key)
                                        return log_oom();
                        }
                } else if (streq(scalar(k), "public")) {
                        w->public_key = strdup(scalar(v));
                        if (!w->public_key)
                                return log_oom();
                }
        }

        return 0;
}

int parse_yaml_bridge_path_cost(const char *key,
                                const char *value,
                                void *data,
                                void *userdata,
                                yaml_document_t *doc,
                                yaml_node_t *node) {

        Networks *p;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = data;

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *k = yaml_document_get_node(doc, *i++);
                yaml_node_t *v = yaml_document_get_node(doc, *i);
                Network *n = g_hash_table_lookup(p->networks, scalar(k));
                uint32_t t;

                r = parse_uint32(scalar(v), &t);
                if (r < 0) {
                        log_warning("Failed to parse bridge cost='%s'", scalar(v));
                        return r;
                }

                if (!n) {
                        r = yaml_network_new(scalar(k), &n);
                        if (r < 0)
                                return r;

                        if (!g_hash_table_insert(p->networks, (gpointer *) n->ifname, (gpointer *) n))
                                return log_oom();
                }
                n->cost = t;
        }

        return 0;
}

int parse_yaml_bridge_port_priority(const char *key,
                                    const char *value,
                                    void *data,
                                    void *userdata,
                                    yaml_document_t *doc,
                                    yaml_node_t *node) {

        Networks *p;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        p = data;

        for (yaml_node_item_t *i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *k = yaml_document_get_node(doc, *i++);
                yaml_node_t *v = yaml_document_get_node(doc, *i);
                Network *n = g_hash_table_lookup(p->networks, scalar(k));
                uint16_t t;

                r = parse_uint16(scalar(v), &t);
                if (r < 0) {
                        log_warning("Failed to parse bridge cost='%s'", scalar(v));
                        return r;
                }

                if (!n) {
                        r = yaml_network_new(scalar(k), &n);
                        if (r < 0)
                                return r;

                        if (!g_hash_table_insert(p->networks, (gpointer *) n->ifname, (gpointer *) n))
                                return log_oom();
                }
                n->priority = t;
        }

        return 0;
}

int parse_yaml_sriov_vlan_protocol(const char *key,
                                   const char *value,
                                   void *data,
                                   void *userdata,
                                   yaml_document_t *doc,
                                   yaml_node_t *node) {

        SRIOV *v;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        r = parse_sriov_vlan_protocol(value);
        if (r < 0) {
                log_warning("Failed to configure sriov vlan proto ='%s': %s", value, strerror(EINVAL));
                return r;
        }

        v->vlan_proto = strdup(value);
        if (!v->vlan_proto)
                return log_oom();

        return 0;
}

int parse_yaml_sriov_link_state(const char *key,
                                const char *value,
                                void *data,
                                void *userdata,
                                yaml_document_t *doc,
                                yaml_node_t *node) {

        SRIOV *v;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        r = parse_sriov_link_state(value);
        if (r < 0) {
                log_warning("Failed to configure sriov link state ='%s': %s", value, strerror(EINVAL));
                return r;
        }

        v->link_state = r;
        return 0;
}
