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

        r = parse_boolean(value);
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

        *mac =  g_strdup(value);
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
        r = address_family_name_to_type(value);
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
                log_warning("Failed to parse activation-mode='%s': %s", value, strerror(EINVAL));
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

int parse_yaml_auth_eap_method(const char *key,
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

        p->auth->key_management = auth_key_management_type_to_mode(key);
        switch (p->auth->key_management) {
                case AUTH_KEY_MANAGEMENT_NONE:
                        p->auth->password = g_strdup(value);
                        if (!p->auth->password)
                                return log_oom();
                        break;
                case AUTH_KEY_MANAGEMENT_WPA_PSK:
                        p->auth->password = g_strdup(value);
                        if (!p->auth->password)
                                return log_oom();
                        break;
                default:
                        break;
        }

        return 0;
}

int parse_yaml_dhcp_client_identifier(const char *key,
                                      const char *value,
                                      void *data,
                                      void *userdata,
                                      yaml_document_t *doc,
                                      yaml_node_t *node) {

        Network *n;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;
        n->dhcp_client_identifier_type = dhcp_client_identifier_to_mode((char *) value);

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

        if (string_equal("dhcp4", key)) {
                r = parse_boolean(value);
                if (r < 0)
                        return r;

                n->dhcp4 = r;

        } else if (string_equal("dhcp6", key)) {
                r = parse_boolean(value);
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

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        n->link_local = link_local_address_type_to_mode((const char *) value);
        return 0;
}

int parse_yaml_ipv6_address_generation_mode(const char *key,
                                            const char *value,
                                            void *data,
                                            void *userdata,
                                            yaml_document_t *doc,
                                            yaml_node_t *node) {
        Network *n;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        n->ipv6_address_generation = ipv6_link_local_address_gen_type_to_mode((const char *) value);
        return 0;
}

int parse_yaml_ipv6_privacy_extensions(const char *key,
                                       const char *value,
                                       void *data,
                                       void *userdata,
                                       yaml_document_t *doc,
                                       yaml_node_t *node) {
        Network *n;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        n = data;

        n->ipv6_privacy = ipv6_privacy_extensions_to_type((const char *) value);
        return 0;
}

int parse_yaml_bond_mode(const char *key,
                         const char *value,
                         void *data,
                         void *userdata,
                         yaml_document_t *doc,
                         yaml_node_t *node) {
        Bond *b;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        b = data;

        b->mode = bond_name_to_mode((const char *) value);
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

        r = parse_ip_from_string(value, &address);
        if (r < 0) {
                log_warning("Failed to parse address %s = %s", key, value);
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

        yaml_node_item_t *i;
        Network *network;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        network = data;
        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                if (string_equal("addresses", key))
                        r = parse_address_from_string_and_add(scalar(entry), network->addresses);
                else if (string_equal("ntps", key))
                        r = parse_address_from_string_and_add(scalar(entry), network->ntps);
                else
                        continue;

                if (r < 0 && r != -EEXIST)
                        return r;
        }

        return 0;
}

int parse_yaml_nameserver_addresses(const char *key,
                                    const char *value,
                                    void *data,
                                    void *userdata,
                                    yaml_document_t *doc,
                                    yaml_node_t *node) {
        yaml_node_item_t *i;
        Network *network;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        network = data;
        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                r = parse_address_from_string_and_add(scalar(entry), network->nameservers);
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

                set_add(network->domains, p);
                steal_pointer(p);
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
        yaml_node_item_t *i;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        if (!isempty_string(key) && !isempty_string(value)) {
                *s = strv_new(value);
                if (!*s)
                        return -ENOMEM;
        }

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);
                _auto_cleanup_ char *c = NULL;

                c = strdup(scalar(entry));
                if (!c)
                        return log_oom();

                if (!*s) {
                        *s = strv_new(c);
                        if (!*s)
                                return log_oom();
                } else {
                        r = strv_add(s, strdup(c));
                        if (r < 0)
                                return r;
                }

                steal_pointer(c);
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
        yaml_node_item_t *i;
        int r;

        assert(key);
        assert(data);
        assert(doc);
        assert(node);

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);
                _auto_cleanup_ char *c = NULL;

                c = strdup(scalar(entry));
                if (!c)
                        return log_oom();

                if (!*s) {
                        *s = strv_new(c);
                        if (!*s)
                                return log_oom();
                } else {
                        r = strv_add(s, strdup(c));
                        if (r < 0)
                                return r;
                }

                steal_pointer(c);
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

        if (string_equal("to", key) || string_equal("via", key)) {
                _auto_cleanup_ IPAddress *address = NULL;
                bool b = false;

                r = parse_ip_from_string(value, &address);
                if (r < 0) {
                        if (string_equal("default", value))
                                b = true;
                        else {
                                log_warning("Failed to parse %s='%s'", key, value);
                                return r;
                        }
                }

                if (string_equal("0.0.0.0/0", value) || string_equal("::/0", value))
                        b = true;

                if (string_equal("to", key)) {
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
                log_warning("Failed to parse route type='%s'\n", value);
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
                log_warning("Failed to parse route scope='%s'\n", value);
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

        yaml_node_item_t *i;
        VxLan *v;;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                if (string_equal(scalar(entry), "l2-miss"))
                        v->l2miss = true;
                else if (string_equal(scalar(entry), "l3-miss"))
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

        yaml_node_item_t *i;
        VxLan *v;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                if (string_equal(scalar(entry), "udp"))
                        v->udpcsum = true;
                else if (string_equal(scalar(entry), "zero-udp6-tx"))
                        v->udp6zerocsumtx = true;
                else if (string_equal(scalar(entry), "zero-udp6-rx"))
                        v->udp6zerocsumrx = true;
                else if (string_equal(scalar(entry), "zero-udp6-tx"))
                        v->udp6zerocsumtx = true;
                else if (string_equal(scalar(entry), "remote-tx"))
                        v->remote_csum_tx = true;
                else if (string_equal(scalar(entry), "remote-rx"))
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

        yaml_node_item_t *i;
        VxLan *v;;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

                if (string_equal(scalar(entry), "group-policy"))
                        v->group_policy = true;
                else if (string_equal(scalar(entry), "generic-protocol"))
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

        yaml_node_item_t *i;
        bool b = false;
        uint16_t k;
        VxLan *v;
        int r;

        assert(key);
        assert(value);
        assert(data);
        assert(doc);
        assert(node);

        v = data;

        for (i = node->data.sequence.items.start; i < node->data.sequence.items.top; i++) {
                yaml_node_t *entry = yaml_document_get_node(doc, *i);

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
                log_warning("Failed to parse bond lacp rate type='%s'\n", value);
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
                log_warning("Failed to parse bond arp validate type='%s'\n", value);
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
                log_warning("Failed to parse bond fail over mac type='%s'\n", value);
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
                log_warning("Failed to parse bond fail over mac type='%s'\n", value);
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
                log_warning("Failed to parse bond primary reselect type='%s'\n", value);
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
                log_warning("Failed to parse bond xmit hash policy type='%s'\n", value);
                return r;
        }

        b->xmit_hash_policy = r;
        return 0;
}
