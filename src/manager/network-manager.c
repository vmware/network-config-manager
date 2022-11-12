/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <net/if.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "dracut-parser.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "network-address.h"
#include "dbus.h"
#include "network.h"
#include "network-link.h"
#include "network-manager.h"
#include "networkd-api.h"
#include "parse-util.h"
#include "string-util.h"
#include "yaml-network-parser.h"
#include "yaml-link-parser.h"

static const Config network_ctl_to_network_section_config_table[] = {
                { "set-link-local-address",   "LinkLocalAddressing"},
                { "set-ipv4ll-route",         "IPv4LLRoute"},
                { "set-llmnr",                "LLMNR"},
                { "set-multicast-dns",        "MulticastDNS" },
                { "set-lldp",                 "LLDP"},
                { "set-emit-lldp",            "EmitLLDP"},
                { "set-ipforward",            "IPForward"},
                { "set-ipv6acceptra",         "IPv6AcceptRA"},
                { "set-ipmasquerade",         "IPMasquerade"},
                { "set-proxyarp",             "IPv4ProxyARP"},
                { "set-proxyndp",             "IPv6ProxyNDP"},
                { "set-conf-without-carrier", "ConfigureWithoutCarrier"},
                {},
};

static const Config network_ctl_to_dhcp4_section_config_table[] = {
                { "use-dns",      "UseDNS"},
                { "use-ntp",      "UseNTP"},
                { "use-domains",  "UseDomains"},
                { "use-mtu",      "UseMTU"},
                { "use-routes",   "UseRoutes"},
                { "use-timezone", "UseTimezone"},
                { "send-release", "SendRelease"},
                {},
};

static const Config network_ctl_to_dhcp6_section_config_table[] = {
                { "use-dns",      "UseDNS"},
                { "use-ntp",      "UseNTP"},
                { "use-domains",  "UseDomains"},
                { "use-mtu",      "UseMTU"},
                {},
};

int manager_network_section_bool_configs_new(ConfigManager **ret) {
        ConfigManager *m;
        int r;

        r = config_manager_new(network_ctl_to_network_section_config_table, &m);
        if (r < 0)
                return r;

        *ret = m;
        return 0;
}

int manager_network_dhcp4_section_configs_new(ConfigManager **ret) {
        ConfigManager *m;
        int r;

        r = config_manager_new(network_ctl_to_dhcp4_section_config_table, &m);
        if (r < 0)
                return r;

        *ret = m;
        return 0;
}

int manager_network_dhcp6_section_configs_new(ConfigManager **ret) {
        ConfigManager *m;
        int r;

        r = config_manager_new(network_ctl_to_dhcp6_section_config_table, &m);
        if (r < 0)
                return r;

        *ret = m;
        return 0;
}

int manager_set_link_flag(const IfNameIndex *ifnameidx, bool mode, const char* key) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);
        assert(key);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        if (!network) {
                log_warning("Failed to find network file for '%s'. systemd-networkd is configuring. Please try in a while.", ifnameidx->ifname);
                return -ENODATA;
        }

        r = set_config_file_bool(network, "Link", key, mode);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_set_link_dhcp_client(const IfNameIndex *ifnameidx, DHCPClient mode) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        if (!network) {
                log_warning("Failed to find network file for '%s'. systemd-networkd is configuring. Please try after a while.", ifnameidx->ifname);
                return -ENODATA;
        }

        r = set_config_file_string(network, "Network", "DHCP", dhcp_client_modes_to_name(mode));
        if (r < 0) {
                log_warning("Failed to write to configuration file: %s", network);
                return r;
        }

        return dbus_network_reload();
}

int manager_get_link_dhcp_client(const IfNameIndex *ifnameidx, DHCPClient *mode) {
        _auto_cleanup_ char *network = NULL, *config_dhcp = NULL;
        int r;

        assert(ifnameidx);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, "Network", "DHCP", &config_dhcp);
        if (r < 0)
                return r;

        r = dhcp_client_name_to_mode(config_dhcp);
        if (r < 0)
                return r;

        *mode = r;
        return 0;
}

int manager_set_link_dhcp4_client_identifier(const IfNameIndex *ifnameidx, DHCPClientIdentifier identifier) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = set_config_file_string(network, "DHCPv4", "ClientIdentifier", dhcp_client_identifier_to_name(identifier));
        if (r < 0) {
                log_warning("Failed to update DHCP4 ClientIdentifier= to configuration file '%s': %s", network, g_strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_get_link_dhcp4_client_identifier(const IfNameIndex *ifnameidx, DHCPClientIdentifier *ret) {
        _auto_cleanup_ char *network = NULL, *config = NULL;
        int r;

        assert(ifnameidx);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, "DHCPv4", "ClientIdentifier", &config);
        if (r < 0)
                return r;

        *ret = dhcp_client_identifier_to_mode(config);
        return 0;
}

int manager_set_link_dhcp_client_iaid(const IfNameIndex *ifnameidx, DHCPClient kind, uint32_t iaid) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = set_config_file_integer(network, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "IAID", iaid);
        if (r < 0) {
                log_warning("Failed to update DHCP IAID= to configuration file '%s': %s", network, g_strerror(-r));
                return r;
        }

        return 0;
}

int manager_get_link_dhcp_client_iaid(const IfNameIndex *ifnameidx, DHCPClient kind, uint32_t *iaid) {
        _auto_cleanup_ char *network = NULL;
        uint32_t v;
        int r;

        assert(ifnameidx);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file_integer(network, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "IAID", &v);
        if (r < 0)
                return r;

        *iaid = v;
        return 0;
}

int manager_set_link_dhcp_client_duid(const IfNameIndex *ifnameidx, DHCPClientDUIDType duid, char *raw_data, bool system, DHCPClient kind) {
        _auto_cleanup_ char *c = NULL;
        int r;

        if (system) {
                c = g_strdup("/etc/systemd/networkd.conf");
                if (!c)
                        return log_oom();
        } else {
                r = create_or_parse_network_file(ifnameidx, &c);
                if (r < 0)
                        return r;
        }

        r = set_config_file_string(c, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "DUIDType", dhcp_client_duid_type_to_name(duid));
        if (r < 0) {
                log_warning("Failed to update %s DUIDType= to configuration file '%s': %s", kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", c, g_strerror(-r));
                return r;
        }

        if (raw_data) {
                r = set_config_file_string(c, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "DUIDRawData", raw_data);
                if (r < 0) {
                        log_warning("Failed to update %s DUIDRawData= to configuration file '%s': %s", kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", c, g_strerror(-r));
                        return r;
                }
        }

        return 0;
}

int manager_set_link_mtu(const IfNameIndex *ifnameidx, uint32_t mtu) {
        _auto_cleanup_ char *network = NULL, *config_update_mtu = NULL;
        int r;

        assert(ifnameidx);
        assert(mtu > 0);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        asprintf(&config_update_mtu, "%u", mtu);
        r = set_config_file_string(network, "Link", "MTUBytes", config_update_mtu);
        if (r < 0) {
                log_warning("Failed to update MTUBytes= to configuration file '%s' = %s", network, g_strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_group(const IfNameIndex *ifnameidx, uint32_t group) {
        _auto_cleanup_ char *network = NULL, *config_update_group = NULL;
        int r;

        assert(ifnameidx);
        assert(group > 0);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        asprintf(&config_update_group, "%u", group);

        r = set_config_file_string(network, "Link", "Group", config_update_group);
        if (r < 0) {
                log_warning("Failed to update Group= to configuration file '%s' = %s", network, g_strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_rf_online(const IfNameIndex *ifnameidx, const char *addrfamily) {
        _auto_cleanup_ char *network = NULL, *config_update_family = NULL;
        int r;

        assert(ifnameidx);
        assert(addrfamily);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        asprintf(&config_update_family, "%s", addrfamily);
        r = set_config_file_string(network, "Link", "RequiredFamilyForOnline", config_update_family);
        if (r < 0) {
                log_warning("Failed to write to configuration file: %s", network);
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_act_policy(const IfNameIndex *ifnameidx, const char *actpolicy) {
        _auto_cleanup_ char *network = NULL, *config_update_policy = NULL;
        int r;

        assert(ifnameidx);
        assert(actpolicy);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        asprintf(&config_update_policy, "%s", actpolicy);
        r = set_config_file_string(network, "Link", "ActivationPolicy", config_update_policy);
        if (r < 0) {
                log_warning("Failed to write to configuration file: %s", network);
                return r;
        }

        return dbus_network_reload();
}

int manager_link_set_network_ipv6_mtu(const IfNameIndex *ifnameidx, uint32_t mtu) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);
        assert(mtu > 0);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = set_config_file_integer(network, "Network", "IPv6MTUBytes", mtu);
        if (r < 0) {
                log_warning("Failed to update IPv6MTUBytes= to configuration file '%s' = %s", network, g_strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_mac_addr(const IfNameIndex *ifnameidx, const char *mac) {
        _auto_cleanup_ char *network = NULL, *config_mac = NULL, *config_update_mac = NULL;
        int r;

        assert(ifnameidx);
        assert(mac);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, "Link", "MACAddress", &config_mac);
        if (r >= 0) {
                if (string_equal(config_mac, mac))
                        return 0;
        }

        asprintf(&config_update_mac, "%s", mac);
        r = set_config_file_string(network, "Link", "MACAddress", config_update_mac);
        if (r < 0) {
                log_warning("Failed to write to configuration file: %s", network);
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_state(const IfNameIndex *ifnameidx, LinkState state) {
        assert(ifnameidx);

        return link_set_state(ifnameidx, state);
}

int manager_configure_link_address(const IfNameIndex *ifnameidx,
                                   IPAddress *address,
                                   IPAddress *peer,
                                   char *scope,
                                   char *pref_lft,
                                   IPDuplicateAddressDetection dad,
                                   int prefix_route,
                                   const char *label) {

        _auto_cleanup_ char *network = NULL, *a = NULL, *p = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = section_new("Address", &section);
        if (r < 0)
                return r;

        if (address) {
                if (!address->prefix_len)
                        r = ip_to_string(address->family, address, &a);
                else
                        r = ip_to_string_prefix(address->family, address, &a);
                if (r < 0)
                        return r;
        }

        if (peer) {
                if (!peer->prefix_len)
                        r = ip_to_string(peer->family, peer, &p);
                else
                        r = ip_to_string_prefix(peer->family, peer, &p);
                if (r < 0)
                        return r;
        }

        if (a)
                add_key_to_section(section, "Address", a);

        if (p)
                add_key_to_section(section, "Peer", p);

        if (scope)
                add_key_to_section(section, "Scope", scope);

        if (pref_lft)
                add_key_to_section(section, "PreferredLifetime", pref_lft);

        if (label)
                add_key_to_section(section, "Label", label);

        if (prefix_route >= 0)
                add_key_to_section(section, "AddPrefixRoute", bool_to_string(prefix_route));

        if (dad != _IP_DUPLICATE_ADDRESS_DETECTION_INVALID)
                add_key_to_section(section, "DuplicateAddressDetection", ip_duplicate_address_detection_type_to_name(dad));

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_pointer(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, g_strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_delete_link_address(const IfNameIndex *ifnameidx, const char *a) {
        _auto_cleanup_ char *setup = NULL, *network = NULL;
        int r;

        assert(ifnameidx);
        assert(a);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0) {
                log_warning("Failed to find link setup '%s': %s", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0) {
                log_warning("Failed to find .network file for '%s': %s", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = remove_section_from_config_file_key(network, "Address", "Address", a);
        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, g_strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_configure_default_gateway(const IfNameIndex *ifnameidx, Route *rt) {
        _auto_cleanup_ char *network = NULL, *a = NULL;
        int r;

        assert(ifnameidx);
        assert(rt);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = manager_link_add_default_gateway(rt);
        if (r < 0 && r != -EEXIST) {
                log_warning("Failed to add Gateway to kernel : %s\n", g_strerror(-r));
                return r;
        }

        r = ip_to_string(rt->gw.family, &rt->gw, &a);
        if (r < 0)
                return r;

        r = set_config_file_string(network, "Route", "Gateway", a);
        if (r < 0) {
                log_warning("Failed to write to configuration file: %s", network);
                return r;
        }

        if (rt->onlink > 0) {
                r = set_config_file_string(network, "Route", "GatewayOnlink", bool_to_string(rt->onlink));
                if (r < 0) {
                        log_warning("Failed to write to configuration file: %s", network);
                        return r;
                }
        }

        return dbus_network_reload();
}

int manager_configure_route(const IfNameIndex *ifnameidx,
                            IPAddress *gateway,
                            IPAddress *destination,
                            IPAddress *source,
                            IPAddress *pref_source,
                            IPv6RoutePreference rt_pref,
                            RouteProtocol protocol,
                            RouteScope scope,
                            RouteType type,
                            RouteTable table,
                            uint32_t mtu,
                            int metric,
                            int onlink) {

        _auto_cleanup_ char *network = NULL, *gw = NULL, *dest = NULL, *src = NULL, *pref_src = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = section_new("Route", &section);
        if (r < 0)
                return r;

        if (gateway) {
                r = ip_to_string(gateway->family, gateway, &gw);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Gateway", gw);
        }

        if (onlink >= 0)
                add_key_to_section(section, "GatewayOnLink", bool_to_string(onlink));

        if (source) {
                r = ip_to_string_prefix(gateway->family, source, &src);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Source", src);
        }

        if (pref_source) {
                r = ip_to_string_prefix(pref_source->family, pref_source, &pref_src);
                if (r < 0)
                        return r;

                add_key_to_section(section, "PreferredSource", pref_src);
        }

        if (destination) {
                r = ip_to_string_prefix(destination->family, destination, &dest);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Destination", dest);
        }

        if (metric > 0)
                add_key_to_section_integer(section, "Metric", metric);

        if (mtu > 0)
                add_key_to_section_integer(section, "MTUBytes", mtu);

        if (protocol > 0) {
                if (route_protocol_to_name(protocol))
                        add_key_to_section(section, "Protocol", route_protocol_to_name(protocol));
                else
                        add_key_to_section_integer(section, "Protocol", protocol);
        }

        if (rt_pref >= 0)
                add_key_to_section(section, "IPv6Preference", ipv6_route_preference_to_name(rt_pref));

        if (scope > 0)
                add_key_to_section(section, "Scope", route_scope_type_to_name(scope));

        if (type > 0)
                add_key_to_section(section, "Type", route_type_to_name(type));

        if (table > 0) {
                if (route_table_to_name(table))
                        add_key_to_section(section, "Table", route_table_to_name(table));
                else
                        add_key_to_section_integer(section, "Table", table);
        }

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_pointer(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, g_strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_remove_gateway_or_route(const IfNameIndex *ifnameidx, bool gateway) {
        _auto_cleanup_ char *setup = NULL, *network = NULL, *config = NULL;
        int r;

        assert(ifnameidx);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0) {
                log_warning("Failed to find link setup '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0)
                return r;

        if (gateway) {
                r = parse_config_file(network, "Route", "Gateway", &config);
                if (r >= 0) {
                        r = remove_key_from_config_file(network, "Route", "Gateway");
                        if (r < 0)
                                return r;

                        (void) remove_key_from_config_file(network, "Route", "GatewayOnlink");
                }
        } else {
                r = parse_config_file(network, "Route", "Destination", &config);
                if (r >= 0) {
                        r = remove_key_from_config_file(network, "Route", "Destination");
                        if (r < 0)
                                return r;
                }

                r = parse_config_file(network, "Route", "Metric", &config);
                if (r >= 0)
                        (void) remove_key_from_config_file(network, "Route", "Metric");
        }

        return dbus_network_reload();
}

int manager_configure_routing_policy_rules(const IfNameIndex *ifnameidx,
                                           const IfNameIndex *iif,
                                           const IfNameIndex *oif,
                                           const IPAddress *to_addr,
                                           const IPAddress *from_addr,
                                           const uint32_t table,
                                           const uint32_t priority,
                                           const char *tos) {

        _auto_cleanup_ char *network = NULL, *to = NULL, *from = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0) {
                log_warning("Failed to find or create network file '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = ip_to_string_prefix(to_addr->family, to_addr, &to);
        if (r < 0)
                return r;

        r = ip_to_string_prefix(from_addr->family, from_addr, &from);
        if (r < 0)
                return r;

        r = section_new("RoutingPolicyRule", &section);
        if (r < 0)
                return r;

        if (tos)
                add_key_to_section(section, "TypeOfService", tos);

        add_key_to_section_integer(section, "Table", table);

        if (priority > 0)
                add_key_to_section_integer(section, "Priority", priority);

        if (from)
                add_key_to_section(section, "From", from);

        if (to)
                add_key_to_section(section, "To", to);

        if (iif)
                add_key_to_section(section, "IncomingInterface", iif->ifname);

        if (oif)
                add_key_to_section(section, "OutgoingInterface", oif->ifname);

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_pointer(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, g_strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_remove_routing_policy_rules(const IfNameIndex *ifnameidx) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0) {
                log_warning("Failed to create or parse network file '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = remove_section_from_config_file(network, "RoutingPolicyRule");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_configure_additional_gw(const IfNameIndex *ifnameidx, Route *rt) {
        _auto_cleanup_ char *network = NULL, *address = NULL, *gw = NULL, *destination = NULL, *pref_source = NULL;
        _cleanup_(g_string_unrefp) GString *config = NULL;
        int r;

        assert(ifnameidx);
        assert(rt);

        r = create_network_conf_file(ifnameidx->ifname, &network);
        if (r < 0) {
                log_warning("Failed to find or create network file '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = ip_to_string_prefix(rt->address.family, &rt->address, &address);
        if (r < 0)
                return r;

        r = ip_to_string(rt->destination.family, &rt->destination, &destination);
        if (r < 0)
                return r;

        r = ip_to_string(rt->gw.family, &rt->gw, &gw);
        if (r < 0)
                return r;

        config = g_string_new(NULL);
        if (!config)
                return log_oom();

        g_string_append(config, "[Match]\n");
        g_string_append_printf(config, "Name=%s\n\n", ifnameidx->ifname);

        g_string_append(config, "[Address]\n");
        g_string_append_printf(config, "Address=%s\n\n", address);

        r = ip_to_string_prefix(rt->address.family, &rt->address, &pref_source);
        if (r < 0)
                return r;

        g_string_append(config, "[Route]\n");
        g_string_append_printf(config, "Table=%d\n", rt->table);
        g_string_append_printf(config, "PreferredSource=%s\n", pref_source);
        g_string_append_printf(config, "Destination=%s\n\n", destination);

        g_string_append(config, "[Route]\n");
        g_string_append_printf(config, "Table=%d\n", rt->table);
        g_string_append_printf(config, "Gateway=%s\n\n", gw);

        g_string_append(config, "[RoutingPolicyRule]\n");
        g_string_append_printf(config, "Table=%d\n", rt->table);
        g_string_append_printf(config, "To=%s\n\n", address);

        g_string_append(config, "[RoutingPolicyRule]\n");
        g_string_append_printf(config, "Table=%d\n", rt->table);
        g_string_append_printf(config, "From=%s\n", address);

        r = write_to_conf_file(network, config);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_configure_dhcpv4_server(const IfNameIndex *ifnameidx,
                                    const IPAddress *dns_address,
                                    const IPAddress *ntp_address,
                                    const uint32_t pool_offset,
                                    const uint32_t pool_size,
                                    const uint32_t default_lease_time,
                                    const uint32_t max_lease_time,
                                    const int emit_dns,
                                    const int emit_ntp,
                                    const int emit_router) {

        _auto_cleanup_ char *network = NULL, *dns = NULL, *ntp = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0) {
                log_warning("Failed to find or create network file '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        if (dns_address) {
                r = ip_to_string(dns_address->family, dns_address, &dns);
                if (r < 0)
                        return r;
        }

        if (ntp_address) {
                r = ip_to_string(ntp_address->family, ntp_address, &ntp);
                if (r < 0)
                        return r;
        }

        r = set_config(key_file, "Network", "DHCPServer", "yes");
        if (r < 0)
                return r;

        r = section_new("DHCPServer", &section);
        if (r < 0)
                return r;

        if (pool_offset > 0)
                add_key_to_section_integer(section, "PoolOffset", pool_offset);

        if (pool_size > 0)
                add_key_to_section_integer(section, "PoolSize", pool_size);

        if (default_lease_time > 0)
                add_key_to_section_integer(section, "DefaultLeaseTimeSec", default_lease_time);

        if (max_lease_time > 0)
                add_key_to_section_integer(section, "MaxLeaseTimeSec", max_lease_time);

        if (dns)
                add_key_to_section(section, "DNS", dns);

        if (emit_dns >= 0)
                add_key_to_section(section, "EmitDNS", bool_to_string(emit_dns));

        if (ntp)
                add_key_to_section(section, "NTP", ntp);

        if (emit_ntp >= 0)
                add_key_to_section(section, "EmitNTP", bool_to_string(emit_ntp));

        if (emit_router >= 0)
                add_key_to_section(section, "EmitRouter", bool_to_string(emit_router));

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_pointer(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, g_strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_remove_dhcpv4_server(const IfNameIndex *ifnameidx) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0) {
                log_warning("Failed to create network file '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = remove_key_from_config_file(network, "Network", "DHCPServer");
        if (r < 0)
                return r;

        r = remove_section_from_config_file(network, "DHCPServer");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_configure_ipv6_router_advertisement(const IfNameIndex *ifnameidx,
                                                const IPAddress *prefix,
                                                const IPAddress *route_prefix,
                                                const IPAddress *dns,
                                                const char *domain,
                                                const uint32_t pref_lifetime,
                                                const uint32_t valid_lifetime,
                                                const uint32_t dns_lifetime,
                                                const uint32_t route_lifetime,
                                                IPv6RAPreference preference,
                                                const int managed,
                                                const int other,
                                                const int emit_dns,
                                                const int emit_domain,
                                                const int assign) {

        _cleanup_(section_freep) Section *ipv6_prefix_section = NULL, *ipv6_sendra_section = NULL, *ipv6_route_prefix_section = NULL;
        _auto_cleanup_ char *network = NULL, *d = NULL, *p = NULL, *rt = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0) {
                log_warning("Failed to find or create network file '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        if (prefix) {
                r = ip_to_string_prefix(dns->family, prefix, &p);
                if (r < 0)
                        return r;
        }

        if (route_prefix) {
                r = ip_to_string_prefix(dns->family, route_prefix, &rt);
                if (r < 0)
                        return r;
        }

        if (dns) {
                r = ip_to_string(dns->family, dns, &d);
                if (r < 0)
                        return r;
        }

        /* [Network] section */
        r = set_config(key_file, "Network", "IPv6SendRA", "yes");
        if (r < 0)
                return r;

        /* [IPv6Prefix] section */
        r = section_new("IPv6Prefix", &ipv6_prefix_section);
        if (r < 0)
                return r;

        if (p)
                add_key_to_section(ipv6_prefix_section, "Prefix", p);

        if (pref_lifetime > 0)
                add_key_to_section_integer(ipv6_prefix_section, "PreferredLifetimeSec", pref_lifetime);

        if (valid_lifetime > 0)
                add_key_to_section_integer(ipv6_prefix_section, "ValidLifetimeSec", valid_lifetime);


        r = section_new("IPv6SendRA", &ipv6_sendra_section);
        if (r < 0)
                return r;

        /* [IPv6SendRA] section */
        if (preference != _IPV6_RA_PREFERENCE_INVALID)
                add_key_to_section(ipv6_sendra_section, "RouterPreference", ipv6_ra_preference_type_to_name(preference));

        if (dns)
                add_key_to_section(ipv6_sendra_section, "DNS", d);

        if (emit_dns >= 0)
                add_key_to_section(ipv6_sendra_section, "EmitDNS", bool_to_string(emit_dns));

        if (dns_lifetime > 0)
                add_key_to_section_integer(ipv6_sendra_section, "DNSLifetimeSec", dns_lifetime);

        if (domain)
                add_key_to_section(ipv6_sendra_section, "Domains", domain);

        if (assign >= 0)
                add_key_to_section(ipv6_sendra_section, "Assign", bool_to_string(assign));

        r = section_new("IPv6RoutePrefix", &ipv6_route_prefix_section);
        if (r < 0)
                return r;

        /* [IPv6RoutePrefix] section */
        if (rt)
                add_key_to_section(ipv6_route_prefix_section, "Route", rt);

        if (route_lifetime > 0)
                add_key_to_section_integer(ipv6_route_prefix_section, "LifetimeSec", route_lifetime);

        r = add_section_to_key_file(key_file, ipv6_sendra_section);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, ipv6_prefix_section);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, ipv6_route_prefix_section);
        if (r < 0)
                return r;

        steal_pointer(ipv6_sendra_section);
        steal_pointer(ipv6_prefix_section);
        steal_pointer(ipv6_route_prefix_section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, g_strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_remove_ipv6_router_advertisement(const IfNameIndex *ifnameidx) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0) {
                log_warning("Failed to create network file '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = remove_key_from_config_file(network, "Network", "IPv6SendRA");
        if (r < 0)
                return r;

        r = remove_section_from_config_file(network, "IPv6SendRA");
        if (r < 0)
                return r;

        r = remove_section_from_config_file(network, "IPv6Prefix");
        if (r < 0)
                return r;

        r = remove_section_from_config_file(network, "IPv6RoutePrefix");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_add_dns_server(const IfNameIndex *ifnameidx, DNSServers *dns, bool system, bool global) {
        _auto_cleanup_ char *setup = NULL, *network = NULL, *config_dns = NULL, *a = NULL;
        GSequenceIter *i;
        int r;

        assert(dns);

        if (system)
                return add_dns_server_and_domain_to_resolv_conf(dns, NULL);
        else if (global)
                return add_dns_server_and_domain_to_resolved_conf(dns, NULL);

        assert(ifnameidx);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0 || string_equal(setup, "unmanaged"))
                return dbus_add_dns_server(ifnameidx->ifindex, dns);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                _auto_cleanup_ char *pretty = NULL;
                DNSServer *d = g_sequence_get(i);

                r = ip_to_string(d->address.family, &d->address, &pretty);
                if (r >= 0) {
                        a = string_join(" ", pretty, a, NULL);
                        if (!a)
                                return log_oom();
                }
        }

        r = parse_config_file(network, "Network", "DNS", &config_dns);
        if (r >= 0) {
                if (string_equal(a, config_dns))
                        return 0;
        }

        r = set_config_file_string(network, "Network", "DNS", a);
        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, g_strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_add_dns_server_domain(const IfNameIndex *ifnameidx, char **domains, bool system, bool global) {
        _auto_cleanup_ char *setup = NULL, *network = NULL, *config_domain = NULL, *a = NULL;
        char **d;
        int r;

        assert(domains);

        if (system)
                return add_dns_server_and_domain_to_resolv_conf(NULL, domains);
        else if (global)
                return add_dns_server_and_domain_to_resolved_conf(NULL, domains);

        assert(ifnameidx);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0 || string_equal(setup, "unmanaged"))
                return dbus_add_dns_domains(ifnameidx->ifindex, domains);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0) {
                r = create_network_conf_file(ifnameidx->ifname, &network);
                if (r < 0)
                        return r;
        }

        strv_foreach(d, domains) {
                a = string_join(" ", *d, a, NULL);
                if (!a)
                        return log_oom();
        }

        r = parse_config_file(network, "Network", "Domains", &config_domain);
        if (r >= 0) {
                if (string_equal(a, config_domain))
                        return 0;
        }

        r = set_config_file_string(network, "Network", "Domains", a);
        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, g_strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_read_domains_from_system_config(char **domains) {
        _auto_cleanup_ char *config_domains = NULL;
        int r;

        r = parse_config_file("/etc/systemd/resolved.conf", "Resolve", "DOMAINS", &config_domains);
        if (r < 0)
                return r;

        *domains = steal_pointer(config_domains);
        return 0;
}

int manager_revert_dns_server_and_domain(const IfNameIndex *ifnameidx) {
        _auto_cleanup_ char *setup = NULL, *network = NULL, *config = NULL;
        int r;

        assert(ifnameidx);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0 || string_equal(setup, "unmanaged"))
                return dbus_revert_resolve_link(ifnameidx->ifindex);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0) {
                log_warning("Failed to find network file for '%s', %s", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = parse_config_file(network, "Network", "DNS", &config);
        if (r >= 0) {
                r = remove_key_from_config_file(network, "Network", "DNS");
                if (r < 0)
                        return r;
        }

        r = parse_config_file(network, "Network", "Domains", &config);
        if (r >= 0) {
                r = remove_key_from_config_file(network, "Network", "Domains");
                if (r < 0)
                        return r;
        }

        return dbus_network_reload();
}

int manager_set_network_section_bool(const IfNameIndex *ifnameidx, const char *k, bool v) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = set_config_file_bool(network, "Network", k, v);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_set_dhcp_section(DHCPClient kind, const IfNameIndex *ifnameidx, const char *k, bool v) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        switch(kind) {
                case DHCP_CLIENT_IPV4:
                        r = set_config_file_bool(network, "DHCPv4", k, v);
                        break;
                case DHCP_CLIENT_IPV6:
                        r = set_config_file_bool(network, "DHCPv6", k, v);
                        break;
                default:
                        return -EINVAL;
        }

        return dbus_network_reload();
}

int manager_add_ntp_addresses(const IfNameIndex *ifnameidx, char **ntps, bool add) {
        _auto_cleanup_ char *network = NULL, *config_ntp = NULL, *a = NULL, *b = NULL;
        char **d;
        int r;

        assert(ifnameidx);
        assert(ntps);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        strv_foreach(d, ntps) {
                a = string_join(" ", *d, a, NULL);
                if (!a)
                        return log_oom();
        }

        r = parse_config_file(network, "Network", "NTP", &config_ntp);
        if (r >= 0) {
                if (string_equal(a, config_ntp))
                        return 0;
        }

        if (add) {
                b = strv_join(config_ntp, &a);
                if (!b)
                        return log_oom();
        }

        r = set_config_file_string(network, "Network", "NTP", add ? b : a);
        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, g_strerror(-r));
                return r;
        }

        (void) dbus_restart_unit("systemd-networkd.service");
        (void) dbus_restart_unit("systemd-timesyncd.service");

        return 0;
}

int manager_remove_ntp_addresses(const IfNameIndex *ifnameidx) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = remove_key_from_config_file(network, "Network", "NTP");
        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, g_strerror(-r));
                return r;
        }

        (void) dbus_restart_unit("systemd-networkd.service");
        (void) dbus_restart_unit("systemd-timesyncd.service");

        return 0;
}

int manager_enable_ipv6(const IfNameIndex *ifnameidx, bool enable) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = set_config_file_string(network, "Network", "DHCP", "ipv4");
        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, g_strerror(-r));
                return r;
        }

        if (enable)
                r = set_config_file_string(network, "Network", "LinkLocalAddressing", "yes");
        else
                r = set_config_file_string(network, "Network", "LinkLocalAddressing", "no");

        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, g_strerror(-r));
                return r;
        }

        r = manager_set_link_state(ifnameidx, LINK_STATE_DOWN);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_reload_network(void) {
        return dbus_network_reload();
}

int manager_reconfigure_link(const IfNameIndex *ifnameidx) {
        return dbus_reconfigure_link(ifnameidx->ifindex);
}

int manager_write_wifi_config(const Network *n, const GString *config) {
        _auto_cleanup_ char *path = NULL;
        _auto_cleanup_close_ int fd = -1;
        int r;

        assert(config);

        (void) mkdir("/etc/network-config-manager", 0755);

        r = create_conf_file("/etc/network-config-manager", "wpa_supplicant", "conf", &path);
        if (r < 0)
                return r;

        r = open(path, O_WRONLY);
        if (r < 0) {
                log_warning("Failed to open wpa supplicant file '%s': %s", path, g_strerror(-r));
                return r;
        }

        fd = r;
        r = write(fd, config->str, config->len);
        if (r < 0)
                return -errno;

        chmod(path, 0644);
        return 0;
}

static int manager_write_network_config(const Network *n, const GString *config) {
        _auto_cleanup_ char *network = NULL, *config_file = NULL;
        _auto_cleanup_close_ int fd = -1;
        int r;

        assert(n);
        assert(config);

        config_file = string_join("-", "10", n->ifname, NULL);
        if (!config_file)
                return log_oom();

        r = create_conf_file("/etc/systemd/network", config_file, "network", &network);
        if (r < 0)
                return r;

        r = open(network, O_WRONLY);
        if (r < 0) {
                log_warning("Failed to open network file '%s': %s", network, g_strerror(-r));
                return r;
        }

        fd = r;
        r = write(fd, config->str, config->len);
        if (r < 0)
                return -errno;

        (void) set_file_permisssion(network, "systemd-network");

        return 0;
}

static int manager_write_netdev_config(const NetDev *n, const GString *config) {
        _auto_cleanup_ char *netdev = NULL, *config_file = NULL;
        _auto_cleanup_close_ int fd = -1;
        int r;

        assert(n);
        assert(config);

        config_file = string_join("-", "10", n->ifname, NULL);
        if (!config_file)
                return log_oom();

        r = create_conf_file("/etc/systemd/network", config_file, "netdev", &netdev);
        if (r < 0)
                return r;

        r = open(netdev, O_WRONLY);
        if (r < 0) {
                log_warning("Failed to open netdev file '%s': %s", netdev, g_strerror(-r));
                return r;
        }

        fd = r;
        r = write(fd, config->str, config->len);
        if (r < 0)
                return -errno;

        (void) set_file_permisssion(netdev, "systemd-network");
        return 0;
}

int manager_remove_netdev(const char *ifname, const char *kind) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        assert(ifname);

        /* remove .netdev file  */
        (void) remove_config_files_glob("/etc/systemd/network/*.netdev", "NetDev", "Name", ifname);
        (void) remove_config_files_glob("/lib/systemd/network/*.netdev", "NetDev", "Name", ifname);

        /* remove .network */
        (void) remove_config_files_glob("/etc/systemd/network/*.network", "Match", "Name", ifname);
        (void) remove_config_files_glob("/lib/systemd/network/*.network", "Match", "Name", ifname);

        /* Remove [Network] section */
        if (kind) {
                (void) remove_config_files_section_glob("/etc/systemd/network/*.network", "Network", kind, ifname);
                (void) remove_config_files_section_glob("/lib/systemd/network/*.network", "Network", kind, ifname);
        }

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return r;

        /* Finally remove the link */
        r = link_remove(p);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_vlan(const IfNameIndex *ifnameidx, const char *vlan, uint32_t id, const char *proto) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *vlan_network_config = NULL;
        _auto_cleanup_ char *vlan_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        int r;

        assert(ifnameidx);
        assert(vlan);
        assert(id > 0);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .id = id,
                        .ifname = strdup(vlan),
                        .kind = NET_DEV_KIND_VLAN,
        };
        if (!netdev->ifname)
                return log_oom();

        if (proto) {
                netdev->proto = strdup(proto);
                if (!netdev->proto)
                        return log_oom();
        }

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(vlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &vlan_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(ifnameidx->ifname, &vlan_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, vlan_network_config);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = add_key_to_section_string(network, "Network", "VLAN", vlan);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_bridge(const char *bridge, char **interfaces) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *bridge_network_config = NULL;
        _auto_cleanup_ char *bridge_netdev = NULL, *bridge_network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        char **s;
        int r;

        assert(bridge);
        assert(interfaces);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(bridge),
                        .kind = NET_DEV_KIND_BRIDGE,
                  };
        if (!netdev->ifname)
                return log_oom();

        r = create_netdev_conf_file(bridge, &bridge_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(bridge);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &bridge_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(bridge, &bridge_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, bridge_network_config);

        strv_foreach(s, interfaces) {
                _auto_cleanup_ IfNameIndex *p = NULL;
                _auto_cleanup_ char *network = NULL;

                r = parse_ifname_or_index(*s, &p);
                if (r < 0)
                        return r;

                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "Bridge", bridge);
                if (r < 0)
                        return r;
        }

        return dbus_network_reload();
}

int manager_create_bond(const char *bond, BondMode mode, char **interfaces) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *bond_network_config = NULL;
        _auto_cleanup_ char *bond_netdev = NULL, *bond_network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        char **s;
        int r;

        assert(bond);
        assert(interfaces);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(bond),
                        .kind = NET_DEV_KIND_BOND,
                        .bond_mode = mode,
                  };

        if (!netdev->ifname)
                return log_oom();

        r = create_netdev_conf_file(bond, &bond_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(bond);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &bond_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(bond, &bond_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, bond_network_config);

        strv_foreach(s, interfaces) {
                _auto_cleanup_ char *network = NULL;

                r = create_network_conf_file(*s, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "Bond", bond);
                if (r < 0)
                        return r;
        }

        return dbus_network_reload();
}

int manager_create_vxlan(const char *vxlan,
                         uint32_t vni,
                         IPAddress *local,
                         IPAddress *remote,
                         IPAddress *group,
                         uint16_t port,
                         const char *dev,
                         bool independent) {

        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *vxlan_network_config = NULL;
        _auto_cleanup_ char *vxlan_netdev = NULL, *vxlan_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        int r;

        assert(vxlan);
        assert(dev);
        assert(vni > 0);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                      .ifname = strdup(vxlan),
                      .kind = NET_DEV_KIND_VXLAN,
                      .id = vni,
                      .destination_port = port,
                      .independent = dev ? false : true,
                  };

        if (!netdev->ifname)
                return log_oom();

        if (local)
                netdev->local = *local;
        if (remote)
                netdev->remote = *remote;
        if (group)
                netdev->group = *group;

        r = create_netdev_conf_file(vxlan, &vxlan_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(vxlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &vxlan_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(vxlan, &vxlan_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, vxlan_network_config);

        if (!independent) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(dev, &p);
                if (r < 0)
                        return r;

                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "VXLAN", vxlan);
                if (r < 0)
                        return r;
        }

        return dbus_network_reload();
}

int manager_create_macvlan(const char *macvlan, const char *dev, MACVLanMode mode, bool kind) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *macvlan_network_config = NULL;
        _auto_cleanup_ char *macvlan_netdev = NULL, *macvlan_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        assert(macvlan);
        assert(dev);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                       .ifname = strdup(macvlan),
                       .kind = kind ? NET_DEV_KIND_MACVLAN : NET_DEV_KIND_MACVTAP,
                       .macvlan_mode = mode,
                };
        if (!netdev->ifname)
                return log_oom();

        r = create_netdev_conf_file(macvlan, &macvlan_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(macvlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &macvlan_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration : %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(macvlan, &macvlan_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, macvlan_network_config);

        r = parse_ifname_or_index(dev, &p);
        if (r < 0)
                return r;

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        if (kind)
                r = add_key_to_section_string(network, "Network", "MACVLAN", macvlan);
        else
                r = add_key_to_section_string(network, "Network", "MACVTAP", macvlan);

        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_ipvlan(const char *ipvlan, const char *dev, IPVLanMode mode, bool kind) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *ipvlan_network_config = NULL;
        _auto_cleanup_ char *ipvlan_netdev = NULL, *ipvlan_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        assert(ipvlan);
        assert(dev);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                          .ifname = strdup(ipvlan),
                          .kind = kind ? NET_DEV_KIND_IPVLAN : NET_DEV_KIND_IPVTAP,
                          .ipvlan_mode = mode,
                 };

        if (!netdev->ifname)
                return log_oom();

        r = create_netdev_conf_file(ipvlan, &ipvlan_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(ipvlan);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &ipvlan_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration : %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(ipvlan, &ipvlan_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, ipvlan_network_config);

        r = parse_ifname_or_index(dev, &p);
        if (r < 0)
                return r;

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        if (kind)
                r = add_key_to_section_string(network, "Network", "IPVLAN", ipvlan);
        else
                r = add_key_to_section_string(network, "Network", "IPVTAP", ipvlan);

        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_create_veth(const char *veth, const char *veth_peer) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *veth_network_config = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ char *veth_network = NULL;
        int r;

        assert(veth);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                       .ifname = strdup(veth),
                       .peer = veth_peer ? strdup(veth_peer) : NULL,
                       .kind = NET_DEV_KIND_VETH,
                  };
        if (!netdev->ifname)
                return log_oom();

        if (veth_peer && !netdev->peer)
                return log_oom();

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(veth);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &veth_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(veth, &veth_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, veth_network_config);

        return dbus_network_reload();
}

int manager_create_tunnel(const char *tunnel,
                          NetDevKind kind,
                          IPAddress *local,
                          IPAddress *remote,
                          const char *dev,
                          bool independent) {

        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *tunnel_network_config = NULL;
        _auto_cleanup_ char *tunnel_netdev = NULL, *tunnel_network = NULL, *network = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        int r;

        assert(tunnel);
        assert(dev);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                .ifname = strdup(tunnel),
                .kind = kind,
                .independent = dev ? false : true,
        };

        if (!netdev->ifname)
                return log_oom();

        if (local)
                netdev->local = *local;
        if (remote)
                netdev->remote = *remote;

        r = create_netdev_conf_file(tunnel, &tunnel_netdev);
        if (r < 0)
                return r;

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(tunnel);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &tunnel_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(tunnel, &tunnel_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, tunnel_network_config);

        if (!independent) {
                _auto_cleanup_ IfNameIndex *p = NULL;

                r = parse_ifname_or_index(dev, &p);
                if (r < 0)
                        return r;

                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;

                r = add_key_to_section_string(network, "Network", "Tunnel", tunnel);
                if (r < 0)
                        return r;
        }

        return dbus_network_reload();
}

int manager_create_vrf(const char *vrf, uint32_t table) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *vrf_network_config = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        _auto_cleanup_ char *vrf_network = NULL;
        int r;

        assert(vrf);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                        .ifname = strdup(vrf),
                        .kind = NET_DEV_KIND_VRF,
                        .table = table
                };
        if (!netdev->ifname)
                return log_oom();

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(vrf);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &vrf_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(vrf, &vrf_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, vrf_network_config);

        return dbus_network_reload();
}

int manager_create_wireguard_tunnel(char *wireguard,
                                    char *private_key,
                                    char *public_key,
                                    char *preshared_key,
                                    char *endpoint,
                                    char *allowed_ips,
                                    uint16_t listen_port) {

        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *wireguard_network_config = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
        _auto_cleanup_ char *wireguard_network = NULL;
        _cleanup_(network_unrefp) Network *v = NULL;
        int r;

        assert(wireguard);
        assert(private_key);
        assert(public_key);

        r = netdev_new(&netdev);
        if (r < 0)
                return log_oom();

        *netdev = (NetDev) {
                         .ifname = strdup(wireguard),
                         .kind = NET_DEV_KIND_WIREGUARD,
                         .wg_private_key = private_key ? strdup(private_key) : private_key,
                         .wg_public_key = public_key ? strdup(public_key) : public_key,
                         .listen_port = listen_port,
                 };
        if (!netdev->ifname || !netdev->wg_private_key || !netdev->wg_public_key)
                return log_oom();

        if (endpoint) {
                netdev->wg_endpoint = strdup(endpoint);
                if (!netdev->wg_endpoint)
                        return log_oom();
        }

        if (allowed_ips) {
                netdev->wg_allowed_ips = strdup(allowed_ips);
                if (!netdev->wg_allowed_ips)
                        return log_oom();
        }

        r = generate_netdev_config(netdev, &netdev_config);
        if (r < 0)
                return r;

        r = manager_write_netdev_config(netdev, netdev_config);
        if (r < 0)
                return r;

        r = network_new(&v);
        if (r < 0)
                return r;

        v->ifname = strdup(wireguard);
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &wireguard_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(wireguard, &wireguard_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, wireguard_network_config);

        return dbus_network_reload();
}

int manager_show_link_network_config(const IfNameIndex *ifnameidx, char **ret) {
        _auto_cleanup_ char *network = NULL, *config = NULL, *c = NULL;
        int r;

        assert(ifnameidx);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0)
                return r;

        r = read_conf_file(network, &config);
        if (r < 0)
                return r;

        c = string_join("\n\n", network, config, NULL);
        if (!c)
                return log_oom();

        *ret = steal_pointer(c);
        return 0;
}

int manager_edit_link_network_config(const IfNameIndex *ifnameidx) {
        _auto_cleanup_ char *network = NULL;
        pid_t pid;
        int r;

        assert(ifnameidx);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0)
                return r;

        pid = fork();
        if (pid < 0)
                return -errno;

        if (pid == 0) {
                _auto_cleanup_strv_ char **editors = NULL;
                char **d;

                editors = strv_new("vim");
                if (!editors)
                        return log_oom();

                r = strv_add(&editors, "vi");
                if (r < 0)
                        return r;

                strv_foreach(d, editors) {
                        const char *args[] = {*d, network, NULL};

                        execvp(*d, (char* const*) args);
                        if (errno != ENOENT) {
                                log_warning("Failed to edit %s via editor %s: %s",  network, *d, g_strerror(-errno));
                                _exit(EXIT_FAILURE);
                        }
                }

                _exit(EXIT_SUCCESS);
        } else {
                int status;

                waitpid(pid, &status, 0);
        }

        return 0;
}

int manager_configure_proxy(int enable,
                            const char *http,
                            const char *https,
                            const char *ftp,
                            const char *gopher,
                            const char *socks,
                            const char *socks5,
                            const char *no_proxy) {

        _auto_cleanup_hash_ GHashTable *table = NULL;
        int r;

        r = parse_state_file("/etc/sysconfig/proxy", NULL, NULL, &table);
        if (r < 0) {
                if (r == -ENOENT) {
                        table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
                        if (!table)
                                return log_oom();
                } else
                        return r;
        }

        if (http) {
                _auto_cleanup_ char *s = NULL, *k = NULL;

                s = strdup(http);
                if (!s)
                        return log_oom();

                k = strdup("HTTP_PROXY");
                if (!k)
                        return log_oom();

                g_hash_table_replace(table, k, s);

                steal_pointer(s);
                steal_pointer(k);
        }

        if (https)  {
                _auto_cleanup_ char *s = NULL, *k = NULL;

                s = strdup(https);
                if (!s)
                        return log_oom();

                k = strdup("HTTPS_PROXY");
                if (!k)
                        return log_oom();

                g_hash_table_replace(table, k, s);

                steal_pointer(s);
                steal_pointer(k);
        }

        if (ftp) {
                _auto_cleanup_ char *s = NULL, *k = NULL;

                s = strdup(ftp);
                if (!s)
                        return log_oom();

                k = strdup("FTP_PROXY");
                if (!k)
                        return log_oom();

                g_hash_table_replace(table, k, s);

                steal_pointer(s);
                steal_pointer(k);
        }

        if (gopher) {
                _auto_cleanup_ char *s = NULL, *k = NULL;

                s = strdup(gopher);
                if (!s)
                        return log_oom();

                k = strdup("GOPHER_PROXY");
                if (!k)
                        return log_oom();

                g_hash_table_replace(table, k, s);

                steal_pointer(s);
                steal_pointer(k);
        }

        if (socks) {
                _auto_cleanup_ char *s = NULL, *k = NULL;

                s = strdup(socks);
                if (!s)
                        return log_oom();

                k = strdup("SOCKS_PROXY");
                if (!k)
                        return log_oom();

                g_hash_table_replace(table, k, s);

                steal_pointer(s);
                steal_pointer(k);
        }

        if (socks5) {
                _auto_cleanup_ char *s = NULL, *k = NULL;

                s = strdup(socks5);
                if (!s)
                        return log_oom();

                k = strdup("SOCKS5_SERVER");
                if (!k)
                        return log_oom();

                g_hash_table_replace(table, k, s);

                steal_pointer(s);
                steal_pointer(k);
        }

        if (no_proxy) {
                _auto_cleanup_ char *s = NULL, *k = NULL;

                s = strdup(no_proxy);
                if (!s)
                        return log_oom();

                k = strdup("NO_PROXY");
                if (!k)
                        return log_oom();

                g_hash_table_replace(table, k, s);

                steal_pointer(s);
                steal_pointer(k);
        }

        if (enable != -1) {
                _auto_cleanup_ char *p = NULL, *t = NULL;

                t = strdup(bool_to_string(enable));
                if (!t)
                        return log_oom();

                p = strdup("PROXY_ENABLED");
                if (!p)
                        return log_oom();

                g_hash_table_replace(table, p, t);

                steal_pointer(t);
                steal_pointer(p);
        }

        return write_to_proxy_conf_file(table);
}

int manager_parse_proxy_config(GHashTable **c) {
        _auto_cleanup_hash_ GHashTable *table = NULL;
        int r;

        assert(c);

        r = parse_state_file("/etc/sysconfig/proxy", NULL, NULL, &table);
        if (r < 0)
                return r;

        *c = steal_pointer(table);
        return 0;
}

int manager_generate_network_config_from_yaml(const char *file) {
        _cleanup_(g_string_unrefp) GString *config = NULL, *wifi_config = NULL;
        _cleanup_(network_unrefp) Network *n = NULL;
        _cleanup_(netdev_link_unrefp) NetDevLink *l = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        assert(file);

        if (string_has_suffix(file, "link.yaml")) {
                r = parse_yaml_link_file(file, &l);
                if (r < 0) {
                        log_warning("Failed to parse configuration file '%s': %s", file, g_strerror(-r));
                        return r;
                }

                r = parse_ifname_or_index(l->ifname, &p);
                if (r < 0) {
                        log_warning("Failed to find link: %s", g_strerror(-r));
                        return r;
                }

                r = netdev_link_configure(p, l);
                if (r < 0) {
                        log_warning("Failed to configure link from yaml file '%s': %s", file, g_strerror(-r));
                        return r;
                }
        } else {
                r = parse_yaml_network_file(file, &n);
                if (r < 0) {
                        log_warning("Failed to parse configuration file '%s': %s", file, g_strerror(-r));
                        return r;
                }

                r = generate_network_config(n, &config);
                if (r < 0) {
                        log_warning("Failed to generate network configuration for file '%s': %s", file, g_strerror(-r));
                        return r;
                }

                r = manager_write_network_config(n, config);
                if (r < 0)
                        return r;

                if (n->access_points) {
                        r = generate_wifi_config(n, &wifi_config);
                        if (r < 0)
                                return r;

                        return manager_write_wifi_config(n, wifi_config);
                }
        }

        return dbus_network_reload();
}

static void manager_command_line_config_generator(void *key, void *value, void *user_data) {
        _cleanup_(g_string_unrefp) GString *config = NULL;
        Network *n;
        int r;

        assert(key);
        assert(value);

        n = (Network *) value;

        r = generate_network_config(n, &config);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                return;
        }

        (void) manager_write_network_config(n, config);
}

static Network *manager_no_interface_name(GHashTable *networks) {
        Network *n;
        GList *l;

        assert(networks);

        if (g_hash_table_size(networks) > 1)
                return NULL;

        l = g_hash_table_get_values(networks);
        if (!l)
                return NULL;

        n = l->data;
        if (!n || !n->ifname)
                return NULL;

        return n;
}

int manager_generate_networkd_config_from_command_line(const char *file, const char *command_line) {
        _auto_cleanup_hash_ GHashTable *networks = NULL;
        _auto_cleanup_ char *line = NULL;
        Network *n;
        int r = 0;

        if (file) {
                r = read_one_line(file, &line);
                if (r < 0)
                        return r;

                (void) truncate_newline(line);

                r = parse_proc_command_line(line, &networks);
        } else if (command_line)
                r = parse_proc_command_line(command_line, &networks);
        if (r < 0)
                return r;

        n = manager_no_interface_name(networks);
        if (n) {
                _cleanup_(links_unrefp) Links *h = NULL;

                r = link_get_links(&h);
                if (r < 0)
                        return r;

                for (GList *i = h->links; i; i = i->next) {
                        _cleanup_(g_string_unrefp) GString *config = NULL;
                        Link *link = NULL;

                        link = i->data;

                        if (string_equal(link->name, "lo"))
                                continue;

                        n->ifname = g_strdup(link->name);
                        if (!n->ifname)
                                return log_oom();

                        r = generate_network_config(n, &config);
                        if (r < 0) {
                                log_warning("Failed to generate network configuration: %s", g_strerror(-r));
                                return r;
                        }

                        (void) manager_write_network_config(n, config);
                        n->ifname = mfree(n->ifname);
                }

        } else
                g_hash_table_foreach(networks, manager_command_line_config_generator, NULL);

        return dbus_network_reload();
}
