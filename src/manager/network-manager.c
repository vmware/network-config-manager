/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
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

static int create_network_conf_file(const IfNameIndex *ifnameidx, char **ret) {
        _auto_cleanup_ char *file = NULL, *network = NULL;
        int r;

        assert(ifnameidx);

        file = string_join("-", "10", ifnameidx->ifname, NULL);
        if (!file)
                return log_oom();

        r = create_conf_file("/etc/systemd/network", file, "network", &network);
        if (r < 0)
                return r;

        r = set_config_file_string(network, "Match", "Name", ifnameidx->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = steal_pointer(network);

        return dbus_network_reload();
}

static int create_or_parse_network_file(const IfNameIndex *ifnameidx, char **ret) {
        _auto_cleanup_ char *setup = NULL, *network = NULL;
        int r;

        assert(ifnameidx);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0) {
                r = create_network_conf_file(ifnameidx, &network);
                if (r < 0)
                        return r;
        } else {
                r = network_parse_link_network_file(ifnameidx->ifindex, &network);
                if (r < 0) {
                        r = create_network_conf_file(ifnameidx, &network);
                        if (r < 0)
                                return r;
                }
        }

        *ret = steal_pointer(network);

        return 0;
}

int manager_set_link_mode(const IfNameIndex *ifnameidx, bool mode) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        if (!network) {
                log_warning("Failed to get network file for '%s'. systemd-networkd is configuring. Please try in a while.", ifnameidx->ifname);
                return -ENODATA;
        }

        r = set_config_file_bool(network, "Link", "Unmanaged", mode);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_set_link_dhcp_mode(const IfNameIndex *ifnameidx, DHCPMode mode) {
        _auto_cleanup_ char *network = NULL, *config_dhcp = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        if (!network) {
                log_warning("Failed to get network file for '%s'. systemd-networkd is configuring. Please try after a while.", ifnameidx->ifname);
                return -ENODATA;
        }

        r = parse_config_file(network, "Network", "DHCP", &config_dhcp);
        if (r >= 0) {
                if (string_equal(dhcp_modes_to_name(mode), config_dhcp))
                        return 0;
        }

        r = set_config_file_string(network, "Network", "DHCP", dhcp_modes_to_name(mode));
        if (r < 0) {
                log_warning("Failed to write to config file: %s", network);
                return r;
        }

        return dbus_network_reload();
}

int manager_get_link_dhcp_mode(const IfNameIndex *ifnameidx, DHCPMode *mode) {
        _auto_cleanup_ char *network = NULL, *config_dhcp = NULL;
        int r;

        assert(ifnameidx);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, "Network", "DHCP", &config_dhcp);
        if (r < 0)
                return r;

        r = dhcp_name_to_mode(config_dhcp);
        if (r < 0)
                return r;

        *mode = r;

        return 0;
}

int manager_set_link_dhcp_client_identifier(const IfNameIndex *ifnameidx, DHCPClientIdentifier identifier) {
        _auto_cleanup_ char *network = NULL, *config = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        (void) parse_config_file(network, "DHCPv4", "ClientIdentifier", &config);
        if (config) {
                if (string_equal(config, dhcp_client_identifier_to_name(identifier)))
                        return 0;
        }

        r = set_config_file_string(network, "DHCPv4", "ClientIdentifier", dhcp_client_identifier_to_name(identifier));
        if (r < 0) {
                log_warning("Failed to update DHCP4 ClientIdentifier= to config file '%s': %s", network, g_strerror(-r));
                return r;
        }

        return 0;
}

int manager_get_link_dhcp_client_identifier(const IfNameIndex *ifnameidx, DHCPClientIdentifier *ret) {
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

int manager_set_link_dhcp_client_iaid(const IfNameIndex *ifnameidx, uint32_t iaid) {
        _auto_cleanup_ char *network = NULL;
        unsigned v;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = parse_config_file_integer(network, "DHCPv6", "IAID", &v);
        if (r >= 0) {
                if (v == iaid)
                        return 0;
        }

        r = set_config_file_integer(network, "DHCP", "IAID", iaid);
        if (r < 0) {
                log_warning("Failed to update DHCP IAID= to config file '%s': %s", network, g_strerror(-r));
                return r;
        }

        return 0;
}

int manager_get_link_dhcp_client_iaid(const IfNameIndex *ifnameidx, uint32_t *iaid) {
        _auto_cleanup_ char *network = NULL;
        unsigned v;
        int r;

        assert(ifnameidx);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file_integer(network, "DHCPv6", "IAID", &v);
        if (r < 0)
                return r;

        *iaid = v;
        return 0;
}

int manager_set_link_dhcp_client_duid(const IfNameIndex *ifnameidx, DHCPClientDUIDType duid, char *raw_data, bool system) {
        _auto_cleanup_ char *network = NULL;
        int r;

        if (system) {
                network = g_strdup("/etc/systemd/networkd.conf");
                if (!network)
                        return log_oom();
        } else {
                assert(ifnameidx);

                r = create_or_parse_network_file(ifnameidx, &network);
                if (r < 0)
                        return r;
        }

        r = set_config_file_string(network, "DHCPv6", "DUIDType", dhcp_client_duid_type_to_name(duid));
        if (r < 0) {
                log_warning("Failed to update DHCP ClientIdentifier= to config file '%s': %s", network, g_strerror(-r));
                return r;
        }

        if (raw_data) {
                r = set_config_file_string(network, "DHCPv6", "DUIDRawData", raw_data);
                if (r < 0) {
                        log_warning("Failed to update DHCPv6 IAID= to config file '%s': %s", network, g_strerror(-r));
                        return r;
                }
        }

        return 0;
}

int manager_set_link_mtu(const IfNameIndex *ifnameidx, uint32_t mtu) {
        _auto_cleanup_ char *network = NULL, *config_mtu = NULL, *config_update_mtu = NULL;
        uint32_t k;
        int r;

        assert(ifnameidx);
        assert(mtu > 0);

        r = link_get_mtu(ifnameidx->ifname, &k);
        if (r < 0)
                return r;

        r = link_update_mtu(ifnameidx, mtu);
        if (r < 0)
                return r;

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        (void) parse_config_file(network, "Link", "MTUBytes", &config_mtu);

        asprintf(&config_update_mtu, "%u", mtu);

        if (config_mtu) {
                if (string_equal(config_mtu, config_update_mtu))
                        return 0;
        }

        r = set_config_file_string(network, "Link", "MTUBytes", config_update_mtu);
        if (r < 0) {
                log_warning("Failed to update MTUBytes= to config file '%s' = %s", network, g_strerror(-r));
                return r;
        }

        return 0;
}

int manager_set_link_mac_addr(const IfNameIndex *ifnameidx, const char *mac) {
        _auto_cleanup_ char *p = NULL, *network = NULL, *config_mac = NULL, *config_update_mac = NULL;
        int r;

        assert(ifnameidx);
        assert(mac);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = link_get_mac_address(ifnameidx->ifname, &p);
        if (r >= 0) {
                if (!string_equal(p, mac)) {
                        r = link_set_mac_address(ifnameidx, mac);
                       if (r < 0)
                                log_warning("Failed to set MAC Address to '%s' : %s", ifnameidx->ifname, mac);
                }
        }

        r = parse_config_file(network, "Link", "MACAddress", &config_mac);
        if (r >= 0) {
                if (string_equal(config_mac, mac))
                        return 0;
        }

        asprintf(&config_update_mac, "%s", mac);
        r = set_config_file_string(network, "Link", "MACAddress", config_update_mac);
        if (r < 0) {
                log_warning("Failed to write to config file: %s", network);
                return r;
        }

        return 0;
}

int manager_set_link_state(const IfNameIndex *ifnameidx, LinkState state) {
        assert(ifnameidx);

        return link_set_state(ifnameidx, state);
}

int manager_configure_link_address(const IfNameIndex *ifnameidx, IPAddress *address, IPAddress *peer) {
        _auto_cleanup_ char *network = NULL, *config_address = NULL, *a = NULL;
        int r;

        assert(ifnameidx);
        assert(address);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        if (!address->prefix_len)
                r = ip_to_string(address->family, address, &a);
        else
                r = ip_to_string_prefix(address->family, address, &a);
        if (r < 0)
                return r;

        r = parse_config_file(network, "Address", "Address", &config_address);
        if (r >= 0) {
                if (string_equal(a, config_address))
                        return 0;
        }

        r = set_config_file_string(network, "Address", "Address", a);
        if (r < 0) {
                log_warning("Failed to write to config file: '%s': %s", network, g_strerror(-r));
                return r;
        }

        if (peer) {
                if (!peer->prefix_len)
                        r = ip_to_string(peer->family, peer, &a);
                else
                        r = ip_to_string_prefix(peer->family, peer, &a);
                if (r < 0)
                        return r;

                r = parse_config_file(network, "Address", "Peer", &config_address);
                if (r >= 0) {
                        if (string_equal(a, config_address))
                                return 0;
                }

                r = set_config_file_string(network, "Address", "Peer", a);
                if (r < 0) {
                        log_warning("Failed to write to config file '%s': %s", network, g_strerror(-r));
                        return r;
                }
        }

        return dbus_network_reload();
}

int manager_delete_link_address(const IfNameIndex *ifnameidx) {
        _auto_cleanup_ char *setup = NULL, *network = NULL;
        int r;

        assert(ifnameidx);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0) {
                log_warning("Failed to get link setup '%s': %s", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0) {
                log_warning("Failed to get .network file for '%s': %s", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = remove_section_from_config(network, "Address");
        if (r < 0) {
                log_warning("Failed to write to config file '%s': %s", network, g_strerror(-r));
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
        if (r < 0 && r != -EEXIST)
               log_warning("Failed to add Gateway to kernel : %s\n", g_strerror(-r));

        r = ip_to_string(rt->gw.family, &rt->gw, &a);
        if (r < 0)
                return r;

        r = set_config_file_string(network, "Route", "Gateway", a);
        if (r < 0) {
                log_warning("Failed to write to config file: %s", network);
                return r;
        }

        if (rt->onlink) {
                r = set_config_file_string(network, "Route", "GatewayOnlink", "yes");
                if (r < 0) {
                        log_warning("Failed to write to config file: %s", network);
                        return r;
                }
        }

        return dbus_network_reload();
}

int manager_configure_route(const IfNameIndex *ifnameidx, Route *rt) {
        _auto_cleanup_ char *network = NULL, *a = NULL;
        int r;

        assert(ifnameidx);
        assert(rt);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = ip_to_string(rt->destination.family, &rt->destination, &a);
        if (r < 0)
                return r;

        r = set_config_file_string(network, "Route", "Destination", a);
        if (r < 0) {
                log_warning("Failed to write to config file: %s", network);
                return r;
        }

        if (rt->metric) {
                r = set_config_file_integer(network, "Route", "Metric", rt->metric);
                if (r < 0) {
                        log_warning("Failed to write to config file: %s", network);
                        return r;
                }
        }

        return dbus_network_reload();
}

int manager_remove_gateway_or_route(const IfNameIndex *ifnameidx, bool gateway) {
        _auto_cleanup_ char *setup = NULL, *network = NULL, *config = NULL;
        int r;

        assert(ifnameidx);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0) {
                log_warning("Failed to get link setup '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
                return r;
        }

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0)
                return r;

        if (gateway) {
                r = parse_config_file(network, "Route", "Gateway", &config);
                if (r >= 0) {
                        r = remove_key_from_config(network, "Route", "Gateway");
                        if (r < 0)
                                return r;

                        (void) remove_key_from_config(network, "Route", "GatewayOnlink");
                }
        } else {
                r = parse_config_file(network, "Route", "Destination", &config);
                if (r >= 0) {
                        r = remove_key_from_config(network, "Route", "Destination");
                        if (r < 0)
                                return r;
                }

                r = parse_config_file(network, "Route", "Metric", &config);
                if (r >= 0)
                        (void) remove_key_from_config(network, "Route", "Metric");
        }

        return dbus_network_reload();
}

int manager_configure_additional_gw(const IfNameIndex *ifnameidx, Route *rt) {
        _auto_cleanup_ char *network = NULL, *address = NULL, *gw = NULL, *destination = NULL, *pref_source = NULL;
        _cleanup_(g_string_unrefp) GString *config = NULL;
        int r;

        assert(ifnameidx);
        assert(rt);

        r = create_network_conf_file(ifnameidx, &network);
        if (r < 0) {
                log_warning("Failed to get create network file '%s': %s\n", ifnameidx->ifname, g_strerror(-r));
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
        if (ifnameidx->ifname)
                g_string_append_printf(config, "Name=%s\n\n", ifnameidx->ifname);

        g_string_append(config, "[Address]\n");
        if (ifnameidx->ifname)
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

        r = write_to_conf(network, config);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_add_dns_server(const IfNameIndex *ifnameidx, DNSServers *dns, bool system) {
        _auto_cleanup_ char *setup = NULL, *network = NULL, *config_dns = NULL, *a = NULL;
        GSequenceIter *i;
        int r;

        assert(dns);

        if (system)
                return add_dns_server_and_domain_to_resolv_conf(dns, NULL);

        assert(ifnameidx);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0 || string_equal(setup, "unmanaged"))
                return dbus_add_dns_server(ifnameidx->ifindex, dns);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0) {
                r = create_network_conf_file(ifnameidx, &network);
                if (r < 0)
                        return r;
        }

        for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                _auto_cleanup_ char *pretty = NULL;
                DNSServer *d = g_sequence_get(i);

                r = ip_to_string(d->family, &d->address, &pretty);
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
                log_warning("Failed to write to config file '%s': %s", network, g_strerror(-r));
                return r;
        }

        return 0;
}

int manager_add_dns_server_domain(const IfNameIndex *ifnameidx, char **domains, bool system) {
        _auto_cleanup_ char *setup = NULL, *network = NULL, *config_domain = NULL, *a = NULL;
        char **d;
        int r;

        assert(domains);

        if (system)
                return add_dns_server_and_domain_to_resolv_conf(NULL, domains);

        assert(ifnameidx);

        r = network_parse_link_setup_state(ifnameidx->ifindex, &setup);
        if (r < 0 || string_equal(setup, "unmanaged"))
                return dbus_add_dns_domains(ifnameidx->ifindex, domains);

        r = network_parse_link_network_file(ifnameidx->ifindex, &network);
        if (r < 0) {
                r = create_network_conf_file(ifnameidx, &network);
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
                log_warning("Failed to write to config file '%s': %s", network, g_strerror(-r));
                return r;
        }

        return 0;
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
                r = remove_key_from_config(network, "Network", "DNS");
                if (r < 0)
                        return r;
        }

        r = parse_config_file(network, "Network", "Domains", &config);
        if (r >= 0) {
                r = remove_key_from_config(network, "Network", "Domains");
                if (r < 0)
                        return r;
        }

        return 0;
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

int manager_set_dhcp_section(const IfNameIndex *ifnameidx, const char *k, bool v, bool dhcp4) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        if (dhcp4)
                r = set_config_file_bool(network, "DHCPv4", k, v);
        else
                r = set_config_file_bool(network, "DHCPv6", k, v);
        if (r < 0)
                return r;

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
                log_warning("Failed to write to config file '%s': %s", network, g_strerror(-r));
                return r;
        }

        (void) dbus_restart_unit("systemd-networkd.service");
        return dbus_restart_unit("systemd-timesyncd.service");
}

int manager_remove_ntp_addresses(const IfNameIndex *ifnameidx) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(ifnameidx);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = remove_key_from_config(network, "Network", "NTP");
        if (r < 0) {
                log_warning("Failed to write to config file '%s': %s", network, g_strerror(-r));
                return r;
        }

        (void) dbus_restart_unit("systemd-networkd.service");
        return dbus_restart_unit("systemd-timesyncd.service");
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
                log_warning("Failed to write to config file '%s': %s", network, g_strerror(-r));
                return r;
        }

        if (enable)
                r = set_config_file_string(network, "Network", "LinkLocalAddressing", "yes");
        else
                r = set_config_file_string(network, "Network", "LinkLocalAddressing", "no");

        if (r < 0) {
                log_warning("Failed to write to config file '%s': %s", network, g_strerror(-r));
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

        chmod(path, 0600);

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

int manager_generate_network_config_from_yaml(const char *file) {
        _cleanup_(g_string_unrefp) GString *config = NULL, *wifi_config = NULL;
        _cleanup_(network_unrefp) Network *n = NULL;
        int r;

        assert(file);

        r = parse_yaml_network_file(file, &n);
        if (r < 0) {
                log_warning("Failed to parse config file '%s': %s", file, g_strerror(-r));
                return r;
        }

        r = generate_network_config(n, &config);
        if (r < 0) {
                log_warning("Failed to generate network configs for file '%s': %s", file, g_strerror(-r));
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
                log_warning("Failed to generate network configs : %s", g_strerror(-r));
                return;
         }

        (void) manager_write_network_config(n, config);
}

static Network *manager_no_interface_name(GHashTable *networks) {
        GList *l;
        Network *n;

        assert(networks);

        if (g_hash_table_size(networks) > 1)
                return NULL;

        l = g_hash_table_get_values(networks);
        if (!l)
                return NULL;

        n = l->data;
        if (n->ifname)
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
                _cleanup_(links_free) Links *h = NULL;
                GList *i;

                r = link_get_links(&h);
                if (r < 0)
                        return r;

                for (i = h->links; i; i = i->next) {
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
                                log_warning("Failed to generate network configs : %s", g_strerror(-r));
                                return r;
                        }

                        (void) manager_write_network_config(n, config);
                        n->ifname = mfree(n->ifname);
                }

        } else
                g_hash_table_foreach(networks, manager_command_line_config_generator, NULL);

        return dbus_network_reload();
}

int manager_create_vlan(const IfNameIndex *ifnameidx, const char *vlan, uint32_t id) {
        _cleanup_(g_string_unrefp) GString *netdev_config = NULL, *vlan_network_config = NULL, *dev_network_config = NULL;
        _auto_cleanup_ char *vlan_netdev = NULL, *vlan_network = NULL, *network = NULL;
        _cleanup_(network_unrefp) Network *v = NULL, *n = NULL;
        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;
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
        };

        if (!netdev->ifname)
                return log_oom();

        r = create_netdev_conf_file(ifnameidx, &vlan_netdev);
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

        *v = (Network) {
                .ifname = strdup(vlan),
        };
        if (!v->ifname)
                return log_oom();

        r = generate_network_config(v, &vlan_network_config);
        if (r < 0) {
                log_warning("Failed to generate network configs : %s", g_strerror(-r));
                return r;
        }

        r = create_network_conf_file(ifnameidx, &vlan_network);
        if (r < 0)
                return r;

        (void) manager_write_network_config(v, vlan_network_config);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

        r = set_config_file_string(network, "Network", "VLAN", vlan);
        if (r < 0)
                return r;

        return dbus_network_reload();
}
