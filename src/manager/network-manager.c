/* Copyright 2024 VMware, Inc.
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
#include "dbus.h"
#include "device.h"
#include "dracut-parser.h"
#include "edit.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "netdev-link.h"
#include "network-address.h"
#include "network-link.h"
#include "network-manager.h"
#include "network.h"
#include "networkd-api.h"
#include "parse-util.h"
#include "string-util.h"
#include "yaml-manager.h"

static const Config network_ctl_to_network_section_config_table[] = {
                { "set-lla",           "LinkLocalAddressing"},
                { "set-ipv4ll-route",  "IPv4LLRoute"},
                { "llmnr",             "LLMNR"},
                { "set-llmnr",         "LLMNR"},
                { "set-mcast-dns",     "MulticastDNS" },
                { "mcast-dns",         "MulticastDNS" },
                { "set-lldp",          "LLDP"},
                { "set-emit-lldp",     "EmitLLDP"},
                { "set-ipforward",     "IPForward"},
                { "set-ipv6acceptra",  "IPv6AcceptRA"},
                { "set-ipmasquerade",  "IPMasquerade"},
                { "set-proxyarp",      "IPv4ProxyARP"},
                { "set-proxyndp",      "IPv6ProxyNDP"},
                { "set-conf-wc",       "ConfigureWithoutCarrier"},
                {},
};

static const Config network_ctl_to_dhcp4_section_config_table[] = {
                { "use-dns",      "UseDNS"},
                { "use-ntp",      "UseNTP"},
                { "use-domains",  "UseDomains"},
                { "use-mtu",      "UseMTU"},
                { "use-routes",   "UseRoutes"},
                { "use-hostname", "UseHostname"},
                { "use-timezone", "UseTimezone"},
                { "send-release", "SendRelease"},
                { "use-routes",   "UseRoutes"},
                { "use-gw",       "UseGateway"},
                { "use-tz",       "UseTimezone"},
                {},
};

static const Config network_ctl_to_dhcp6_section_config_table[] = {
                { "use-dns",               "UseDNS"},
                { "use-ntp",               "UseNTP"},
                { "use-domains",           "UseDomains"},
                { "use-mtu",               "UseMTU"},
                { "use-hostname",          "UseHostname"},
                { "rapid-commit",          "RapidCommit"},
                { "use-addr",              "UseAddress"},
                { "use-delegataed-prefix", "UseDelegatedPrefix"},
                { "without-ra",            "WithoutRA"},
                { "send-release",          "SendRelease"},
                {},
};

static const Config network_ctl_to_link_section_config_table[] = {
                { "manage", "Unmanaged"},
                { "arp",    "ARP"},
                { "mc",     "Multicast"},
                { "amc",    "AllMulticast"},
                { "pcs",    "Promiscuous"},
                {},
};

int manager_network_section_configs_new(ConfigManager **ret) {
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

int manager_network_link_section_configs_new(ConfigManager **ret) {
        ConfigManager *m;
        int r;

        r = config_manager_new(network_ctl_to_link_section_config_table, &m);
        if (r < 0)
                return r;

        *ret = m;
        return 0;
}

int manager_set_link_flag(const IfNameIndex *p, const char *k, const char *v) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);
        assert(k);
        assert(v);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = set_config_file_str(network, "Link", k, v);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_set_link_dhcp_client(const IfNameIndex *p,
                                 DHCPClient mode,
                                 int use_dns_ipv4,
                                 int use_dns_ipv6,
                                 int use_domains_ipv4,
                                 int use_domains_ipv6,
                                 int send_release_ipv4,
                                 int send_release_ipv6) {

        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = key_file_set_str(key_file, "Network", "DHCP", dhcp_client_modes_to_name(mode));
        if (r < 0)
                return r;

        if (use_dns_ipv4 >= 0) {
                r = key_file_set_str(key_file, "DHCPv4", "UseDNS", bool_to_str(use_dns_ipv4));
                if (r < 0)
                        return r;
        }

        if (use_dns_ipv6 >= 0) {
                r = key_file_set_str(key_file, "DHCPv6", "UseDNS", bool_to_str(use_dns_ipv6));
                if (r < 0)
                        return r;
        }

        if (use_domains_ipv4 >= 0) {
                r = key_file_set_str(key_file, "DHCPv4", "UseDomains", bool_to_str(use_domains_ipv4));
                if (r < 0)
                        return r;
        }

        if (use_domains_ipv6 >= 0) {
                r = key_file_set_str(key_file, "DHCPv6", "UseDomains", bool_to_str(use_domains_ipv6));
                if (r < 0)
                        return r;
        }

        if (send_release_ipv4 >= 0) {
                r = key_file_set_str(key_file, "DHCPv4", "SendRelease", bool_to_str(send_release_ipv4));
                if (r < 0)
                        return r;
        }

        if (send_release_ipv6 >= 0) {
                r = key_file_set_str(key_file, "DHCPv6", "SendRelease", bool_to_str(send_release_ipv6));
                if (r < 0)
                        return r;
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_acquire_link_dhcp_client_kind(const IfNameIndex *p, DHCPClient *mode) {
        _auto_cleanup_ char *network = NULL, *config_dhcp = NULL;
        int r;

        assert(p);

        r = network_parse_link_network_file(p->ifindex, &network);
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

static int manager_set_link_dynamic_conf_internal(KeyFile *key_file,
                                                  const IfNameIndex *p,
                                                  int accept_ra,
                                                  DHCPClient dhcp_kind,
                                                  int use_dns_ipv4,
                                                  int use_dns_ipv6,
                                                  int use_domains_ipv4,
                                                  int use_domains_ipv6,
                                                  int send_release_ipv4,
                                                  int send_release_ipv6,
                                                  const DHCPClientIdentifier dhcp4_identifier,
                                                  const char *iaid4,
                                                  const char *iaid6,
                                                  int lla) {

        int r;

        assert(p);

        if (dhcp4_identifier >= 0) {
                r = key_file_set_str(key_file, "DHCPv4", "ClientIdentifier", dhcp_client_identifier_to_name(dhcp4_identifier));
                if (r < 0) {
                        log_warning("Failed to update DHCP4 ClientIdentifier= to configuration file '%s': %s", key_file->name, strerror(-r));
                        return r;
                }
        }

        if (iaid4) {
                r = key_file_set_str(key_file, "DHCPv4", "IAID", iaid4);
                if (r < 0) {
                        log_warning("Failed to update DHCP4 IAID= to configuration file '%s': %s", key_file->name, strerror(-r));
                        return r;
                }
        }

        if (iaid6) {
                r = key_file_set_str(key_file, "DHCPv6", "IAID", iaid6);
                if (r < 0) {
                        log_warning("Failed to update DHCP6 IAID= to configuration file '%s': %s", key_file->name, strerror(-r));
                        return r;
                }
        }

        /* IPv6AcceptRA= and LinkLocalAddressing= is required for DHCPv6 */
        if (dhcp_kind == DHCP_CLIENT_YES || dhcp_kind == DHCP_CLIENT_IPV6) {
                r = key_file_set_str(key_file, "Network", "LinkLocalAddressing", "ipv6");
                if (r < 0)
                        return r;

                r = key_file_set_str(key_file, "Network", "IPv6AcceptRA", "yes");
                if (r < 0)
                        return r;
        } else if (dhcp_kind == DHCP_CLIENT_IPV4) {
                r = key_file_set_str(key_file, "Network", "LinkLocalAddressing", "no");
                if (r < 0)
                        return r;

                r = key_file_set_str(key_file, "Network", "IPv6AcceptRA", "no");
                if (r < 0)
                        return r;
        }

        if (accept_ra >= 0) {
                r = key_file_set_str(key_file, "Network", "LinkLocalAddressing", "ipv6");
                if (r < 0)
                        return r;

                r = key_file_set_str(key_file, "Network", "IPv6AcceptRA", bool_to_str(accept_ra));
                if (r < 0)
                        return r;
        }

        if (lla >= 0) {
                r = key_file_set_str(key_file, "Network", "LinkLocalAddressing", link_local_address_type_to_name(lla));
                if (r < 0)
                        return r;
        }

        if (dhcp_kind >= 0) {
                r = key_file_set_str(key_file, "Network", "DHCP", dhcp_client_modes_to_name(dhcp_kind));
                if (r < 0)
                        return r;
        }

        if (use_dns_ipv4 >= 0) {
                r = key_file_set_str(key_file, "DHCPv4", "UseDNS", bool_to_str(use_dns_ipv4));
                if (r < 0)
                        return r;
        }

        if (use_dns_ipv6 >= 0) {
                r = key_file_set_str(key_file, "DHCPv6", "UseDNS", bool_to_str(use_dns_ipv6));
                if (r < 0)
                        return r;
        }

        if (use_domains_ipv4 >= 0) {
                r = key_file_set_str(key_file, "DHCPv4", "UseDomains", bool_to_str(use_domains_ipv4));
                if (r < 0)
                        return r;
        }

        if (use_domains_ipv6 >= 0) {
                r = key_file_set_str(key_file, "DHCPv6", "UseDomains", bool_to_str(use_domains_ipv6));
                if (r < 0)
                        return r;
        }

        if (send_release_ipv4 >= 0) {
                r = key_file_set_str(key_file, "DHCPv4", "SendRelease", bool_to_str(send_release_ipv4));
                if (r < 0)
                        return r;
        }

        if (send_release_ipv6 >= 0) {
                r = key_file_set_str(key_file, "DHCPv6", "SendRelease", bool_to_str(send_release_ipv6));
                if (r < 0)
                        return r;
        }

        return 0;
}
int manager_set_link_dynamic_conf(const IfNameIndex *p,
                                  int accept_ra,
                                  DHCPClient dhcp_kind,
                                  int use_dns_ipv4,
                                  int use_dns_ipv6,
                                  int use_domains_ipv4,
                                  int use_domains_ipv6,
                                  int send_release_ipv4,
                                  int send_release_ipv6,
                                  const DHCPClientIdentifier dhcp4_identifier,
                                  const char *iaid4,
                                  const char *iaid6,
                                  int lla,
                                  bool keep) {

        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);

        if (keep) {
                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;
        } else {
                r = create_network_conf_file(p->ifname, &network);
                if (r < 0)
                        return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = manager_set_link_dynamic_conf_internal(key_file,
                                                   p,
                                                   accept_ra,
                                                   dhcp_kind,
                                                   use_dns_ipv4,
                                                   use_dns_ipv6,
                                                   use_domains_ipv4,
                                                   use_domains_ipv6,
                                                   send_release_ipv4,
                                                   send_release_ipv6,
                                                   dhcp4_identifier,
                                                   iaid4,
                                                   iaid6,
                                                   lla);

        if (r < 0)
                return r;

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}


static int manager_set_link_static_conf_internal(KeyFile *key_file,
                                                 const IfNameIndex *p,
                                                 char **addrs,
                                                 char **gws,
                                                 char **dns,
                                                 int lla,
                                                 bool keep) {
        _auto_cleanup_ char *address = NULL, *gw = NULL;
        char **a;
        int r;

        assert(p);

        if (lla >= 0) {
                r = key_file_set_str(key_file, "Network", "LinkLocalAddressing", link_local_address_type_to_name(lla));
                if (r < 0)
                        return r;
        }

        if (dns) {
                _auto_cleanup_strv_ char **s = NULL, **t = NULL;
                char **l;

                if (keep) {
                        r = key_file_network_parse_dns(key_file->name, &s);
                        if (r < 0)
                                return r;

                        if (strv_empty((const char **) s)) {
                                t = strv_dup(dns);
                                if (!t)
                                        return log_oom();
                        } else {
                                t = strv_unique(dns, s);
                                if (!t)
                                        return log_oom();
                        }

                        l = t;
                } else
                        l = dns;

                r = set_config(key_file, "Network", "DNS", strv_join(" ", l));
                if (r < 0)
                        return r;
        }

        strv_foreach(a, addrs) {
                _cleanup_(section_freep) Section *section = NULL;

                r = section_new("Address", &section);
                if (r < 0)
                        return r;

                r = add_key_to_section(section, "Address", *a);
                if (r < 0)
                        return r;

                r = add_section_to_key_file(key_file, section);
                if (r < 0)
                        return r;

                steal_ptr(section);
        }

        strv_foreach(a, gws) {
                _cleanup_(section_freep) Section *section = NULL;

                r = section_new("Route", &section);
                if (r < 0)
                        return r;

                r = add_key_to_section(section, "Gateway", *a);
                if (r < 0)
                        return r;

                r = add_section_to_key_file(key_file, section);
                if (r < 0)
                        return r;

                steal_ptr(section);
        }

        return 0;
}

int manager_set_link_static_conf(const IfNameIndex *p, char **addrs, char **gws, char **dns, int lla, bool keep) {
        _auto_cleanup_ char *network = NULL, *address = NULL, *gw = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        char **a;
        int r;

        assert(p);

        if (keep) {
                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;
        } else {
                r = create_network_conf_file(p->ifname, &network);
                if (r < 0)
                        return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = manager_set_link_static_conf_internal(key_file, p, addrs, gws, dns, lla, keep);
        if (r < 0)
                return r;

        /* Enable IPv6 for the device */
        strv_foreach(a, addrs) {
                _auto_cleanup_ IPAddress *addr = NULL;

                r = parse_ip(*a, &addr);
                if (r < 0)
                        continue;

                if (addr->family == AF_INET6) {
                        r = key_file_set_str(key_file, "Network", "LinkLocalAddressing", "ipv6");
                        if (r < 0)
                                return r;
                        break;
                }
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_network_conf(const IfNameIndex *p,
                                  int accept_ra,
                                  DHCPClient dhcp_kind,
                                  int use_dns_ipv4,
                                  int use_dns_ipv6,
                                  int use_domains_ipv4,
                                  int use_domains_ipv6,
                                  int send_release_ipv4,
                                  int send_release_ipv6,
                                  const DHCPClientIdentifier dhcp4_identifier,
                                  const char *iaid4,
                                  const char *iaid6,
                                  char **addrs,
                                  char **gws,
                                  char **dns,
                                  int lla,
                                  bool keep) {
        _auto_cleanup_ char *network = NULL, *address = NULL, *gw = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        char **a;
        int r;

        assert(p);

        if (keep) {
                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;
        } else {
                r = create_network_conf_file(p->ifname, &network);
                if (r < 0)
                        return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = manager_set_link_dynamic_conf_internal(key_file,
                                                   p,
                                                   accept_ra,
                                                   dhcp_kind,
                                                   use_dns_ipv4,
                                                   use_dns_ipv6,
                                                   use_domains_ipv4,
                                                   use_domains_ipv6,
                                                   send_release_ipv4,
                                                   send_release_ipv6,
                                                   dhcp4_identifier,
                                                   iaid4,
                                                   iaid6,
                                                   lla);
        if (r < 0)
                return r;

        r = manager_set_link_static_conf_internal(key_file, p, addrs, gws, dns, lla,  keep);
        if (r < 0)
                return r;

        strv_foreach(a, addrs) {
                _auto_cleanup_ IPAddress *addr = NULL;

                r = parse_ip(*a, &addr);
                if (r < 0)
                        continue;

                if (addr->family == AF_INET6) {
                        r = key_file_set_str(key_file, "Network", "LinkLocalAddressing", "ipv6");
                        if (r < 0)
                                return r;
                        break;
                }
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

bool manager_link_has_static_address(const IfNameIndex *p) {
        _auto_cleanup_ char *network = NULL, *addr = NULL;
        int r;

        assert(p);

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0)
                return false;

        r = parse_config_file(network, "Network", "Address", &addr);
        if (r >= 0)
                return true;

        r = parse_config_file(network, "Address", "Address", &addr);
        if (r >= 0)
                return true;

        return false;
}

int manager_set_link_dhcp4_client_identifier(const IfNameIndex *p, const DHCPClientIdentifier identifier) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = set_config_file_str(network, "DHCPv4", "ClientIdentifier", dhcp_client_identifier_to_name(identifier));
        if (r < 0) {
                log_warning("Failed to update DHCP4 ClientIdentifier= to configuration file '%s': %s", network, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_ipv6_dad(const IfNameIndex *p, int dad) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = set_config_file_int(network, "Network", "IPv6DuplicateAddressDetection", dad);
        if (r < 0) {
                log_warning("Failed to update IPv6DuplicateAddressDetection= to configuration file '%s': %s", network, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_ipv6_link_local_address_generation_mode(const IfNameIndex *p, int mode) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = set_config_file_str(network, "Network", "IPv6LinkLocalAddressGenerationMode", ipv6_link_local_address_gen_type_to_name(mode));
        if (r < 0) {
                log_warning("Failed to update IPv6LinkLocalAddressGenerationMode= to configuration file '%s': %s", network, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_parse_link_dns_servers(const IfNameIndex *p, char ***ret) {
        _auto_cleanup_ char *network = NULL, *config = NULL;
        int r;

        assert(p);

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, "Network", "DNS", &config);
        if (r < 0)
                return r;

        if (config)
                *ret = strsplit(config, " ", 0);
        return 0;
}

int manager_acquire_all_link_dns(char ***ret) {
        _cleanup_(links_freep) Links *links = NULL;
        _auto_cleanup_ char *dns = NULL;
        int r;

        r = netlink_acquire_all_links(&links);
        if (r < 0)
                return r;

        for (GList *i = links->links; i; i = g_list_next (i)) {
                _auto_cleanup_ char *c = NULL, *network = NULL;
                _auto_cleanup_ IfNameIndex *p = NULL;
                Link *link = (Link *) i->data;

                r = parse_ifname_or_index(link->name, &p);
                if (r < 0)
                        continue;

                r = network_parse_link_network_file(link->ifindex, &network);
                if (r < 0)
                        continue;

                r = parse_config_file(network, "Network", "DNS", &c);
                if (r < 0)
                        continue;

                dns = strjoin(" ", c, dns, NULL);
                if (!dns)
                        return log_oom();
        }

        if (dns)
                *ret = strsplit(dns, " ", 0);
        return 0;
}

int manager_acquire_all_link_dhcp_lease_dns(char ***ret) {
        _cleanup_(links_freep) Links *links = NULL;
        _auto_cleanup_ char *dns = NULL;
        int r;

        r = netlink_acquire_all_links(&links);
        if (r < 0)
                return r;

        for (GList *i = links->links; i; i = g_list_next (i)) {
                _auto_cleanup_strv_ char **c = NULL;
                _auto_cleanup_ IfNameIndex *p = NULL;
                _auto_cleanup_ char *s = NULL;
                Link *link = (Link *) i->data;

                r = parse_ifname_or_index(link->name, &p);
                if (r < 0)
                        continue;

                r = network_parse_link_dhcp4_dns(link->ifindex, &c);
                if (r < 0)
                        continue;

                dns = strjoin(" ", strv_join(" ", c), dns, NULL);
                if (!dns)
                        return log_oom();
        }

        if (dns)
                *ret = strsplit(dns, " ", 0);
        return 0;
}

int manager_parse_link_ntp_servers(const IfNameIndex *p, char ***ret) {
        _auto_cleanup_ char *network = NULL, *config = NULL;
        int r;

        assert(p);

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, "Network", "NTP", &config);
        if (r < 0)
                return r;

        if (config)
                *ret = strsplit(config, " ", 0);
        return 0;
}

int manager_acquire_all_link_ntp(char ***ret) {
        _cleanup_(links_freep) Links *links = NULL;
        _auto_cleanup_ char *ntp = NULL;
        int r;

        r = netlink_acquire_all_links(&links);
        if (r < 0)
                return r;

        for (GList *i = links->links; i; i = g_list_next (i)) {
                _auto_cleanup_ char *c = NULL, *network = NULL;
                _auto_cleanup_ IfNameIndex *p = NULL;
                Link *link = (Link *) i->data;

                r = parse_ifname_or_index(link->name, &p);
                if (r < 0)
                        continue;

                r = network_parse_link_network_file(link->ifindex, &network);
                if (r < 0)
                        continue;

                r = parse_config_file(network, "Network", "NTP", &c);
                if (r < 0)
                        continue;

                ntp = strjoin(" ", c, ntp, NULL);
                if (!ntp)
                        return log_oom();
        }

        if (ntp)
                *ret = strsplit(ntp, " ", 0);
        return 0;
}

int manager_acquire_link_dhcp4_client_identifier(const IfNameIndex *p, DHCPClientIdentifier *ret) {
        _auto_cleanup_ char *network = NULL, *config = NULL;
        int r;

        assert(p);

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, "DHCPv4", "ClientIdentifier", &config);
        if (r < 0)
                return r;

        *ret = dhcp_client_identifier_to_kind(config);
        return 0;
}

int manager_set_link_dhcp_client_iaid(const IfNameIndex *p, const DHCPClient kind, const char *iaid) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = set_config_file_str(network, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "IAID", iaid);
        if (r < 0) {
                log_warning("Failed to update DHCP IAID= to configuration file '%s': %s", network, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_acquire_link_dhcp_client_iaid(const IfNameIndex *p, const DHCPClient kind, char **iaid) {
        _auto_cleanup_ char *network = NULL, *v = NULL;
        int r;

        assert(p);

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "IAID", &v);
        if (r < 0)
                return r;

        *iaid = strdup(v);
        if(!*iaid)
                return log_oom();

        return 0;
}

int manager_acquire_link_dhcp_client_duid(const IfNameIndex *p, const DHCPClient kind, char **duid_kind, char **raw_data) {
        _auto_cleanup_ char *network = NULL, *v = NULL;
        int r;

        assert(p);

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "DUIDType", &v);
        if (r < 0)
                return r;

        *duid_kind = strdup(v);
        if(!*duid_kind)
                return log_oom();

        r = parse_config_file(network, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "DUIDRawData", &v);
        if (r < 0)
                return r;

        *raw_data = strdup(v);
        if(!*raw_data)
                return log_oom();

        return 0;
}

int manager_set_link_dhcp_client_duid(const IfNameIndex *p,
                                      const char *duid,
                                      const char *raw_data,
                                      const bool system,
                                      const DHCPClient kind) {
        _auto_cleanup_ char *c = NULL;
        int r;

        if (system) {
                c = g_strdup("/etc/systemd/networkd.conf");
                if (!c)
                        return log_oom();
        } else {
                r = create_or_parse_network_file(p, &c);
                if (r < 0)
                        return r;
        }

        r = set_config_file_str(c, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "DUIDType", duid);
        if (r < 0) {
                log_warning("Failed to update %s DUIDType= to configuration file '%s': %s", kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", c, strerror(-r));
                return r;
        }

        if (raw_data) {
                r = set_config_file_str(c, kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", "DUIDRawData", raw_data);
                if (r < 0) {
                        log_warning("Failed to update %s DUIDRawData= to configuration file '%s': %s", kind == DHCP_CLIENT_IPV4 ? "DHCPv4" : "DHCPv6", c, strerror(-r));
                        return r;
                }
        }

        return dbus_network_reload();
}

int manager_set_link_mtu(const IfNameIndex *p, uint32_t mtu) {
        _auto_cleanup_ char *network = NULL, *config_update_mtu = NULL;
        int r;

        assert(p);
        assert(mtu > 0);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        asprintf(&config_update_mtu, "%u", mtu);
        r = set_config_file_str(network, "Link", "MTUBytes", config_update_mtu);
        if (r < 0) {
                log_warning("Failed to update MTUBytes= to configuration file '%s' = %s", network, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_group(const IfNameIndex *p, uint32_t group) {
        _auto_cleanup_ char *network = NULL, *config_update_group = NULL;
        int r;

        assert(p);
        assert(group > 0);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        asprintf(&config_update_group, "%u", group);

        r = set_config_file_str(network, "Link", "Group", config_update_group);
        if (r < 0) {
                log_warning("Failed to update Group= to configuration file '%s' = %s", network, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_rf_online(const IfNameIndex *p, const char *addrfamily) {
        _auto_cleanup_ char *network = NULL, *config_update_family = NULL;
        int r;

        assert(p);
        assert(addrfamily);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        asprintf(&config_update_family, "%s", addrfamily);
        r = set_config_file_str(network, "Link", "RequiredFamilyForOnline", config_update_family);
        if (r < 0) {
                log_warning("Failed to write to configuration file: %s", network);
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_act_policy(const IfNameIndex *p, const char *actpolicy) {
        _auto_cleanup_ char *network = NULL, *config_update_policy = NULL;
        int r;

        assert(p);
        assert(actpolicy);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        asprintf(&config_update_policy, "%s", actpolicy);
        r = set_config_file_str(network, "Link", "ActivationPolicy", config_update_policy);
        if (r < 0) {
                log_warning("Failed to write to configuration file: %s", network);
                return r;
        }

        return dbus_network_reload();
}

int manager_link_set_network_ipv6_mtu(const IfNameIndex *p, uint32_t mtu) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);
        assert(mtu > 0);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = set_config_file_int(network, "Network", "IPv6MTUBytes", mtu);
        if (r < 0) {
                log_warning("Failed to update IPv6MTUBytes= to configuration file '%s' = %s", network, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_local_address(const IfNameIndex *p, const char *k, const char *v) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);
        assert(k);
        assert(v);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = set_config_file_str(network, "Network", k, v);
        if (r < 0) {
                log_warning("Failed to update LinkLocalAddressing= to configuration file '%s' = %s", network, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_mac_addr(const IfNameIndex *p, const char *mac) {
        _auto_cleanup_ char *network = NULL, *config_mac = NULL, *config_update_mac = NULL;
        int r;

        assert(p);
        assert(mac);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = parse_config_file(network, "Link", "MACAddress", &config_mac);
        if (r >= 0) {
                if (streq(config_mac, mac))
                        return 0;
        }

        asprintf(&config_update_mac, "%s", mac);
        r = set_config_file_str(network, "Link", "MACAddress", config_update_mac);
        if (r < 0) {
                log_warning("Failed to write to configuration file: %s", network);
                return r;
        }

        return dbus_network_reload();
}

int manager_set_link_state(const IfNameIndex *p, LinkState state) {
        assert(p);

        return netlink_set_link_state(p, state);
}

int manager_configure_link_address(const IfNameIndex *p,
                                   const IPAddress *address,
                                   const IPAddress *peer,
                                   const char *scope,
                                   const char *pref_lft,
                                   const IPDuplicateAddressDetection dad,
                                   const int prefix_route,
                                   const char *label,
                                   char **many) {

        _auto_cleanup_ char *network = NULL, *a = NULL, *b = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        char **t;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
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
                        r = ip_to_str(address->family, address, &a);
                else
                        r = ip_to_str_prefix(address->family, address, &a);
                if (r < 0)
                        return r;
        }

        if (peer) {
                if (!peer->prefix_len)
                        r = ip_to_str(peer->family, peer, &b);
                else
                        r = ip_to_str_prefix(peer->family, peer, &b);
                if (r < 0)
                        return r;
        }

        if (a && !key_file_config_exists(key_file, "Address", "Address", a)) {
                add_key_to_section(section, "Address", a);

                if (b)
                        add_key_to_section(section, "Peer", b);

                if (scope)
                        add_key_to_section(section, "Scope", scope);

                if (pref_lft)
                        add_key_to_section(section, "PreferredLifetime", pref_lft);

                if (label)
                        add_key_to_section(section, "Label", label);

                if (prefix_route >= 0)
                add_key_to_section(section, "AddPrefixRoute", bool_to_str(prefix_route));

                if (dad != _IP_DUPLICATE_ADDRESS_DETECTION_INVALID)
                        add_key_to_section(section, "DuplicateAddressDetection", ip_duplicate_address_detection_type_to_name(dad));

                r = add_section_to_key_file(key_file, section);
                if (r < 0)
                        return r;

                steal_ptr(section);
        }

        strv_foreach(t, many) {
                if (key_file_config_exists(key_file, "Address", "Address", *t))
                        continue;

                r = section_new("Address", &section);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Address", *t);
                add_section_to_key_file(key_file, section);
                steal_ptr(section);
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_replace_link_address_internal(KeyFile *key_file, char **many, AddressFamily family) {
        char **t;
        int r;

        assert(key_file);

        for (GList *i = key_file->sections; i; i = g_list_next (i)) {
                _auto_cleanup_ IPAddress *addr = NULL;
                Section *s = (Section *) i->data;

                if (!streq(s->name, "Address"))
                        continue;

                for (GList *j = s->keys; j; j = g_list_next (j)) {
                        Key *key = (Key *) j->data;

                        if (!streq(key->name, "Address"))
                                continue;

                        r = parse_ip_from_str(key->v, &addr);
                        if (r >= 0) {
                                if ((addr->family == AF_INET && family & ADDRESS_FAMILY_IPV4) ||
                                    (addr->family == AF_INET6 && family & ADDRESS_FAMILY_IPV6))
                                        i = g_list_delete_link(key_file->sections, i);
                        }
                }
        }

        strv_foreach(t, many) {
                _cleanup_(section_freep) Section *section = NULL;

                if (key_file_config_exists(key_file, "Address", "Address", *t))
                        continue;

                r = section_new("Address", &section);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Address", *t);
                add_section_to_key_file(key_file, section);
                steal_ptr(section);
        }

        return 0;
}

int manager_replace_link_address(const IfNameIndex *p, char **many, AddressFamily family) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ char *setup = NULL, *network = NULL;
        int r;

        assert(p);

        r = network_parse_link_setup_state(p->ifindex, &setup);
        if (r < 0) {
                log_warning("Failed to find device setup '%s': %s", p->ifname, strerror(-r));
                return r;
        }

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0) {
                log_warning("Failed to find .network file for '%s': %s", p->ifname, strerror(-r));
                return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = manager_replace_link_address_internal(key_file, many, family);
        if (r < 0)
                return r;

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_remove_link_address(const IfNameIndex *p, char **addresses, AddressFamily family) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ char *setup = NULL, *network = NULL;
        char **a;
        int r;

        assert(p);

        r = network_parse_link_setup_state(p->ifindex, &setup);
        if (r < 0) {
                log_warning("Failed to find device setup '%s': %s", p->ifname, strerror(-r));
                return r;
        }

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0) {
                log_warning("Failed to find .network file for '%s': %s", p->ifname, strerror(-r));
                return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        strv_foreach(a, addresses)
                key_file_remove_section_key_value(key_file, "Address", "Address", *a);

        for (GList *i = key_file->sections; i; i = g_list_next (i)) {
                _auto_cleanup_ IPAddress *addr = NULL;
                Section *s = (Section *) i->data;

                if (!streq(s->name, "Address"))
                        continue;

                for (GList *j = s->keys; j; j = g_list_next (j)) {
                        Key *key = (Key *) j->data;

                        if (!streq(key->name, "Address"))
                                continue;

                        r = parse_ip_from_str(key->v, &addr);
                        if (r >= 0) {
                                if ((addr->family == AF_INET && family & ADDRESS_FAMILY_IPV4) ||
                                    (addr->family == AF_INET6 && family & ADDRESS_FAMILY_IPV6))
                                        i = g_list_delete_link(key_file->sections, i);
                        }
                }
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

static int manager_set_gateway(KeyFile *key_file, Route *rt) {
        _auto_cleanup_ IPAddress *a = NULL;
        _auto_cleanup_ char *gw = NULL;
        bool b = false;
        int r;

        assert(key_file);
        assert(rt);

        for (GList *i = key_file->sections; i; i = g_list_next (i)) {
                Section *s = (Section *) i->data;

                if (!streq(s->name, "Route"))
                        continue;

                for (GList *j = s->keys; j; j = g_list_next (j)) {
                        Key *key = (Key *) j->data;

                        if (!streq(key->name, "Gateway"))
                                continue;

                        r = parse_ip(key->v, &a);
                        if (r >= 0) {
                                if (a->family == rt->family) {
                                        free(key->v);

                                        r = ip_to_str(rt->family, &rt->gw, &gw);
                                        if (r >= 0) {
                                                key->v = steal_ptr(gw);
                                                b = true;

                                                break;
                                        }
                                }
                        }
                }
        }

        if (!b) {
                _cleanup_(section_freep) Section *section = NULL;

                r = ip_to_str(rt->gw.family, &rt->gw, &gw);
                if (r < 0)
                        return r;

                r = section_new("Route", &section);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Gateway", gw);

                r = add_section_to_key_file(key_file, section);
                if (r < 0)
                        return r;

                steal_ptr(section);
        }

        return 0;
}

int manager_configure_default_gateway_full(const IfNameIndex *p, Route *rt4, Route *rt6) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        if (rt4) {
                r = manager_set_gateway(key_file, rt4);
                if (r < 0)
                        return r;
        }

        if (rt6) {
                r = manager_set_gateway(key_file, rt6);
                if (r < 0)
                        return r;
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_configure_default_gateway(const IfNameIndex *p, Route *rt, bool keep) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ char *network = NULL, *gw = NULL;
        int r;

        assert(p);
        assert(rt);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = ip_to_str(rt->gw.family, &rt->gw, &gw);
        if (r < 0)
                return r;

        if (!keep) {
                   r = key_file_set_str(key_file, "Route", "Gateway", gw);
                if (r < 0)
                        return r;

                if (rt->onlink >= 0) {
                        r = key_file_set_str(key_file, "Route", "GatewayOnlink", bool_to_str(rt->onlink));
                        if (r < 0)
                                return r;
                }
        } else {
                _cleanup_(section_freep) Section *section = NULL;

                r = section_new("Route", &section);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Gateway", gw);
                if (rt->onlink >= 0)
                        add_key_to_section(section, "GatewayOnlink", bool_to_str(rt->onlink));

                add_section_to_key_file(key_file, section);
                steal_ptr(section);
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_configure_route(const IfNameIndex *p,
                            const IPAddress *gateway,
                            const IPAddress *destination,
                            const IPAddress *source,
                            const IPAddress *pref_source,
                            const IPv6RoutePreference rt_pref,
                            const RouteProtocol protocol,
                            const RouteScope scope,
                            const RouteType type,
                            const RouteTable table,
                            const uint32_t mtu,
                            const int metric,
                            const int onlink,
                            const bool b) {

        _auto_cleanup_ char *network = NULL, *gw = NULL, *dest = NULL, *src = NULL, *pref_src = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = section_new("Route", &section);
        if (r < 0)
                return r;

        if (gateway) {
                r = ip_to_str(gateway->family, gateway, &gw);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Gateway", gw);
        }

        if (onlink >= 0)
                add_key_to_section(section, "GatewayOnLink", bool_to_str(onlink));

        if (source) {
                r = ip_to_str_prefix(gateway->family, source, &src);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Source", src);
        }

        if (pref_source) {
                r = ip_to_str_prefix(pref_source->family, pref_source, &pref_src);
                if (r < 0)
                        return r;

                add_key_to_section(section, "PreferredSource", pref_src);
        }

        if (destination) {
                r = ip_to_str_prefix(destination->family, destination, &dest);
                if (r < 0)
                        return r;

                add_key_to_section(section, "Destination", dest);
        } else if (b) {
                switch(gateway->family) {
                        case AF_INET:
                                add_key_to_section(section, "Destination", "0.0.0.0/0");
                                break;
                        case AF_INET6:
                                add_key_to_section(section, "Destination", "::/0");
                                break;
                }
        }

        if (metric > 0)
                add_key_to_section_int(section, "Metric", metric);

        if (mtu > 0)
                add_key_to_section_int(section, "MTUBytes", mtu);

        if (protocol > 0) {
                if (route_protocol_to_name(protocol))
                        add_key_to_section(section, "Protocol", route_protocol_to_name(protocol));
                else
                        add_key_to_section_int(section, "Protocol", protocol);
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
                        add_key_to_section_int(section, "Table", table);
        }

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_ptr(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_remove_gateway_or_route_full_internal(KeyFile *key_file, bool gateway, AddressFamily family) {
        int r;

        assert(key_file);

        for (GList *i = key_file->sections; i; i = g_list_next (i)) {
                _auto_cleanup_ IPAddress *a = NULL;
                Section *s = (Section *) i->data;

                if (streq(s->name, "Route")) {
                        for (GList *j = s->keys; j; j = g_list_next (j)) {
                                Key *key = (Key *) j->data;

                                if (gateway) {
                                        if (streq(key->name, "Gateway")) {
                                                r = parse_ip(key->v, &a);
                                                if (r >= 0) {
                                                        if ((a->family == AF_INET && family & ADDRESS_FAMILY_IPV4) ||
                                                            (a->family == AF_INET6 && family & ADDRESS_FAMILY_IPV6))
                                                                i = g_list_delete_link(key_file->sections, i);
                                                }
                                        }
                                } else {
                                        if (streq(key->name, "Destination")) {
                                                r = parse_ip(key->v, &a);
                                                if (r >= 0) {
                                                        if ((a->family == AF_INET && family & ADDRESS_FAMILY_IPV4) ||
                                                            (a->family == AF_INET6 && family & ADDRESS_FAMILY_IPV6))
                                                                i = g_list_delete_link(key_file->sections, i);
                                                }
                                        }
                                }
                        }
                }
        }

        return 0;
}

int manager_remove_gateway_or_route_full(const char *network, bool gateway, AddressFamily family) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        int r;

        assert(network);

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = manager_remove_gateway_or_route_full_internal(key_file, gateway, family);
        if (r < 0)
                return r;

        r = key_file_save (key_file);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_remove_gateway_or_route(const IfNameIndex *p, bool gateway, AddressFamily family) {
        _auto_cleanup_ char *setup = NULL, *network = NULL, *config = NULL;
        int r;

        assert(p);

        r = network_parse_link_setup_state(p->ifindex, &setup);
        if (r < 0) {
                log_warning("Failed to find setup for device'%s': %s", p->ifname, strerror(-r));
                return r;
        }

        r = network_parse_link_network_file(p->ifindex, &network);
        if (r < 0)
                return r;

        if (family > 0)
                return manager_remove_gateway_or_route_full(network, gateway, family);

        if (gateway) {
                r = parse_config_file(network, "Route", "Gateway", &config);
                if (r >= 0) {
                        r = remove_section_from_config_file_key(network, "Route", "Gateway", true);
                        if (r < 0)
                                return r;
                }
        } else {
                r = parse_config_file(network, "Route", "Destination", &config);
                if (r >= 0) {
                        r = remove_section_from_config_file_key(network, "Route", "Destination", true);
                        if (r < 0)
                                return r;
                }
        }

        return dbus_network_reload();
}

int manager_configure_routing_policy_rules(const IfNameIndex *p, RoutingPolicyRule *rule) {
        _auto_cleanup_ char *network = NULL, *to = NULL, *from = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
        if (r < 0) {
                log_warning("Failed to find or create network file for device '%s': %s\n", p->ifname, strerror(-r));
                return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = ip_to_str_prefix(rule->to.family, &rule->to, &to);
        if (r < 0)
                return r;

        r = ip_to_str_prefix(rule->from.family, &rule->from, &from);
        if (r < 0)
                return r;

        r = section_new("RoutingPolicyRule", &section);
        if (r < 0)
                return r;

        if (rule->tos > 0)
                add_key_to_section_uint(section, "TypeOfService", rule->tos);

        add_key_to_section_int(section, "Table", rule->table);

        if (rule->priority > 0)
                add_key_to_section_int(section, "Priority", rule->priority);

        if (from)
                add_key_to_section(section, "From", from);

        if (to)
                add_key_to_section(section, "To", to);

        if (rule->iif)
                add_key_to_section(section, "IncomingInterface", rule->iif);

        if (rule->oif)
                add_key_to_section(section, "OutgoingInterface", rule->oif);

        if (rule->invert_rule)
                add_key_to_section(section, "Invert", bool_to_str(rule->invert_rule));

        if (rule->sport_str)
                add_key_to_section(section, "SourcePort", rule->sport_str);

        if (rule->dport_str)
                add_key_to_section(section, "DestinationPort", rule->dport_str);

        if (rule->ipproto_str)
                add_key_to_section(section, "IPProtocol", rule->ipproto_str);

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_ptr(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_remove_routing_policy_rules(const IfNameIndex *p) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);

        r = create_or_parse_network_file(p, &network);
        if (r < 0) {
                log_warning("Failed to create or parse network file '%s': %s\n", p->ifname, strerror(-r));
                return r;
        }

        r = remove_section_from_config_file(network, "RoutingPolicyRule");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_configure_routing_policy_rule(const IfNameIndex *p, const IPAddress *a, const Route *rt, bool keep) {
        _auto_cleanup_ char *network = NULL, *address = NULL, *gw = NULL, *destination = NULL, *pref_source = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
         _cleanup_(section_freep) Section *section = NULL;
        int r;

        assert(p);
        assert(rt);

        if (keep) {
                r = create_or_parse_network_file(p, &network);
                if (r < 0)
                        return r;
        } else {
                r = create_network_conf_file(p->ifname, &network);
                if (r < 0)
                        return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = ip_to_str(rt->gw.family, &rt->gw, &gw);
        if (r < 0)
                return r;

        if (a) {
                r = ip_to_str_prefix(a->family, a, &address);
                if (r < 0)
                        return r;

                r = key_file_set_str(key_file, "Address", "Address", address);
                if (r < 0)
                        return r;
        }

        pref_source = strdup(address);
        if (!pref_source)
                return log_oom();

        if (!ip_is_null(&rt->gw)) {
                r = ip_to_str(rt->gw.family, &rt->gw, &gw);
                if (r < 0)
                        return r;
        }

        r = section_new("Route", &section);
        if (r < 0)
                return r;

        r = add_key_to_section_int(section, "Table", rt->table);
        if (r < 0)
                return r;

        r = add_key_to_section(section, "PreferredSource", pref_source);
        if (r < 0)
                return r;

        if (!ip_is_null(&rt->dst)) {
                r = ip_to_str(rt->dst.family, &rt->dst, &destination);
                if (r < 0)
                        return r;
        } else if (rt->to_default || ip_is_null(&rt->dst)) {
                switch(rt->family) {
                        case AF_INET:
                                destination = strdup("0.0.0.0/0");
                                if (!destination)
                                        return log_oom();
                                break;
                        case AF_INET6:
                                destination = strdup("::/0");
                                if (!destination)
                                        return log_oom();
                                break;
                }
        }

        r = add_key_to_section(section, "Destination", destination);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_ptr(section);

        r = section_new("Route", &section);
        if (r < 0)
                return r;

        r = add_key_to_section_int(section, "Table", rt->table);
        if (r < 0)
                return r;

        r = add_key_to_section(section, "Gateway", gw);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_ptr(section);

        /* To= */
        r = section_new("RoutingPolicyRule", &section);
        if (r < 0)
                return r;

        r = add_key_to_section_int(section, "Table", rt->table);
        if (r < 0)
                return r;

        r = add_key_to_section(section, "To", address);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_ptr(section);

        /* From= */
        r = section_new("RoutingPolicyRule", &section);
        if (r < 0)
                return r;

        r = add_key_to_section_int(section, "Table", rt->table);
        if (r < 0)
                return r;

        r = add_key_to_section(section, "From", address);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_ptr(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_configure_dhcpv4_server(const IfNameIndex *i,
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

        assert(i);

        r = create_or_parse_network_file(i, &network);
        if (r < 0) {
                log_warning("Failed to find or create network file for device '%s': %s\n", i->ifname, strerror(-r));
                return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        if (dns_address) {
                r = ip_to_str(dns_address->family, dns_address, &dns);
                if (r < 0)
                        return r;
        }

        if (ntp_address) {
                r = ip_to_str(ntp_address->family, ntp_address, &ntp);
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
                add_key_to_section_int(section, "PoolOffset", pool_offset);

        if (pool_size > 0)
                add_key_to_section_int(section, "PoolSize", pool_size);

        if (default_lease_time > 0)
                add_key_to_section_int(section, "DefaultLeaseTimeSec", default_lease_time);

        if (max_lease_time > 0)
                add_key_to_section_int(section, "MaxLeaseTimeSec", max_lease_time);

        if (dns)
                add_key_to_section(section, "DNS", dns);

        if (emit_dns >= 0)
                add_key_to_section(section, "EmitDNS", bool_to_str(emit_dns));

        if (ntp)
                add_key_to_section(section, "NTP", ntp);

        if (emit_ntp >= 0)
                add_key_to_section(section, "EmitNTP", bool_to_str(emit_ntp));

        if (emit_router >= 0)
                add_key_to_section(section, "EmitRouter", bool_to_str(emit_router));

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_ptr(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_remove_dhcpv4_server(const IfNameIndex *i) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(i);

        r = create_or_parse_network_file(i, &network);
        if (r < 0) {
                log_warning("Failed to create network file for device '%s': %s\n", i->ifname, strerror(-r));
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

int manager_add_dhcpv4_server_static_address(const IfNameIndex *i, const IPAddress *addr, const char *mac) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        _auto_cleanup_ char *network = NULL, *a = NULL;
        int r;

        assert(i);

        r = create_or_parse_network_file(i, &network);
        if (r < 0) {
                log_warning("Failed to create network file '%s': %s\n", i->ifname, strerror(-r));
                return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = ip_to_str_prefix(addr->family, addr, &a);
        if (r < 0)
                return r;

        /* [DHCPServerStaticLease] section */
        r = section_new("DHCPServerStaticLease", &section);
        if (r < 0)
                return r;

        r = add_key_to_section(section, "MACAddress", mac);
        if (r < 0)
                return r;
        r = add_key_to_section(section, "Address", a);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;
        steal_ptr(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_remove_dhcpv4_server_static_address(const IfNameIndex *i, const IPAddress *addr, const char *mac) {
        _auto_cleanup_ char *network = NULL, *a = NULL;
        int r;

        assert(i);

        r = create_or_parse_network_file(i, &network);
        if (r < 0) {
                log_warning("Failed to create network file for device '%s': %s", i->ifname, strerror(-r));
                return r;
        }

        r = ip_to_str_prefix(addr->family, addr, &a);
        if (r < 0)
                return r;

        r = remove_section_from_config_file_key_value(network, "DHCPServerStaticLease", "Address", a);
        if (r < 0) {
                r = remove_section_from_config_file_key_value(network, "DHCPServerStaticLease", "MACAddress", mac);
                if (r < 0)
                        return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_configure_ipv6_router_advertisement(const IfNameIndex *i,
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

        assert(i);

        r = create_or_parse_network_file(i, &network);
        if (r < 0) {
                log_warning("Failed to find or create network file for device '%s': %s\n", i->ifname, strerror(-r));
                return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        if (prefix) {
                r = ip_to_str_prefix(dns->family, prefix, &p);
                if (r < 0)
                        return r;
        }

        if (route_prefix) {
                r = ip_to_str_prefix(dns->family, route_prefix, &rt);
                if (r < 0)
                        return r;
        }

        if (dns) {
                r = ip_to_str(dns->family, dns, &d);
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
                add_key_to_section_int(ipv6_prefix_section, "PreferredLifetimeSec", pref_lifetime);

        if (valid_lifetime > 0)
                add_key_to_section_int(ipv6_prefix_section, "ValidLifetimeSec", valid_lifetime);


        r = section_new("IPv6SendRA", &ipv6_sendra_section);
        if (r < 0)
                return r;

        /* [IPv6SendRA] section */
        if (preference != _IPV6_RA_PREFERENCE_INVALID)
                add_key_to_section(ipv6_sendra_section, "RouterPreference", ipv6_ra_preference_type_to_name(preference));

        if (dns)
                add_key_to_section(ipv6_sendra_section, "DNS", d);

        if (emit_dns >= 0)
                add_key_to_section(ipv6_sendra_section, "EmitDNS", bool_to_str(emit_dns));

        if (dns_lifetime > 0)
                add_key_to_section_int(ipv6_sendra_section, "DNSLifetimeSec", dns_lifetime);

        if (domain)
                add_key_to_section(ipv6_sendra_section, "Domains", domain);

        if (assign >= 0)
                add_key_to_section(ipv6_sendra_section, "Assign", bool_to_str(assign));

        r = section_new("IPv6RoutePrefix", &ipv6_route_prefix_section);
        if (r < 0)
                return r;

        /* [IPv6RoutePrefix] section */
        if (rt)
                add_key_to_section(ipv6_route_prefix_section, "Route", rt);

        if (route_lifetime > 0)
                add_key_to_section_int(ipv6_route_prefix_section, "LifetimeSec", route_lifetime);

        r = add_section_to_key_file(key_file, ipv6_sendra_section);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, ipv6_prefix_section);
        if (r < 0)
                return r;

        r = add_section_to_key_file(key_file, ipv6_route_prefix_section);
        if (r < 0)
                return r;

        steal_ptr(ipv6_sendra_section);
        steal_ptr(ipv6_prefix_section);
        steal_ptr(ipv6_route_prefix_section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_remove_ipv6_router_advertisement(const IfNameIndex *i) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(i);

        r = create_or_parse_network_file(i, &network);
        if (r < 0) {
                log_warning("Failed to create network file for device '%s': %s\n", i->ifname, strerror(-r));
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

int manager_set_dns_server(const IfNameIndex *i, char **dns, int ipv4, int ipv6, bool keep) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_strv_ char **s = NULL, **t = NULL;
        _auto_cleanup_ char *network = NULL;
        char **l;
        int r;

        assert(i);

        r = create_or_parse_network_file(i, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        if (dns) {
                if (keep) {
                        r = key_file_network_parse_dns(network, &s);
                        if (r < 0)
                                return r;

                        if (strv_empty((const char **) s)) {
                                t = strv_dup(dns);
                                if (!t)
                                        return log_oom();
                        } else {
                                t = strv_unique(dns, s);
                                if (!t)
                                        return log_oom();
                        }

                        l = t;
                } else
                        l = dns;

                r = set_config(key_file, "Network", "DNS", strv_join(" ", l));
                if (r < 0) {
                        log_warning("Failed to write Network DNS= '%s': %s", network, strerror(-r));
                        return r;
                }
        }

        if(ipv4 >= 0) {
                r = set_config(key_file, "DHCPv4", "UseDNS", bool_to_str(ipv4));
                if (r < 0) {
                        log_warning("Failed to write to DHCPv4 UseDNS= '%s': %s", network, strerror(-r));
                        return r;
                }
        }

        if(ipv6 >= 0) {
                r = set_config(key_file, "DHCPv6", "UseDNS", bool_to_str(ipv6));
                if (r < 0) {
                        log_warning("Failed to write to DHCPv6 UseDNS= '%s': %s", network, strerror(-r));
                        return r;
                }
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_dns_server_domain(const IfNameIndex *i, char **domains, bool keep) {
        _auto_cleanup_ char *network = NULL, *setup = NULL, *c = NULL;
        _auto_cleanup_strv_ char **s = NULL, **t = NULL;
        char **l;
        int r;

        assert(i);
        assert(domains);

        r = network_parse_link_setup_state(i->ifindex, &setup);
        if (r < 0 || streq(setup, "unmanaged"))
                return dbus_add_dns_domains(i->ifindex, domains);

        r = create_or_parse_network_file(i, &network);
        if (r < 0)
                return r;

        if (keep) {
                r = key_file_network_parse_search_domains(network, &s);
                if (r < 0)
                        return r;

                if (strv_empty((const char **) s)) {
                        t = strv_dup(domains);
                        if (!t)
                                return log_oom();
                } else {
                        t = strv_unique(domains, s);
                        if (!t)
                                return log_oom();
                }

                l = t;
        } else
                l = domains;

        r = set_config_file_str(network, "Network", "Domains", strv_join(" ", l));
        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, strerror(-r));
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

        *domains = steal_ptr(config_domains);
        return 0;
}

int manager_revert_dns_server_and_domain(const IfNameIndex *i, bool dns, bool domain) {
        _auto_cleanup_ char *setup = NULL, *network = NULL, *config = NULL;
        int r;

        assert(i);

        r = network_parse_link_setup_state(i->ifindex, &setup);
        if (r < 0 || streq(setup, "unmanaged"))
                return dbus_revert_resolve_link(i->ifindex);

        r = network_parse_link_network_file(i->ifindex, &network);
        if (r < 0) {
                log_warning("Failed to find network file for '%s', %s", i->ifname, strerror(-r));
                return r;
        }

        if (dns) {
                r = parse_config_file(network, "Network", "DNS", &config);
                if (r >= 0) {
                        r = remove_key_from_config_file(network, "Network", "DNS");
                        if (r < 0)
                                return r;
                }
        }

        if (domain) {
                r = parse_config_file(network, "Network", "Domains", &config);
                if (r >= 0) {
                        r = remove_key_from_config_file(network, "Network", "Domains");
                        if (r < 0)
                                return r;
                }
        }

        return dbus_network_reload();
}

int manager_set_network_section_bool(const IfNameIndex *i, const char *k, bool v) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(i);
        assert(k);

        r = create_or_parse_network_file(i, &network);
        if (r < 0)
                return r;

        r = set_config_file_bool(network, "Network", k, v);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_set_network_section(const IfNameIndex *i, const char *k, const char *v) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(i);
        assert(k);

        r = create_or_parse_network_file(i, &network);
        if (r < 0)
                return r;

        r = set_config_file_str(network, "Network", k, v);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_set_dhcp_section(DHCPClient kind, const IfNameIndex *i, const char *k, bool v) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(i);

        r = create_or_parse_network_file(i, &network);
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

int manager_set_ntp_servers(const IfNameIndex *i, char **ntp, bool keep) {
        _auto_cleanup_strv_ char **s = NULL, **t = NULL;
        _auto_cleanup_ char *network = NULL, *c = NULL;
        char **l;
        int r;

        assert(i);
        assert(ntp);

        r = create_or_parse_network_file(i, &network);
        if (r < 0)
                return r;

        if (keep) {
                r = key_file_network_parse_ntp(network, &s);
                if (r < 0)
                        return r;

                if (strv_empty((const char **) s)) {
                        t = strv_dup(ntp);
                        if (!t)
                                return log_oom();
                } else {
                        t = strv_unique(ntp, s);
                        if (!t)
                                return log_oom();
                }

                l = t;
        } else
                l = ntp;

        r = set_config_file_str(network, "Network", "NTP", strv_join(" ", l));
        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, strerror(-r));
                return r;
        }

        (void) dbus_network_reload();
        (void) dbus_restart_unit("systemd-timesyncd.service");

        return 0;
}

int manager_remove_ntp_addresses(const IfNameIndex *i) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(i);

        r = create_or_parse_network_file(i, &network);
        if (r < 0)
                return r;

        r = remove_key_from_config_file(network, "Network", "NTP");
        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, strerror(-r));
                return r;
        }

        (void) dbus_network_reload();
        (void) dbus_restart_unit("systemd-timesyncd.service");

        return 0;
}

int manager_enable_ipv6(const IfNameIndex *i, bool enable) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(i);

        r = create_or_parse_network_file(i, &network);
        if (r < 0)
                return r;

        if (enable)
                r = set_config_file_str(network, "Network", "LinkLocalAddressing", "ipv6");
        else
                r = set_config_file_str(network, "Network", "LinkLocalAddressing", "no");

        if (r < 0) {
                log_warning("Failed to write to configuration file '%s': %s", network, strerror(-r));
                return r;
        }

        r = manager_set_link_state(i, LINK_STATE_DOWN);
        if (r < 0)
                return r;

        return dbus_network_reload();
}

int manager_set_ipv6(const IfNameIndex *p, const int dhcp, const int accept_ra, char **addrs, Route *rt6, bool keep) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        DHCPClient mode = _DHCP_CLIENT_INVALID;
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(p);

        if (keep)
                r = create_or_parse_network_file(p, &network);
        else
                r = create_network_conf_file(p->ifname, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        if (accept_ra >= 0)
                set_config(key_file, "Network", "IPv6AcceptRA", bool_to_str(accept_ra));

        r = manager_acquire_link_dhcp_client_kind(p, &mode);
        if (dhcp > 0) {
                set_config(key_file, "Network", "LinkLocalAddressing", "ipv6");
                if (mode == DHCP_CLIENT_NO || mode == _DHCP_CLIENT_INVALID)
                        set_config(key_file, "Network", "DHCP", "ipv6");
                else  if (mode == DHCP_CLIENT_IPV4)
                        set_config(key_file, "Network", "DHCP", "yes");
        } else if (dhcp == DHCP_CLIENT_NO) {
                if (mode == DHCP_CLIENT_YES)
                        set_config(key_file, "Network", "DHCP", "ipv4");
                else  if (mode == DHCP_CLIENT_IPV6 || mode == _DHCP_CLIENT_INVALID)
                        set_config(key_file, "Network", "DHCP", "no");
        }

        r = manager_replace_link_address_internal(key_file, addrs, AF_INET6);
        if (r < 0) {
                log_warning("Failed to replace address on device '%s': %s", p->ifname, strerror(-r));
                return r;
        }

        if (rt6) {
                r = manager_set_gateway(key_file, rt6);
                if (r < 0) {
                        log_warning("Failed to configure gateway on device '%s': %s", p->ifname, strerror(-r));
                        return r;
                }
        } else {
                r = manager_remove_gateway_or_route_full_internal(key_file, true, ADDRESS_FAMILY_IPV6);
                if (r < 0) {
                        log_warning("Failed to remove gateway from device=%s: %s", p->ifname, strerror(-r));
                        return r;
                }
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_set_ipv4(const IfNameIndex *p, const int dhcp, char **addrs, Route *rt4, bool keep) {
        _auto_cleanup_ char *network = NULL, *gw = NULL, *addr = NULL;
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        DHCPClient mode = _DHCP_CLIENT_INVALID;
        int r;

        assert(p);

        if (keep)
                r = create_or_parse_network_file(p, &network);
        else
                r = create_network_conf_file(p->ifname, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = manager_acquire_link_dhcp_client_kind(p, &mode);
        if (dhcp > 0) {
                if (mode == DHCP_CLIENT_NO || mode == _DHCP_CLIENT_INVALID)
                        set_config(key_file, "Network", "DHCP", "ipv4");
                else  if (mode == DHCP_CLIENT_IPV6)
                        set_config(key_file, "Network", "DHCP", "yes");
        } else if (dhcp == DHCP_CLIENT_NO) {
                if (mode == DHCP_CLIENT_YES)
                        set_config(key_file, "Network", "DHCP", "ipv6");
                else  if (mode == DHCP_CLIENT_IPV4 || mode == _DHCP_CLIENT_INVALID)
                        set_config(key_file, "Network", "DHCP", "no");
        }

        r = manager_replace_link_address_internal(key_file, addrs, AF_INET);
        if (r < 0) {
                log_warning("Failed to replace address on device '%s': %s", p->ifname, strerror(-r));
                return r;
        }

        if (rt4) {
                r = manager_set_gateway(key_file, rt4);
                if (r < 0) {
                        log_warning("Failed to configure gateway on device '%s': %s", p->ifname, strerror(-r));
                        return r;
                }
        } else {
                r = manager_remove_gateway_or_route_full_internal(key_file, true, ADDRESS_FAMILY_IPV4);
                if (r < 0) {
                        log_warning("Failed to remove gateway from device=%s: %s", p->ifname, strerror(-r));
                        return r;
                }
        }

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        return dbus_network_reload();
}

int manager_reload_network(void) {
        return dbus_network_reload();
}

int manager_reconfigure_link(const IfNameIndex *i) {
        return dbus_reconfigure_link(i->ifindex);
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
                log_warning("Failed to open wpa supplicant file '%s': %s", path, strerror(-r));
                return r;
        }

        fd = r;
        r = write(fd, config->str, config->len);
        if (r < 0)
                return -errno;

        chmod(path, 0644);
        return 0;
}

int manager_write_network_config(const Network *n, const GString *config) {
        _auto_cleanup_ char *network = NULL, *config_file = NULL;
        _auto_cleanup_close_ int fd = -1;
        int r;

        assert(n);
        assert(config);

        config_file = strjoin("-", "10", n->ifname, NULL);
        if (!config_file)
                return log_oom();

        r = create_conf_file("/etc/systemd/network", config_file, "network", &network);
        if (r < 0)
                return r;

        r = open(network, O_WRONLY);
        if (r < 0) {
                log_warning("Failed to open network file '%s': %s", network, strerror(-r));
                return r;
        }

        fd = r;
        r = write(fd, config->str, config->len);
        if (r < 0)
                return -errno;

        (void) set_file_permisssion(network, "systemd-network");

        return 0;
}

int manager_show_link_network_config(const IfNameIndex *i, char **ret) {
        _auto_cleanup_ char *network = NULL, *config = NULL, *c = NULL;
        int r;

        assert(i);

        r = network_parse_link_network_file(i->ifindex, &network);
        if (r < 0)
                return r;

        r = read_conf_file(network, &config);
        if (r < 0)
                return r;

        c = strjoin("\n\n", network, config, NULL);
        if (!c)
                return log_oom();

        *ret = steal_ptr(c);
        return 0;
}

int manager_edit_link_network_config(const IfNameIndex *i) {
        _auto_cleanup_ char *network = NULL;
        int r;

        assert(i);

        r = network_parse_link_network_file(i->ifindex, &network);
        if (r < 0)
                return r;

        return edit_file(network);
}

int manager_edit_link_config(const IfNameIndex *i) {
        _cleanup_(sd_device_unrefp) sd_device *sd_device = NULL;
        const char *link = NULL;
        int r;

        assert(i);

        r = device_new_from_ifname(&sd_device, i->ifname);
        if (r < 0)
             return r;

        r = sd_device_get_property_value(sd_device, "ID_NET_LINK_FILE", &link);
        if (r < 0)
              return r;

        return edit_file(link);
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

                steal_ptr(s);
                steal_ptr(k);
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

                steal_ptr(s);
                steal_ptr(k);
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

                steal_ptr(s);
                steal_ptr(k);
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

                steal_ptr(s);
                steal_ptr(k);
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

                steal_ptr(s);
                steal_ptr(k);
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

                steal_ptr(s);
               steal_ptr(k);
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

                steal_ptr(s);
                steal_ptr(k);
        }

        if (enable >= 0) {
                _auto_cleanup_ char *p = NULL, *t = NULL;

                t = strdup(bool_to_str(enable));
                if (!t)
                        return log_oom();

                p = strdup("PROXY_ENABLED");
                if (!p)
                        return log_oom();

                g_hash_table_replace(table, p, t);

                steal_ptr(t);
                steal_ptr(p);
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

        *c = steal_ptr(table);
        return 0;
}

int manager_generate_network_config_from_yaml(const char *file) {
        _cleanup_(networks_freep) Networks *n = NULL;
        GHashTableIter iter;
        gpointer k, v;
        int r;

        assert(file);

        r = yaml_parse_file(file, &n);
        if (r < 0) {
                log_warning("Failed to parse configuration file '%s': %s", file, strerror(-r));
                return r;
        }

        /* generate netdev */
        g_hash_table_iter_init (&iter, n->networks);
        for (;g_hash_table_iter_next (&iter, (gpointer *) &k, (gpointer *) &v);) {
                Network *net = (Network *) v;

                if (net->netdev) {
                        r = generate_netdev_config(net->netdev);
                        if (r < 0) {
                                log_warning("Failed to generate network configuration for file '%s': %s", file, strerror(-r));
                                return r;
                        }
                }
        }

        /* generate network */
        g_hash_table_iter_init (&iter, n->networks);
        for (;g_hash_table_iter_next (&iter, (gpointer *) &k, (gpointer *) &v);) {
                Network *net = (Network *) v;

                r = generate_network_config(net);
                if (r < 0) {
                        log_warning("Failed to generate network configuration for file '%s': %s", file, strerror(-r));
                        return r;
                }

                if (net->link) {
                        _auto_cleanup_ IfNameIndex *p = NULL;
                        NetDevLink *l = net->link;

                        r = parse_ifname_or_index(net->ifname, &p);
                        if (r < 0)
                                log_debug("Failed to resolve link '%s': %s", net->ifname, strerror(-r));

                        r = netdev_link_configure(net->ifname, l);
                        if (r < 0)
                                log_debug("Failed to generate .link file for link '%s': %s", net->ifname, strerror(-r));
                }
        }

        /* generate master device network section  */
        g_hash_table_iter_init (&iter, n->networks);
        for (;g_hash_table_iter_next (&iter, (gpointer *) &k, (gpointer *) &v);) {
                Network *net = (Network *) v;

                if (!net->netdev)
                        continue;

                r = generate_master_device_network(net);
                if (r < 0) {

                        log_warning("Failed to configure device: %s", strerror(-r));
                }
        }

        return dbus_network_reload();
}

static void manager_command_line_config_generator(void *key, void *value, void *user_data) {
        Network *n;
        int r;

        assert(key);
        assert(value);

        n = (Network *) value;
        r = generate_network_config(n);
        if (r < 0) {
                log_warning("Failed to generate network configuration: %s", strerror(-r));
                return;
        }
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
                r = generate_network_config(n);
                if (r < 0) {
                        log_warning("Failed to generate network configuration: %s", strerror(-r));
                        return r;
                }
        } else
                g_hash_table_foreach(networks, manager_command_line_config_generator, NULL);

        return dbus_network_reload();
}

bool manager_config_exists(const char *section, const char *k, const char *v) {
         _cleanup_(globfree) glob_t g = {};
        int r;

        assert(section);
        assert(k);
        assert(v);

        r = glob_files("/run/systemd/netif/links/*", 0, &g);
        if (r != -ENOENT)
                return false;

        for (size_t i = 0; i < g.gl_pathc; i++) {
                _auto_cleanup_ char *network = NULL;
                int index;

                r = parse_int(g_path_get_basename(g.gl_pathv[i]), &index);
                if (r < 0)
                        continue;
                r = network_parse_link_network_file(index, &network);
                if (r < 0)
                        continue;

                if (config_contains(network, section, k, v))
                        return true;
        }

        return false;
}
