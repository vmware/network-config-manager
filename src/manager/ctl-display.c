/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <network-config-manager.h>

#include <systemd/sd-hwdb.h>
#include <systemd/sd-device.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "config-parser.h"
#include "ctl-display.h"
#include "ctl.h"
#include "dbus.h"
#include "device.h"
#include "dns.h"
#include "log.h"
#include "macros.h"
#include "netdev-link.h"
#include "network-address.h"
#include "network-json.h"
#include "network-link.h"
#include "network-manager.h"
#include "network-route.h"
#include "network-sriov.h"
#include "network-util.h"
#include "networkd-api.h"
#include "nftables.h"
#include "parse-util.h"
#include "udev-hwdb.h"

static bool arg_json = false;
static bool arg_beautify = true;

void set_json(bool k) {
        arg_json = k;
}

bool json_enabled(void) {
        return arg_json;
}

void set_beautify(bool k) {
        arg_beautify = k;
}

bool beautify_enabled(void) {
        return arg_beautify;
}

static void system_online_state_to_color(const char *state, const char **on) {
        if (string_equal(state, "online"))
                *on = ansi_color_green();
        else if (string_equal(state, "offline"))
                *on = ansi_color_red();
        else if (string_equal(state, "partial"))
                *on = ansi_color_bold_yellow();
        else
                *on = ansi_color_reset();
}

static void link_state_to_color(const char *state, const char **on) {
        if (string_equal(state, "routable") || string_equal(state, "configured") || string_equal(state,"up"))
                *on = ansi_color_green();
        else if (string_equal(state, "failed") || string_equal(state,"down") || string_equal(state,"no-carrier") ||
                 string_equal(state,"off")|| string_equal(state, "lower-layerdown"))
                *on = ansi_color_red();
        else if (string_equal(state, "configuring") || string_equal(state, "carrier"))
                *on = ansi_color_yellow();
        else if (string_equal(state, "degraded") || string_equal(state, "dormant"))
                *on = ansi_color_bold_yellow();
        else if (string_equal(state, "unmanaged"))
                *on = ansi_color_blue();
        else
                *on = ansi_color_reset();
}

static int list_links(int argc, char *argv[]) {
        _cleanup_(sd_device_unrefp) sd_device *sd_device = NULL;
        _cleanup_(links_unrefp) Links *h = NULL;
        int r;

        r = link_get_links(&h);
        if (r < 0)
               return r;


        if (arg_beautify)
                printf("%s %10s %8s %13s %15s %10s\n",
                        "INDEX",
                        "DEVICE",
                        "TYPE",
                        "STATE",
                        "OPERATIONAL",
                        "SETUP");

        for (GList *i = h->links; i; i = g_list_next (i)) {
                const char *setup_color, *operational_color, *operstates, *operstates_color;
                _auto_cleanup_ char *setup = NULL, *operational = NULL;
                Link *link = (Link *) i->data;
                const char *t = NULL;

                setup_color = operational_color = operstates = operstates_color = ansi_color_reset();

                (void) network_parse_link_setup_state(link->ifindex, &setup);
                (void) network_parse_link_operational_state(link->ifindex, &operational);
                operstates = link_operstates_to_name(link->operstate);

                if (setup)
                        link_state_to_color(setup, &setup_color);
                if (operational)
                        link_state_to_color(operational, &operational_color);
                if (operstates)
                        link_state_to_color(operstates, &operstates_color);

                display(arg_beautify, ansi_color_bold(), "%-8d", link->ifindex);
                display(arg_beautify, ansi_color_bold_cyan(), "  %-10s ", link->name);

                (void) device_new_from_ifname(&sd_device, link->name);
                if (sd_device && sd_device_get_devtype(sd_device, &t) >= 0 &&  !isempty_string(t))
                        display(arg_beautify, ansi_color_blue_magenta(), "%-12s ", t);
                else
                        display(arg_beautify, ansi_color_blue_magenta(), "%-12s ", arphrd_to_name(link->iftype));

                display(arg_beautify, operstates_color, "%-9s ", operstates);
                display(arg_beautify, operational_color, "%-16s ", string_na(operational));
                display(arg_beautify, setup_color, "%-10s\n", string_na(setup));
        }

        return 0;
}

static void list_one_link_addresses(gpointer key, gpointer value, gpointer userdata) {
        _auto_cleanup_ char *c = NULL, *dhcp = NULL;
        static bool first = true;
        unsigned long size;
        Address *a = NULL;
        int r;

        a = (Address *) g_bytes_get_data(key, &size);
        (void) ip_to_string_prefix(a->family, &a->address, &c);
        if (first) {
                printf("%s", c);
                first = false;
        } else
                printf("                              %s", c);

        r = network_parse_link_dhcp4_address(a->ifindex, &dhcp);
        if (r >= 0 && string_has_prefix(c, dhcp)) {
                _auto_cleanup_ char *server = NULL, *life_time = NULL, *t1 = NULL, *t2 = NULL;

                (void) network_parse_link_dhcp4_server_address(a->ifindex, &server);
                (void) network_parse_link_dhcp4_address_lifetime(a->ifindex, &life_time);
                (void) network_parse_link_dhcp4_address_lifetime_t1(a->ifindex, &t1);
                (void) network_parse_link_dhcp4_address_lifetime_t2(a->ifindex, &t2);

                printf(" (DHCPv4 via %s) lease time: %s seconds T1: %s seconds T2: %s seconds\n", string_na(server), string_na(life_time),
                       string_na(t1), string_na(t2));
        } else
                printf("\n");
}

_public_ int ncm_display_one_link_addresses(int argc, char *argv[]) {
        _cleanup_(addresses_unrefp) Addresses *addr = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool ipv4 = false, ipv6 = false;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        for (int i = 1; i < argc; i++) {
                if (string_equal_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        break;
                } else  {
                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[1]);
                                return r;
                        }
                }
        }

        if (argc >= 2) {
                for (int i = 2; i < argc; i++) {
                        if (string_equal(argv[i], "family") || string_equal(argv[i], "f")) {
                                parse_next_arg(argv, argc, i);

                                if (string_equal(argv[i], "ipv4") || string_equal(argv[i], "4"))
                                        ipv4 = true;
                                else if (string_equal(argv[i], "ipv6") || string_equal(argv[i], "6"))
                                        ipv6 = true;
                        }
                }
        }

        r = manager_get_one_link_address(p->ifindex, &addr);
        if (r < 0)
                return r;

        if (!set_size(addr->addresses))
                return -ENODATA;

        printf("Addresses: ");
        g_hash_table_iter_init(&iter, addr->addresses->hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                Address *a = (Address *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL;

                r = ip_to_string_prefix(a->family, &a->address, &c);
                if (r < 0)
                        return r;

                if ((a->family == AF_INET && ipv4 ) || (a->family == AF_INET6 && ipv6))
                        printf("%s ", c);

                if (!ipv4 && !ipv6)
                        printf("%s ", c);
        }

        printf("\n");

        return 0;
}

static void list_one_link_routes(gpointer key, gpointer value, gpointer userdata) {
        _auto_cleanup_ char *c = NULL;
        static bool first = true;
        unsigned long size;
        Route *rt = NULL;

        rt = (Route *) g_bytes_get_data(key, &size);
        (void) ip_to_string(rt->family, &rt->address, &c);
        if (first) {
                printf("%s\n", c);
                first = false;
        } else
                printf("                   %s\n", c);
}

static int display_one_link_device(Link *l, bool show, char **link_file) {
        const char *link = NULL, *driver = NULL, *path = NULL, *vendor = NULL, *model = NULL;
        _cleanup_(sd_device_unrefp) sd_device *sd_device = NULL;
        const char *t = NULL;

        assert(l);

        (void) device_new_from_ifname(&sd_device, l->name);
        if (sd_device) {
                (void) sd_device_get_property_value(sd_device, "ID_NET_LINK_FILE", &link);
                (void) sd_device_get_property_value(sd_device, "ID_NET_DRIVER", &driver);
                (void) sd_device_get_property_value(sd_device, "ID_PATH", &path);

                if (sd_device_get_property_value(sd_device, "ID_VENDOR_FROM_DATABASE", &vendor) < 0)
                        (void) sd_device_get_property_value(sd_device, "ID_VENDOR", &vendor);

                if (sd_device_get_property_value(sd_device, "ID_MODEL_FROM_DATABASE", &model) < 0)
                        (void) sd_device_get_property_value(sd_device, "ID_MODEL", &model);
        }
        if (l->kind) {
                display(arg_beautify, ansi_color_bold_cyan(), "                        Kind: ");
                printf("%s\n", l->kind);
        }

        display(arg_beautify, ansi_color_bold_cyan(), "                        Type: ");
        if (sd_device_get_devtype(sd_device, &t) >= 0 &&  !isempty_string(t))
                printf("%s\n", t);
        else
                printf("%s\n", string_na(arphrd_to_name(l->iftype)));

        if (link && link_file) {
                *link_file = g_strdup(link);
                if (!*link_file)
                        return log_oom();
        }

        if (path) {
                display(arg_beautify, ansi_color_bold_cyan(), "                        Path: ");
                printf("%s\n", path);
        }
        if (l->parent_dev) {
                display(arg_beautify, ansi_color_bold_cyan(), "                  Parent Dev: ");
                printf("%s\n", l->parent_dev);
        }
        if (l->parent_bus) {
                display(arg_beautify, ansi_color_bold_cyan(), "                  Parent Bus: ");
                printf("%s\n", l->parent_bus);
        }
        if (driver) {
                display(arg_beautify, ansi_color_bold_cyan(), "                      Driver: ");
                printf("%s\n", driver);
        }
        if (vendor) {
                display(arg_beautify, ansi_color_bold_cyan(), "                      Vendor: ");
                printf("%s \n", vendor);
        }
        if (model) {
                display(arg_beautify, ansi_color_bold_cyan(), "                       Model: ");
                printf("%s \n", model);
        }

        return 0;
}

static void list_link_attributes(Link *l) {
        _auto_cleanup_ char *duplex = NULL, *speed = NULL, *ether = NULL;

        (void) link_read_sysfs_attribute(l->name, "speed", &speed);
        (void) link_read_sysfs_attribute(l->name, "duplex", &duplex);
        (void) link_read_sysfs_attribute(l->name, "address", &ether);

        if (!isempty_string(ether)) {
                _auto_cleanup_ char *desc = NULL;
                 hwdb_get_vendor((uint8_t *) &l->mac_address.ether_addr_octet, &desc);

                display(arg_beautify, ansi_color_bold_cyan(), "                  HW Address: ");
                printf("%s (%s)\n", ether, desc);
        }
        if (l->contains_mtu) {
                display(arg_beautify, ansi_color_bold_cyan(), "                         MTU: ");
                printf("%d (min: %d max: %d) \n", l->mtu, l->min_mtu, l->max_mtu);
        }
        if (!isempty_string(duplex)) {
                display(arg_beautify, ansi_color_bold_cyan(), "                      Duplex: ");
                printf("%s\n", duplex);
        }
        if (!isempty_string(speed)) {
                display(arg_beautify, ansi_color_bold_cyan(), "                       Speed: ");
                printf("%s\n", speed);
        }
        if (!isempty_string(l->qdisc)) {
                display(arg_beautify, ansi_color_bold_cyan(), "                       QDISC: ");
                printf("%s \n", l->qdisc);
        }
        display(arg_beautify, ansi_color_bold_cyan(), "              Queues (Tx/Rx): ");
        printf("%d/%d \n", l->n_tx_queues, l->n_rx_queues);

        display(arg_beautify, ansi_color_bold_cyan(), "             Tx Queue Length: ");
        printf("%d \n", l->tx_queue_len);

        display(arg_beautify, ansi_color_bold_cyan(), "IPv6 Address Generation Mode: ");
        printf("%s \n", ipv6_address_generation_mode_to_name(l->ipv6_addr_gen_mode));
        display(arg_beautify, ansi_color_bold_cyan(), "                GSO Max Size: ");
        printf("%d ", l->gso_max_size);
        display(arg_beautify, ansi_color_bold_cyan(), "GSO Max Segments: ");
        printf("%d \n", l->gso_max_segments);
}

static void display_alterative_names(gpointer data, gpointer user_data) {
        char *s = data;

        printf("%s ", s);
}

static int list_one_link(char *argv[]) {
        _auto_cleanup_ char *setup_state = NULL, *operational_state = NULL, *address_state = NULL, *ipv4_state = NULL,
                *ipv6_state = NULL, *required_for_online = NULL, *device_activation_policy = NULL, *tz = NULL, *network = NULL,
                *online_state = NULL, *link = NULL, *dhcp4_identifier = NULL, *dhcp6_duid = NULL, *dhcp6_iaid = NULL;
        _auto_cleanup_strv_ char **dns = NULL, **ntp = NULL, **search_domains = NULL, **route_domains = NULL;
        const char *operational_state_color, *setup_set_color;
        _cleanup_(addresses_unrefp) Addresses *addr = NULL;
        _cleanup_(routes_unrefp) Routes *route = NULL;
        _cleanup_(link_unrefp) Link *l = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t iaid;
        int r;

        r = parse_ifname_or_index(*argv, &p);
        if (r < 0) {
                log_warning("Failed to find device: %s", *argv);
                return r;
        }

        if (arg_json)
                return json_list_one_link(p, NULL);

        r = link_get_one_link(p->ifname, &l);
        if (r < 0)
                return r;

        if (l->alt_names) {
                display(arg_beautify, ansi_color_bold_cyan(), "           Alternative names: ");
                g_ptr_array_foreach(l->alt_names, display_alterative_names, NULL);
                printf("\n");
        }

        (void) network_parse_link_operational_state(l->ifindex, &operational_state);

        r = network_parse_link_setup_state(l->ifindex, &setup_state);
        if (r == -ENODATA) {
                setup_state = g_strdup("unmanaged");
                if (!setup_state)
                        return log_oom();
        }

        if (l->flags > 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "                       Flags: ");
                if (l->flags & IFF_UP)
                        printf("UP ");

                if (l->flags & IFF_BROADCAST)
                        printf("BROADCAST ");

                if (l->flags & IFF_RUNNING)
                        printf("RUNNING ");

                if (l->flags & IFF_NOARP)
                        printf("NOARP ");

                if (l->flags & IFF_MASTER)
                        printf("MASTER ");

                if (l->flags & IFF_SLAVE)
                        printf("SLAVE ");

                if (l->flags & IFF_MULTICAST)
                        printf("MULTICAST ");

                if (l->flags & IFF_LOWER_UP)
                        printf("LOWERUP ");

                if (l->flags & IFF_DORMANT)
                        printf("DORMANT");

                printf("\n");
        }

        link_state_to_color(operational_state, &operational_state_color);
        link_state_to_color(setup_state, &setup_set_color);

        (void) network_parse_link_dns(l->ifindex, &dns);
        (void) network_parse_link_search_domains(l->ifindex, &search_domains);
        (void) network_parse_link_route_domains(l->ifindex, &route_domains);
        (void) network_parse_link_ntp(l->ifindex, &ntp);

        (void) network_parse_link_network_file(l->ifindex, &network);

        (void)  display_one_link_device(l, true, &link);
        display(arg_beautify, ansi_color_bold_cyan(), "                   Link File: ");
        printf("%s\n", string_na(link));

        display(arg_beautify, ansi_color_bold_cyan(), "                Network File: ");
        printf("%s\n", string_na(network));

        display(arg_beautify, ansi_color_bold_cyan(), "                       State: ");
        display(arg_beautify, operational_state_color, "%s", string_na(operational_state));
        printf(" (");
        display(arg_beautify, setup_set_color, "%s", string_na(setup_state));
        printf(") \n");

        r = network_parse_link_address_state(l->ifindex, &address_state);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "               Address State: ");
                printf("%s\n", address_state);
        }
        r = network_parse_link_ipv4_state(l->ifindex, &ipv4_state);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "          IPv4 Address State: ");
                printf("%s\n", ipv4_state);
        }
        r = network_parse_link_ipv6_state(l->ifindex, &ipv6_state);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "          IPv6 Address State: ");
                printf("%s\n", ipv6_state);
        }
        r = network_parse_link_online_state(l->ifindex, &online_state);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "                Online State: ");
                printf("%s\n", online_state);
        }
        r = network_parse_link_required_for_online(l->ifindex, &required_for_online);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "         Required for Online: ");
                printf("%s\n", required_for_online);
        }
        r = network_parse_link_device_activation_policy(l->ifindex, &device_activation_policy);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "           Activation Policy: ");
                printf("%s\n", device_activation_policy);
        }

        list_link_attributes(l);

        r = manager_get_one_link_address(l->ifindex, &addr);
        if (r >= 0 && addr && set_size(addr->addresses) > 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "                     Address: ");
                set_foreach(addr->addresses, list_one_link_addresses, NULL);
        }

        r = manager_get_one_link_route(l->ifindex, &route);
        if (r >= 0 && route && set_size(route->routes) > 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "                     Gateway: ");
                set_foreach(route->routes, list_one_link_routes, NULL);
        }

        if (dns) {
                _auto_cleanup_ char *s = NULL;

                s = strv_join(" ", dns);
                if (!s)
                        return log_oom();

                display(arg_beautify, ansi_color_bold_cyan(), "                         DNS: ");
                printf("%s\n", s);
        }

        if (search_domains) {
                _auto_cleanup_ char *s = NULL;

                s = strv_join(" ", search_domains);
                if (!s)
                        return log_oom();

                display(arg_beautify, ansi_color_bold_cyan(), "              Search Domains: ");
                printf("%s\n", s);
        }

        if (route_domains) {
                _auto_cleanup_ char *s = NULL;

                s = strv_join(" ", route_domains);
                if (!s)
                        return log_oom();

                display(arg_beautify, ansi_color_bold_cyan(), "               Route Domains: ");
                printf("%s\n", s);
        }

        if (ntp) {
                _auto_cleanup_ char *s = NULL;

                s = strv_join(" ", ntp);
                if (!s)
                        return log_oom();

                display(arg_beautify, ansi_color_bold_cyan(), "                         NTP: ");
                printf("%s\n", s);
        }

        (void) network_parse_link_timezone(l->ifindex, &tz);
        if (tz) {
                display(arg_beautify, ansi_color_bold_cyan(), "                   Time Zone: ");
                printf("%s\n", tz);
        }

        r = manager_get_link_dhcp_client_iaid(p, DHCP_CLIENT_IPV4, &iaid);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "                 DHCPv4 IAID: ");
                printf("%d\n", iaid);
        }

        iaid = 0;
        r = manager_get_link_dhcp_client_iaid(p, DHCP_CLIENT_IPV6, &iaid);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "                 DHCPv6 IAID: ");
                printf("%d\n", iaid);
        }

        r = network_parse_link_dhcp4_client_id(p->ifindex, &dhcp4_identifier);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "             DHCP4 Client ID: ");
                printf("%s\n", dhcp4_identifier);
        }

        if (!iaid) {
                r = network_parse_link_dhcp6_client_iaid(p->ifindex, &dhcp6_iaid);
                if (r >= 0) {
                        display(arg_beautify, ansi_color_bold_cyan(), "           DHCP6 Client IAID: ");
                        printf("%s\n", dhcp6_iaid);
                }
        }

        r = network_parse_link_dhcp6_client_duid(p->ifindex, &dhcp6_duid);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "           DHCP6 Client DUID: ");
                printf("%s\n", dhcp6_duid);
        }

        return 0;
}

static void list_link_addresses(gpointer key, gpointer value, gpointer userdata) {
        _auto_cleanup_ char *c = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        static bool first = true;
        unsigned long size;
        Address *a;

        a = (Address *) g_bytes_get_data(key, &size);

        if_indextoname(a->ifindex, buf);

        (void) ip_to_string_prefix(a->family, &a->address, &c);
        if (first) {
                printf("%-30s on device ", c);
                display(arg_beautify, ansi_color_bold_blue(), "%s\n", buf);
                first = false;
        } else {
                printf("                      %-30s on device ", c);
                display(arg_beautify, ansi_color_bold_blue(), "%s\n", buf);
        }
}

static void list_link_routes(gpointer key, gpointer value, gpointer userdata) {
        _auto_cleanup_ char *c = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        static bool first = true;
        unsigned long size;
        Route *rt;

        rt = (Route *) g_bytes_get_data(key, &size);

        if_indextoname(rt->ifindex, buf);

        (void) ip_to_string_prefix(rt->family, &rt->address, &c);
        if (first) {
                printf("%-30s on device ", c);
                display(arg_beautify, ansi_color_bold_blue(), "%s\n", buf);
                first = false;
        } else {
                printf("                      %-30s on device ", c);
                display(arg_beautify, ansi_color_bold_blue(), "%s\n", buf);
        }
}

_public_ int ncm_system_status(int argc, char *argv[]) {
        _auto_cleanup_ char *state = NULL, *carrier_state = NULL, *hostname = NULL, *kernel = NULL,
                *kernel_release = NULL, *arch = NULL, *virt = NULL, *os = NULL, *systemd = NULL;
        _auto_cleanup_strv_ char **dns = NULL, **search_domains = NULL, **ntp = NULL;
        _cleanup_(routes_unrefp) Routes *routes = NULL;
        _cleanup_(addresses_unrefp) Addresses *h = NULL;
        sd_id128_t machine_id = {};
        int r;

        if (argc > 1)
                return list_one_link(argv + 1);

        if (arg_json)
                return json_system_status(NULL);

        (void) dbus_get_property_from_hostnamed("StaticHostname", &hostname);
        if (hostname) {
                display(arg_beautify, ansi_color_bold_cyan(), "         System Name: ");
                printf("%s\n",hostname);
        }

        (void) dbus_get_property_from_hostnamed("KernelRelease", &kernel_release);
        (void) dbus_get_property_from_hostnamed("KernelName", &kernel);
        if (kernel) {
                display(arg_beautify, ansi_color_bold_cyan(), "              Kernel: ");
                printf("%s (%s)\n", kernel, string_na(kernel_release));
        }

        (void) dbus_get_string_systemd_manager("Version", &systemd);
        if (systemd) {
                display(arg_beautify, ansi_color_bold_cyan(), "     systemd version: ");
                printf("%s\n", systemd);
        }

        (void) dbus_get_string_systemd_manager("Architecture", &arch);
        if (arch) {
                display(arg_beautify, ansi_color_bold_cyan(), "        Architecture: ");
                printf("%s\n", arch);
        }

        (void) dbus_get_string_systemd_manager("Virtualization", &virt);
        if (virt) {
                display(arg_beautify, ansi_color_bold_cyan(), "      Virtualization: ");
                printf("%s\n", virt);
        }

        (void) dbus_get_property_from_hostnamed("OperatingSystemPrettyName", &os);
        if (os) {
                display(arg_beautify, ansi_color_bold_cyan(), "    Operating System: ");
                printf("%s\n", os);
        }

        r = sd_id128_get_machine(&machine_id);
        if (r >= 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "          Machine ID: ");
                printf(SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(machine_id));
                printf("\n");
        }

        r = dbus_get_system_property_from_networkd("OperationalState", &state);
        if (r >= 0) {
                const char *state_color;

                link_state_to_color(state, &state_color);

                display(arg_beautify, ansi_color_bold_cyan(), "        System State: ");
                display(arg_beautify, state_color, "%s\n", state);
        }

        r = dbus_get_system_property_from_networkd("OnlineState", &state);
        if (r >= 0) {
                const char *state_color;

                system_online_state_to_color(state, &state_color);

                display(arg_beautify, ansi_color_bold_cyan(), "        Online State: ");
                display(arg_beautify, state_color, "%s\n", state);
        }

        r = manager_link_get_address(&h);
        if (r >= 0 && set_size(h->addresses) > 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "           Addresses: ");
                set_foreach(h->addresses, list_link_addresses, NULL);
        }

        r = manager_link_get_routes(&routes);
        if (r >= 0 && set_size(routes->routes) > 0) {
                display(arg_beautify, ansi_color_bold_cyan(), "             Gateway: ");
                set_foreach(routes->routes, list_link_routes, NULL);
        }

        (void) network_parse_dns(&dns);
        (void) network_parse_ntp(&ntp);
        (void) network_parse_search_domains(&search_domains);

        if (dns) {
                _auto_cleanup_ char *s = NULL;

                s = strv_join(" ", dns);
                if (!s)
                        return log_oom();

                display(arg_beautify, ansi_color_bold_cyan(), "                 DNS: ");
                printf("%s\n", s);
        }

        if (search_domains) {
                _auto_cleanup_ char *s = NULL;

                s = strv_join(" ", search_domains);
                if (!s)
                        return log_oom();

                display(arg_beautify, ansi_color_bold_cyan(), "      Search Domains: ");
                printf("%s\n", s);
        }

        if (ntp) {
                _auto_cleanup_ char *s = NULL;

                s = strv_join(" ", ntp);
                if (!s)
                        return log_oom();

                display(arg_beautify, ansi_color_bold_cyan(), "                 NTP: ");
                printf("%s\n", s);
        }

        return r;
}

_public_ int ncm_link_status(int argc, char *argv[]) {
        int r;

        if (argc <= 1)
                return list_links(argc, argv);
        else
                r = list_one_link(argv + 1);

        return r;
}

_public_ int ncm_get_system_status(char **ret) {
        assert(ret);

        return json_system_status(ret);
}

_public_ int ncm_get_link_status(const char *ifname, char **ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        assert(ifname);
        assert(ret);

        r = parse_ifname_or_index(ifname, &p);
        if (r < 0)
                return r;

        return json_list_one_link(p, ret);
}
