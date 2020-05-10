/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2019 VMware, Inc.
 */

#include <getopt.h>
#include <glib.h>
#include <libudev.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "cli.h"
#include "dns.h"
#include "log.h"
#include "macros.h"
#include "network-address.h"
#include "dbus.h"
#include "network-link.h"
#include "network-route.h"
#include "network-manager.h"
#include "network-util.h"
#include "networkd-api.h"
#include "parse-util.h"
#include "udev-hwdb.h"

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

static void display_links_info(gpointer data_ptr, gpointer ignored) {
        const char *setup_color, *operational_color, *operstates, *operstates_color;
        _auto_cleanup_ char *setup = NULL, *operational = NULL;
        Link *link = NULL;

        setup_color = operational_color = operstates = operstates_color = ansi_color_reset();

        link = data_ptr;

        (void) network_parse_link_setup_state(link->ifindex, &setup);
        (void) network_parse_link_operational_state(link->ifindex, &operational);
        operstates = link_operstates_to_name(link->operstate);

        if (setup)
                link_state_to_color(setup, &setup_color);
        if (operational)
                link_state_to_color(operational, &operational_color);
        if (operstates)
                link_state_to_color(operstates, &operstates_color);

        printf("%s%5i%s %s%-20s%s %s%-18s%s %s%-16s%s %s%-16s%s %s%-10s%s\n",
               ansi_color_bold(), link->ifindex, ansi_color_reset(),
               ansi_color_bold_cyan(), link->name, ansi_color_reset(),
               ansi_color_blue_magenta(), arphrd_to_name(link->iftype), ansi_color_reset(),
               operstates_color, operstates, ansi_color_reset(),
               operational_color, string_na(operational), ansi_color_reset(),
               setup_color, string_na(setup), ansi_color_reset());
}

static int list_links(int argc, char *argv[]) {
        _cleanup_(links_free) Links *h = NULL;
        int r;

        r = link_get_links(&h);
        if (r < 0)
               return r;

        printf("%s %5s %-20s %-18s %-16s %-16s %-10s %s\n",
               ansi_color_blue_header(),
               "INDEX",
               "LINK",
               "TYPE",
               "STATE",
               "OPERATIONAL",
               "SETUP",
               ansi_color_header_reset());

        g_list_foreach(h->links, display_links_info, NULL);

        return 0;
}

static void list_one_link_addresses(gpointer key, gpointer value, gpointer userdata) {
        _auto_cleanup_strv_ char **dhcp = NULL;
        _auto_cleanup_ char *c = NULL;
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
                printf("                  %s", c);

        r = network_parse_link_dhcp4_addresses(a->ifindex, &dhcp);
        if (r >= 0 && strv_contains((const char **) dhcp, c))
                printf(" %s(DHCPv4)%s\n", ansi_color_bold_yellow(), ansi_color_reset());
        else
                printf("\n");
}

static int display_one_link_udev(Link *l, bool display, char **link_file) {
        _auto_cleanup_ char *devid = NULL, *device = NULL, *manufacturer = NULL;
        const char *link, *driver, *path, *vendor, *model;
        struct udev_device *dev;
        struct udev *udev;

        assert(l);

        asprintf(&devid, "n%i", l->ifindex);

        asprintf(&device,"%s/%s", "/sys/class/net", l->name);
        udev = udev_new();
        if (!udev)
                return log_oom();

        dev = udev_device_new_from_syspath(udev, device);
        if (!dev)
                return log_oom();

        path = udev_device_get_property_value(dev, "ID_PATH");
        driver = udev_device_get_property_value(dev, "ID_NET_DRIVER");
        link = udev_device_get_property_value(dev, "ID_NET_LINK_FILE");
        vendor = udev_device_get_property_value(dev, "ID_VENDOR_FROM_DATABASE");
        model = udev_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE");

        if (link && link_file) {
                *link_file = g_strdup(link);
                if (!*link_file)
                        return log_oom();
        }

        if (!display)
                return 0;

        if (path)
                printf("            %sPath%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), path);
        if (driver)
                printf("          %sDriver%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), driver);
        if (vendor)
                printf("          %sVendor%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), vendor);
        if (model)
                printf("           %sModel%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), model);

        hwdb_get_manufacturer((uint8_t *) &l->mac_address.ether_addr_octet, &manufacturer);
        if (manufacturer)
                printf("    %sManufacturer%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), manufacturer);

        udev_device_unref(dev);
        udev_unref(udev);

        return 0;
}

static void list_link_sysfs_attributes(Link *l) {
        _auto_cleanup_ char *duplex = NULL, *speed = NULL, *ether = NULL, *mtu = NULL;

        (void) link_read_sysfs_attribute(l->name, "speed", &speed);
        (void) link_read_sysfs_attribute(l->name, "duplex", &duplex);
        (void) link_read_sysfs_attribute(l->name, "address", &ether);
        (void) link_read_sysfs_attribute(l->name, "mtu", &mtu);

        if (ether)
                printf("      %sHW Address%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), ether);
        if (mtu)
                printf("             %sMTU%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), mtu);

        if (duplex)
                printf("          %sDuplex%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), duplex);
        if (speed)
                printf("           %sSpeed%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), speed);
}

static int list_one_link(char *argv[]) {
        _auto_cleanup_ char *setup_state = NULL, *operational_state = NULL, *tz = NULL, *network = NULL, *link = NULL;
        _auto_cleanup_strv_ char **dns = NULL, **ntp = NULL, **search_domains = NULL, **route_domains = NULL;
        const char *operational_state_color, *setup_set_color;
        _cleanup_(addresses_unref) Addresses *addr = NULL;
        _cleanup_(routes_free) Routes *route = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ Link *l = NULL;
        int r;

        r = parse_ifname_or_index(*argv, &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", *argv);
                return -errno;
        }

        r = link_get_one_link(*argv, &l);
        if (r < 0)
                return r;

        (void) network_parse_link_operational_state(l->ifindex, &operational_state);

        r = network_parse_link_setup_state(l->ifindex, &setup_state);
        if (r == -ENODATA) {
                setup_state = g_strdup("unmanaged");
                if (!setup_state)
                        return log_oom();
        }

        link_state_to_color(operational_state, &operational_state_color);
        link_state_to_color(setup_state, &setup_set_color);

        (void) network_parse_link_dns(l->ifindex, &dns);
        (void) network_parse_link_search_domains(l->ifindex, &search_domains);
        (void) network_parse_link_route_domains(l->ifindex, &route_domains);
        (void) network_parse_link_ntp(l->ifindex, &ntp);

        (void) network_parse_link_network_file(l->ifindex, &network);
        (void)  display_one_link_udev(l, false, &link);
         printf("       %sLink File%s: %s\n"
                "    %sNetwork File%s: %s\n"
                "            %sType%s: %s\n"
                "           %sState%s: %s%s%s %s(%s)%s\n",
                ansi_color_bold_cyan(), ansi_color_reset(), string_na(link),
                ansi_color_bold_cyan(), ansi_color_reset(), string_na(network),
                ansi_color_bold_cyan(), ansi_color_reset(), string_na(arphrd_to_name(l->iftype)),
                ansi_color_bold_cyan(), ansi_color_reset(), operational_state_color, string_na(operational_state), ansi_color_reset(),
                setup_set_color, string_na(setup_state), ansi_color_reset());

         (void)  display_one_link_udev(l, true, NULL);
         list_link_sysfs_attributes(l);

         r = manager_get_one_link_address(l->ifindex, &addr);
         if (r >= 0 && addr && set_size(addr->addresses) > 0) {
                 printf("         %sAddress%s: ", ansi_color_bold_cyan(), ansi_color_reset());
                 set_foreach(addr->addresses, list_one_link_addresses, NULL);
         }

         r = manager_get_one_link_route(l->ifindex, &route);
         if (r >= 0 && route && g_list_length(route->routes) > 0) {
                 bool first = true;
                 GList *i;

                 printf("         %sGateway%s: ", ansi_color_bold_cyan(), ansi_color_reset());
                 for (i = route->routes; i; i = i->next) {
                         _auto_cleanup_ char *c = NULL;
                         Route *a = NULL;

                         a = i->data;
                         (void) ip_to_string(a->family, &a->address, &c);
                         if (first) {
                                 printf("%s\n", c);
                                 first = false;
                         } else
                                 printf("                  %s\n", c);
                 }
         }

         if (dns) {
                 _auto_cleanup_ char *s = NULL;

                 s = strv_join(" ", dns);
                 if (!s)
                         return log_oom();

                 printf("             %sDNS%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), s);
         }

         if (search_domains) {
                 _auto_cleanup_ char *s = NULL;

                 s = strv_join(" ", search_domains);
                 if (!s)
                         return log_oom();

                 printf("  %sSearch Domains%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), s);
        }

         if (route_domains) {
                 _auto_cleanup_ char *s = NULL;

                 s = strv_join(" ", route_domains);
                 if (!s)
                         return log_oom();

                 printf("             %sRoute Domains%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), s);
         }

         if (ntp) {
                 _auto_cleanup_ char *s = NULL;

                 s = strv_join(" ", ntp);
                 if (!s)
                         return log_oom();

                 printf("             %sNTP%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), s);
         }

         (void) network_parse_link_timezone(l->ifindex, &tz);
         if (tz)
                 printf("       %sTime Zone%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), tz);


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
                printf("%-30s on link %s%s%s \n", c, ansi_color_bold_blue(), buf, ansi_color_reset());
                first = false;
        } else
                printf("                      %-30s on link %s%s%s \n", c, ansi_color_bold_blue(), buf, ansi_color_reset());
}

static int system_status(int argc, char *argv[]) {
        _auto_cleanup_ char *state = NULL, *hostname = NULL, *kernel = NULL, *kernel_release = NULL,
                            *arch = NULL, *virt = NULL, *os = NULL, *systemd = NULL;
        _auto_cleanup_strv_ char **dns = NULL, **ntp = NULL;
        _cleanup_(routes_free) Routes *routes = NULL;
        _cleanup_(addresses_unref) Addresses *h = NULL;
        Route *rt;
        GList *i;
        int r;

        (void) dbus_get_property_from_hostnamed("StaticHostname", &hostname);
        if (hostname)
                printf("         %sSystem Name%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), hostname);

        (void) dbus_get_property_from_hostnamed("KernelRelease", &kernel_release);
        (void) dbus_get_property_from_hostnamed("KernelName", &kernel);
        if (kernel)
                printf("              %sKernel%s: %s (%s) \n", ansi_color_bold_cyan(), ansi_color_reset(), kernel, string_na(kernel_release));

        (void) dbus_get_string_systemd_manager("Version", &systemd);
        if (systemd)
                printf("     %ssystemd version%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), systemd);

        (void) dbus_get_string_systemd_manager("Architecture", &arch);
        if (arch)
                printf("        %sArchitecture%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), arch);

        (void) dbus_get_string_systemd_manager("Virtualization", &virt);
        if (virt)
                printf("      %sVirtualization%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), virt);

        (void) dbus_get_property_from_hostnamed("OperatingSystemPrettyName", &os);
        if (os)
                printf("    %sOperating System%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), os);

        (void) network_parse_operational_state(&state);
        if (state) {
                const char *state_color;

                link_state_to_color(state, &state_color);
                printf("        %sSystem State%s: %s%s%s\n", ansi_color_bold_cyan(), ansi_color_reset(), state_color,  state, ansi_color_reset());
        }

        r = manager_link_get_address(&h);
        if (r >= 0 && set_size(h->addresses) > 0) {
                printf("           %sAddresses%s: ", ansi_color_bold_cyan(), ansi_color_reset());
                set_foreach(h->addresses, list_link_addresses, NULL);
        }

        r = manager_link_get_routes(&routes);
        if (r >= 0 && g_list_length(routes->routes) > 0) {
                bool first = true;

                printf("             %sGateway%s: ", ansi_color_bold_cyan(), ansi_color_reset());
                for (i = routes->routes; i; i = i->next) {
                        _auto_cleanup_ char *c = NULL;
                        char buf[IF_NAMESIZE + 1] = {};

                        rt = i->data;
                        if_indextoname(rt->ifindex, buf);

                        (void) ip_to_string_prefix(rt->family, &rt->address, &c);
                        if (first) {
                                printf("%-30s on link %s%s%s \n", c, ansi_color_bold_blue(), buf, ansi_color_reset());
                                first = false;
                        } else
                                printf("                      %-30s on link %s%s%s \n", c, ansi_color_bold_blue(), buf, ansi_color_reset());
                }
        }

        (void) network_parse_dns(&dns);
        (void) network_parse_ntp(&ntp);

        if (dns) {
                _auto_cleanup_ char *s = NULL;

                s = strv_join(" ", dns);
                if (!s)
                        return log_oom();

                printf("                 %sDNS%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), s);
        }

        if (ntp) {
                _auto_cleanup_ char *s = NULL;

                s = strv_join(" ", ntp);
                if (!s)
                        return log_oom();

                printf("                 %sNTP%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), s);
        }

        return r;
}

static int link_status(int argc, char *argv[]) {
        int c;

        if (argc <= 1)
                return list_links(argc, argv);
        else
                c = list_one_link(argv + 1);

        if (c < 0)
                return c;

        return 0;
}

static int link_set_mtu(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t mtu;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        r = parse_mtu(argv[2], &mtu);
        if (r < 0)
                return r;

        r = manager_set_link_mtu(p, mtu);
        if (r < 0) {
                log_warning("Failed to update MTU for '%s': %s", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

static int link_set_mac(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        if (!parse_ether_address(argv[2])) {
               log_warning("Failed to parse MAC address: %s", argv[2]);
               return -EINVAL;
        }

        r = manager_set_link_mac_addr(p, argv[2]);
        if (r < 0) {
                log_warning("Failed to update MAC Address for '%s': %s", p->ifname, g_strerror(-r) );
                return r;
        }

        return 0;
}

static int link_set_mode(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool k;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link: %s", argv[1]);
                return -errno;
        }

        r = parse_boolean(argv[2]);
        if (r < 0) {
                log_warning("Failed to parse link mode '%s' '%s': %s", p->ifname, argv[2], g_strerror(-r));
                return r;
        }

        k = r;
        r = manager_set_link_mode(p, !k, NULL);
        if (r < 0) {
                printf("Failed to set link mode '%s': %s\n", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

static int link_set_dhcp_mode(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int mode, r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        mode = dhcp_name_to_mode(argv[2]);
        if (mode < 0) {
                log_warning("Failed to find DHCP mode : %s", argv[2]);
                return r;
        }

        r = manager_set_link_dhcp_mode(p, mode);
        if (r < 0) {
                log_warning("Failed to set link mode '%s': %s\n", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

static int link_set_dhcp_client_identifier(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        DHCPClientIdentifier d;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        d = dhcp_client_identifier_to_mode(argv[2]);
        if (d == _DHCP_CLIENT_IDENTIFIER_INVALID) {
                log_warning("Failed to parse DHCP4 client identifier: %s", argv[2]);
                return -EINVAL;
        }

        r = manager_set_link_dhcp_client_identifier(p, d);
        if (r < 0) {
                log_warning("Failed to set link DHCP4 client identifier '%s': %s\n", p->ifname, g_strerror(r));
                return r;
        }

        return 0;
}

static int link_set_dhcp_client_iaid(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        uint32_t v;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = parse_uint32(argv[2], &v);
        if (r < 0) {
                log_warning("Failed to parse IAID '%s' for link '%s': %s", argv[2], argv[1], g_strerror(-r));
                return r;
        }

        r = manager_set_link_dhcp_client_iaid(p, v);
        if (r < 0) {
                log_warning("Failed to set link DHCP4 client IAID for'%s': %s\n", p->ifname, g_strerror(r));
                return r;
        }

        return 0;
}

static int link_set_network_section_bool(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        const char *k;
        bool v;
        int r;

        if (string_equal(argv[0], "set-link-local-address"))
                k = "LinkLocalAddressing";
        else if (string_equal(argv[0], "set-ipv4ll-route"))
                k = "IPv4LLRoute";
        else if (string_equal(argv[0], "set-llmnr"))
                k = "LLMNR";
        else if (string_equal(argv[0], "set-multicast-dns"))
                k = "MulticastDNS";
        else if (string_equal(argv[0], "set-lldp"))
                k = "LLDP";
        else if (string_equal(argv[0], "set-emit-lldp"))
                k = "EmitLLDP";
        else if (string_equal(argv[0], "set-ipforward"))
                k = "IPForward";
        else if (string_equal(argv[0], "set-ipv6acceptra"))
                k = "IPv6AcceptRA";
        else if (string_equal(argv[0], "set-ipmasquerade"))
                k = "IPMasquerade";

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = parse_boolean(argv[2]);
        if (r < 0) {
                log_warning("Failed to parse %s=%s for link '%s': %s", argv[0], argv[2], argv[1], g_strerror(-r));
                return r;
        }

        v = r;
        r = manager_set_network_section_bool(p, k, v);
        if (r < 0)
                return r;

        return 0;
}

static int link_set_dhcp_section(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        const char *k;
        bool v;
        int r;

        if (string_equal(argv[0], "set-dhcp-use-dns"))
                k = "UseDNS";
        else if (string_equal(argv[0], "set-dhcp-use-ntp"))
                k = "UseNTP";
        else if (string_equal(argv[0], "set-dhcp-use-domains"))
                k = "UseDomains";
        else if (string_equal(argv[0], "set-dhcp-use-mtu"))
                k = "UseMTU";
        else if (string_equal(argv[0], "set-dhcp-use-routes"))
                k = "UseRoutes";
        else if (string_equal(argv[0], "set-dhcp-use-timezone"))
                k = "UseTimezone";

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = parse_boolean(argv[2]);
        if (r < 0) {
                log_warning("Failed to parse %s=%s for link '%s': %s", argv[0], argv[2], argv[1], g_strerror(-r));
                return r;
        }

        v = r;
        r = manager_set_dhcp_section(p, k, v);
        if (r < 0)
                return r;

        return 0;
}

static int link_set_dhcp_client_duid(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        DHCPClientDUIDType d;
        bool system = false;
        int r;

        /* Try to resolve the link name. If not assume this is for the system, i.e. /etc/systemd/networkd.conf */
        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                if (!string_equal("system", argv[1])) {
                        log_warning("Failed to resolve link '%s': %s", argv[1], g_strerror(EINVAL));
                        return -EINVAL;
                }

                system = true;
        }

        d = dhcp_client_duid_type_to_mode(argv[2]);
        if (d == _DHCP_CLIENT_DUID_TYPE_INVALID) {
                log_warning("Failed to parse DHCPv4 DUID type: %s", argv[2]);
                return -EINVAL;
        }

        r = manager_set_link_dhcp_client_duid(p, d, argv[3], system);
        if (r < 0) {
                log_warning("Failed to set link DHCP4 client IAID for'%s': %s\n", p->ifname, g_strerror(r));
                return r;
        }

        return 0;
}

static int link_update_state(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        LinkState state;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        state = link_name_to_state(argv[2]);
        if (state < 0) {
                log_warning("Failed to find link state : %s", argv[2]);
                return r;
        }

        r = manager_set_link_state(p, state);
        if (r < 0) {
                log_warning("Failed to set link state '%s': %s\n", p->ifname, g_strerror(r));
                return r;
        }

        return 0;
}

static int link_add_address(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *address = NULL, *peer = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = parse_ip_from_string(argv[2], &address);
        if (r < 0) {
                log_warning("Failed to parse address : %s", argv[2]);
                return r;
        }

        if (argc > 3) {
                r = parse_ip_from_string(argv[3], &peer);
                if (r < 0) {
                        log_warning("Failed to parse peer address: %s", argv[3]);
                        return r;
                }
        }

        r = manager_configure_link_address(p, address, peer);
        if (r < 0) {
                log_warning("Failed to set link address '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

static int link_delete_address(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_delete_link_address(p);
        if (r < 0) {
                log_warning("Failed to set link address '%s': %s\n", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

static int link_add_default_gateway(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *address = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ Route *rt = NULL;
        int r, onlink = 0;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = parse_ip_from_string(argv[2], &address);
        if (r < 0) {
                log_warning("Failed to parse address : %s", argv[2]);
                return r;
        }

        if (argc > 4) {
                if (string_equal(argv[3], "onlink")) {
                        onlink = parse_boolean(argv[4]);
                        if (onlink < 0)
                                log_warning("Failed to parse onlink '%s': %s\n", argv[1], argv[4]);
                } else {
                        log_warning("Failed to parse unknow option: '%s'\n", argv[3]);
                        return -EINVAL;
                }
        }

        r = route_new(&rt);
        if (r < 0)
                return log_oom();

        *rt = (Route) {
                  .onlink = onlink,
                  .ifindex = p->ifindex,
                  .family = address->family,
                  .gw = *address,
        };

        r = manager_configure_default_gateway(p, rt);
        if (r < 0) {
                log_warning("Failed to set link default gateway '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

static int link_add_route(int argc, char *argv[]) {
        _auto_cleanup_ IPAddress *address = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ Route *rt = NULL;
        int r, metric = 0;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = parse_ip_from_string(argv[2], &address);
        if (r < 0) {
                log_warning("Failed to parse address : %s", argv[2]);
                return r;
        }

        if (argc > 4) {
                if (string_equal(argv[3], "metric")) {
                        r = parse_integer(argv[4], &metric);
                        if (r < 0)
                                log_warning("Failed to parse metric '%s': %s\n", argv[1], argv[4]);
                } else {
                        log_warning("Failed to parse unknow option: '%s'\n", argv[3]);
                        return -EINVAL;
                }
        }

        r = route_new(&rt);
        if (r < 0)
                return log_oom();

        *rt = (Route) {
                 .metric = metric,
                 .family = address->family,
                 .ifindex = p->ifindex,
                 .dst_prefixlen = address->prefix_len,
                 .destination = *address,
        };

        r = manager_configure_route(p, rt);
        if (r < 0) {
                log_warning("Failed to add route to link '%s': %s\n", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

static int link_delete_gateway_or_route(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        if (string_equal(argv[0], "delete-gateway"))
                r = manager_remove_gateway_or_route(p, true);
        else
                r = manager_remove_gateway_or_route(p, false);

        if (r < 0) {
                log_warning("Failed to delete %s on '%s': %s\n", argv[0], p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

static int show_dns_server(int argc, char *argv[]) {
        _cleanup_(dns_servers_free) DNSServers *fallback = NULL, *dns = NULL, *current = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        _auto_cleanup_ char *setup = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        GSequenceIter *i;
        DNSServer *d;
        int r;

        /* backward compatinility */
        if (argc > 1 && string_equal(argv[1], "system")) {
                r = parse_ifname_or_index(argv[1], &p);
                if (r < 0) {
                        log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                        return -errno;
                }

                r = network_parse_link_setup_state(p->ifindex, &setup);
                if (r < 0) {
                        log_warning("Failed to get link setup '%s': %s\n", p->ifname, g_strerror(-r));
                        return r;
                }

                if (string_equal(setup, "unmanaged")) {
                       _auto_cleanup_strv_ char **a = NULL, **b = NULL;
                        char **j;

                        r = dns_read_resolv_conf(&a, &b);
                        if (r < 0) {
                                log_warning("Failed to read resolv.conf: %s", g_strerror(-r));
                                return r;

                        }

                        printf("DNSMode=static\n");
                        printf("DNSServers=");
                        strv_foreach(j, a) {
                                printf("%s ", *j);
                        }

                        printf("\n");

                        return 0;
                }
        }

        r = dbus_get_dns_servers_from_resolved("DNS", &dns);
        if (r >= 0 && dns && g_sequence_is_empty(dns->dns_servers)) {
                printf("                 %sDNS%s:", ansi_color_bold_cyan(), ansi_color_reset());

                for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(i);

                        if (d->ifindex != 0)
                                continue;

                        r = ip_to_string(d->family, &d->address, &pretty);
                        if (r >= 0)
                                printf(" %s", string_na(pretty));
                }
                printf("\n");
        }

        r = dbus_get_dns_servers_from_resolved("CurrentDNSServer", &current);
        if (r >= 0 && current && !g_sequence_is_empty(current->dns_servers)) {
                _auto_cleanup_ char *pretty = NULL;

                i = g_sequence_get_begin_iter(current->dns_servers);
                d = g_sequence_get(i);
                r = ip_to_string(d->family, &d->address, &pretty);
                if (r >= 0) {
                        printf("    %sCurrentDNSServer%s:", ansi_color_bold_cyan(), ansi_color_reset());
                        printf(" %s\n", pretty);
                }
        }

        r = dbus_get_dns_servers_from_resolved("FallbackDNS", &fallback);
        if (r >= 0 && !g_sequence_is_empty(fallback->dns_servers)) {
                bool first = true;

                printf("         %sFallbackDNS%s: ", ansi_color_bold_cyan(), ansi_color_reset());
                for (i = g_sequence_get_begin_iter(fallback->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(i);

                        if_indextoname(d->ifindex, buf);

                        r = ip_to_string(d->family, &d->address, &pretty);
                        if (r >= 0) {
                                if (first) {
                                        printf("%-24s\n", pretty);
                                        first = false;
                                } else
                                        printf("                      %-24s\n", pretty);
                        }
                }
        }

        if (dns && !g_sequence_is_empty(dns->dns_servers)) {

                printf("%s%5s %-20s %-18s%s\n", ansi_color_blue_header(), "INDEX", "LINK", "DNS", ansi_color_reset());

                for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(i);

                        if (!d->ifindex)
                                continue;

                        if_indextoname(d->ifindex, buf);
                        r = ip_to_string(d->family, &d->address, &pretty);
                        if (r >= 0)
                                printf("%5d%5s %-20s %s%s\n", d->ifindex, ansi_color_bold_cyan(), buf, ansi_color_reset(), pretty);
                }
        }

        return 0;
}

static int add_dns_server(int argc, char *argv[]) {
        _cleanup_(dns_servers_free) DNSServers *dns = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool system = false;
        int r, i;

        if (string_equal(argv[1], "system"))
                system = true;
        else {
                r = parse_ifname_or_index(argv[1], &p);
                if (r < 0) {
                        log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                        return -EINVAL;
                }
        }

        for (i = 2; i < argc; i++) {
                _auto_cleanup_ IPAddress *a = NULL;
                _auto_cleanup_ DNSServer *s = NULL;

                r = parse_ip(argv[i], &a);
                if (r < 0) {
                        log_warning("Failed to parse DNS server address: %s", argv[i]);
                        return r;
                }

                r = dns_server_new(&s);
                if (r < 0)
                        return log_oom();

                *s = (DNSServer) {
                        .ifindex = p ? p->ifindex : 0,
                        .family = a->family,
                        .address = *a,
                };

                r = dns_server_add(&dns, s);
                if (r < 0) {
                        log_warning("Failed to add DNS server address: %s", argv[i]);
                        return r;
                }

                s = NULL;
        }

        r = manager_add_dns_server(p, dns, system);
        if (r < 0) {
                log_warning("Failed to add DNS server %s: %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

static int add_dns_domains(int argc, char *argv[]) {
       _auto_cleanup_strv_ char **domains = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool system = false;
        int r;

        if (string_equal(argv[1], "system"))
                system = true;
        else {
                r = parse_ifname_or_index(argv[1], &p);
                if (r < 0) {
                        log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                        return -errno;
                }
        }

        r = argv_to_strv(argc - 1, argv + 1, &domains);
        if (r < 0) {
                log_warning("Failed to parse domains addresses: %s", g_strerror(-r));
                return r;
        }

        r = manager_add_dns_server_domain(p, domains, system);
        if (r < 0) {
                log_warning("Failed to add DNS domain to resolved '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

static int show_dns_server_domains(int argc, char *argv[]) {
        _cleanup_(dns_domains_free) DNSDomains *domains = NULL;
        _auto_cleanup_ char *config_domain = NULL, *setup = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        char buffer[LINE_MAX] = {};
        GSequenceIter *i;
        DNSDomain *d;
        int r;

        /* backward compatibility */
        if (argc > 1 && string_equal(argv[1], "system")) {
                r = parse_ifname_or_index(argv[1], &p);
                if (r < 0) {
                        log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                        return -errno;
                }

                r = network_parse_link_setup_state(p->ifindex, &setup);
                if (r < 0) {
                        log_warning("Failed to get link setup '%s': %s\n", p->ifname, g_strerror(-r));
                        return r;
                }

                if (string_equal(setup, "unmanaged")) {
                       _auto_cleanup_strv_ char **a = NULL, **b = NULL;
                        char **j;

                        r = dns_read_resolv_conf(&a, &b);
                        if (r < 0) {
                                log_warning("Failed to read resolv.conf: %s", g_strerror(-r));
                                return r;

                        }

                        printf("DNSMode=static\n");
                        printf("DOMAINS=");
                        strv_foreach(j, b) {
                                printf("%s ", *j);
                        }

                        printf("\n");

                        return 0;
                }
        }

        if (argc >= 2 && string_equal(argv[1], "system")) {
                r = manager_read_domains_from_system_config(&config_domain);
                if (r < 0) {
                        log_warning("Failed to read DNS domain from '/etc/systemd/resolved.conf': %s", g_strerror(-r));
                        return r;
                }

                printf("%s\n", config_domain);

                return 0;
        }

        r = dbus_get_dns_domains_from_resolved(&domains);
        if (r < 0){
                log_warning("Failed to fetch DNS domain from resolved: %s", g_strerror(-r));
                return r;
        }

        if (!domains || g_sequence_is_empty(domains->dns_domains)) {
                log_warning("No DNS Domain configured: %s", g_strerror(ENODATA));
                return -ENODATA;
        } else if (g_sequence_get_length(domains->dns_domains) == 1) {

                i = g_sequence_get_begin_iter(domains->dns_domains);
                d = g_sequence_get(i);

                printf("%sDNS Domain%s: %s\n", ansi_color_bold_cyan(), ansi_color_reset(), d->domain);
        } else {
                _cleanup_(set_unrefp) Set *all_domains = NULL;
                bool first = true;

                r = set_new(&all_domains, NULL, NULL);
                if (r < 0) {
                        log_debug("Failed to init set for domains: %s", g_strerror(-r));
                        return r;
                }

                printf("%sDNS Domain%s: ", ansi_color_bold_cyan(), ansi_color_reset());
                for (i = g_sequence_get_begin_iter(domains->dns_domains); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i))  {
                        char *s;

                        d = g_sequence_get(i);

                        if (*d->domain == '.')
                                continue;

                        if (set_contains(all_domains, d->domain))
                                continue;

                        s = g_strdup(d->domain);
                        if (!s)
                                log_oom();

                        if (!set_add(all_domains, s)) {
                                log_debug("Failed to add domain to set '%s': %s", d->domain, g_strerror(-r));
                                return -EINVAL;
                        }

                        if (first) {
                                printf("%s\n", d->domain);
                                first = false;
                        } else
                                printf("            %s\n", d->domain);
                }

                printf("%s%5s %-20s %-18s%s\n", ansi_color_blue_header(), "INDEX", "LINK", "Domain", ansi_color_reset());
                for (i = g_sequence_get_begin_iter(domains->dns_domains); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        d = g_sequence_get(i);

                        sprintf(buffer, "%" PRIu32, d->ifindex);

                        if (!d->ifindex)
                                continue;

                        r = parse_ifname_or_index(buffer, &p);
                        if (r < 0) {
                                log_warning("Failed to find link '%d': %s", d->ifindex, g_strerror(-r));
                                return -errno;
                        }
                        printf("%5d %s%-20s%s %-18s\n", d->ifindex, ansi_color_bold_cyan(),p->ifname, ansi_color_reset(),
                                *d->domain == '.' ? "~." : d->domain);
                }
        }

        return 0;
}

static int revert_resolve_link(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_revert_dns_server_and_domain(p);
        if (r < 0) {
                log_warning("Failed to flush resolved settings for %s: %s", p->ifname, g_strerror(-r));
                return r;
        }

        return 0;
}

static int set_system_hostname(int argc, char *argv[]) {
        int r;

        if (isempty_string(argv[1])) {
                log_warning("Invalid hostname. Ignoring");
                return -EINVAL;
        }

        r = dbus_set_hostname(argv[1]);
        if (r < 0) {
                log_warning("Failed to set hostname '%s': %s", argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

static int link_add_ntp(int argc, char *argv[]) {
       _auto_cleanup_strv_ char **ntps = NULL;
       _auto_cleanup_ IfNameIndex *p = NULL;
       char **d;
       int r;

       r = parse_ifname_or_index(argv[1], &p);
       if (r < 0) {
               log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
               return -errno;
       }

       r = argv_to_strv(argc - 1, argv + 1, &ntps);
       if (r < 0) {
               log_warning("Failed to parse NTP addresses: %s", g_strerror(-r));
               return r;
       }

       strv_foreach(d, ntps) {
               _auto_cleanup_ IPAddress *a = NULL;

               r = parse_ip(*d, &a);
               if (r < 0) {
                       log_warning("Failed to parse NTP server address: %s", *d);
                       return r;
                }
       }

       r = manager_add_ntp_addresses(p, ntps);
       if (r < 0) {
               log_warning("Failed to add NTP addresses '%s': %s", argv[1], g_strerror(-r));
               return r;
       }

       return 0;
}

static int link_enable_ipv6(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        if (string_equal(argv[0], "enable-ipv6"))
                r = manager_enable_ipv6(p, true);
        else
                r = manager_enable_ipv6(p, false);

        if (r < 0) {
                log_warning("Failed to %s IPv6 for the link '%s': %s",argv[0],  argv[1], g_strerror(-r));
                return r;
        }

        return 0;
}

static int network_reload(int argc, char *argv[]) {
        int r;

        r = manager_reload_network();
        if (r < 0)
                return r;

        return 0;
}

static int link_reconfigure(int argc, char *argv[]) {
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find link '%s': %s", argv[1], g_strerror(-r));
                return -errno;
        }

        r = manager_reconfigure_link(p);
        if (r < 0)
                return r;

        return 0;

}
static int generate_networkd_config_from_yaml(int argc, char *argv[]) {
        const char *file = NULL;
        GDir *dir;
        int r, i;

        if (string_equal(argv[0], "apply-yaml-config")) {
                dir = g_dir_open("/etc/network-config-manager/yaml", 0, NULL);
                if (!dir) {
                        log_warning("Failed to open directory '/etc/network-config-manager/yaml': %m");
                        return -errno;
                }

                for (;;) {
                        _auto_cleanup_ char *path = NULL;

                        file = g_dir_read_name(dir);
                        if (!file)
                                break;

                        path = g_build_path("/", "/etc/network-config-manager/yaml", file, NULL);
                        if (!path)
                                return log_oom();

                        r = manager_generate_network_config_from_yaml(path);
                        if (r < 0)
                                return r;
                }
        } else {
                for (i = 1; i < argc; i++) {
                        r = manager_generate_network_config_from_yaml(argv[i]);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int generate_networkd_config_from_command_line(int argc, char *argv[]) {
        _auto_cleanup_ char *argv_line = NULL;
        int r;

        if (argc <= 1)
                r = manager_generate_networkd_config_from_command_line("/proc/cmdline", NULL);
        else {
                argv_line = strv_join(" ", ++argv);
                if (!argv_line)
                        return log_oom();

                r = manager_generate_networkd_config_from_command_line(NULL, argv_line);
        }

        return r;
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Query and control the netmanager subsystem.\n\n"
               "  -h --help                    Show this help message and exit\n"
               "     --version                 Show package version\n"
               "\nCommands:\n"
               "  show                         Show system status\n"
               "  status                       List links\n"
               "  status                       [LINK] Show link status\n"
               "  set-mtu                      [LINK] [MTU] Set Link MTU\n"
               "  set-mac                      [LINK] [MAC] Set Link MAC\n"
               "  set-link-mode                [LINK] [MODE { yes | no | on | off | 1 | 0} ] Set Link managed by networkd\n"
               "  set-dhcp-mode                [LINK] [DHCP-MODE { yes | no | ipv4 | ipv6 } ] Set Link DHCP setting\n"
               "  set-dhcp-client-identifier   [LINK] [IDENTIFIER { mac | duid | duid-only}\n"
               "  set-dhcp-iaid                [LINK] [IAID] Sets the DHCP Identity Association Identifier (IAID) for the interface, a 32-bit unsigned integer.\n"
               "  set-dhcp-duid                [LINK | system] [DUID { link-layer-time | vendor | link-layer | uuid } ] [RAWDATA] Sets the DHCP Client\n"
               "                                      DUID type which specifies how the DUID should be generated and [RAWDATA] to overides the global DUIDRawData.\n"
               "  set-link-state               [LINK] [STATE { up | down } ] Set Link State\n"
               "  add-link-address             [LINK] [ADDRESS] [PEER] ] Add Link Address\n"
               "  delete-link-address          [LINK] Removes Address from Link\n"
               "  add-default-gateway          [LINK] [ADDRESS] onlink [ONLINK { yes | no | on | off | 1 | 0}] Add Link Default Gateway\n"
               "  delete-gateway               [LINK] Removes Gateway from Link\n"
               "  add-route                    [LINK] [ADDRESS] metric [METRIC { number }] Set Link route\n"
               "  delete-route                 [LINK] Removes route from Link\n"
               "  set-hostname                 [HOSTNAME] Sets hostname\n"
               "  show-dns                            Show DNS Servers\n"
               "  add-dns                      [LINK | system] [ADDRESS] Set Link DNS servers\n"
               "  add-domain                   [LINK | system] [DOMAIN] Set Link DOMAIN \n"
               "  show-domains                        Show DNS Server DOMAINS\n"
               "  revert-resolve-link          [LINK] Flushes all DNS server and Domain settings of the link\n"
               "  set-link-local-address       [LINK] [LinkLocalAddressing { yes | no | on | off | 1 | 0}] Set Link link-local address autoconfiguration\n"
               "  set-ipv4ll-route             [LINK] [IPv4LLRoute { yes | no | on | off | 1 | 0}] Set the route needed for non-IPv4LL hosts to communicate\n"
               "                                      with IPv4LL-only hosts\n"
               "  set-llmnr                    [LINK] [LLMNR { yes | no | on | off | 1 | 0}] Set Link Link-Local Multicast Name Resolution\n"
               "  set-multicast-dns            [LINK] [MulticastDNS { yes | no | on | off | 1 | 0}] Set Link Multicast DNS\n"
               "  set-lldp                     [LINK] [LLDP { yes | no | on | off | 1 | 0}] Set Link Ethernet LLDP packet reception\n"
               "  set-emit-lldp                [LINK] [EmitLLDP { yes | no | on | off | 1 | 0}] Set Link Ethernet LLDP packet emission\n"
               "  set-ipforward                [LINK] [IPForward { yes | no | on | off | 1 | 0}] Set Link IP packet forwarding for the system\n"
               "  set-ipv6acceptra             [LINK] [IPv6AcceptRA { yes | no | on | off | 1 | 0}] Set Link IPv6 Router Advertisement (RA) reception support for the interface\n"
               "  set-ipmasquerade             [LINK] [IPMasquerade { yes | no | on | off | 1 | 0}] Set IP masquerading for the network interface\n"
               "  set-dhcp-use-dns             [LINK] [UseDNS { yes | no | on | off | 1 | 0}] Set Link DHCP Use DNS\n"
               "  set-dhcp-use-domains         [LINK] [UseDomains { yes | no | on | off | 1 | 0}] Set Link DHCP Use DOMAINS\n"
               "  set-dhcp-use-mtu             [LINK] [UseMTU { yes | no | on | off | 1 | 0}] Set Link DHCP Use MTU\n"
               "  set-dhcp-use-ntp             [LINK] [UseNTP { yes | no | on | off | 1 | 0}] Set Link DHCP Use NTP\n"
               "  set-dhcp-use-routes          [LINK] [UseRoutes { yes | no | on | off | 1 | 0}] Set Link DHCP Use ROUTES\n"
               "  add-ntp                      [LINK] [NTP] Add Link NTP server address. This option may be specified more than once.\n"
               "                                       This setting is read by systemd-timesyncd.service(8)\n"
               "  disable-ipv6                 [LINK]  Disables IPv6 on the interface.\n"
               "  enable-ipv6                  [LINK]  Enables IPv6 on the interface.\n"
               "  reload                               Reload .network and .netdev files.\n"
               "  reconfigure                  [LINK]  Reconfigure Link.\n"
               "  generate-config-from-yaml    [FILE]  Generates network file configuration from yaml file.\n"
               "  apply-yaml-config                    Generates network file configuration from yaml files found in /etc/network-config-manager/yaml.\n"
               "  generate-config-from-cmdline [FILE | COMMAND LINE] Generates network file configuration from command kernel command line or command line.\n"

               , program_invocation_short_name
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                {}
        };
        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case '?':
                        return -EINVAL;

                default:
                        assert(0);
                }
        }

        return 1;
}

static int cli_run(int argc, char *argv[]) {
        _cleanup_(cli_unrefp) CliManager *m = NULL;
        int r;

        static const Cli commands[] = {
                { "status",                       WORD_ANY, WORD_ANY, true, system_status },
                { "show",                         WORD_ANY, WORD_ANY, false, link_status },
                { "set-mtu",                      2,        WORD_ANY, false, link_set_mtu },
                { "set-mac",                      2,        WORD_ANY, false, link_set_mac },
                { "set-link-mode",                2,        WORD_ANY, false, link_set_mode },
                { "set-dhcp-mode",                2,        WORD_ANY, false, link_set_dhcp_mode },
                { "set-dhcp-client-identifier",   2,        WORD_ANY, false, link_set_dhcp_client_identifier},
                { "set-dhcp-iaid",                2,        WORD_ANY, false, link_set_dhcp_client_iaid},
                { "set-dhcp-duid",                2,        WORD_ANY, false, link_set_dhcp_client_duid},
                { "set-link-state",               2,        WORD_ANY, false, link_update_state },
                { "add-link-address",             2,        WORD_ANY, false, link_add_address },
                { "delete-link-address",          1,        WORD_ANY, false, link_delete_address },
                { "add-default-gateway",          2,        WORD_ANY, false, link_add_default_gateway },
                { "delete-gateway",               1,        WORD_ANY, false, link_delete_gateway_or_route },
                { "add-route",                    2,        WORD_ANY, false, link_add_route },
                { "delete-route",                 1,        WORD_ANY, false, link_delete_gateway_or_route },
                { "set-hostname",                 1,        WORD_ANY, false, set_system_hostname },
                { "show-dns",                     WORD_ANY, WORD_ANY, false, show_dns_server },
                { "add-dns",                      2,        WORD_ANY, false, add_dns_server },
                { "add-domain",                   1,        WORD_ANY, false, add_dns_domains },
                { "show-domains",                 WORD_ANY, WORD_ANY, false,  show_dns_server_domains },
                { "revert-resolve-link",          1,        WORD_ANY, false, revert_resolve_link },
                { "set-link-local-address",       2,        WORD_ANY, false, link_set_network_section_bool },
                { "set-ipv4ll-route",             2,        WORD_ANY, false, link_set_network_section_bool },
                { "set-llmnr",                    2,        WORD_ANY, false, link_set_network_section_bool },
                { "set-multicast-dns",            2,        WORD_ANY, false, link_set_network_section_bool },
                { "set-lldp",                     2,        WORD_ANY, false, link_set_network_section_bool },
                { "set-emit-lldp",                2,        WORD_ANY, false, link_set_network_section_bool },
                { "set-ipforward",                2,        WORD_ANY, false, link_set_network_section_bool },
                { "set-ipv6acceptra",             2,        WORD_ANY, false, link_set_network_section_bool },
                { "set-ipmasquerade",             2,        WORD_ANY, false, link_set_network_section_bool },
                { "set-dhcp-use-dns",             2,        WORD_ANY, false, link_set_dhcp_section },
                { "set-dhcp-use-domains",         2,        WORD_ANY, false, link_set_dhcp_section },
                { "set-dhcp-use-ntp",             2,        WORD_ANY, false, link_set_dhcp_section },
                { "set-dhcp-use-mtu",             2,        WORD_ANY, false, link_set_dhcp_section },
                { "set-dhcp-use-timezone",        2,        WORD_ANY, false, link_set_dhcp_section },
                { "set-dhcp-use-routes",          2,        WORD_ANY, false, link_set_dhcp_section },
                { "add-ntp",                      2,        WORD_ANY, false, link_add_ntp },
                { "disable-ipv6",                 1,        WORD_ANY, false, link_enable_ipv6 },
                { "enable-ipv6",                  1,        WORD_ANY, false, link_enable_ipv6 },
                { "reload",                       WORD_ANY, WORD_ANY, false, network_reload },
                { "reconfigure",                  WORD_ANY, WORD_ANY, false, link_reconfigure },
                { "generate-config-from-yaml",    1,        WORD_ANY, false, generate_networkd_config_from_yaml },
                { "apply-yaml-config"           , WORD_ANY, WORD_ANY, false, generate_networkd_config_from_yaml },
                { "generate-config-from-cmdline", WORD_ANY, WORD_ANY, false, generate_networkd_config_from_command_line },
                {}
        };

        r = cli_manager_new(commands, &m);
        if (r < 0)
                return r;

        return cli_run_command(m, argc, argv);
}

static void is_netword_running(void) {
        if (access("/run/systemd/netif/state", F_OK) < 0) {
                log_warning("systemd-networkd is not running. Failed to continue.\n\n");
                exit(-1);
        }
}

int main(int argc, char *argv[]) {
        int r;

        g_log_set_default_handler (g_log_default_handler, NULL);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (!isempty_string(argv[1]) && !string_equal(argv[1], "generate-config-from-cmdline"))
                is_netword_running();

        return cli_run(argc, argv);
}
