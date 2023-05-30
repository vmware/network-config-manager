/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <json-c/json.h>

#include <systemd/sd-device.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "ctl.h"
#include "config-parser.h"
#include "dbus.h"
#include "device.h"
#include "dns.h"
#include "log.h"
#include "macros.h"
#include "network-address.h"
#include "network-link.h"
#include "network-manager.h"
#include "network-route.h"
#include "network-util.h"
#include "networkd-api.h"
#include "network-json.h"
#include "parse-util.h"
#include "udev-hwdb.h"

DEFINE_CLEANUP(json_object*, json_object_put);

static void json_list_link_addresses(gpointer key, gpointer value, gpointer userdata) {
        _cleanup_(json_object_putp) json_object *jip = NULL, *jname = NULL, *jfamily = NULL,
                *jidx = NULL, *jaddr = NULL;
        json_object *jobj = (json_object *) userdata;
        _auto_cleanup_ char *c = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        size_t size;
        Address *a;
        int r;

        jaddr = json_object_new_object();
        if (!jaddr)
                return;

        a = (Address *) g_bytes_get_data(key, &size);

        if_indextoname(a->ifindex, buf);

        r = ip_to_str_prefix(a->family, &a->address, &c);
        if (r < 0)
                return;

        jname = json_object_new_string(buf);
        if (!jname)
                return;

        json_object_object_add(jaddr, "ifname", jname);

        jip = json_object_new_string(c);
        if (!jip)
                return;

        json_object_object_add(jaddr, "ip", jip);

        if (a->family == AF_INET)
                jfamily = json_object_new_string("ipv4");
        else
                jfamily = json_object_new_string("ipv6");

        if (!jfamily)
                return;

        json_object_object_add(jaddr, "family", jfamily);

        jidx = json_object_new_int(a->ifindex);
        if (!jidx)
                return;

        json_object_object_add(jaddr, "ifindex", jidx);
        json_object_array_add(jobj, jaddr);

        steal_pointer(jaddr);
        steal_pointer(jip);
        steal_pointer(jname);
        steal_pointer(jfamily);
        steal_pointer(jidx);
}

static void json_list_link_routes(gpointer key, gpointer value, gpointer userdata) {
        _cleanup_(json_object_putp) json_object *jip = NULL, *jname = NULL, *jfamily = NULL,
                *jidx = NULL, *jrt = NULL;
        json_object *jobj = (json_object *) userdata;
        _auto_cleanup_ char *c = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        Route *route;
        size_t size;
        int r;

        jrt = json_object_new_object();
        if (!jrt)
                return;

        route = (Route *) g_bytes_get_data(key, &size);
        if_indextoname(route->ifindex, buf);

        r = ip_to_str_prefix(route->gw.family, &route->gw, &c);
        if (r < 0)
                return;

        jname = json_object_new_string(buf);
        if (!jname)
                return;

        json_object_object_add(jrt, "ifname", jname);

        jip = json_object_new_string(c);
        if (!jip)
                return;

        json_object_object_add(jrt, "gateway", jip);
        steal_pointer(jip);

        r = ip_to_str_prefix(route->family, &route->dst, &c);
        if (r < 0)
                return;

        jip = json_object_new_string(c);
        if (!jip)
                return;

        json_object_object_add(jrt, "destination", jip);
        steal_pointer(jip);

        if (route->family == AF_INET)
                jfamily = json_object_new_string("ipv4");
        else
                jfamily = json_object_new_string("ipv6");
        if (!jfamily)
                return;

        json_object_object_add(jrt, "family", jfamily);

        jidx = json_object_new_int(route->ifindex);
        if (!jidx)
                return;

        json_object_object_add(jrt, "ifindex", jidx);
        json_object_array_add(jobj, jrt);

        steal_pointer(jrt);
        steal_pointer(jname);
        steal_pointer(jfamily);
        steal_pointer(jidx);
}

int json_system_status(char **ret) {
        _cleanup_(json_object_putp) json_object *jobj = NULL, *jaddress = NULL, *jroutes = NULL;
        _auto_cleanup_ char *state = NULL, *carrier_state = NULL, *hostname = NULL, *kernel = NULL,
                *kernel_release = NULL, *arch = NULL, *virt = NULL, *os = NULL, *systemd = NULL,
                *online_state;
        _auto_cleanup_strv_ char **dns = NULL, **domains = NULL, **ntp = NULL;
        _cleanup_(routes_freep) Routes *routes = NULL;
        _cleanup_(addresses_freep) Addresses *h = NULL;
        sd_id128_t machine_id = {};
        int r;

        jobj = json_object_new_object();
        if (!jobj)
                return log_oom();

        (void) dbus_get_property_from_hostnamed("StaticHostname", &hostname);
        if (hostname) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(hostname);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "System Name", js);
                steal_pointer(js);
        }

        (void) dbus_get_property_from_hostnamed("KernelName", &kernel);
        if (kernel) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(kernel);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj,"KernelName", js);
                steal_pointer(js);
        }

        (void) dbus_get_property_from_hostnamed("KernelRelease", &kernel_release);
        if (kernel_release) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(kernel_release);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj,"KernelRelease", js);
                steal_pointer(js);
        }

        (void) dbus_get_string_systemd_manager("Version", &systemd);
        if (systemd) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(systemd);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "SystemdVersion", js);
                steal_pointer(js);
        }

        (void) dbus_get_string_systemd_manager("Architecture", &arch);
        if (arch) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(arch);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Architecture", js);
                steal_pointer(js);
        }

        (void) dbus_get_string_systemd_manager("Virtualization", &virt);
        if (virt) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(virt);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Virtualization", js);
                steal_pointer(js);
        }

        (void) dbus_get_property_from_hostnamed("OperatingSystemPrettyName", &os);
        if (os) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(os);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OperatingSystem", js);
                steal_pointer(js);
        }

        r = sd_id128_get_machine(&machine_id);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;
                char ids[SD_ID128_STRING_MAX];

                sd_id128_to_string(machine_id, ids);

                js = json_object_new_string(ids);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "MachineID", js);
                steal_pointer(js);
        }

        r = dbus_get_system_property_from_networkd("OperationalState", &state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OperationalState", js);
                steal_pointer(js);
        }

        r = dbus_get_system_property_from_networkd("CarrierState", &carrier_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(carrier_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "CarrierState", js);
                steal_pointer(js);
        }

        r = dbus_get_system_property_from_networkd("OnlineState", &online_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(online_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OnlineState", js);
                steal_pointer(js);
        }

        r = manager_link_get_address(&h);
        if (r >= 0 && set_size(h->addresses) > 0) {
                jaddress = json_object_new_array();
                if (!jaddress)
                        return log_oom();


                set_foreach(h->addresses, json_list_link_addresses, jaddress);
        }

        json_object_object_add(jobj, "Addresses", jaddress);
        steal_pointer(jaddress);

        r = manager_link_get_routes(&routes);
        if (r >= 0 && set_size(routes->routes) > 0) {
                jroutes = json_object_new_array();
                if (!jroutes)
                        return log_oom();

                set_foreach(routes->routes, json_list_link_routes, jroutes);
        }

        json_object_object_add(jobj, "Routes", jroutes);
        steal_pointer(jroutes);

        (void) network_parse_dns(&dns);
        if (dns) {
                _cleanup_(json_object_putp) json_object *ja = json_object_new_array();
                char **d;

                if (!ja)
                        return log_oom();

                strv_foreach(d, dns) {
                        json_object *jdns = json_object_new_string(*d);

                        if (!jdns)
                                return log_oom();

                        json_object_array_add(ja, jdns);
                }

                json_object_object_add(jobj, "DNS", ja);
                steal_pointer(ja);
        }

        (void) network_parse_search_domains(&domains);
        if (domains) {
                _cleanup_(json_object_putp) json_object *ja = json_object_new_array();
                char **d;

                if (!ja)
                        return log_oom();

                strv_foreach(d, domains) {
                        json_object *jdomains = json_object_new_string(*d);
                        if (!jdomains)
                                return log_oom();

                        json_object_array_add(ja, jdomains);
                }

                json_object_object_add(jobj, "SearchDomains", ja);
                steal_pointer(ja);
        }

        (void) network_parse_ntp(&ntp);
        if (ntp) {
                _cleanup_(json_object_putp) json_object *ja = json_object_new_array();
                char **d;

                if (!ja)
                        return log_oom();

                strv_foreach(d, ntp) {
                        json_object *jntp = json_object_new_string(*d);
                        if (!jntp)
                                return log_oom();

                        json_object_array_add(ja, jntp);
                }

                json_object_object_add(jobj, "NTP", ja);
                steal_pointer(ja);
        }

        if (ret) {
                char *s;

                s = strdup(json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
                if (!s)
                        return log_oom();

                *ret = steal_pointer(s);
        } else
                printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

        return r;
}

static int json_list_one_link_addresses(Link *l, Addresses *addr, json_object *ret) {
        _cleanup_(json_object_putp) json_object *js = NULL, *jobj = NULL;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        g_hash_table_iter_init(&iter, addr->addresses->hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                _cleanup_(json_object_putp) json_object *jscope = NULL, *jflags = NULL;
                Address *a = (Address *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL, *dhcp = NULL;

                r = ip_to_str_prefix(a->family, &a->address, &c);
                if (r < 0)
                        return r;

                jobj = json_object_new_object();
                if (!jobj)
                        return log_oom();

                js = json_object_new_string(c);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Address", js);
                steal_pointer(js);

                jscope = json_object_new_int(a->scope);
                if (!jscope)
                        return log_oom();
                json_object_object_add(jobj, "Scope", jscope);

                steal_pointer(jscope);

                jflags= json_object_new_int(a->flags);
                if (!jflags)
                        return log_oom();
                json_object_object_add(jobj, "Flags", jflags);
                steal_pointer(jflags);

                r = network_parse_link_dhcp4_address(a->ifindex, &dhcp);
                if (r >= 0 && string_has_prefix(c, dhcp)) {
                        _auto_cleanup_ char *provider = NULL;

                        js = json_object_new_string("dhcp");
                        if (!js)
                                return log_oom();

                        json_object_object_add(jobj, "ConfigSource", js);
                        steal_pointer(js);

                        r = network_parse_link_dhcp4_server_address(a->ifindex, &provider);
                        if (r >= 0) {
                                js = json_object_new_string(provider);
                                if (!js)
                                        return log_oom();

                                json_object_object_add(jobj, "ConfigProvider", js);
                                steal_pointer(js);

                        }
                } else {
                        _auto_cleanup_ char *network = NULL;

                        r = parse_network_file(l->ifindex, NULL, &network);
                        if (r >= 0) {
                                if (config_exists(network, "Network", "Address", c) || config_exists(network, "Address", "Address", c)) {
                                        js = json_object_new_string("static");
                                        if (!js)
                                                return log_oom();
                                } else {
                                        js = json_object_new_string("foreign");
                                        if (!js)
                                        return log_oom();
                                }
                        }

                        json_object_object_add(jobj, "ConfigSource", js);
                        steal_pointer(js);
                }

                json_object_array_add(ret, jobj);
                steal_pointer(jobj);
        }

        return 0;
}

static int json_list_one_link_routes(Link *l, Routes *rts, json_object *ret) {
        _cleanup_(json_object_putp) json_object *js = NULL, *jobj = NULL;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        g_hash_table_iter_init(&iter, rts->routes->hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                _cleanup_(json_object_putp) json_object *jscope = NULL, *jflags = NULL;
                Route *rt = (Route *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL, *dhcp = NULL;

                jobj = json_object_new_object();
                if (!jobj)
                        return log_oom();

                rt = (Route *) g_bytes_get_data(key, &size);
                if (ip_is_null(&rt->gw))
                        continue;

                r = ip_to_str(rt->family, &rt->gw, &c);
                if (r < 0)
                        return r;

                js = json_object_new_string(c);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Gateway", js);
                steal_pointer(js);

                r = network_parse_link_dhcp4_router(rt->ifindex, &dhcp);
                if (r >= 0 && string_has_prefix(c, dhcp)) {
                        _auto_cleanup_ char *provider = NULL;

                        js = json_object_new_string("dhcp");
                        if (!js)
                                return log_oom();

                        json_object_object_add(jobj, "ConfigSource", js);
                        steal_pointer(js);

                        r = network_parse_link_dhcp4_server_address(rt->ifindex, &provider);
                        if (r >= 0) {
                                js = json_object_new_string(provider);
                                if (!js)
                                        return log_oom();

                                json_object_object_add(jobj, "ConfigProvider", js);
                                steal_pointer(js);

                        }
                } else {
                        _auto_cleanup_ char *network = NULL;

                        r = parse_network_file(l->ifindex, NULL, &network);
                        if (r >= 0) {
                                if (config_exists(network, "Network", "Gateway", c) || config_exists(network, "Route", "Gateway", c)) {
                                        js = json_object_new_string("static");
                                        if (!js)
                                                return log_oom();
                                } else {
                                        js = json_object_new_string("foreign");
                                        if (!js)
                                        return log_oom();
                                }
                        }

                        json_object_object_add(jobj, "ConfigSource", js);
                        steal_pointer(js);
                }

                json_object_array_add(ret, jobj);
                steal_pointer(jobj);
        }

        return 0;
}

static int json_one_link_udev(json_object *j, Link *l, char **link_file) {
        const char *link = NULL, *driver =  NULL, *path = NULL, *vendor = NULL, *model = NULL;
        _cleanup_(sd_device_unrefp) sd_device *sd_device = NULL;
        _auto_cleanup_ char *desc = NULL;
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
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(l->kind);
                if (!js)
                        return log_oom();

               json_object_object_add(j, "Kind", js);
               steal_pointer(js);
        }

        if (sd_device && sd_device_get_devtype(sd_device, &t) >= 0 && !isempty_str(t)) {
                _cleanup_(json_object_putp) json_object *js = NULL;

               if (sd_device_get_devtype(sd_device, &t) >= 0 &&  !isempty_str(t))
                        js = json_object_new_string(t);
               else
                       js = json_object_new_string(string_na(arphrd_to_name(l->iftype)));
               if (!js)
                       return log_oom();

               json_object_object_add(j, "Type", js);
               steal_pointer(js);
        }

        if (path) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(path);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Path", js);
                steal_pointer(js);
        }

        if (driver) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(driver);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Driver", js);
                steal_pointer(js);
        }

        if (vendor) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(vendor);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Vendor", js);
                steal_pointer(js);

        }

        if (model) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(path);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Model", js);
                steal_pointer(js);
        }

        if (link && link_file) {
                *link_file = g_strdup(link);
                if (!*link_file)
                        return log_oom();
        }

        if (!l->kind) {
                hwdb_get_description((uint8_t *) &l->mac_address.ether_addr_octet, &desc);
                if (desc) {
                        _cleanup_(json_object_putp) json_object *js = NULL;

                        js = json_object_new_string(desc);
                        if (!js)
                                return log_oom();

                        json_object_object_add(j, "HWDescription", js);
                        steal_pointer(js);
                }
        }

        return 0;
}

static int json_list_link_attributes(json_object *jobj, Link *l) {
        _auto_cleanup_ char *duplex = NULL, *speed = NULL, *ether = NULL, *mtu = NULL;
        int r;

        assert(jobj);
        assert(l);

        r = link_read_sysfs_attribute(l->name, "speed", &speed);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(speed);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Speed", js);
                steal_pointer(js);
        }

        r = link_read_sysfs_attribute(l->name, "duplex", &duplex);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(duplex);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Duplex", js);
                steal_pointer(js);
        }

        r = link_read_sysfs_attribute(l->name, "address", &ether);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(ether);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "HWAddress", js);
                steal_pointer(js);
        }

        r = link_read_sysfs_attribute(l->name, "mtu", &mtu);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(mtu);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "MTU", js);
                steal_pointer(js);
        }

        if (l->qdisc) {
                 _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(l->qdisc);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "QDisc", js);
                steal_pointer(js);
        }

        return 0;
}

static void display_alterative_names(gpointer data, gpointer user_data) {
        _cleanup_(json_object_putp) json_object *js = NULL;
        json_object *ja = user_data;
        char *s = data;

        assert(s);
        assert(ja);

        js = json_object_new_string(s);
        if (!js)
                return;

        json_object_array_add(ja, js);
        steal_pointer(js);
}

int json_list_one_link(IfNameIndex *p, char **ret) {
        _auto_cleanup_strv_ char **dns = NULL, **ntp = NULL, **search_domains = NULL, **route_domains = NULL;
        _auto_cleanup_ char *setup_state = NULL, *tz = NULL, *network = NULL, *link = NULL, *online_state = NULL,
                *address_state = NULL, *ipv4_state = NULL, *ipv6_state = NULL, *required_for_online = NULL,
                *device_activation_policy = NULL, *mdns = NULL, *llmnr = NULL;
        _auto_cleanup_strv_ char **dns_servers = NULL, **dns_domains = NULL;
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _cleanup_(addresses_freep) Addresses *addr = NULL;
        _cleanup_(routes_freep) Routes *route = NULL;
        _cleanup_(link_freep) Link *l = NULL;
        int r;

        assert(p);

        jobj = json_object_new_object();
        if (!jobj)
                return log_oom();

        r = link_get_one_link(p->ifname, &l);
        if (r < 0)
                return r;

        if (l->alt_names) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                g_ptr_array_foreach(l->alt_names, display_alterative_names, ja);
                json_object_object_add(jobj, "AlternativeNames", ja);
                steal_pointer(ja);
        }

        r = network_parse_link_setup_state(l->ifindex, &setup_state);
        if (r == -ENODATA) {
                setup_state = g_strdup("unmanaged");
                if (!setup_state)
                        return log_oom();

                r = 0;
        }
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(setup_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "SetupState", js);
                steal_pointer(js);
        }

        r = json_list_link_attributes(jobj, l);
        if (r < 0)
                return r;

        r = json_one_link_udev(jobj, l, &link);
        if (r < 0)
                return r;

        if (string_na(link)) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(string_na(link));
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "LinkFile", js);
                steal_pointer(js);
        }

        (void) network_parse_link_network_file(l->ifindex, &network);
        if (network) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(string_na(network));
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "NetworkFile", js);
                steal_pointer(js);
        }

        if (string_na(link_operstates_to_name(l->operstate))) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(string_na(link_operstates_to_name(l->operstate)));
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OperState", js);
                steal_pointer(js);
        }

        r = network_parse_link_address_state(l->ifindex, &address_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(address_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "AddressState", js);
                steal_pointer(js);
        }

        r = network_parse_link_ipv4_state(l->ifindex, &ipv4_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(ipv4_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "IPv4AddressState", js);
                steal_pointer(js);
        }

        r = network_parse_link_ipv6_state(l->ifindex, &ipv6_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                 js = json_object_new_string(ipv6_state);
                 if (!js)
                        return log_oom();

                json_object_object_add(jobj, "IPv6AddressState", js);
                steal_pointer(js);
        }

        r = network_parse_link_online_state(l->ifindex, &online_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                 js = json_object_new_string(online_state);
                 if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OnlineState", js);
                steal_pointer(js);
        }

        r = network_parse_link_required_for_online(l->ifindex, &required_for_online);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(required_for_online);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "RequiredforOnline", js);
                steal_pointer(js);
        }

        r = network_parse_link_device_activation_policy(l->ifindex, &device_activation_policy);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(device_activation_policy);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "ActivationPolicy", js);
                steal_pointer(js);
        }

        if (l->flags > 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL, *js = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                if (l->flags & IFF_UP) {
                        js = json_object_new_string("up");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_BROADCAST) {
                        js = json_object_new_string("broadcast");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_RUNNING) {
                        js = json_object_new_string("running");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_NOARP) {
                        js = json_object_new_string("noarp");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_MASTER) {
                        js = json_object_new_string("master");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_SLAVE) {
                        js = json_object_new_string("slave");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_MULTICAST) {
                        js = json_object_new_string("multicast");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_LOWER_UP) {
                        js = json_object_new_string("lowerup");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_DORMANT) {
                        js = json_object_new_string("dormant");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                json_object_object_add(jobj, "Flags", ja);
                steal_pointer(ja);
        }

        if (l->master > 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;
                char ifname[IFNAMSIZ] = {};

                if (if_indextoname(l->master, ifname)) {
                        js = json_object_new_string(ifname);
                        if (!js)
                                return log_oom();

                        json_object_object_add(jobj, "Master", js);
                        steal_pointer(js);
                }
        }

        if (l->min_mtu > 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_int(l->min_mtu);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "MinMTU", js);
                steal_pointer(js);
        }

        if (l->max_mtu > 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_int(l->max_mtu);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "MaxMTU", js);
                steal_pointer(js);
        }

        if (l->n_tx_queues > 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_int(l->n_tx_queues);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "NTXQueues", js);
                steal_pointer(js);
        }

        if (l->n_rx_queues > 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_int(l->n_rx_queues);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "NRXQueues", js);
                steal_pointer(js);
        }

        if (l->gso_max_size > 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_int(l->gso_max_size);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "GSOMaxSize", js);
                steal_pointer(js);
        }

        if (l->gso_max_segments > 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_int(l->gso_max_segments);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "GSOMaxSegments", js);
                steal_pointer(js);
        }

        if (l->contains_stats || l->contains_stats64) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_bytes);
                else
                        js = json_object_new_double(l->stats64.rx_bytes);

                json_object_object_add(jobj, "RXBytes", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_bytes);
                else
                        js = json_object_new_double(l->stats64.tx_bytes);

                json_object_object_add(jobj, "TXBytes", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_packets);
                else
                        js = json_object_new_double(l->stats64.rx_packets);

                json_object_object_add(jobj, "RXPackets", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_packets);
                else
                        js = json_object_new_double(l->stats64.tx_packets);

                json_object_object_add(jobj, "TXPackets", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_errors);
                else
                        js = json_object_new_double(l->stats64.tx_errors);

                json_object_object_add(jobj, "TXErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_errors);
                else
                        js = json_object_new_double(l->stats64.rx_errors);

                json_object_object_add(jobj, "RXErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_dropped);
                else
                        js = json_object_new_double(l->stats64.rx_dropped);

                json_object_object_add(jobj, "TXDropped", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_dropped);
                else
                        js = json_object_new_double(l->stats64.tx_dropped);

                json_object_object_add(jobj, "RXDropped", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_over_errors);
                else
                        js = json_object_new_double(l->stats64.rx_over_errors);

                json_object_object_add(jobj, "RXOverErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.multicast);
                else
                        js = json_object_new_double(l->stats64.multicast);

                json_object_object_add(jobj, "MulticastPackets", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.collisions);
                else
                        js = json_object_new_double(l->stats64.collisions);

                json_object_object_add(jobj, "Collisions", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_length_errors);
                else
                        js = json_object_new_double(l->stats64.rx_length_errors);

                json_object_object_add(jobj, "RXLengthErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_over_errors);
                else
                        js = json_object_new_double(l->stats64.rx_over_errors);

                json_object_object_add(jobj, "RXOverErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_crc_errors);
                else
                        js = json_object_new_double(l->stats64.rx_crc_errors);

                json_object_object_add(jobj, "RXCRCErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_frame_errors);
                else
                        js = json_object_new_double(l->stats64.rx_frame_errors);

                json_object_object_add(jobj, "RXFrameErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_fifo_errors);
                else
                        js = json_object_new_double(l->stats64.rx_fifo_errors);

                json_object_object_add(jobj, "RXFIFOErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_missed_errors);
                else
                        js = json_object_new_double(l->stats64.rx_missed_errors);

                json_object_object_add(jobj, "RXMissedErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_aborted_errors);
                else
                        js = json_object_new_double(l->stats64.tx_aborted_errors);

                json_object_object_add(jobj, "TXAbortedErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_carrier_errors);
                else
                        js = json_object_new_double(l->stats64.tx_carrier_errors);

                json_object_object_add(jobj, "TXCarrierErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_fifo_errors);
                else
                        js = json_object_new_double(l->stats64.tx_fifo_errors);

                json_object_object_add(jobj, "TXFIFOErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_heartbeat_errors);
                else
                        js = json_object_new_double(l->stats64.tx_heartbeat_errors);

                json_object_object_add(jobj, "TXHeartBeatErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_window_errors);
                else
                        js = json_object_new_double(l->stats64.tx_window_errors);

                json_object_object_add(jobj, "TXWindowErrors", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_compressed);
                else
                        js = json_object_new_double(l->stats64.rx_compressed);

                json_object_object_add(jobj, "RXCompressed", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.tx_compressed);
                else
                        js = json_object_new_double(l->stats64.tx_compressed);

                json_object_object_add(jobj, "TXCompressed", js);
                steal_pointer(js);

                if (l->contains_stats)
                        js = json_object_new_int(l->stats.rx_nohandler);
                else
                        js = json_object_new_double(l->stats64.rx_nohandler);

                json_object_object_add(jobj, "RXNoHandler", js);
                steal_pointer(js);
        }

        (void) network_parse_link_route_domains(l->ifindex, &route_domains);
        (void) network_parse_link_ntp(l->ifindex, &ntp);

        r = manager_get_one_link_address(l->ifindex, &addr);
        if (r >= 0 && addr && set_size(addr->addresses) > 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                json_list_one_link_addresses(l, addr, ja);

                json_object_object_add(jobj, "Addresses", ja);
                steal_pointer(ja);
        }

        r = manager_get_one_link_route(l->ifindex, &route);
        if (r >= 0 && route && set_size(route->routes) > 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                json_list_one_link_routes(l, route, ja);

                json_object_object_add(jobj, "Routes", ja);
                steal_pointer(ja);
        }

        (void) network_parse_link_dhcp4_dns(l->ifindex, &dns_servers);
        (void) network_parse_link_dns(l->ifindex, &dns);
        if (dns) {
                _cleanup_(json_object_putp) json_object *ja = NULL;
                char **d;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                strv_foreach(d, dns) {
                        _cleanup_(json_object_putp) json_object *j = NULL, *jdns = NULL;

                        jdns = json_object_new_string(*d);
                        if (!jdns)
                                return log_oom();

                        j = json_object_new_object();
                        if (!j)
                                return log_oom();

                        json_object_object_add(j, "Address", jdns);
                        steal_pointer(jdns);

                        if (dns_servers && strv_length(dns_servers) && strv_contains((const char **) dns_servers, *d)) {
                                _cleanup_(json_object_putp) json_object *js = NULL;
                                _auto_cleanup_ char *provider = NULL;

                                js = json_object_new_string("dhcp");
                                if (!js)
                                        return log_oom();

                                json_object_object_add(j, "ConfigSource", js);
                                steal_pointer(js);

                                r = network_parse_link_dhcp4_server_address(l->ifindex, &provider);
                                if (r >= 0) {
                                        js = json_object_new_string(provider);
                                        if (!js)
                                                return log_oom();

                                        json_object_object_add(j, "ConfigProvider", js);
                                        steal_pointer(js);
                                        steal_pointer(provider);
                                }
                        } else  {
                                _cleanup_(json_object_putp) json_object *js = NULL;

                                if (config_contains(network, "Network", "DNS", *d)) {
                                        js = json_object_new_string("static");
                                        if (!js)
                                                return log_oom();
                                } else {
                                        js = json_object_new_string("foreign");
                                        if (!js)
                                                return log_oom();
                                }
                                json_object_object_add(j, "ConfigProvider", js);
                                steal_pointer(js);
                        }

                        json_object_array_add(ja, j);
                        steal_pointer(j);
                }

                json_object_object_add(jobj, "DNS", ja);
                steal_pointer(ja);
        }

        (void) network_parse_link_dhcp4_search_domains(l->ifindex, &dns_domains);
        (void) network_parse_link_search_domains(l->ifindex, &search_domains);
        if (search_domains) {
                _cleanup_(json_object_putp) json_object *ja = NULL;
                char **d;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                strv_foreach(d, search_domains) {
                        _cleanup_(json_object_putp) json_object *j = NULL, *jdns = NULL;

                        jdns = json_object_new_string(*d);
                        if (!jdns)
                                return log_oom();

                        j = json_object_new_object();
                        if (!j)
                                return log_oom();

                        json_object_object_add(j, "Domain", jdns);
                        steal_pointer(jdns);

                        if (dns_domains && strv_length(dns_domains) && strv_contains((const char **) dns_domains, *d)) {
                                _cleanup_(json_object_putp) json_object *js = NULL;
                                _auto_cleanup_ char *provider = NULL;

                                js = json_object_new_string("dhcp");
                                if (!js)
                                        return log_oom();

                                json_object_object_add(j, "ConfigSource", js);
                                steal_pointer(js);

                                r = network_parse_link_dhcp4_server_address(l->ifindex, &provider);
                                if (r >= 0) {
                                        js = json_object_new_string(provider);
                                        if (!js)
                                                return log_oom();

                                        json_object_object_add(j, "ConfigProvider", js);
                                        steal_pointer(js);
                                        steal_pointer(provider);
                                }
                        } else  {
                                _cleanup_(json_object_putp) json_object *js = NULL;

                                if (config_contains(network, "Network", "Domains", *d)) {
                                        js = json_object_new_string("static");
                                        if (!js)
                                                return log_oom();
                                } else {
                                        js = json_object_new_string("foreign");
                                        if (!js)
                                                return log_oom();
                                }
                                json_object_object_add(j, "ConfigProvider", js);
                                steal_pointer(js);
                        }

                        json_object_array_add(ja, j);
                        steal_pointer(j);
                }

                json_object_object_add(jobj, "SearchDomains", ja);
                steal_pointer(ja);
        }

        (void) network_parse_link_mdns(l->ifindex, &mdns);
        (void) network_parse_link_llmnr(l->ifindex, &llmnr);
        if (mdns || llmnr) {
                _cleanup_(json_object_putp) json_object *j = NULL, *jmdns = NULL, *jllmnr = NULL;

                j = json_object_new_object();
                if (!j)
                        return log_oom();

                jmdns = json_object_new_string(mdns);
                if (!jmdns)
                        return log_oom();

                json_object_object_add(j, "MDNS", jmdns);
                steal_pointer(jmdns);

                jllmnr = json_object_new_string(llmnr);
                if (!jllmnr)
                        return log_oom();

                json_object_object_add(j, "LLMNR", jllmnr);
                steal_pointer(jllmnr);

                json_object_object_add(jobj, "DNSSettings", j);
                steal_pointer(j);
        }

        if (ntp) {
                _cleanup_(json_object_putp) json_object *ja = NULL;
                char **d;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                strv_foreach(d, ntp) {
                        json_object *jntp = json_object_new_string(*d);
                        if (!jntp)
                                return log_oom();

                        json_object_array_add(ja, jntp);
                }

                json_object_object_add(jobj, "NTP", ja);
                steal_pointer(ja);
        }

        (void) network_parse_link_timezone(l->ifindex, &tz);
        if (tz) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(string_na(tz));
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "TimeZone", js);
                steal_pointer(js);
        }

        if (ret) {
                char *s;

                s = strdup(json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
                if (!s)
                        return log_oom();

                *ret = steal_pointer(s);
        } else
                printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

        return 0;
}

int json_show_dns_server(const IfNameIndex *p, char *dns_config) {
        _cleanup_(dns_servers_freep) DNSServers *fallback = NULL, *dns = NULL, *current = NULL;
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _auto_cleanup_ char *provider = NULL;
        GSequenceIter *i;
        DNSServer *d;
        int r;

        jobj = json_object_new_object();
        if (!jobj)
                return log_oom();

        if(p) {
                r = network_parse_link_dhcp4_server_address(p->ifindex, &provider);
                if(r < 0)
                        return r;
        }

        r = dbus_acquire_dns_servers_from_resolved("DNS", &dns);
        if (r >= 0 && dns && !g_sequence_is_empty(dns->dns_servers)) {
                _cleanup_(json_object_putp) json_object *jdns = json_object_new_array();
                if (!jdns)
                        return log_oom();

                for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _cleanup_(json_object_putp) json_object *jaddr = json_object_new_object();
                        _auto_cleanup_ char *pretty = NULL;

                        if (!jaddr)
                                return log_oom();

                        d = g_sequence_get(i);
                        if (!d->ifindex)
                                continue;

                        r = ip_to_str(d->address.family, &d->address, &pretty);
                        if (r >= 0) {
                                json_object *s = json_object_new_string(pretty);
                                if (!s)
                                        return log_oom();

                                json_object_object_add(jaddr, "Address", s);
                                steal_pointer(s);

                                if (dns_config && g_strrstr(dns_config, pretty))
                                        s = json_object_new_string("static");
                                else {
                                        s = json_object_new_string("dhcp");

                                        if(provider) {
                                                json_object *js = json_object_new_string(provider);
                                                if (!js)
                                                        return log_oom();

                                                json_object_object_add(jaddr, "ConfigProvider", js);
                                                steal_pointer(js);
                                        }
                                }

                                if (!s)
                                        return log_oom();

                                json_object_object_add(jaddr, "ConfigSource", s);
                                steal_pointer(s);

                                json_object_array_add(jdns, jaddr);
                                steal_pointer(jaddr);
                        }

                }

                json_object_object_add(jobj, "DNS", jdns);
                steal_pointer(jdns);
        }

        r = dbus_get_current_dns_servers_from_resolved(&current);
        if (r >= 0 && current && !g_sequence_is_empty(current->dns_servers)) {
                _auto_cleanup_ char *pretty = NULL;

                i = g_sequence_get_begin_iter(current->dns_servers);
                d = g_sequence_get(i);
                r = ip_to_str(d->address.family, &d->address, &pretty);
                if (r >= 0) {
                        json_object *s = json_object_new_string(pretty);
                        if (!s)
                                return log_oom();

                        json_object_object_add(jobj, "CurrentDNSServer", s);
                        steal_pointer(s);
                }
        }

        r = dbus_acquire_dns_servers_from_resolved("FallbackDNS", &fallback);
        if (r >= 0 && !g_sequence_is_empty(fallback->dns_servers)) {
                _cleanup_(json_object_putp) json_object *ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                for (i = g_sequence_get_begin_iter(fallback->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;

                        d = g_sequence_get(i);

                        r = ip_to_str(d->address.family, &d->address, &pretty);
                        if (r >= 0) {
                                json_object *s = json_object_new_string(pretty);
                                if (!s)
                                        return log_oom();

                                json_object_array_add(ja, s);
                        }
                }
                json_object_object_add(jobj, "FallbackDNS", ja);
                steal_pointer(ja);
        }

        printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
        return 0;
}

int json_show_dns_server_domains(void) {
        _cleanup_(dns_domains_freep) DNSDomains *domains = NULL;
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        char buffer[LINE_MAX] = {};
        GSequenceIter *i;
        DNSDomain *d;
        int r;

        r = dbus_acquire_dns_domains_from_resolved(&domains);
        if (r < 0){
                log_warning("Failed to fetch DNS domain from resolved: %s", strerror(-r));
                return r;
        }

        jobj = json_object_new_object();
        if (!jobj)
                return log_oom();

        if (!domains || g_sequence_is_empty(domains->dns_domains)) {
                log_warning("No DNS Domain configured: %s", strerror(ENODATA));
                return -ENODATA;
        } else {
                 _cleanup_(json_object_putp) json_object *ja = NULL;
                _cleanup_(set_freep) Set *all_domains = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                r = set_new(&all_domains, NULL, NULL);
                if (r < 0) {
                        log_debug("Failed to init set for domains: %s", strerror(-r));
                        return r;
                }

                for (i = g_sequence_get_begin_iter(domains->dns_domains); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i))  {
                        json_object *a;
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
                                log_debug("Failed to add domain to set '%s': %s", d->domain, strerror(-r));
                                return -EINVAL;
                        }

                        a = json_object_new_string(s);
                        if (!a)
                                return log_oom();

                        json_object_array_add(ja, a);
                }

                json_object_object_add(jobj, "DNSDomain", ja);
                steal_pointer(ja);

                for (i = g_sequence_get_begin_iter(domains->dns_domains); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _cleanup_(json_object_putp) json_object *j = NULL;

                        j = json_object_new_array();
                        if (!j)
                                return log_oom();

                        d = g_sequence_get(i);
                        if (!d->ifindex)
                                continue;

                        sprintf(buffer, "%" PRIu32, d->ifindex);
                        r = parse_ifname_or_index(buffer, &p);
                        if (r >= 0) {
                                _cleanup_(json_object_putp) json_object *a = NULL;

                                 a = json_object_new_string(d->domain);
                                 if (!a)
                                         return log_oom();

                                 json_object_array_add(j, a);
                                 steal_pointer(a);

                        }
                        json_object_object_add(jobj, p->ifname, j);
                        steal_pointer(j);
                }
        }

        printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
        return 0;
}
