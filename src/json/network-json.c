/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <json-c/json.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "cli.h"
#include "dbus.h"
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
                *jifindex = NULL, *jobj_address = NULL;
        json_object *jobj = (json_object *) userdata;
        _auto_cleanup_ char *c = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        size_t size;
        Address *a;
        int r;

        jobj_address = json_object_new_object();
        if (!jobj_address)
                return;

        a = (Address *) g_bytes_get_data(key, &size);

        if_indextoname(a->ifindex, buf);

        r = ip_to_string_prefix(a->family, &a->address, &c);
        if (r < 0)
                return;

        jname = json_object_new_string(buf);
        if (!jname)
                return;

        json_object_object_add(jobj_address, "ifname", jname);

        jip = json_object_new_string(c);
        if (!jip)
                return;

        json_object_object_add(jobj_address, "ip", jip);

        if (a->family == AF_INET)
                jfamily = json_object_new_string("ipv4");
        else
                jfamily = json_object_new_string("ipv6");

        if (!jfamily)
                return;

        json_object_object_add(jobj_address, "family", jfamily);

        jifindex = json_object_new_int(a->ifindex);
        if (!jifindex)
                return;

        json_object_object_add(jobj_address, "ifindex", jifindex);
        json_object_array_add(jobj, jobj_address);

        steal_pointer(jobj_address);
        steal_pointer(jip);
        steal_pointer(jname);
        steal_pointer(jfamily);
        steal_pointer(jifindex);
}

static void json_list_link_gateways(gpointer key, gpointer value, gpointer userdata) {
        _cleanup_(json_object_putp) json_object *jip = NULL, *jname = NULL, *jfamily = NULL,
                *jifindex = NULL, *jobj_gw = NULL;
        json_object *jobj = (json_object *) userdata;
        _auto_cleanup_ char *c = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        size_t size;
        Route *route;
        int r;

        jobj_gw = json_object_new_object();
        if (!jobj_gw)
                return;

        route = (Route *) g_bytes_get_data(key, &size);
        if_indextoname(route->ifindex, buf);

        r = ip_to_string_prefix(route->family, &route->address, &c);
        if (r < 0)
                return;

        jname = json_object_new_string(buf);
        if (!jname)
                return;

        json_object_object_add(jobj_gw, "ifname", jname);


        jip = json_object_new_string(c);
        if (!jip)
                return;

        json_object_object_add(jobj_gw, "ip", jip);

        if (route->family == AF_INET)
                jfamily = json_object_new_string("ipv4");
        else
                jfamily = json_object_new_string("ipv6");
        if (!jfamily)
                return;

        json_object_object_add(jobj_gw, "family", jfamily);

        jifindex = json_object_new_int(route->ifindex);
        if (!jifindex)
                return;

        json_object_object_add(jobj_gw, "ifindex", jifindex);
        json_object_array_add(jobj, jobj_gw);

        steal_pointer(jobj_gw);
        steal_pointer(jip);
        steal_pointer(jname);
        steal_pointer(jfamily);
        steal_pointer(jifindex);
}

int json_system_status(char **ret) {
        _cleanup_(json_object_putp) json_object *jobj = NULL, *jaddress = NULL, *jroutes = NULL;
        _auto_cleanup_ char *state = NULL, *carrier_state = NULL, *hostname = NULL, *kernel = NULL,
                *kernel_release = NULL, *arch = NULL, *virt = NULL, *os = NULL, *systemd = NULL;
        _auto_cleanup_strv_ char **dns = NULL, **domains = NULL, **ntp = NULL;
        _cleanup_(routes_unrefp) Routes *routes = NULL;
        _cleanup_(addresses_unrefp) Addresses *h = NULL;
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

                set_foreach(routes->routes, json_list_link_gateways, jroutes);
        }

        json_object_object_add(jobj, "Gateways", jroutes);
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

                json_object_object_add(jobj, "Domains", ja);
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

static void json_list_one_link_addresses(gpointer key, gpointer value, gpointer userdata) {
        _cleanup_(json_object_putp) json_object *js = NULL;
        json_object *ja = (json_object *) userdata;
        _auto_cleanup_ char *c = NULL;
        unsigned long size;
        Address *a = NULL;
        int r;

        a = (Address *) g_bytes_get_data(key, &size);

        r = ip_to_string_prefix(a->family, &a->address, &c);
        if (r < 0)
                return;

        js = json_object_new_string(c);
        if (!js)
                return;

        json_object_array_add(ja, js);
        steal_pointer(js);
}

static void json_list_one_link_routes(gpointer key, gpointer value, gpointer userdata) {
        _cleanup_(json_object_putp) json_object *js = NULL;
        json_object *ja = (json_object *) userdata;
        _auto_cleanup_ char *c = NULL;
        unsigned long size;
        Route *rt = NULL;
        int r;

        rt = (Route *) g_bytes_get_data(key, &size);
        r = ip_to_string(rt->family, &rt->address, &c);
        if (r < 0)
                return;

        js = json_object_new_string(c);
        if (!js)
                return;

        json_object_array_add(ja, js);
        steal_pointer(js);
}

static int json_one_link_udev(json_object *j, Link *l, char **link_file) {
        _auto_cleanup_ char *devid = NULL, *device = NULL, *manufacturer = NULL;
        _cleanup_(udev_device_unrefp) struct udev_device *dev = NULL;
        const char *link, *driver, *path, *vendor, *model;
        _cleanup_(udev_unrefp) struct udev *udev = NULL;
        int r;

        assert(l);

        r = asprintf(&devid, "n%i", l->ifindex);
        if (r < 0)
                return log_oom();

        r = asprintf(&device,"%s/%s", "/sys/class/net", l->name);
        if (r < 0)
                return log_oom();

        udev = udev_new();
        if (!udev)
                return log_oom();

        dev = udev_device_new_from_syspath(udev, device);
        if (!dev)
                return log_oom();

        path = udev_device_get_property_value(dev, "ID_PATH");
        if (path) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(path);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Path", js);
                steal_pointer(js);
        }

        driver = udev_device_get_property_value(dev, "ID_NET_DRIVER");
        if (driver) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(driver);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Driver", js);
                steal_pointer(js);
        }

        vendor = udev_device_get_property_value(dev, "ID_VENDOR_FROM_DATABASE");
        if (vendor) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(vendor);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Vendor", js);
                steal_pointer(js);

        }

        model = udev_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE");
        if (model) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(path);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Model", js);
                steal_pointer(js);
        }

        link = udev_device_get_property_value(dev, "ID_NET_LINK_FILE");
        if (link && link_file) {
                *link_file = g_strdup(link);
                if (!*link_file)
                        return log_oom();
        }

        hwdb_get_manufacturer((uint8_t *) &l->mac_address.ether_addr_octet, &manufacturer);
        if (manufacturer) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(manufacturer);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Manufacturer", js);
                steal_pointer(js);
        }

        return 0;
}

static int json_list_link_sysfs_attributes(json_object *jobj, Link *l) {
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
        _cleanup_(json_object_putp) json_object *jobj = NULL, *jobj_routes = NULL, *jaddress = NULL;
        _auto_cleanup_ char *setup_state = NULL, *tz = NULL, *network = NULL, *link = NULL;
        _cleanup_(addresses_unrefp) Addresses *addr = NULL;
        _cleanup_(routes_unrefp) Routes *route = NULL;
        _cleanup_(link_unrefp) Link *l = NULL;
        int r;

        assert(p);

        jobj = json_object_new_object();
        if (!jobj)
                return log_oom();

        r = link_get_one_link(p->ifname, &l);
        if (r < 0)
                return r;

        if (l->alt_names) {
                _cleanup_(json_object_putp) json_object *ja = json_object_new_array();
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

        r = json_list_link_sysfs_attributes(jobj, l);
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

        if (string_na(arphrd_to_name(l->iftype))) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(string_na(arphrd_to_name(l->iftype)));
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Type", js);
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

        if (l->flags > 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL, *js = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                if (l->flags & IFF_UP) {
                        js = json_object_new_string("UP");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_BROADCAST) {
                        js = json_object_new_string("BROADCAST");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_RUNNING) {
                        js = json_object_new_string("RUNNING");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_NOARP) {
                        js = json_object_new_string("NOARP");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_MASTER) {
                        js = json_object_new_string("MASTER");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_SLAVE) {
                        js = json_object_new_string("SLAVE");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_MULTICAST) {
                        js = json_object_new_string("MULTICAST");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_LOWER_UP) {
                        js = json_object_new_string("LOWERUP");
                        if (!js)
                                return log_oom();

                        json_object_array_add(ja, js);
                        steal_pointer(js);
                }

                if (l->flags & IFF_DORMANT) {
                        js = json_object_new_string("DORMANT");
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

        (void) network_parse_link_dns(l->ifindex, &dns);
        (void) network_parse_link_search_domains(l->ifindex, &search_domains);
        (void) network_parse_link_route_domains(l->ifindex, &route_domains);
        (void) network_parse_link_ntp(l->ifindex, &ntp);

        r = manager_get_one_link_address(l->ifindex, &addr);
        if (r >= 0 && addr && set_size(addr->addresses) > 0) {
                _cleanup_(json_object_putp) json_object *ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                set_foreach(addr->addresses, json_list_one_link_addresses, ja);

                json_object_object_add(jobj, "Addresses", ja);
                steal_pointer(ja);
        }

        r = manager_get_one_link_route(l->ifindex, &route);
        if (r >= 0 && route && set_size(route->routes) > 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                set_foreach(route->routes, json_list_one_link_routes, ja);

                json_object_object_add(jobj, "Routes", ja);
                steal_pointer(ja);
        }

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

        if (search_domains) {
                _cleanup_(json_object_putp) json_object *ja = json_object_new_array();
                char **d;

                if (!ja)
                        return log_oom();

                strv_foreach(d, search_domains) {
                        json_object *jdomains = json_object_new_string(*d);
                        if (!jdomains)
                                return log_oom();

                        json_object_array_add(ja, jdomains);
                }

                json_object_object_add(jobj, "Domains", ja);
                steal_pointer(ja);
        }

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
