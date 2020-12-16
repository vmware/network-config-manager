/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
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
        json_object_object_add(jobj, buf, jobj_address);

        steal_pointer(jobj_address);
        steal_pointer(jip);
        steal_pointer(jname);
        steal_pointer(jfamily);
        steal_pointer(jifindex);
}

static void json_list_link_gateways(Route *route, json_object *jobj) {
        _cleanup_(json_object_putp) json_object *jip = NULL, *jname = NULL, *jfamily = NULL,
                *jifindex = NULL, *jobj_address = NULL;
        _auto_cleanup_ char *c = NULL;
        char buf[IF_NAMESIZE + 1] = {};
        int r;

        jobj_address = json_object_new_object();
        if (!jobj_address)
                return;

        if_indextoname(route->ifindex, buf);

        r = ip_to_string_prefix(route->family, &route->address, &c);
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

        if (route->family == AF_INET)
                jfamily = json_object_new_string("ipv4");
        else
                jfamily = json_object_new_string("ipv6");
        if (!jfamily)
                return;

        json_object_object_add(jobj_address, "family", jfamily);

        jifindex = json_object_new_int(route->ifindex);
        if (!jifindex)
                return;

        json_object_object_add(jobj_address, "ifindex", jifindex);
        json_object_object_add(jobj, buf, jobj_address);

        steal_pointer(jobj_address);
        steal_pointer(jip);
        steal_pointer(jname);
        steal_pointer(jfamily);
        steal_pointer(jifindex);
}

int json_system_status(void) {
        _cleanup_(json_object_putp) json_object *jobj = NULL, *jarray = NULL, *jobj_address = NULL,
                *jobj_routes = NULL, *jaddress = NULL, *jroutes = NULL;
        _auto_cleanup_ char *state = NULL, *carrier_state = NULL, *hostname = NULL, *kernel = NULL,
                *kernel_release = NULL, *arch = NULL, *virt = NULL, *os = NULL, *systemd = NULL;
        _auto_cleanup_strv_ char **dns = NULL, **domains = NULL, **ntp = NULL;
        _cleanup_(routes_free) Routes *routes = NULL;
        _cleanup_(addresses_unref) Addresses *h = NULL;
        sd_id128_t machine_id = {};
        GList *i;
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

        (void) dbus_get_property_from_hostnamed("KernelRelease", &kernel_release);
        if (kernel) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(kernel_release);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj,"KernelRelease", js);
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
                jaddress = json_object_new_object();
                if (!jaddress)
                        return log_oom();

                set_foreach(h->addresses, json_list_link_addresses, jaddress);
        }

        json_object_object_add(jobj, "Addresses", jaddress);
        steal_pointer(jaddress);

        r = manager_link_get_routes(&routes);
        if (r >= 0 && g_list_length(routes->routes) > 0) {
                Route *rt;

                jroutes = json_object_new_object();
                if (!jroutes)
                        return log_oom();

                for (i = routes->routes; i; i = i->next) {
                        rt = i->data;
                        json_list_link_gateways(rt, jroutes);
                }
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

        printf ("%s\n",json_object_to_json_string(jobj));

        return r;
}
