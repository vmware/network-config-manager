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
#include "netlink-missing.h"
#include "network-util.h"
#include "networkd-api.h"
#include "network-json.h"
#include "parse-util.h"
#include "udev-hwdb.h"

int address_flags_to_string(Address *a, json_object *jobj, uint32_t flags) {
        static const char* table[] = {
                           [IFA_F_NODAD]          = "nodad",
                           [IFA_F_OPTIMISTIC]     = "optimistic",
                           [IFA_F_DADFAILED]      = "dadfailed",
                           [IFA_F_HOMEADDRESS]    = "home-address",
                           [IFA_F_DEPRECATED]     = "deprecated",
                           [IFA_F_TENTATIVE]      = "tentative",
                           [IFA_F_PERMANENT]      = "permanent",
                           [IFA_F_MANAGETEMPADDR] = "manage-temporary-address",
                           [IFA_F_NOPREFIXROUTE]  = "no-prefixroute",
                           [IFA_F_MCAUTOJOIN]     = "auto-join",
                           [IFA_F_STABLE_PRIVACY] = "stable-privacy",
        };
        _cleanup_(json_object_putp) json_object *ja = NULL, *js = NULL;

        assert(jobj);

        ja = json_object_new_array();
        if (!ja)
                return log_oom();

        if (flags & IFA_F_NODAD) {
                js = json_object_new_string(table[IFA_F_NODAD]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & IFA_F_OPTIMISTIC) {
                js = json_object_new_string(table[IFA_F_OPTIMISTIC]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }
        if (flags & IFA_F_DADFAILED) {
                js = json_object_new_string(table[IFA_F_DADFAILED]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }
        if (flags & IFA_F_HOMEADDRESS) {
                js = json_object_new_string(table[IFA_F_HOMEADDRESS]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }
        if (flags & IFA_F_DEPRECATED) {
                js = json_object_new_string(table[IFA_F_DEPRECATED]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }
        if (flags & IFA_F_TENTATIVE) {
                js = json_object_new_string(table[IFA_F_TENTATIVE]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }
        if (flags & IFA_F_PERMANENT) {
                js = json_object_new_string(table[IFA_F_PERMANENT]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        } else {
                js = json_object_new_string("dynamic");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);

        }
        if (flags & IFA_F_MANAGETEMPADDR) {
                js = json_object_new_string(table[IFA_F_MANAGETEMPADDR]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }
        if (flags & IFA_F_NOPREFIXROUTE) {
                js = json_object_new_string(table[IFA_F_NOPREFIXROUTE]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }
        if (flags & IFA_F_MCAUTOJOIN) {
                js = json_object_new_string(table[IFA_F_MCAUTOJOIN]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }
        if (flags & IFA_F_STABLE_PRIVACY) {
                js = json_object_new_string(table[IFA_F_STABLE_PRIVACY]);
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }
        if (flags & IFA_F_SECONDARY && a->family == AF_INET6) {
                js = json_object_new_string("temporary");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        } else if (flags & IFA_F_SECONDARY) {
                js = json_object_new_string("secondary");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        json_object_object_add(jobj, "FlagsString", ja);
        steal_ptr(ja);

        return 0;
}

static int json_fill_ipv6_link_local_addresses(Link *l, Addresses *addr, json_object *ret) {
        _cleanup_(json_object_putp) json_object *js = NULL;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        g_hash_table_iter_init(&iter, addr->addresses->hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                Address *a = (Address *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL;

                if (a->family != AF_INET6)
                        continue;

                if (IN6_IS_ADDR_LINKLOCAL(&a->address.in6)) {
                        r = ip_to_str(a->family, &a->address, &c);
                        if (r < 0)
                                return r;

                        js = json_object_new_string(c);
                        if (!js)
                                return log_oom();

                        json_object_object_add(ret, "IPv6LinkLocalAddress", js);
                        steal_ptr(js);
                }
        }

        return 0;
}

static int json_fill_one_link_addresses(bool ipv4, Link *l, Addresses *addr, json_object *ret) {
        _cleanup_(json_object_putp) json_object *js = NULL, *jobj = NULL;
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        assert(l);
        assert(addr);
        assert(l);

        g_hash_table_iter_init(&iter, addr->addresses->hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                _cleanup_(json_object_putp) json_object *jscope = NULL, *jflags = NULL, *jlft = NULL, *jlabel = NULL, *jproto = NULL;
                Address *a = (Address *) g_bytes_get_data(key, &size);
                _auto_cleanup_ char *c = NULL, *b = NULL, *dhcp = NULL;

                if (ipv4 && a->family != AF_INET)
                        continue;

                jobj = json_object_new_object();
                if (!jobj)
                        return log_oom();

                r = ip_to_str(a->family, &a->address, &c);
                if (r < 0)
                        return r;

                js = json_object_new_string(c);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Address", js);
                steal_ptr(js);

                js = json_object_new_int(a->address.prefix_len);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "PrefixLength", js);
                steal_ptr(js);

                r = ip_to_str_prefix(a->family, &a->broadcast, &b);
                if (r < 0)
                        return r;

                js = json_object_new_string(b);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "BroadcastAddress", js);
                steal_ptr(js);

                jscope = json_object_new_int(a->scope);
                if (!jscope)
                        return log_oom();
                json_object_object_add(jobj, "Scope", jscope);
                steal_ptr(jscope);

                jscope = json_object_new_string(route_scope_type_to_name(a->scope));
                if (!jscope)
                        return log_oom();
                json_object_object_add(jobj, "ScopeString", jscope);
                steal_ptr(jscope);

                jflags= json_object_new_int(a->flags);
                if (!jflags)
                        return log_oom();
                json_object_object_add(jobj, "Flags", jflags);
                steal_ptr(jflags);

                address_flags_to_string(a, jobj, a->flags);

                if (a->ci.ifa_prefered != UINT32_MAX)
                        jlft = json_object_new_int(a->ci.ifa_prefered);
                else
                        jlft = json_object_new_string("forever");

                if (!jlft)
                        return log_oom();

                json_object_object_add(jobj, "PreferedLifetime", jlft);
                steal_ptr(jlft);

                if (a->ci.ifa_valid != UINT32_MAX)
                        jlft = json_object_new_int(a->ci.ifa_valid);
                else
                        jlft = json_object_new_string("forever");

                if (!jlft)
                        return log_oom();

                json_object_object_add(jobj, "ValidLifetime", jlft);
                steal_ptr(jlft);

                jlabel = json_object_new_string(a->label ? a->label : "");
                if (!jlabel)
                        return log_oom();

                json_object_object_add(jobj, "Label", jlabel);
                steal_ptr(jlabel);

                if (a->proto > 0 && address_protocol_type_to_name(a->proto))
                        jproto = json_object_new_string(address_protocol_type_to_name(a->proto));
                else
                        jproto = json_object_new_string("");

                json_object_object_add(jobj, "Protocol", jproto);
                steal_ptr(jproto);

                r = network_parse_link_dhcp4_address(a->ifindex, &dhcp);
                if (r >= 0 && string_has_prefix(c, dhcp)) {
                        _auto_cleanup_ char *provider = NULL;

                        js = json_object_new_string("DHCPv4");
                        if (!js)
                                return log_oom();

                        json_object_object_add(jobj, "ConfigSource", js);
                        steal_ptr(js);

                        r = network_parse_link_dhcp4_server_address(a->ifindex, &provider);
                        if (r >= 0) {
                                js = json_object_new_string(provider);
                                if (!js)
                                        return log_oom();

                                json_object_object_add(jobj, "ConfigProvider", js);
                                steal_ptr(js);

                        }
                } else {
                        _auto_cleanup_ char *network = NULL;

                        r = parse_network_file(l->ifindex, l->name, &network);
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
                        steal_ptr(js);
                }

                json_object_array_add(ret, jobj);
                steal_ptr(jobj);
        }

        return 0;
}

int routes_flags_to_string(Route *rt, json_object *jobj, uint32_t flags) {
        _cleanup_(json_object_putp) json_object *ja = NULL, *js = NULL;

        assert(jobj);

        ja = json_object_new_array();
        if (!ja)
                return log_oom();

        if (flags & RTNH_F_DEAD) {
                js = json_object_new_string("dead");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTNH_F_ONLINK) {
                js = json_object_new_string("onlink");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTNH_F_PERVASIVE) {
                js = json_object_new_string("pervasive");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTNH_F_OFFLOAD) {
                js = json_object_new_string("offload");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTNH_F_TRAP) {
                js = json_object_new_string("trap");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTM_F_NOTIFY) {
                js = json_object_new_string("notify");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTNH_F_LINKDOWN) {
                js = json_object_new_string("linkdown");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTNH_F_UNRESOLVED) {
                js = json_object_new_string("unresolved");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTM_F_TRAP) {
                js = json_object_new_string("rt-trap");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTM_F_OFFLOAD) {
                js = json_object_new_string("rt-offload");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (flags & RTM_F_OFFLOAD_FAILED) {
                js = json_object_new_string("rt-offload-failed");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        json_object_object_add(jobj, "FlagsString", ja);
        steal_ptr(ja);

        return 0;
}

static int json_fill_one_link_routes(bool ipv4, Link *l, Routes *rts, json_object *ret) {
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        int r;

        g_hash_table_iter_init(&iter, rts->routes->hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                _auto_cleanup_ char *c = NULL, *dhcp = NULL, *prefsrc = NULL, *destination = NULL, *table = NULL;
                _cleanup_(json_object_putp) json_object *js = NULL, *jobj = NULL;
                Route *rt = (Route *) g_bytes_get_data(key, &size);

                if (ipv4 && rt->family != AF_INET)
                        continue;

                jobj = json_object_new_object();
                if (!jobj)
                        return log_oom();

                rt = (Route *) g_bytes_get_data(key, &size);

                js = json_object_new_int(rt->type);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Type", js);
                steal_ptr(js);

                js = json_object_new_string(route_type_to_name(rt->type));
                if (!js)
                        return log_oom();
                json_object_object_add(jobj, "TypeString", js);
                steal_ptr(js);

                js = json_object_new_int(rt->scope);
                if (!js)
                        return log_oom();
                json_object_object_add(jobj, "Scope", js);
                steal_ptr(js);

                js = json_object_new_string(route_scope_type_to_name(rt->scope));
                if (!js)
                        return log_oom();
                json_object_object_add(jobj, "ScopeString", js);
                steal_ptr(js);

                js = json_object_new_int(rt->table);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Table", js);
                steal_ptr(js);

                r = route_table_to_string(rt->table, &table);
                if (r >= 0) {
                        js = json_object_new_string(table);
                        if (!js)
                                return log_oom();

                        json_object_object_add(jobj, "TableString", js);
                        steal_ptr(js);
                }

                js = json_object_new_int(rt->protocol);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Protocol", js);
                steal_ptr(js);

                js = json_object_new_int(rt->pref);
                if (!js)
                        return log_oom();
                json_object_object_add(jobj, "Preference", js);
                steal_ptr(js);

                if (!ip_is_null(&rt->dst)) {
                        r = ip_to_str(rt->family, &rt->dst, &destination);
                        if (r < 0)
                                return r;
                }

                js = json_object_new_string(destination ? destination : "");
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Destination", js);
                steal_ptr(js);

                js = json_object_new_int(rt->dst_prefixlen);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "DestinationPrefixLength", js);
                steal_ptr(js);

                js = json_object_new_int(rt->priority);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Priority", js);
                steal_ptr(js);

                js = json_object_new_int(rt->ifindex);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OutgoingInterface", js);
                steal_ptr(js);

                js = json_object_new_int(rt->iif);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "IncomingInterface", js);
                steal_ptr(js);

                js = json_object_new_int(rt->ttl_propogate);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "TTLPropogate", js);
                steal_ptr(js);

                if (!ip_is_null(&rt->prefsrc)) {
                        r = ip_to_str(rt->family, &rt->prefsrc, &prefsrc);
                        if (r < 0)
                                return r;
                }

                js = json_object_new_string(prefsrc ? prefsrc : "");
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "PreferredSource", js);
                steal_ptr(js);

                if (!ip_is_null(&rt->gw)) {
                        r = ip_to_str(rt->family, &rt->gw, &c);
                        if (r < 0)
                                return r;
                }

                js = json_object_new_string(c ? c : "");
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Gateway", js);
                steal_ptr(js);

                routes_flags_to_string(rt, jobj, rt->flags);

                if (c) {
                        r = network_parse_link_dhcp4_router(rt->ifindex, &dhcp);
                        if (r >= 0 && string_has_prefix(c, dhcp)) {
                                _auto_cleanup_ char *provider = NULL;

                                js = json_object_new_string("DHCPv4");
                                if (!js)
                                        return log_oom();

                                json_object_object_add(jobj, "ConfigSource", js);
                                steal_ptr(js);

                                r = network_parse_link_dhcp4_server_address(rt->ifindex, &provider);
                                if (r >= 0) {
                                        js = json_object_new_string(provider);
                                        if (!js)
                                                return log_oom();

                                        json_object_object_add(jobj, "ConfigProvider", js);
                                        steal_ptr(js);
                                }
                        } else {
                                _auto_cleanup_ char *network = NULL;

                                r = parse_network_file(l->ifindex, l->name, &network);
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
                                steal_ptr(js);
                        }

                        json_object_array_add(ret, jobj);
                        steal_ptr(jobj);
                }
        }

        return 0;
}

static int json_fill_one_link_udev(json_object *j, Link *l, char **link_file) {
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
               steal_ptr(js);
        }

        if (sd_device && sd_device_get_devtype(sd_device, &t) >= 0 && !isempty_str(t)) {
                _cleanup_(json_object_putp) json_object *js = NULL;

               if (sd_device_get_devtype(sd_device, &t) >= 0 &&  !isempty_str(t))
                        js = json_object_new_string(t);
               else
                       js = json_object_new_string(str_na(arphrd_to_name(l->iftype)));
               if (!js)
                       return log_oom();

               json_object_object_add(j, "Type", js);
               steal_ptr(js);
        }

        if (path) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(path);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Path", js);
                steal_ptr(js);
        }

        if (driver) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(driver);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Driver", js);
                steal_ptr(js);
        }

        if (vendor) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(vendor);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Vendor", js);
                steal_ptr(js);

        }

        if (model) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(path);
                if (!js)
                        return log_oom();

                json_object_object_add(j, "Model", js);
                steal_ptr(js);
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

                        json_object_object_add(j, "HardwareDescription", js);
                        steal_ptr(js);
                }
        }

        return 0;
}

static int json_fill_link_attributes(json_object *jobj, Link *l) {
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
                steal_ptr(js);
        }

        r = link_read_sysfs_attribute(l->name, "duplex", &duplex);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(duplex);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Duplex", js);
                steal_ptr(js);
        }

        r = link_read_sysfs_attribute(l->name, "address", &ether);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(ether);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "HardwareAddress", js);
                steal_ptr(js);
        }

        if (l->contains_perm_address) {
                _cleanup_(json_object_putp) json_object *js = NULL;
                char s[ETHER_ADDR_LEN * 6] = {};

                ether_addr_to_string(&l->perm_address, s);
                js = json_object_new_string(s);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "PermanentHardwareAddress", js);
                steal_ptr(js);
        }

        r = link_read_sysfs_attribute(l->name, "mtu", &mtu);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(mtu);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "MTU", js);
                steal_ptr(js);
        }

        if (l->qdisc) {
                 _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(l->qdisc);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "QDisc", js);
                steal_ptr(js);
        }

        return 0;
}

static void fill_alterative_names(gpointer data, gpointer user_data) {
        _cleanup_(json_object_putp) json_object *js = NULL;
        json_object *ja = user_data;
        char *s = data;

        assert(s);
        assert(ja);

        js = json_object_new_string(s);
        if (!js)
                return;

        json_object_array_add(ja, js);
        steal_ptr(js);
}

static int fill_link_message(json_object *jobj, Link *l) {
        _cleanup_(json_object_putp) json_object *js = NULL;

        assert(jobj);
        assert(l);

        js = json_object_new_string(l->alias);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "Alias", js);
        steal_ptr(js);

        js = json_object_new_string(link_event_type_to_name(l->event));
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "LinkEvent", js);
        steal_ptr(js);

        if (l->master > 0) {
                char ifname[IFNAMSIZ] = {};

                if (if_indextoname(l->master, ifname)) {
                        js = json_object_new_string(ifname);
                        if (!js)
                                return log_oom();

                        json_object_object_add(jobj, "Master", js);
                        steal_ptr(js);
                }
        }

        js = json_object_new_string(ipv6_address_generation_mode_to_name(l->ipv6_addr_gen_mode));
        if (!js)
                return log_oom();
        json_object_object_add(jobj, "IPv6AddressGenerationMode", js);
        steal_ptr(js);

        js = json_object_new_int(l->netnsid);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "NetNSId", js);
        steal_ptr(js);

        js = json_object_new_int(l->new_netnsid);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "NewNetNSId", js);
        steal_ptr(js);

        js = json_object_new_int(l->new_ifindex);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "NewIfIndex", js);
        steal_ptr(js);

        js = json_object_new_int(l->min_mtu);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "MinMTU", js);
        steal_ptr(js);

        js = json_object_new_int(l->max_mtu);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "MaxMTU", js);
        steal_ptr(js);

        js = json_object_new_int(l->n_tx_queues);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "NTXQueues", js);
        steal_ptr(js);

        js = json_object_new_int(l->n_rx_queues);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "NRXQueues", js);
        steal_ptr(js);

        js = json_object_new_int(l->gso_max_size);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "GSOMaxSize", js);
        steal_ptr(js);

        js = json_object_new_int(l->gso_max_segments);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "GSOMaxSegments", js);
        steal_ptr(js);

        js = json_object_new_int(l->tso_max_size);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "TSOMaxSize", js);
        steal_ptr(js);

        js = json_object_new_int(l->tso_max_segments);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "TSOMaxSegments", js);
        steal_ptr(js);

        js = json_object_new_int(l->gro_max_size);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "GROMaxSize", js);
        steal_ptr(js);

        js = json_object_new_int(l->gro_ipv4_max_size);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "GROIPv4MaxSize", js);
        steal_ptr(js);

        js = json_object_new_string(l->parent_dev ? l->parent_dev : "");
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "ParentDev", js);
        steal_ptr(js);

        js = json_object_new_string(l->parent_bus ? l->parent_bus : "");
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "ParentBus", js);
        steal_ptr(js);

        js = json_object_new_int(l->gso_ipv4_max_size);
        if (!js)
                return log_oom();

        json_object_object_add(jobj, "GSOIPv4MaxSize", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_bytes);
        else
                js = json_object_new_double(l->stats64.rx_bytes);

        json_object_object_add(jobj, "RXBytes", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_bytes);
        else
                js = json_object_new_double(l->stats64.tx_bytes);

        json_object_object_add(jobj, "TXBytes", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_packets);
        else
                js = json_object_new_double(l->stats64.rx_packets);

        json_object_object_add(jobj, "RXPackets", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_packets);
        else
                js = json_object_new_double(l->stats64.tx_packets);

        json_object_object_add(jobj, "TXPackets", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_errors);
        else
                js = json_object_new_double(l->stats64.tx_errors);

        json_object_object_add(jobj, "TXErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_errors);
        else
                js = json_object_new_double(l->stats64.rx_errors);

        json_object_object_add(jobj, "RXErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_dropped);
        else
                js = json_object_new_double(l->stats64.rx_dropped);

        json_object_object_add(jobj, "TXDropped", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_dropped);
        else
                js = json_object_new_double(l->stats64.tx_dropped);

        json_object_object_add(jobj, "RXDropped", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_over_errors);
        else
                js = json_object_new_double(l->stats64.rx_over_errors);

        json_object_object_add(jobj, "RXOverErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.multicast);
        else
                js = json_object_new_double(l->stats64.multicast);

        json_object_object_add(jobj, "MulticastPackets", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.collisions);
        else
                js = json_object_new_double(l->stats64.collisions);

        json_object_object_add(jobj, "Collisions", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_length_errors);
        else
                js = json_object_new_double(l->stats64.rx_length_errors);

        json_object_object_add(jobj, "RXLengthErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_over_errors);
        else
                js = json_object_new_double(l->stats64.rx_over_errors);

        json_object_object_add(jobj, "RXOverErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_crc_errors);
        else
                js = json_object_new_double(l->stats64.rx_crc_errors);

        json_object_object_add(jobj, "RXCRCErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_frame_errors);
        else
                js = json_object_new_double(l->stats64.rx_frame_errors);

        json_object_object_add(jobj, "RXFrameErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_fifo_errors);
        else
                js = json_object_new_double(l->stats64.rx_fifo_errors);

        json_object_object_add(jobj, "RXFIFOErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_missed_errors);
        else
                js = json_object_new_double(l->stats64.rx_missed_errors);

        json_object_object_add(jobj, "RXMissedErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_aborted_errors);
        else
                js = json_object_new_double(l->stats64.tx_aborted_errors);

        json_object_object_add(jobj, "TXAbortedErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_carrier_errors);
        else
                js = json_object_new_double(l->stats64.tx_carrier_errors);

        json_object_object_add(jobj, "TXCarrierErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_fifo_errors);
        else
                js = json_object_new_double(l->stats64.tx_fifo_errors);

        json_object_object_add(jobj, "TXFIFOErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_heartbeat_errors);
        else
                js = json_object_new_double(l->stats64.tx_heartbeat_errors);

        json_object_object_add(jobj, "TXHeartBeatErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_window_errors);
        else
                js = json_object_new_double(l->stats64.tx_window_errors);

        json_object_object_add(jobj, "TXWindowErrors", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_compressed);
        else
                js = json_object_new_double(l->stats64.rx_compressed);

        json_object_object_add(jobj, "RXCompressed", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.tx_compressed);
        else
                js = json_object_new_double(l->stats64.tx_compressed);

        json_object_object_add(jobj, "TXCompressed", js);
        steal_ptr(js);

        if (l->contains_stats)
                js = json_object_new_int(l->stats.rx_nohandler);
        else
                js = json_object_new_double(l->stats64.rx_nohandler);

        json_object_object_add(jobj, "RXNoHandler", js);
        steal_ptr(js);

        return 0;
}

static int fill_link_flags(json_object *jobj, Link *l) {
        _cleanup_(json_object_putp) json_object *ja = NULL, *js = NULL;

        assert(jobj);
        assert(l);

        ja = json_object_new_array();
        if (!ja)
                return log_oom();

        if (l->flags & IFF_UP) {
                js = json_object_new_string("up");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (l->flags & IFF_BROADCAST) {
                js = json_object_new_string("broadcast");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (l->flags & IFF_RUNNING) {
                js = json_object_new_string("running");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (l->flags & IFF_NOARP) {
                js = json_object_new_string("noarp");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (l->flags & IFF_MASTER) {
                js = json_object_new_string("master");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (l->flags & IFF_SLAVE) {
                js = json_object_new_string("slave");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (l->flags & IFF_MULTICAST) {
                js = json_object_new_string("multicast");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (l->flags & IFF_LOWER_UP) {
                js = json_object_new_string("lowerup");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        if (l->flags & IFF_DORMANT) {
                js = json_object_new_string("dormant");
                if (!js)
                        return log_oom();

                json_object_array_add(ja, js);
                steal_ptr(js);
        }

        json_object_object_add(jobj, "Flags", ja);
        steal_ptr(ja);

        return 0;
}

static int fill_link_networkd_message(json_object *jobj, Link *l, char *network) {
        _auto_cleanup_ char *online_state = NULL, *link = NULL, *address_state = NULL, *ipv4_state = NULL,
                *ipv6_state = NULL, *required_for_online = NULL, *device_activation_policy = NULL;
        int r;

        assert(jobj);
        assert(l);

        r = json_fill_one_link_udev(jobj, l, &link);
        if (r < 0)
                return r;

        if (str_na(link)) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(str_na(link));
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "LinkFile", js);
                steal_ptr(js);
        }

        if (network) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(str_na(network));
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "NetworkFile", js);
                steal_ptr(js);
        }

        if (str_na(link_operstates_to_name(l->operstate))) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(str_na(link_operstates_to_name(l->operstate)));
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "KernelOperStateString", js);
                steal_ptr(js);

                js = json_object_new_int(l->operstate);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "KernelOperState", js);
                steal_ptr(js);
        }

        r = network_parse_link_address_state(l->ifindex, &address_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(address_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "AddressState", js);
                steal_ptr(js);
        }

        r = network_parse_link_ipv4_state(l->ifindex, &ipv4_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(ipv4_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "IPv4AddressState", js);
                steal_ptr(js);
        }

        r = network_parse_link_ipv6_state(l->ifindex, &ipv6_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                 js = json_object_new_string(ipv6_state);
                 if (!js)
                        return log_oom();

                json_object_object_add(jobj, "IPv6AddressState", js);
                steal_ptr(js);
        }

        r = network_parse_link_online_state(l->ifindex, &online_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                 js = json_object_new_string(online_state);
                 if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OnlineState", js);
                steal_ptr(js);
        }

        r = network_parse_link_required_for_online(l->ifindex, &required_for_online);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(required_for_online);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "RequiredforOnline", js);
                steal_ptr(js);
        }

        r = network_parse_link_device_activation_policy(l->ifindex, &device_activation_policy);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(device_activation_policy);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "ActivationPolicy", js);
                steal_ptr(js);
        }

        return 0;
}

static int fill_link_dns_message(json_object *jobj, Link *l, char *network) {
        _auto_cleanup_strv_ char **dns_servers = NULL, **dns_domains = NULL, **search_domains = NULL, **dns = NULL;
        _auto_cleanup_ char *mdns = NULL, *llmnr = NULL;
        _cleanup_(json_object_putp) json_object *ja = NULL;
        char **d;
        int r;

        (void) network_parse_link_dhcp4_dns(l->ifindex, &dns_servers);
        r = network_parse_link_dns(l->ifindex, &dns);
        if (r < 0)
                return r;

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
                steal_ptr(jdns);

                if (dns_servers && strv_length(dns_servers) && strv_contains((const char **) dns_servers, *d)) {
                        _cleanup_(json_object_putp) json_object *js = NULL;
                        _auto_cleanup_ char *provider = NULL;

                        js = json_object_new_string("DHCPv4");
                        if (!js)
                                return log_oom();

                        json_object_object_add(j, "ConfigSource", js);
                        steal_ptr(js);

                        r = network_parse_link_dhcp4_server_address(l->ifindex, &provider);
                        if (r >= 0) {
                                js = json_object_new_string(provider);
                                if (!js)
                                        return log_oom();

                                json_object_object_add(j, "ConfigProvider", js);
                                steal_ptr(js);
                                steal_ptr(provider);
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
                        steal_ptr(js);
                }

                json_object_array_add(ja, j);
                steal_ptr(j);
        }

        json_object_object_add(jobj, "DNS", ja);
        steal_ptr(ja);

        (void) network_parse_link_dhcp4_search_domains(l->ifindex, &dns_domains);
        r = network_parse_link_search_domains(l->ifindex, &search_domains);
        if (r < 0)
                return r;

        ja = json_object_new_array();
        if (!ja)
                return log_oom();

        strv_foreach(d, search_domains) {
                _cleanup_(json_object_putp) json_object *j = NULL, *jdomain = NULL;

                jdomain = json_object_new_string(*d);
                if (!jdomain)
                        return log_oom();

                j = json_object_new_object();
                if (!j)
                        return log_oom();

                json_object_object_add(j, "Domain", jdomain);
                steal_ptr(jdomain);

                if (dns_domains && strv_length(dns_domains) && strv_contains((const char **) dns_domains, *d)) {
                        _cleanup_(json_object_putp) json_object *js = NULL;
                        _auto_cleanup_ char *provider = NULL;

                        js = json_object_new_string("DHCPv4");
                        if (!js)
                                return log_oom();

                        json_object_object_add(j, "ConfigSource", js);
                        steal_ptr(js);

                        r = network_parse_link_dhcp4_server_address(l->ifindex, &provider);
                        if (r >= 0) {
                                js = json_object_new_string(provider);
                                if (!js)
                                        return log_oom();

                                json_object_object_add(j, "ConfigProvider", js);
                                steal_ptr(js);
                                steal_ptr(provider);
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
                        steal_ptr(js);
                }

                json_object_array_add(ja, j);
                steal_ptr(j);
        }

        json_object_object_add(jobj, "SearchDomains", ja);
        steal_ptr(ja);

        (void) network_parse_link_mdns(l->ifindex, &mdns);
        (void) network_parse_link_llmnr(l->ifindex, &llmnr);
        if (mdns || llmnr) {
                _cleanup_(json_object_putp) json_object *j = NULL, *jmdns = NULL, *jllmnr = NULL;

                j = json_object_new_object();
                if (!j)
                        return log_oom();

                jmdns = json_object_new_string(str_na(mdns));
                if (!jmdns)
                        return log_oom();

                json_object_object_add(j, "MDNS", jmdns);
                steal_ptr(jmdns);

                jllmnr = json_object_new_string(str_na(llmnr));
                if (!jllmnr)
                        return log_oom();

                json_object_object_add(j, "LLMNR", jllmnr);
                steal_ptr(jllmnr);

                json_object_object_add(jobj, "DNSSettings", j);
                steal_ptr(j);
        }

        return 0;
}

static int fill_link_ntp_message(json_object *jobj, Link *l, char *network) {
        _auto_cleanup_strv_ char **ntp = NULL, **config_ntp = NULL;
        _cleanup_(json_object_putp) json_object *ja = NULL;
        char **d;
        int r;

        assert(jobj);
        assert(l);

        (void) network_parse_link_dhcp4_ntp(l->ifindex, &ntp);
        r = network_parse_link_ntp(l->ifindex, &config_ntp);
        if (r < 0)
                return r;

       ja = json_object_new_array();
       if (!ja)
               return log_oom();

       strv_foreach(d, config_ntp) {
               _cleanup_(json_object_putp) json_object *j = NULL, *jntp = NULL;

                jntp = json_object_new_string(*d);
                if (!jntp)
                        return log_oom();

                j = json_object_new_object();
                if (!j)
                        return log_oom();

                json_object_object_add(j, "Address", jntp);
                steal_ptr(jntp);

                if (ntp && strv_length(ntp) && strv_contains((const char **) ntp, *d)) {
                        _cleanup_(json_object_putp) json_object *js = NULL;
                        _auto_cleanup_ char *provider = NULL;

                        js = json_object_new_string("DHCPv4");
                        if (!js)
                                return log_oom();

                        json_object_object_add(j, "ConfigSource", js);
                        steal_ptr(js);

                        r = network_parse_link_dhcp4_server_address(l->ifindex, &provider);
                        if (r >= 0) {
                                js = json_object_new_string(provider);
                                if (!js)
                                        return log_oom();

                                json_object_object_add(j, "ConfigProvider", js);
                                steal_ptr(js);
                                steal_ptr(provider);
                        }
                } else  {
                        _cleanup_(json_object_putp) json_object *js = NULL;

                        if (config_contains(network, "Network", "NTP", *d)) {
                                js = json_object_new_string("static");
                                if (!js)
                                        return log_oom();
                        } else {
                                js = json_object_new_string("foreign");
                                if (!js)
                                        return log_oom();
                        }
                        json_object_object_add(j, "ConfigProvider", js);
                        steal_ptr(js);
                }

                json_object_array_add(ja, j);
                steal_ptr(j);
        }

        json_object_object_add(jobj, "NTP", ja);
        steal_ptr(ja);

        return 0;
}

int json_fill_one_link(IfNameIndex *p, bool ipv4, json_object **ret) {
        _auto_cleanup_ char *setup_state = NULL, *tz = NULL, *network = NULL;
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _cleanup_(addresses_freep) Addresses *addr = NULL;
        _cleanup_(routes_freep) Routes *route = NULL;
        _cleanup_(link_freep) Link *l = NULL;
        int r;

        assert(p);

        jobj = json_object_new_object();
        if (!jobj)
                return log_oom();

        r = netlink_acqure_one_link(p->ifname, &l);
        if (r < 0)
                return r;

        if (l->ifindex > 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_int(l->ifindex);
                if (!ja)
                        return log_oom();

                json_object_object_add(jobj, "Index", ja);
                steal_ptr(ja);

                ja = json_object_new_string(p->ifname);
                if (!ja)
                        return log_oom();

                json_object_object_add(jobj, "Name", ja);
                steal_ptr(ja);
        }

        if (l->alt_names) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                g_ptr_array_foreach(l->alt_names, fill_alterative_names, ja);
                json_object_object_add(jobj, "AlternativeNames", ja);
                steal_ptr(ja);
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
                steal_ptr(js);
        }

        r = json_fill_link_attributes(jobj, l);
        if (r < 0)
                return r;


        (void) network_parse_link_network_file(l->ifindex, &network);
        r = fill_link_networkd_message(jobj, l, network);
        if (r < 0)
                return r;

        r = fill_link_flags(jobj, l);
        if (r < 0)
                return r;

        r = fill_link_message(jobj, l);
        if (r < 0)
                return r;

        r = netlink_get_one_link_address(l->ifindex, &addr);
        if (r >= 0 && addr && set_size(addr->addresses) > 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                json_fill_ipv6_link_local_addresses(l, addr, jobj);

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                json_fill_one_link_addresses(ipv4, l, addr, ja);

                json_object_object_add(jobj, "Addresses", ja);
                steal_ptr(ja);
        }

        r = netlink_get_one_link_route(l->ifindex, &route);
        if (r >= 0 && route && set_size(route->routes) > 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                json_fill_one_link_routes(ipv4, l, route, ja);

                json_object_object_add(jobj, "Routes", ja);
                steal_ptr(ja);
        }

        r = fill_link_dns_message(jobj, l, network);
        if (r < 0)
                return r;

        r = fill_link_ntp_message(jobj, l, network);
        if (r < 0)
                return r;

        (void) network_parse_link_timezone(l->ifindex, &tz);
        if (tz) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(str_na(tz));
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "TimeZone", js);
                steal_ptr(js);
        }

        if (ret)
                *ret = steal_ptr(jobj);
        else
                printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

        return 0;
}
