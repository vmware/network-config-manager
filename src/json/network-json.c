/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <json-c/json.h>

#include <systemd/sd-device.h>
#include <netdb.h>

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
#include "network-routing-policy-rule.h"
#include "network-util.h"
#include "networkd-api.h"
#include "network-json.h"
#include "parse-util.h"
#include "udev-hwdb.h"

static void json_fill_routing_policy_rules(gpointer key, gpointer value, gpointer userdata) {
        _cleanup_(json_object_putp) json_object *jd = NULL, *jrule = NULL, *config_source = NULL;
        _auto_cleanup_ char *from = NULL, *to = NULL, *table = NULL;
        json_object *jobj = (json_object *) userdata;
        RoutingPolicyRule *rule;
        size_t size;
        int r;

        assert(key);
        assert(value);
        assert(userdata);

        jrule = json_object_new_object();
        if (!jrule)
                return;

        rule = (RoutingPolicyRule *) g_bytes_get_data(key, &size);
        if (rule->family == AF_INET)
                jd = json_object_new_string("ipv4");
        else
                jd = json_object_new_string("ipv6");
        if (!jd)
                return;

        json_object_object_add(jrule, "Family", jd);
        steal_ptr(jd);

        if (rule->from_prefixlen > 0) {
                r = ip_to_str(rule->from.family, &rule->from, &from);
                if (r < 0)
                        return;
                jd = json_object_new_string(from);
        } else
                jd = json_object_new_string("");

        if (!jd)
                return;

        json_object_object_add(jrule, "From", jd);
        steal_ptr(jd);

        jd = json_object_new_int(rule->from_prefixlen);
        if (!jd)
                return;

        json_object_object_add(jrule, "FromPrefixLength", jd);
        steal_ptr(jd);

        if (rule->to_prefixlen > 0) {
                r = ip_to_str(rule->to.family, &rule->to, &to);
                if (r < 0)
                        return;

                jd = json_object_new_string(to);
        } else
                jd = json_object_new_string("");

        if (!jd)
                return;

        json_object_object_add(jrule, "To", jd);
        steal_ptr(jd);

        jd = json_object_new_int(rule->to_prefixlen);
        if (!jd)
                return;

        json_object_object_add(jrule, "ToPrefixLength", jd);
        steal_ptr(jd);

        jd = json_object_new_int(rule->table);
        if (!jd)
                return;

        json_object_object_add(jrule, "Table", jd);
        steal_ptr(jd);

        r = route_table_to_string(rule->table, &table);
        if (r >= 0) {
                jd = json_object_new_string(str_na_json(table));
                if (!jd)
                        return;

                json_object_object_add(jrule, "TableString", jd);
                steal_ptr(jd);
                steal_ptr(table);
        }

        jd = json_object_new_int(rule->tos);
        if (!jd)
                return;

        json_object_object_add(jrule, "TOS", jd);
        steal_ptr(jd);

        jd = json_object_new_int(rule->type);
        if (!jd)
                return;

        json_object_object_add(jrule, "Type", jd);
        steal_ptr(jd);

        jd = json_object_new_int(rule->priority);
        if (!jd)
                return;

        json_object_object_add(jrule, "Priority", jd);
        steal_ptr(jd);

        jd = json_object_new_int(rule->protocol);
        if (!jd)
                return;

        json_object_object_add(jrule, "Protocol", jd);
        steal_ptr(jd);

        jd = json_object_new_boolean(rule->invert_rule);
        if (!jd)
                return;

        json_object_object_add(jrule, "Invert", jd);
        steal_ptr(jd);

        if (rule->ipproto_set) {
                _auto_cleanup_ struct protoent *pe = NULL;

                jd = json_object_new_int(rule->ipproto);
                if (!jd)
                        return;

                json_object_object_add(jrule, "IPProtocol", jd);
                steal_ptr(jd);

                pe = new(struct protoent, 1);
                if (!pe)
                        return;

                pe = getprotobynumber(rule->ipproto);
                if (pe) {
                        jd = json_object_new_string(pe->p_name);
                        if (!jd)
                                return;

                        json_object_object_add(jrule, "IPProtocolString", jd);
                        steal_ptr(jd);
                }

                steal_ptr(pe);
        }

        jd = json_object_new_int(rule->fwmark);
        if (!jd)
                return;

        json_object_object_add(jrule, "FirewallMark", jd);
        steal_ptr(jd);

        jd = json_object_new_int(rule->fwmask);
        if (!jd)
                return;

        json_object_object_add(jrule, "FirewallMask", jd);
        steal_ptr(jd);

        jd = json_object_new_string(str_na_json(rule->iif));
        if (!jd)
                return;

        json_object_object_add(jrule, "IncomingInterface", jd);
        steal_ptr(jd);

        jd = json_object_new_string(str_na_json(rule->oif));
        if (!jd)
                return;

        json_object_object_add(jrule, "OutgoingInterface", jd);
        steal_ptr(jd);

        jd = json_object_new_int(rule->l3mdev);
        if (!jd)
                return;

        json_object_object_add(jrule, "L3MDev", jd);
        steal_ptr(jd);

        if (rule->suppress_prefixlen >= 0) {
                jd = json_object_new_int(rule->suppress_prefixlen);
                if (!jd)
                        return;

                json_object_object_add(jrule, "SuppressPrefixLength", jd);
                steal_ptr(jd);
        }

        if (rule->suppress_ifgroup >= 0) {
                jd = json_object_new_int(rule->suppress_ifgroup);
                if (!jd)
                        return;

                json_object_object_add(jrule, "SuppressInterfaceGroup", jd);
                steal_ptr(jd);
        }

        if (rule->sport.start != 0 || rule->sport.end != 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return;

                jd = json_object_new_int(rule->sport.start);
                if (!jd)
                        return;

                json_object_array_add(ja,  jd);
                steal_ptr(jd);

                jd = json_object_new_int(rule->sport.end);
                if (!jd)
                        return;

                json_object_array_add(ja,  jd);
                steal_ptr(jd);

                json_object_object_add(jrule, "SourcePort", ja);
                steal_ptr(ja);
        }

        if (rule->dport.start != 0 || rule->dport.end != 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return;

                jd = json_object_new_int(rule->dport.start);
                if (!jd)
                        return;

                json_object_array_add(ja,  jd);
                steal_ptr(jd);

                jd = json_object_new_int(rule->dport.end);
                if (!jd)
                        return;

                json_object_array_add(ja,  jd);
                steal_ptr(jd);

                json_object_object_add(jrule, "DestinationPort", ja);
                steal_ptr(ja);
        }

        if ((from && manager_config_exists("RoutingPolicyRule", "From", from)) || (to && manager_config_exists("RoutingPolicyRule", "To", to)))
                config_source = json_object_new_string("static");
        else
                config_source = json_object_new_string("foreign");

        json_object_object_add(jrule, "ConfigSource", config_source);
        steal_ptr(config_source);

        json_object_array_add(jobj, jrule);
        steal_ptr(jrule);
}

int json_fill_system_status(char **ret) {
        _cleanup_(json_object_putp) json_object *jobj = NULL, *jn = NULL;
        _auto_cleanup_ char *state = NULL, *carrier_state = NULL, *hostname = NULL, *kernel = NULL,
                *kernel_release = NULL, *arch = NULL, *virt = NULL, *os = NULL, *systemd = NULL,
                *online_state = NULL, *address_state = NULL, *ipv4_address_state = NULL,
                *ipv6_address_state = NULL, *hwvendor = NULL, *hwmodel = NULL, *firmware = NULL,
                *firmware_vendor = NULL, *firmware_date = NULL;
        _auto_cleanup_ char *mdns = NULL, *llmnr = NULL, *dns_over_tls = NULL, *conf_mode = NULL;
        _cleanup_(routing_policy_rules_freep) RoutingPolicyRules *rules = NULL;
        _cleanup_(links_freep) Links *links = NULL;
        _auto_cleanup_strv_ char **ntp = NULL;
        _auto_cleanup_ DNSServer *c = NULL;
        sd_id128_t machine_id = {};
        int r;

        r = json_acquire_and_parse_network_data(&jn);
        if (r < 0) {
                log_warning("Failed acquire network data: %s", strerror(-r));
                return r;
        }

        jobj = json_object_new_object();
        if (!jobj)
                return log_oom();

        r = dbus_get_property_from_hostnamed("StaticHostname", &hostname);
        if (r >=0 && hostname) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(hostname);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "SystemName", js);
                steal_ptr(js);
        }

        r = dbus_get_property_from_hostnamed("KernelName", &kernel);
        if (r >=0 && kernel) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(kernel);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj,"KernelName", js);
                steal_ptr(js);
        }

        r = dbus_get_property_from_hostnamed("KernelRelease", &kernel_release);
        if (r >=0 && kernel_release) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(kernel_release);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj,"KernelRelease", js);
                steal_ptr(js);
        }

        r = dbus_get_string_systemd_manager("Version", &systemd);
        if (r >=0 && systemd) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(systemd);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "SystemdVersion", js);
                steal_ptr(js);
        }

        r = dbus_get_string_systemd_manager("Architecture", &arch);
        if (r >=0 && arch) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(arch);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Architecture", js);
                steal_ptr(js);
        }

        r = dbus_get_string_systemd_manager("Virtualization", &virt);
        if (r >=0 && virt) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(virt);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Virtualization", js);
                steal_ptr(js);
        }

        r = dbus_get_property_from_hostnamed("OperatingSystemPrettyName", &os);
        if (r >=0 && os) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(os);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OperatingSystemPrettyName", js);
                steal_ptr(js);
        }

        r = dbus_get_property_from_hostnamed("HardwareVendor", &hwvendor);
        if (r >= 0 && hwvendor) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(hwvendor);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "HardwareVendor", js);
                steal_ptr(js);
        }

        r = dbus_get_property_from_hostnamed("HardwareModel", &hwmodel);
        if (r >= 0 && hwmodel) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(hwmodel);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "HardwareModel", js);
                steal_ptr(js);
        }

        r = dbus_get_property_from_hostnamed("FirmwareVersion", &firmware);
        if (r >= 0 && firmware) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(firmware);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "FirmwareVersion", js);
                steal_ptr(js);
        }

        r = dbus_get_property_from_hostnamed("FirmwareVendor", &firmware_vendor);
        if (r >= 0 && firmware_vendor) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(firmware_vendor);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "FirmwareVendor", js);
                steal_ptr(js);
        }

        r = dbus_get_property_from_hostnamed("FirmwareDate", &firmware_date);
        if (r >= 0 && firmware_date) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(firmware_date);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "FirmwareDate", js);
                steal_ptr(js);
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
                steal_ptr(js);
        }

        r = dbus_get_system_property_from_networkd("OperationalState", &state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OperationalState", js);
                steal_ptr(js);
        }

        r = dbus_get_system_property_from_networkd("CarrierState", &carrier_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(carrier_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "CarrierState", js);
                steal_ptr(js);
        }

        r = dbus_get_system_property_from_networkd("OnlineState", &online_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(online_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OnlineState", js);
                steal_ptr(js);
        }

        r = dbus_get_system_property_from_networkd("AddressState", &address_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(address_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "AddressState", js);
                steal_ptr(js);
        }

        r = dbus_get_system_property_from_networkd("IPv4AddressState", &ipv4_address_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(ipv4_address_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "IPv4AddressState", js);
                steal_ptr(js);
        }

        r = dbus_get_system_property_from_networkd("IPv6AddressState", &ipv6_address_state);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(ipv6_address_state);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "IPv6AddressState", js);
                steal_ptr(js);
        }

        r = netlink_acquire_all_links(&links);
        if (r >= 0) {
                _cleanup_(json_object_putp) json_object *ja = NULL;

                ja = json_object_new_array();
                if (!ja)
                        return log_oom();

                for (GList *i = links->links; i; i = g_list_next (i)) {
                        _cleanup_(json_object_putp) json_object *js = NULL;
                        _auto_cleanup_ IfNameIndex *p = NULL;
                        Link *link = (Link *) i->data;

                        r = parse_ifname_or_index(link->name, &p);
                        if (r >= 0) {
                                r = json_fill_one_link(p, false, jn, &js);
                                if (r >= 0) {
                                        json_object_array_add(ja, js);
                                        steal_ptr(js);
                                }
                        }
                }

                json_object_object_add(jobj, "Interfaces", ja);
                steal_ptr(ja);
        }

        r = dbus_get_current_dns_server_from_resolved(&c);
        if (r >= 0 && c) {
                _auto_cleanup_ char *pretty = NULL;

                r =ip_to_str(c->address.family, &c->address, &pretty);
                if (r >= 0) {
                        _cleanup_(json_object_putp) json_object *jd = NULL;

                        jd = json_object_new_string(pretty);
                        if (!jd)
                                return log_oom();

                        json_object_object_add(jobj, "CurrentDNSServer", jd);
                        steal_ptr(jd);
                        steal_ptr(pretty);
                }
        }

        (void) dbus_acqure_dns_setting_from_resolved("MulticastDNS", &mdns);
        (void) dbus_acqure_dns_setting_from_resolved("LLMNR", &llmnr);
        (void) dbus_acqure_dns_setting_from_resolved("DNSOverTLS", &dns_over_tls);
        (void) dbus_acqure_dns_setting_from_resolved("ResolvConfMode", &conf_mode);

        if (mdns || llmnr || conf_mode || dns_over_tls) {
                _cleanup_(json_object_putp) json_object *j = NULL, *js = NULL;


                j = json_object_new_object();
                if (!j)
                        return log_oom();

                js = json_object_new_string(str_na(mdns));
                if (!js)
                        return log_oom();

                json_object_object_add(j, "MDNS", js);
                steal_ptr(js);

                js = json_object_new_string(str_na(llmnr));
                if (!js)
                        return log_oom();

                json_object_object_add(j, "LLMNR", js);
                steal_ptr(js);

                js = json_object_new_string(str_na(dns_over_tls));
                if (!js)
                        return log_oom();

                json_object_object_add(j, "DNSOverTLS", js);
                steal_ptr(js);

                js = json_object_new_string(str_na(conf_mode));
                if (!js)
                        return log_oom();

                json_object_object_add(j, "ResolvConfMode", js);
                steal_ptr(js);

                json_object_object_add(jobj, "DNSSettings", j);
                steal_ptr(j);
        }

        r = network_parse_ntp(&ntp);
        if (r >= 0 && ntp) {
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
                steal_ptr(ja);
        }

        r = acquire_routing_policy_rules(&rules);
        if (r >= 0 && set_size(rules->routing_policy_rules) > 0) {
                _cleanup_(json_object_putp) json_object *jrules = NULL;

                jrules = json_object_new_array();
                if (!jrules)
                        return log_oom();

                set_foreach(rules->routing_policy_rules, json_fill_routing_policy_rules, jrules);
                json_object_object_add(jobj, "RoutingPolicyRules", jrules);
                steal_ptr(jrules);
        }

        if (ret) {
                char *s;

                s = strdup(json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
                if (!s)
                        return log_oom();

                *ret = steal_ptr(s);
        } else
                printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

        return r;
}

int json_fill_dns_server(const IfNameIndex *p, char **dns_config, int ifindex, json_object *jn) {
        _cleanup_(dns_servers_freep) DNSServers *fallback = NULL, *dns = NULL;
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _auto_cleanup_strv_ char **dhcp_dns = NULL;
        _auto_cleanup_ DNSServer *current = NULL;
        _auto_cleanup_ char *provider = NULL;
        GSequenceIter *i;
        DNSServer *d;
        int r;

        assert(jn);

        jobj = json_object_new_object();
        if (!jobj)
                return log_oom();

        if(p) {
                r = network_parse_link_dhcp4_server_address(p->ifindex, &provider);
                if(r < 0)
                        return r;
        }

        (void) manager_get_all_link_dhcp_lease_dns(&dhcp_dns);

        r = dbus_acquire_dns_servers_from_resolved("DNS", &dns);
        if (r >= 0 && dns && !g_sequence_is_empty(dns->dns_servers)) {
                _cleanup_(json_object_putp) json_object *jdns = json_object_new_array();
                _auto_cleanup_ char *config_source = NULL, *config_provider = NULL;
                if (!jdns)
                        return log_oom();

                for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _cleanup_(json_object_putp) json_object *jaddr = json_object_new_object();
                        _auto_cleanup_ char *pretty = NULL;

                        if (!jaddr)
                                return log_oom();

                        d = g_sequence_get(i);
                        if (!d->ifindex && d->ifindex != ifindex)
                                continue;

                        r = ip_to_str(d->address.family, &d->address, &pretty);
                        if (r >= 0) {
                                json_object *s = json_object_new_string(pretty);
                                if (!s)
                                        return log_oom();

                                json_object_object_add(jaddr, "Address", s);
                                steal_ptr(s);

                                r = json_parse_dns_config_source(jn, pretty, &config_source, &config_provider);
                                if (r < 0)
                                        continue;

                                if (config_source) {
                                        json_object *js = json_object_new_string(config_source);
                                        if (!js)
                                                return log_oom();

                                        json_object_object_add(jaddr, "ConfigSource", js);
                                        steal_ptr(js);
                                }

                                if(config_provider) {
                                        json_object *js = json_object_new_string(config_provider);
                                        if (!js)
                                                return log_oom();

                                        json_object_object_add(jaddr, "ConfigProvider", js);
                                        steal_ptr(js);
                                }

                                json_object_array_add(jdns, jaddr);
                                steal_ptr(jaddr);
                        }
                }

                json_object_object_add(jobj, "DNS", jdns);
                steal_ptr(jdns);
        }

        if (ifindex == 0) {
                r = dbus_get_current_dns_server_from_resolved(&current);
                if (r >= 0 && current) {
                        _auto_cleanup_ char *pretty = NULL;

                        r = ip_to_str(current->address.family, &current->address, &pretty);
                        if (r >= 0) {
                                json_object *s = json_object_new_string(pretty);
                                if (!s)
                                        return log_oom();

                                json_object_object_add(jobj, "CurrentDNSServer", s);
                                steal_ptr(s);
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
                        steal_ptr(ja);
                }
        }

        printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
        return 0;
}

int json_fill_dns_server_domains(void) {
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

                json_object_object_add(jobj, "SearchDomains", ja);
                steal_ptr(ja);

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
                                steal_ptr(a);

                        }
                        json_object_object_add(jobj, p->ifname, j);
                        steal_ptr(j);
                }
        }

        printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
        return 0;
}

int json_get_dns_mode(DHCPClient mode, bool dhcpv4, bool dhcpv6, bool static_dns) {
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _cleanup_(json_object_putp) json_object *s = NULL;

        jobj = json_object_new_object();
        if (!jobj)
                return log_oom();

        if ((dhcpv4 || dhcpv6) && static_dns)
                s = json_object_new_string("merged");
        else {
                if (static_dns)
                        s = json_object_new_string("static");
                else if ((dhcpv4 || dhcpv6) && (mode == DHCP_CLIENT_YES || mode == DHCP_CLIENT_IPV4 || mode == DHCP_CLIENT_IPV6))
                        s = json_object_new_string("DHCP");
                else
                        s = json_object_new_string("foreign");
        }

        json_object_object_add(jobj, "DNSMode", s);
        steal_ptr(s);

        printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
        return 0;
}

static int json_array_to_ip(const json_object *obj, const int family, const char *prefix, char **ret) {
        _auto_cleanup_ char *ip = NULL;

        assert(obj);

        for (size_t i = 0; i < json_object_array_length(obj); i++) {
                json_object *a = json_object_array_get_idx(obj, i);

                if (!ip)
                        ip = strdup(json_object_get_string(a));
                else {
                        if (family == AF_INET)
                                ip = strjoin(".", ip, json_object_get_string(a), NULL);
                        else
                                ip = strjoin(":", ip, json_object_get_string(a), NULL);
                }
                if (!ip)
                        return -ENOMEM;
        }

        if (family == AF_INET6) {
                _auto_cleanup_ IPAddress *addr = NULL;
                int r;

                r = parse_ipv6(ip, &addr);
                if (r < 0)
                        return r;

                r = ip_to_str(AF_INET6, addr, &ip);
                if (r < 0)
                        return r;
        }

        ip = strjoin("/", ip, prefix, NULL);
        if (!ip)
                return -ENOMEM;

        *ret = steal_ptr(ip);
        return 0;
}

int json_parse_search_domain_config_source(const json_object *jobj,
                                           const char *domain_name,
                                           char **ret_config_source,
                                           char **ret_config_provider) {
        json_object *interfaces = NULL;

        assert(jobj);
        assert(domain_name);

        if (!json_object_object_get_ex(jobj, "Interfaces", &interfaces))
                return -ENOENT;

        for (size_t i = 0; i < json_object_array_length(interfaces); i++){
                json_object *interface = json_object_array_get_idx(interfaces, i);
                json_object *domain;

                if (!json_object_object_get_ex(interface, "SearchDomains", &domain))
                        continue;

                for (size_t j = 0; j < json_object_array_length(domain); j++){
                        json_object *config_source = NULL, *config_provider = NULL, *a = NULL;
                        json_object *addr = json_object_array_get_idx(domain, j);

                        if (json_object_object_get_ex(addr, "Domain", &a)) {
                                if (str_eq(domain_name, json_object_get_string(a))) {
                                        if (json_object_object_get_ex(addr, "ConfigSource", &config_source)) {
                                                *ret_config_source = strdup(json_object_get_string(config_source));
                                                if (!*ret_config_source)
                                                        return -ENOMEM;
                                        }

                                        if (json_object_object_get_ex(addr, "ConfigProvider", &config_provider)) {
                                                *ret_config_provider = strdup(json_object_get_string(config_provider));
                                                if (!*ret_config_provider)
                                                        return -ENOMEM;
                                        }

                                        return 0;
                                }
                        }
                }
        }

        return -ENOENT;
}


int json_parse_dns_config_source(const json_object *jobj,
                                 const char *address,
                                 char **ret_config_source,
                                 char **ret_config_provider) {
        json_object *interfaces = NULL;
        int r;

        assert(jobj);
        assert(link);
        assert(address);

        if (!json_object_object_get_ex(jobj, "Interfaces", &interfaces))
                return -ENOENT;

        for (size_t i = 0; i < json_object_array_length(interfaces); i++){
                json_object *interface = json_object_array_get_idx(interfaces, i);
                json_object *dns;

                if (!json_object_object_get_ex(interface, "DNS", &dns))
                        continue;

                for (size_t j = 0; j < json_object_array_length(dns); j++){
                        json_object *config_source = NULL, *config_provider = NULL, *a = NULL, *family = NULL;
                        json_object *addr = json_object_array_get_idx(dns, j);

                        if (json_object_object_get_ex(addr, "Address", &a) && json_object_object_get_ex(addr, "Family", &family)) {
                                _auto_cleanup_ char *ip = NULL, *provider = NULL;

                                r = json_array_to_ip(a, json_object_get_int(family), NULL, &ip);
                                if (r < 0)
                                        return r;

                                if (str_eq(address, ip)) {
                                        if (json_object_object_get_ex(addr, "ConfigSource", &config_source)) {
                                                *ret_config_source = strdup(json_object_get_string(config_source));
                                                if (!*ret_config_source)
                                                        return -ENOMEM;
                                        }

                                        if (json_object_object_get_ex(addr, "ConfigProvider", &config_provider)) {
                                                r = json_array_to_ip(config_provider, json_object_get_int(family), NULL, &provider);
                                                if (r < 0)
                                                        return r;

                                                *ret_config_provider = strdup(provider);
                                                if (!*ret_config_provider)
                                                        return -ENOMEM;
                                        }

                                        return 0;
                                }
                        }
                }
        }

        return -ENOENT;
}

int json_parse_address_config_source(const json_object *jobj,
                                     const char *link,
                                     const char *address,
                                     char **ret_config_source,
                                     char **ret_config_provider) {
        json_object *interfaces = NULL;
        int r;

        assert(jobj);
        assert(link);
        assert(address);

        if (!json_object_object_get_ex(jobj, "Interfaces", &interfaces))
                return -ENOENT;

        for (size_t i = 0; i < json_object_array_length(interfaces); i++){
                json_object *interface = json_object_array_get_idx(interfaces, i);
                json_object *name;

                if (json_object_object_get_ex(interface, "Name", &name) && str_eq(json_object_get_string(name), link)) {
                        json_object *addresses = NULL;

                        if (!json_object_object_get_ex(interface, "Addresses", &addresses))
                                continue;

                        for (size_t j = 0; j < json_object_array_length(addresses); j++){
                                json_object *config_source = NULL, *config_provider = NULL, *a = NULL, *prefix = NULL, *family = NULL;
                                json_object *addr = json_object_array_get_idx(addresses, j);

                                if (json_object_object_get_ex(addr, "Address", &a) && json_object_object_get_ex(addr, "PrefixLength", &prefix) &&
                                    json_object_object_get_ex(addr, "Family", &family)) {
                                        _auto_cleanup_ char *ip = NULL, *provider = NULL;

                                        r = json_array_to_ip(a, json_object_get_int(family), json_object_get_string(prefix), &ip);
                                        if (r < 0)
                                                return r;

                                        if (str_eq(address, ip)) {
                                                if (json_object_object_get_ex(addr, "ConfigSource", &config_source)) {
                                                        *ret_config_source = strdup(json_object_get_string(config_source));
                                                        if (!*ret_config_source)
                                                                return -ENOMEM;
                                                }

                                                if (json_object_object_get_ex(addr, "ConfigProvider", &config_provider)) {
                                                        r = json_array_to_ip(config_provider, json_object_get_int(family), NULL, &provider);
                                                        if (r < 0)
                                                                return r;

                                                        *ret_config_provider = strdup(provider);
                                                        if (!*ret_config_provider)
                                                                return -ENOMEM;
                                                }

                                                return 0;
                                        }
                                }
                        }
                }
        }

        return -ENOENT;
}

int json_acquire_and_parse_network_data(json_object **ret) {
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _auto_cleanup_ char *s = NULL;
        int r;

        r = dbus_describe_network(&s);
        if (r < 0)
                return r;

        jobj = json_tokener_parse(s);

        *ret = steal_ptr(jobj);
        return 0;
}
