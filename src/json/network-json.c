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
        _cleanup_(json_object_putp) json_object *jobj = NULL;
        _auto_cleanup_ char *state = NULL, *carrier_state = NULL, *hostname = NULL, *kernel = NULL,
                *kernel_release = NULL, *arch = NULL, *virt = NULL, *os = NULL, *systemd = NULL,
                *online_state = NULL, *address_state = NULL, *ipv4_address_state = NULL, *ipv6_address_state = NULL;
        _auto_cleanup_ char *mdns = NULL, *llmnr = NULL, *dns_over_tls = NULL, *conf_mode = NULL;
        _cleanup_(routing_policy_rules_freep) RoutingPolicyRules *rules = NULL;
        _cleanup_(dns_servers_freep) DNSServers *c = NULL;
        _cleanup_(links_freep) Links *links = NULL;
        _auto_cleanup_strv_ char **ntp = NULL;
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

                json_object_object_add(jobj, "SystemName", js);
                steal_ptr(js);
        }

        (void) dbus_get_property_from_hostnamed("KernelName", &kernel);
        if (kernel) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(kernel);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj,"KernelName", js);
                steal_ptr(js);
        }

        (void) dbus_get_property_from_hostnamed("KernelRelease", &kernel_release);
        if (kernel_release) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(kernel_release);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj,"KernelRelease", js);
                steal_ptr(js);
        }

        (void) dbus_get_string_systemd_manager("Version", &systemd);
        if (systemd) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(systemd);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "SystemdVersion", js);
                steal_ptr(js);
        }

        (void) dbus_get_string_systemd_manager("Architecture", &arch);
        if (arch) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(arch);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Architecture", js);
                steal_ptr(js);
        }

        (void) dbus_get_string_systemd_manager("Virtualization", &virt);
        if (virt) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(virt);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "Virtualization", js);
                steal_ptr(js);
        }

        (void) dbus_get_property_from_hostnamed("OperatingSystemPrettyName", &os);
        if (os) {
                _cleanup_(json_object_putp) json_object *js = NULL;

                js = json_object_new_string(os);
                if (!js)
                        return log_oom();

                json_object_object_add(jobj, "OperatingSystem", js);
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
                                r = json_fill_one_link(p, false, &js);
                                if (r >= 0) {
                                       json_object_array_add(ja, js);
                                       steal_ptr(js);
                                }
                        }
                }

                json_object_object_add(jobj, "Interfaces", ja);
                steal_ptr(ja);
        }

        r = dbus_get_current_dns_servers_from_resolved(&c);
        if (r >= 0 && c && !g_sequence_is_empty(c->dns_servers)) {
                _auto_cleanup_ char *pretty = NULL;
                GSequenceIter *itr;
                DNSServer *d;

                itr = g_sequence_get_begin_iter(c->dns_servers);
                d = g_sequence_get(itr);
                r =ip_to_str(d->address.family, &d->address, &pretty);
                if (r >= 0) {
                        _cleanup_(json_object_putp) json_object *jd = NULL;

                        jd = json_object_new_string(pretty);
                        if (!jd)
                                return log_oom();

                        json_object_object_add(jobj, "CurrentDNSServer",jd);
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

int json_fill_dns_server(const IfNameIndex *p, char *dns_config) {
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
                                steal_ptr(s);

                                if (dns_config && g_strrstr(dns_config, pretty))
                                        s = json_object_new_string("static");
                                else {
                                        s = json_object_new_string("dhcp");

                                        if(provider) {
                                                json_object *js = json_object_new_string(provider);
                                                if (!js)
                                                        return log_oom();

                                                json_object_object_add(jaddr, "ConfigProvider", js);
                                                steal_ptr(js);
                                        }
                                }

                                if (!s)
                                        return log_oom();

                                json_object_object_add(jaddr, "ConfigSource", s);
                                steal_ptr(s);

                                json_object_array_add(jdns, jaddr);
                                steal_ptr(jaddr);
                        }

                }

                json_object_object_add(jobj, "DNS", jdns);
                steal_ptr(jdns);

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
