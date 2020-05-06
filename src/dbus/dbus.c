/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2019 VMware, Inc.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>

#include "alloc-util.h"
#include "dbus.h"
#include "network-util.h"
#include "log.h"
#include "string-util.h"

int dbus_get_string_systemd_manager(const char *p, char **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        char *v;
        int r;

        assert(p);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_get_property(bus,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                p,
                                &bus_error,
                                &m,
                                "s");
        if (r < 0) {
                log_warning("Failed to issue method call: %s", bus_error.message);
                return r;
        }

        r = sd_bus_message_read(m, "s", &v);
        if (r < 0)
                return r;

        v = g_strdup(v);
        if (!v)
                return log_oom();
        else
                *ret = v;

        return 0;
}

int dbus_set_hostname(const char *hostname) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        int r;

        assert(hostname);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.hostname1",
                               "/org/freedesktop/hostname1",
                               "org.freedesktop.hostname1",
                               "SetStaticHostname",
                               &bus_error,
                               &reply,
                               "sb",
                               hostname);
        if (r < 0) {
                log_warning("Failed to issue method call: %s\n", bus_error.message);
                return r;
        }

        return 0;
}

int dbus_get_property_from_hostnamed(const char *p, char **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        _auto_cleanup_ char *t = NULL;
        char *s;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_get_property(bus,
                                "org.freedesktop.hostname1",
                                "/org/freedesktop/hostname1",
                                "org.freedesktop.hostname1",
                                p,
                                &bus_error,
                                &reply,
                                "s");
        if (r < 0) {
                log_warning("Failed to issue method call: %s\n", bus_error.message);
                return r;
        }

        r = sd_bus_message_read(reply, "s", &s);
        if (r < 0)
                return r;

        t = g_strdup(s);
        if (!t)
                return log_oom();
        else
                *ret = steal_pointer(t);

        return 0;
}

int dbus_stop_unit(const char *unit) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        int r;

        assert(unit);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "StopUnit",
                               &bus_error,
                               &reply,
                               "ss",
                               unit,
                               "fail");
        if (r < 0)
                log_warning("Failed to issue method call: %s\n", bus_error.message);

        return 0;
}

int dbus_restart_unit(const char *unit) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "RestartUnit",
                               &bus_error,
                               &reply,
                               "ss",
                               unit,
                               "replace");
        if (r < 0)
                log_warning("Failed to issue method call: %s\n", bus_error.message);

        return 0;
}

int dbus_get_dns_servers_from_resolved(const char *dns, DNSServers **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        const char *type = "a(iiay)";
        int ifindex, family, r;
        DNSServers *serv = NULL;
        DNSServer *i = NULL;
        const void *a;
        size_t sz;

        assert(dns);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        if (string_equal(dns, "CurrentDNSServer"))
                type = "(iiay)";

        r = sd_bus_get_property(bus,
                                "org.freedesktop.resolve1",
                                "/org/freedesktop/resolve1",
                                "org.freedesktop.resolve1.Manager",
                                dns,
                                &bus_error,
                                &reply,
                                type);
        if (r < 0) {
                log_warning("Failed to get D-Bus property '%s': %s", dns, bus_error.message);
                return r;
        }

        r = dns_servers_new(&serv);
        if (r < 0)
                return r;

        if (!string_equal(dns, "CurrentDNSServer")) {
                r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
                if (r < 0) {
                        log_warning("Failed to enter variant container of '%s': %s", dns, g_strerror(-r));
                        return r;
                }
        }

        for (;;) {
                r = sd_bus_message_enter_container(reply, 'r', "iiay");
                if (r < 0) {
                        if (r == -ENXIO)
                                break;

                        log_warning("Failed to create bus message: %s", g_strerror(-r));
                        return r;
                }

                r = sd_bus_message_read(reply, "i", &ifindex);
                if (r < 0) {
                        log_warning("Failed to read integer bus message: %s", g_strerror(-r));
                        return r;
                }

                r = sd_bus_message_read(reply, "i", &family);
                if (r < 0) {
                        log_warning("Failed to read integrr bus message: %s", g_strerror(-r));
                        return r;
                }

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0) {
                        log_warning("Failed to read array bus message: %s", g_strerror(-r));
                        return r;
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0) {
                        log_warning("Failed to exit container bus message: %s", g_strerror(-r));
                        return r;
                }

                r = dns_server_new(&i);
                if (r < 0)
                        return r;

                memcpy(&i->address, a, sz);
                i->family = family;
                i->ifindex = ifindex;

                r = dns_server_add(&serv, i);
                if (r < 0)
                        return r;

                i = NULL;
        }

        *ret = steal_pointer(serv);

        return 0;
}

int dbus_add_dns_server(int ifindex, DNSServers *dns) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        GSequenceIter *i;
        int r;

        assert(dns);
        assert(ifindex > 0);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(bus,
                                           &m,
                                           "org.freedesktop.resolve1",
                                           "/org/freedesktop/resolve1",
                                           "org.freedesktop.resolve1.Manager",
                                           "SetLinkDNS");
        if (r < 0) {
                log_warning("Failed create bus message: %s", g_strerror(-r));
                return r;
        }

        r = sd_bus_message_append(m, "i", ifindex);
        if (r < 0) {
                log_warning("Failed to create bus message: %s", g_strerror(-r));
                return r;
        }

        r = sd_bus_message_open_container(m, 'a', "(iay)");
        if (r < 0) {
                log_warning("Failed to create bus message: %s", g_strerror(-r));
                return r;
        }

        for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                DNSServer *d = g_sequence_get(i);

                r = sd_bus_message_open_container(m, 'r', "iay");
                if (r < 0) {
                        log_warning("Failed to create bus message: %s", g_strerror(-r));
                        return r;
                }

                r = sd_bus_message_append(m, "i", d->family);
                if (r < 0) {
                        log_warning("Failed to create bus message: %s", g_strerror(-r));
                        return r;
                }

                if (d->family == AF_INET)
                        r = sd_bus_message_append_array(m, 'y', &d->address.in, sizeof(d->address.in));
                else
                        r = sd_bus_message_append_array(m, 'y', &d->address.in6, sizeof(d->address.in6));

                if (r < 0) {
                        log_warning("Failed to create bus message: %s", g_strerror(-r));
                        return r;
                }

                r = sd_bus_message_close_container(m);
                if (r < 0) {
                        log_warning("Failed to create bus message: %s", g_strerror(-r));
                        return r;
                }
        }

        r = sd_bus_message_close_container(m);
        if (r < 0) {
                log_warning("Failed to close container: %s", g_strerror(-r));
                return r;
        }

        r = sd_bus_call(bus, m, 0, &bus_error, NULL);
        if (r < 0) {
                log_warning("Failed to add DNS server: %s", bus_error.message);
                return r;
        }

        return 0;
}

int dbus_add_dns_domains(int ifindex, char **domains) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        char **d;
        int r;

        assert(domains);
        assert(ifindex > 0);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(bus,
                                           &m,
                                           "org.freedesktop.resolve1",
                                           "/org/freedesktop/resolve1",
                                           "org.freedesktop.resolve1.Manager",
                                           "SetLinkDomains");
        if (r < 0) {
                log_warning("Failed create bus message: %s", g_strerror(-r));
                return r;
        }

        r = sd_bus_message_append(m, "i", ifindex);
        if (r < 0) {
                log_warning("Failed to create bus message: %s", g_strerror(-r));
                return r;
        }

        r = sd_bus_message_open_container(m, 'a', "(sb)");
        if (r < 0) {
                log_warning("Failed to create bus message: %s", g_strerror(-r));
                return r;
        }

        strv_foreach(d, domains) {
                r = sd_bus_message_append(m, "(sb)", *d);
                if (r < 0) {
                        log_warning("Failed to create bus message: %s", g_strerror(-r));
                        return r;
                }
        }

        r = sd_bus_message_close_container(m);
        if (r < 0) {
                log_warning("Failed to create bus mess: %s", g_strerror(-r));
                return r;
        }

        r = sd_bus_call(bus, m, 0, &bus_error, NULL);
        if (r < 0) {
                log_warning("Failed to add DNS server: %s", bus_error.message);
                return r;
        }

        return 0;
}

int dbus_get_dns_domains_from_resolved(DNSDomains **domains) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        int r, route_only, ifindex = 0;
        DNSDomains *serv = NULL;
        DNSDomain *i = NULL;

        assert(domains);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_get_property(bus,
                                "org.freedesktop.resolve1",
                                "/org/freedesktop/resolve1",
                                "org.freedesktop.resolve1.Manager",
                                "Domains",
                                &bus_error,
                                &m,
                                "a(isb)");
        if (r < 0) {
                log_warning("Failed to get D-Bus property 'Domains': %s", bus_error.message);
                return r;
        }

        r = sd_bus_message_enter_container(m, 'a', "(isb)");
        if (r < 0)
                return r;

        for (;;) {
                char *domain = NULL;

                r = sd_bus_message_enter_container(m, 'r', "isb");
                if (r < 0) {
                        if (r == -ENXIO)
                                break;

                        log_warning("Failed to enter bus message container: %s", g_strerror(-r));
                        return r;
                }
                r = sd_bus_message_read(m, "i", &ifindex);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(m, "sb", &domain, &route_only);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (isempty_string(domain))
                        continue;

                r = sd_bus_message_exit_container(m);
                if (r < 0) {
                        log_warning("Failed to exit container bus message: %s", g_strerror(-r));
                        return r;
                }

                r = dns_domain_new(&i);
                if (r < 0)
                        return r;

                *i = (DNSDomain) {
                         .domain = g_strdup(domain),
                         .ifindex = ifindex,
                };

                if (!i->domain)
                        return log_oom();

                r = dns_domain_add(&serv, i);
                if (r < 0)
                        return r;

                i = NULL;

        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        *domains = steal_pointer(serv);

        return 0;
}

int dbus_revert_resolve_link(int ifindex) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        int r;

        assert(ifindex > 0);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.resolve1",
                               "/org/freedesktop/resolve1",
                               "org.freedesktop.resolve1.Manager",
                               "RevertLink",
                               &bus_error,
                               NULL,
                               "i",
                               ifindex);
        if (r < 0) {
                log_warning("Failed to flush resolve: %s", bus_error.message);
                return r;
        }

        return 0;
}

int dbus_network_reload(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                log_warning("Failed to connect system bus: %s", bus_error.message);
                return r;
        }

        r = sd_bus_call_method(bus,
                               "org.freedesktop.network1",
                               "/org/freedesktop/network1",
                               "org.freedesktop.network1.Manager",
                               "Reload",
                               &bus_error,
                               NULL,
                               NULL);
        if (r < 0) {
                log_warning("Failed to reload network settings: %s", bus_error.message);
                return r;
        }

        return 0;
}

int dbus_reconfigure_link(int ifindex) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        int r;

        assert(ifindex > 0);

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                log_warning("Failed to connect system bus: %s", bus_error.message);
                return r;
        }

        r = sd_bus_call_method(bus,
                               "org.freedesktop.network1",
                               "/org/freedesktop/network1",
                               "org.freedesktop.network1.Manager",
                               "ReconfigureLink",
                               &bus_error,
                               NULL,
                               "i",
                               ifindex);
        if (r < 0) {
                log_warning("Failed to configure link: %s", bus_error.message);
                return r;
        }

        return 0;
}
