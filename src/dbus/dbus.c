/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "alloc-util.h"
#include "dbus.h"
#include "log.h"
#include "string-util.h"

void sd_bus_free(sd_bus *bus) {
        if (!bus)
                return;

        sd_bus_close(bus);
        bus = sd_bus_unref(bus);
}

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
                *ret = steal_ptr(t);

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
        if (r < 0){
                log_warning("Failed to issue method call: %s\n", bus_error.message);
                return r;
        }

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
                return r;

        return 0;
}

int dbus_get_current_dns_servers_from_resolved(DNSServers **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        _auto_cleanup_ DNSServer *i = NULL;
        int r, ifindex = 0, family = 0;
        DNSServers *serv = NULL;
        const void *a;
        size_t sz;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_get_property(bus,
                                "org.freedesktop.resolve1",
                                "/org/freedesktop/resolve1",
                                "org.freedesktop.resolve1.Manager",
                                "CurrentDNSServer",
                                &bus_error,
                                &reply,
                                "(iiay)");
        if (r < 0) {
                log_warning("Failed to get D-Bus property 'CurrentDNSServer': %s", bus_error.message);
                return r;
        }

        r = dns_servers_new(&serv);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(reply, 'r', "iiay");
        if (r < 0) {
                log_warning("Failed to enter bus message container: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_read(reply, "i", &ifindex);
        if (r < 0) {
                log_warning("Failed to read integer bus message: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_read(reply, "i", &family);
        if (r < 0) {
                log_warning("Failed to read integer bus message: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_read_array(reply, 'y', &a, &sz);
        if (r < 0) {
                log_warning("Failed to read array bus message: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0) {
                log_warning("Failed to exit container bus message: %s", strerror(-r));
                return r;
        }

        r = dns_server_new(&i);
        if (r < 0)
                return r;

        i->address.family = family;
        i->ifindex = ifindex;

        switch (i->address.family) {
                case AF_INET:
                        memcpy(&i->address.in, a, sz);
                        break;
                case AF_INET6:
                        memcpy(&i->address.in6, a, sz);
                        break;
                default:
                      return -ENODATA;
        }

        r = dns_server_add(&serv, i);
        if (r < 0)
                return r;

        steal_ptr(i);

        *ret = steal_ptr(serv);
        return 0;
}

int dbus_acquire_dns_servers_from_resolved(const char *dns, DNSServers **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        DNSServers *serv = NULL;
        int r;

        assert(dns);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_get_property(bus,
                                "org.freedesktop.resolve1",
                                "/org/freedesktop/resolve1",
                                "org.freedesktop.resolve1.Manager",
                                dns,
                                &bus_error,
                                &reply,
                                "a(iiay)");
        if (r < 0) {
                log_warning("Failed to get D-Bus property '%s': %s", dns, bus_error.message);
                return r;
        }

        r = dns_servers_new(&serv);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
        if (r < 0) {
                log_warning("Failed to enter variant container of '%s': %s", dns, strerror(-r));
                return r;
        }

        for (;;) {
               _auto_cleanup_ DNSServer *i = NULL;
               int ifindex, family;
               const void *a;
               size_t sz;

                r = sd_bus_message_enter_container(reply, 'r', "iiay");
                if (r < 0) {
                        if (r == -ENXIO)
                                break;

                        log_warning("Failed to enter bus message container: %s", strerror(-r));
                        return r;
                }


                r = sd_bus_message_read(reply, "i", &ifindex);
                if (r < 0) {
                        log_warning("Failed to read integer bus message: %s", strerror(-r));
                        return r;
                }

                r = sd_bus_message_read(reply, "i", &family);
                if (r < 0) {
                        log_warning("Failed to read integrr bus message: %s", strerror(-r));
                        return r;
                }

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0) {
                        log_warning("Failed to read array bus message: %s", strerror(-r));
                        return r;
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0) {
                        log_warning("Failed to exit container bus message: %s", strerror(-r));
                        return r;
                }

                r = dns_server_new(&i);
                if (r < 0)
                        return r;

                i->address.family = family;
                i->ifindex = ifindex;

                if (sz == 0)
                        continue;

                switch (family) {
                        case AF_INET:
                                memcpy(&i->address.in, a, sz);
                                break;
                        case  AF_INET6:
                                memcpy(&i->address.in6, a, sz);
                                break;
                        default:
                                continue;
                }

                r = dns_server_add(&serv, i);
                if (r < 0)
                        return r;

                steal_ptr(i);
        }

        *ret = steal_ptr(serv);
        return 0;
}

int dbus_add_dns_server(int ifindex, DNSServers *dns) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
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
                log_warning("Failed create bus message: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_append(m, "i", ifindex);
        if (r < 0) {
                log_warning("Failed to create bus message: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_open_container(m, 'a', "(iay)");
        if (r < 0) {
                log_warning("Failed to create bus message: %s", strerror(-r));
                return r;
        }

        for (GSequenceIter *i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                DNSServer *d = g_sequence_get(i);

                r = sd_bus_message_open_container(m, 'r', "iay");
                if (r < 0) {
                        log_warning("Failed to create bus message: %s", strerror(-r));
                        return r;
                }

                r = sd_bus_message_append(m, "i", d->address.family);
                if (r < 0) {
                        log_warning("Failed to create bus message: %s", strerror(-r));
                        return r;
                }

                if (d->address.family == AF_INET)
                        r = sd_bus_message_append_array(m, 'y', &d->address.in, sizeof(d->address.in));
                else
                        r = sd_bus_message_append_array(m, 'y', &d->address.in6, sizeof(d->address.in6));

                if (r < 0) {
                        log_warning("Failed to create bus message: %s", strerror(-r));
                        return r;
                }

                r = sd_bus_message_close_container(m);
                if (r < 0) {
                        log_warning("Failed to create bus message: %s", strerror(-r));
                        return r;
                }
        }

        r = sd_bus_message_close_container(m);
        if (r < 0) {
                log_warning("Failed to close container: %s", strerror(-r));
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
                log_warning("Failed create bus message: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_append(m, "i", ifindex);
        if (r < 0) {
                log_warning("Failed to create bus message: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_open_container(m, 'a', "(sb)");
        if (r < 0) {
                log_warning("Failed to create bus message: %s", strerror(-r));
                return r;
        }

        strv_foreach(d, domains) {
                r = sd_bus_message_append(m, "(sb)", *d);
                if (r < 0) {
                        log_warning("Failed to create bus message: %s", strerror(-r));
                        return r;
                }
        }

        r = sd_bus_message_close_container(m);
        if (r < 0) {
                log_warning("Failed to create bus mess: %s", strerror(-r));
                return r;
        }

        r = sd_bus_call(bus, m, 0, &bus_error, NULL);
        if (r < 0) {
                log_warning("Failed to add DNS server: %s", bus_error.message);
                return r;
        }

        return 0;
}

int dbus_acquire_dns_domains_from_resolved(DNSDomains **domains) {
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

                        log_warning("Failed to enter bus message container: %s", strerror(-r));
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

                if (isempty_str(domain))
                        continue;

                r = sd_bus_message_exit_container(m);
                if (r < 0) {
                        log_warning("Failed to exit container bus message: %s", strerror(-r));
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

        *domains = steal_ptr(serv);
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

int dbus_acqure_dns_setting_from_resolved(const char *setting, char **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        const void *a;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_get_property(bus,
                                "org.freedesktop.resolve1",
                                "/org/freedesktop/resolve1",
                                "org.freedesktop.resolve1.Manager",
                                setting,
                                &bus_error,
                                &reply,
                                "s");
        if (r < 0) {
                log_warning("Failed to get D-Bus property 'CurrentDNSServer': %s", bus_error.message);
                return r;
        }

        r = sd_bus_message_read(reply, "s", &a);
        if (r < 0) {
                log_warning("Failed to read %s: %s", setting, strerror(-r));
                return r;
        }

        *ret = strdup(a);
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
                log_warning("Failed to configure device: %s", bus_error.message);
                return r;
        }

        return 0;
}

int dbus_get_system_property_from_networkd(const char *p, char **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error bus_error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_freep) sd_bus *bus = NULL;
        char *v;
        int r;

        assert(p);

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                log_warning("Failed to connect system bus: %s", bus_error.message);
                return r;
        }


        r = sd_bus_get_property(bus,
                                "org.freedesktop.network1",
                                "/org/freedesktop/network1",
                                "org.freedesktop.network1.Manager",
                                p,
                                &bus_error,
                                &m,
                                "s");
        if (r < 0)
                return r;

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
