/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "dbus.h"
#include "dns.h"
#include "file-util.h"
#include "macros.h"
#include "string-util.h"

int dns_server_new(DNSServer **ret) {
        DNSServer *a;

        assert(ret);

        a = new0(DNSServer, 1);
        if (!a)
                return -ENOMEM;

        *ret = steal_pointer(a);
        return 0;
}

static void dns_server_data_destroy(gpointer data) {
        free(data);
}

void dns_servers_free(DNSServers *d) {
        if (!d)
                return;

        if (d->dns_servers)
                g_sequence_free(d->dns_servers);

        g_free(d);
}

int dns_servers_new(DNSServers **ret) {
        _auto_cleanup_ DNSServers *h = NULL;

        h = new0(DNSServers, 1);
        if (!h)
                return -ENOMEM;

        h->dns_servers = g_sequence_new(dns_server_data_destroy);
        if (!h->dns_servers)
                return -ENOMEM;

        *ret = steal_pointer(h);

        return 0;
}

static int dns_compare_func(gconstpointer x, gconstpointer y, gpointer user_data) {
        const DNSServer *a, *b;

        assert(x);
        assert(y);

        a = x;
        b = y;

        if (a->address.family != b->address.family)
                return a->address.family - b->address.family;

        if (a->ifindex != b->ifindex)
                return a->ifindex - b->ifindex;

        switch(a->address.family) {
        case AF_INET:
                return memcmp(&a->address.in, &b->address.in, sizeof(struct in_addr));
        case AF_INET6:
                return memcmp(&a->address.in6, &b->address.in6, sizeof(struct in6_addr));
        default:
                break;
        }

        return 0;
}

int dns_server_add(DNSServers **h, DNSServer *a) {
        GSequenceIter *iter = NULL;
        int r;

        assert(h);
        assert(a);

        if (!*h) {
                r = dns_servers_new(h);
                if (r < 0)
                        return r;
        }

        iter = g_sequence_lookup((*h)->dns_servers, a, dns_compare_func, NULL);
        if (!iter) {
                iter = g_sequence_insert_sorted((*h)->dns_servers, a, dns_compare_func, NULL);
                if (!iter)
                        return -EEXIST;
        }

        return 0;
}

int dns_domain_new(DNSDomain **ret) {
        DNSDomain *a = NULL;

        assert(ret);

        a = new0(DNSDomain, 1);
        if (!a)
                return -ENOMEM;

        *ret = steal_pointer(a);
        return 0;
}

void dns_domain_free(void *d) {
        DNSDomain *p = (DNSDomain *) d;

        if (!d)
                return;

        g_free(p->domain);
        g_free(p);
}

int dns_domains_new(DNSDomains **ret) {
        _auto_cleanup_ DNSDomains *h = NULL;

        h = new0(DNSDomains, 1);
        if (!h)
                return -ENOMEM;

        h->dns_domains = g_sequence_new(dns_domain_free);
        if (!h->dns_domains)
                return -ENOMEM;

        *ret = steal_pointer(h);
        return 0;
}

void dns_domains_free(DNSDomains *d) {
        if (!d)
                return;

        if (d->dns_domains)
                g_sequence_free(d->dns_domains);

        g_free(d);
}

static int dns_domain_compare_func(gconstpointer x, gconstpointer y, gpointer user_data) {
        const DNSDomain *a, *b;

        assert(x);
        assert(y);

        a = x;
        b = y;

        if (a->ifindex != b->ifindex)
                return a->ifindex - b->ifindex;

        return g_str_equal(a->domain, b->domain);
}

int dns_domain_add(DNSDomains **h, DNSDomain *a) {
        GSequenceIter *iter = NULL;
        int r;

        assert(h);
        assert(a);

        if (!*h) {
                r = dns_domains_new(h);
                if (r < 0)
                        return r;
        }

        iter = g_sequence_lookup((*h)->dns_domains, a, dns_compare_func, NULL);
        if (!iter) {
                iter = g_sequence_insert_sorted((*h)->dns_domains, a, dns_domain_compare_func, NULL);
                if (!iter)
                        return -EEXIST;
        }

        return 0;
}

int dns_read_resolv_conf(char ***dns, char ***domains) {
        return parse_resolv_conf(dns, domains);
}

int add_dns_server_and_domain_to_resolv_conf(DNSServers *dns, char **domains) {
        _auto_cleanup_strv_ char **dns_config = NULL, **domain_config = NULL;
        char **j;
        int r;

        r = dns_read_resolv_conf(&dns_config, &domain_config);
        if (r < 0)
                return r;

        if (dns) {
                for (GSequenceIter *i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;
                        DNSServer *d =  g_sequence_get(i);

                        r = ip_to_string(d->address.family, &d->address, &pretty);
                        if (r < 0)
                                continue;

                        if (!strv_contains((const char **) dns_config, pretty)) {
                                r = strv_add(&dns_config, pretty);
                                if (r < 0)
                                        return r;
                        }

                        steal_pointer(pretty);
                }
        }

        if (domains && domain_config) {
                strv_foreach(j, domains) {
                        _auto_cleanup_ char *s = NULL;

                        if (!strv_contains((const char **) domain_config, *j)) {

                                s = g_strdup(*j);
                                if (!s)
                                        return -ENOMEM;

                                r = strv_add(&domain_config, s);
                                if (r < 0)
                                        return r;

                                steal_pointer(s);
                        }
                }
        }

        if (!domain_config && domains)
                domain_config = domains;

        r = write_to_resolv_conf_file(dns_config, domain_config);
        if (r < 0)
                return r;

        return dbus_restart_unit("systemd-resolved.service");
}

/* write to /etc/systemd/resolved.conf */
int add_dns_server_and_domain_to_resolved_conf(DNSServers *dns, char **domains) {
        _cleanup_(key_file_freep) GKeyFile *key_file = NULL;
        _cleanup_(g_error_freep) GError *e = NULL;
        int r;

        r = load_config_file("/etc/systemd/resolved.conf", &key_file);
        if (r < 0)
                return r;

        if (dns) {
                _auto_cleanup_ char *dns_line = NULL, *l = NULL;
                _auto_cleanup_strv_ char **s = NULL;

                dns_line = g_key_file_get_string(key_file, "Resolve", "DNS", &e);
                if (e && e->code > 0) {
                        if (e->code == ESRCH) {
                                g_error_free(e);
                                e = NULL;
                        } else
                                return -e->code;
                }

                if (dns_line)
                        s = strsplit(dns_line, " ", -1);

                for (GSequenceIter *i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;
                        DNSServer *d =  g_sequence_get(i);

                        r = ip_to_string(d->address.family, &d->address, &pretty);
                        if (r < 0)
                                continue;

                        if (!s || strv_length(s) == 0) {
                                s = strv_new(pretty);
                                if (!s)
                                        return -ENOMEM;

                        } else if (!strv_contains((const char **) s, pretty)) {
                                r = strv_add(&s, pretty);
                                if (r < 0)
                                        return r;
                        }

                        steal_pointer(pretty);
                }

                g_key_file_set_string(key_file, "Resolve", "DNS", strv_join(" ", s));
        }

        if (domains) {
                _auto_cleanup_ char *domain_line = NULL, *l = NULL;
                _auto_cleanup_strv_ char **s = NULL;
                char **j;

                domain_line = g_key_file_get_string(key_file, "Resolve", "Domains", &e);
                if (e && e->code > 0) {
                        if (e->code == ESRCH) {
                                g_error_free(e);
                                e = NULL;
                        } else
                                return -e->code;
                }

                if (domain_line)
                        s = strsplit(domain_line, " ", -1);

                strv_foreach(j, domains) {
                        if (!s || strv_length(s) == 0) {
                                s = strv_new(*j);
                                if (!s)
                                        return -ENOMEM;
                        } else if (!strv_contains((const char **) s, *j)) {
                                r = strv_add(&s, *j);
                                if (r < 0)
                                        return r;
                        }
                }
                g_key_file_set_string(key_file, "Resolve", "Domains", strv_join(" ", s));
        }

        if (!g_key_file_save_to_file (key_file, "/etc/systemd/resolved.conf", &e))
                return -e->code;

        r = set_file_permisssion("/etc/systemd/resolved.conf", "systemd-resolve");
        if (r < 0)
                return r;

        return dbus_restart_unit("systemd-resolved.service");
}
