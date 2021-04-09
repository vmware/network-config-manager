/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "dbus.h"
#include "dns.h"
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

        if (a->family != b->family)
                return a->family - b->family;

        if (a->ifindex != b->ifindex)
                return a->ifindex - b->ifindex;

        switch(a->family) {
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
        GSequenceIter *i;
        char **j;
        int r;

        r = dns_read_resolv_conf(&dns_config, &domain_config);
        if (r < 0)
                return r;

        if (dns) {
                for (i = g_sequence_get_begin_iter(dns->dns_servers); !g_sequence_iter_is_end(i); i = g_sequence_iter_next(i)) {
                        _auto_cleanup_ char *pretty = NULL;
                        DNSServer *d =  g_sequence_get(i);

                        r = ip_to_string(d->family, &d->address, &pretty);
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
