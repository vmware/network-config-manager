/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2019 VMware, Inc.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <glib.h>
#include <net/if.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "alloc-util.h"
#include "log.h"
#include "macros.h"
#include "network-util.h"
#include "parse-util.h"
#include "string-util.h"

bool ip4_addr_is_null(const IPAddress *a) {
        assert(a);

        return a->in.s_addr == 0;
}

int ip_is_null(const IPAddress *a) {
        assert(a);

        if (a->family == AF_INET)
                return ip4_addr_is_null(a);

        if (a->family == AF_INET6)
                return IN6_IS_ADDR_UNSPECIFIED(&a->in6);

        return -EAFNOSUPPORT;
}

int ip_to_string(int family, const struct IPAddress *u, char **ret) {
        _cleanup_free_ char *x = NULL;
        const char *p = NULL;
        size_t l = 0;

        assert(u);
        assert(ret);

        if (family == AF_INET)
                l = INET_ADDRSTRLEN;
        else if (family == AF_INET6)
                l = INET6_ADDRSTRLEN;
        else
                return -EAFNOSUPPORT;

        x = new0(char, l);
        if (!x)
                return -ENOMEM;

        errno = 0;
        if (family == AF_INET)
                p = inet_ntop(family, &u->in, x, l);
        else
                p = inet_ntop(family, &u->in6, x, l);

        if (!p) {
                if (errno > 0)
                        return -errno;
                else
                        return -EINVAL;
        }

        *ret = steal_pointer(x);

        return 0;
}

int ip_to_string_prefix(int family, const struct IPAddress *u, char **ret) {
        _cleanup_free_ char *x = NULL, *y = NULL;
        char buf[1024] = {};
        int r;

        assert(u);
        assert(ret);

        r = ip_to_string(family, u, &x);
        if (r < 0)
                return r;

        if (u->prefix_len > 0) {
                sprintf(buf, "%d", u->prefix_len);
                y = string_join("/", x, buf, NULL);
                if (!y)
                        return -ENOMEM;
        } else {
                y = x;
                x = NULL;
        }

        *ret = steal_pointer(y);

        return 0;
}

int parse_ipv4(const char *s, IPAddress **ret) {
        _cleanup_free_ struct IPAddress *b = NULL;
        struct in_addr buffer;

        assert(s);

        b = new0(IPAddress, 1);
        if (!b)
                return -ENOMEM;

        errno = 0;
        if (inet_pton(AF_INET, s, &buffer) <= 0)
                return errno > 0 ? -errno : -EINVAL;

        memcpy(b, &buffer, sizeof(IPAddress));
        b->family = AF_INET;

        *ret = steal_pointer(b);

        return 0;
}

int parse_ipv6(const char *s, IPAddress **ret) {
        _cleanup_free_ struct IPAddress *b = NULL;
        struct in_addr buffer;

        assert(s);

        b = new0(IPAddress, 1);
        if (!b)
                return -ENOMEM;

        errno = 0;
        if (inet_pton(AF_INET6, s, &buffer) <= 0)
                return errno > 0 ? -errno : -EINVAL;

        memcpy(b, &buffer, sizeof(IPAddress));
        b->family = AF_INET6;

        *ret = steal_pointer(b);

        return 0;
}

int parse_ip(const char *s, IPAddress **ret) {
        int r;

        assert(s);

        r = parse_ipv4(s, ret);
        if (r >= 0)
                return 0;

        r = parse_ipv6(s, ret);
        if (r < 0)
                return r;

        return 0;
}

int parse_ip_from_string(const char *s, IPAddress **ret) {
        _cleanup_free_ char *m = NULL;
        char *p, *k;
        long l;
        int r;

        assert(s);
        assert(ret);

        m = g_strdup(s);
        if (!m)
                return log_oom();

        p = strchr(m, '/');
        if (p)
                *p++ = 0;

        r = parse_ip(m, ret);
        if (r < 0)
                return r;

        if (p) {
                l = strtol(p, &k, 0);
                if (p == k)
                        return -EINVAL;

                (*ret)->prefix_len = l;
        } else
                (*ret)->prefix_len = 0;

        return 0;
}


int ipv4_netmask_to_prefixlen(IPAddress *addr) {
        assert(addr);

        return 32U - __builtin_ctz(be32toh(addr->in.s_addr));
}

int parse_ifname_or_index(char *s, IfNameIndex **ret) {
        _cleanup_free_ IfNameIndex *p = NULL;
        int r, ifindex;

        assert(s);

        p = new0(IfNameIndex, 1);
        if (!p)
                return -ENOMEM;

        r = (int) if_nametoindex(s);
        if (r <= 0) {
                char *n;
                r = parse_integer(s, &ifindex);
                if (r < 0)
                        return r;

                n = if_indextoname(ifindex, p->ifname);
                if (!n)
                        return -errno;
        } else {
                p->ifindex = r;
                memcpy(p->ifname, s, IFNAMSIZ);
        }

        *ret = steal_pointer(p);

        return 0;
}

char *ether_addr_to_string(const struct ether_addr *addr, char *s) {
        assert(addr);
        assert(s);

        sprintf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
                addr->ether_addr_octet[0], addr->ether_addr_octet[1],
                addr->ether_addr_octet[2], addr->ether_addr_octet[3],
                addr->ether_addr_octet[4], addr->ether_addr_octet[5]);

        return s;
}

bool ether_addr_is_not_null(const struct ether_addr *addr) {
        assert(addr);

        if (addr->ether_addr_octet[0] != 0x00 &&
            addr->ether_addr_octet[1] != 0x00 &&
            addr->ether_addr_octet[2] != 0x00 &&
            addr->ether_addr_octet[3] != 0x00 &&
            addr->ether_addr_octet[4] != 0x00 &&
            addr->ether_addr_octet[5] != 0x00)
                return true;

        return false;
}

int parse_mtu(char *mtu, uint32_t *ret) {
        uint32_t j;
        int r;

        r = parse_uint32(mtu, &j);
        if (r < 0)
                return r;

        *ret = j;

        return 0;
}
