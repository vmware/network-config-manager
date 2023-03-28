/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
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

static const char * const address_family_table[_ADDRESS_FAMILY_MAX] = {
        [ADDRESS_FAMILY_NO]   = "no",
        [ADDRESS_FAMILY_YES]  = "yes",
        [ADDRESS_FAMILY_IPV4] = "ipv4",
        [ADDRESS_FAMILY_IPV6] = "ipv6",
};

const char *address_family_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(address_family_table))
                return NULL;

        return address_family_table[id];
}

int address_family_name_to_type(const char *name) {
        assert(name);

        for (size_t i = ADDRESS_FAMILY_NO; i < (size_t) ELEMENTSOF(address_family_table); i++)
                if (str_equal_fold(name, address_family_table[i]))
                        return i;

        return _ADDRESS_FAMILY_INVALID;
}

static const char* const device_activation_policy_table[_DEVICE_ACTIVATION_POLICY_MAX] = {
        [DEVICE_ACTIVATION_POLICY_UP] =          "up",
        [DEVICE_ACTIVATION_POLICY_ALWAYS_UP] =   "always-up",
        [DEVICE_ACTIVATION_POLICY_MANUAL] =      "manual",
        [DEVICE_ACTIVATION_POLICY_ALWAYS_DOWN] = "always-down",
        [DEVICE_ACTIVATION_POLICY_DOWN] =        "down",
        [DEVICE_ACTIVATION_POLICY_BOUND] =       "bound",
};

const char *device_activation_policy_type_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(device_activation_policy_table))
                return NULL;

        return address_family_table[id];
}

int device_activation_policy_name_to_type(const char *name) {
        assert(name);

        for (size_t i = DEVICE_ACTIVATION_POLICY_UP; i < (size_t) ELEMENTSOF(device_activation_policy_table); i++)
                if (str_equal_fold(name, device_activation_policy_table[i]))
                        return i;

        return _DEVICE_ACTIVATION_POLICY_INVALID;
}

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
        _auto_cleanup_ char *x = NULL;
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
        _auto_cleanup_ char *x = NULL, *y = NULL;
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
        _auto_cleanup_ struct IPAddress *b = NULL;
        struct in_addr buffer;

        assert(s);

        b = new0(IPAddress, 1);
        if (!b)
                return -ENOMEM;

        errno = 0;
        if (inet_pton(AF_INET, s, &buffer) <= 0)
                return errno > 0 ? -errno : -EINVAL;

        memcpy(&b->in, &buffer, sizeof(struct in_addr));
        b->family = AF_INET;

        *ret = steal_pointer(b);
        return 0;
}

int parse_ipv6(const char *s, IPAddress **ret) {
        _auto_cleanup_ struct IPAddress *b = NULL;
        struct in6_addr buffer;

        assert(s);

        b = new0(IPAddress, 1);
        if (!b)
                return -ENOMEM;

        errno = 0;
        if (inet_pton(AF_INET6, s, &buffer) <= 0)
                return errno > 0 ? -errno : -EINVAL;

        memcpy(&b->in6, &buffer, sizeof(struct in6_addr));
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

        return parse_ipv6(s, ret);
}

int parse_ip_from_string(const char *s, IPAddress **ret) {
        _auto_cleanup_ char *m = NULL;
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

int parse_ip_port(const char *s, IPAddress **ret, uint16_t *port) {
        _auto_cleanup_ char *c = NULL;
        char *p;
        int r;

        assert(s);

        c = strdup(s);
        if (!c)
                return -ENOMEM;

        p = strchr(c, ':');
        if (p) {
                uint16_t k;

                *p++ = 0;

                r = parse_uint16(p, &k);
                if (r < 0)
                        return r;

                *port = k;
        }

        return parse_ip_from_string(c, ret);
}

int parse_ifname_or_index(const char *s, IfNameIndex **ret) {
        _auto_cleanup_ IfNameIndex *p = NULL;
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
                        return -ENOENT;

                n = if_indextoname(ifindex, p->ifname);
                if (!n)
                        return -ENOENT;
                p->ifindex = ifindex;
        } else {
                p->ifindex = r;
                memcpy(p->ifname, s, IFNAMSIZ);
        }

        *ret = steal_pointer(p);
        return 0;
}

char *mac_addr_to_string(const char *addr, char *buf) {
        assert(addr);

        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        return buf;
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

        assert(mtu);

        r = parse_uint32(mtu, &j);
        if (r < 0)
                return r;

        *ret = j;
        return 0;
}

int parse_group(char *group, uint32_t *ret) {
        uint32_t j;
        int r;

        assert(group);

        r = parse_uint32(group, &j);
        if (r < 0)
                return r;

        *ret = j;
        return 0;
}

bool valid_hostname(const char *host)  {
        const char *p;

        p = host;
        if (*p == '-')
                return 0;

        for (;*p != 0;) {
                if (!(isalnum(*p)) && !(*p == '-') && !(*p == '.'))
                        return false;
                p++;
        }
        return true;
}

bool valid_ifname(const char *s) {
        if (!s || !s[0])
                return false;

        if (!g_utf8_validate(s, -1, NULL))
                return false;

        if(strlen(s) >= IFNAMSIZ)
                return false;

        while(*s) {
                if (*s == ':' || *s == '/' || *s == '%')
                        return false;

                if ((unsigned char) *s >= 127U)
                        return false;

                if ((unsigned char) *s <= 32U)
                        return false;

                s++;
        }

        return true;
}
