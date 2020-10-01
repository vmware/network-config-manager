/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <glib.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "alloc-util.h"
#include "log.h"
#include "macros.h"
#include "netlink-message.h"
#include "netlink.h"
#include "network-address.h"
#include "network-util.h"
#include "set.h"

static int addresses_new(Addresses **ret) {
        Addresses *h = NULL;
        int r;

        h = new0(Addresses, 1);
        if (!h)
                return log_oom();

        r = set_new(&h->addresses, g_bytes_hash, g_bytes_equal);
        if (r < 0)
                return r;

        *ret = steal_pointer(h);

        return 0;
}

int address_new(Address **ret) {
        Address *a = NULL;

        assert(ret);

        a = new0(Address, 1);
        if (!a)
                return log_oom();

        *ret = a;

        return 0;
}

void addresses_unref(Addresses **a) {
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        Address *addr;

        if (!a || !*a)
                return;

        g_hash_table_iter_init(&iter, (*a)->addresses->hash);

        while (g_hash_table_iter_next(&iter, &key, &value)) {

                addr = (Address *) g_bytes_get_data(key, &size);
                free(addr);

                g_bytes_unref(key);
                g_hash_table_iter_remove(&iter);
        }

        set_unrefp(&(*a)->addresses);
        free(*a);
}


int address_add(Addresses **h, Address *a) {
        GBytes *b = NULL;
        int r;

        assert(h);
        assert(a);

        if (!*h) {
                r = addresses_new(h);
                if (r < 0)
                        return r;
        }

        b = g_bytes_new_with_free_func(a, sizeof(Address), g_free, NULL);
        if (!b)
                return log_oom();

        if (!set_contains((*h)->addresses, b))
                return set_add((*h)->addresses, b);

        return -EEXIST;
}

static int fill_link_address(struct nlmsghdr *h, size_t len, int ifindex, Addresses **ret) {
        _auto_cleanup_ Address *a = NULL;
        struct ifaddrmsg *ifm;
        struct nlmsghdr *p;
        int r, l;

        assert(h);
        assert(ret);

        for (p = h; NLMSG_OK(p, len); p = NLMSG_NEXT(p, len)) {
                _auto_cleanup_ struct rtattr **rta_tb = NULL;
                ifm = NLMSG_DATA(p);

                l = p->nlmsg_len;
                l -= NLMSG_LENGTH(sizeof(*ifm));


                if (ifindex > 0 && ifindex != (int) ifm->ifa_index)
                        continue;

                rta_tb = new0(struct rtattr *, IFA_MAX + 1);
                if (!rta_tb)
                        return log_oom();

                r = rtnl_message_parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifm), l);
                if (r < 0)
                        return r;

                r = address_new(&a);
                if (r < 0)
                        return r;

                a->family = ifm->ifa_family;
                a->ifindex = ifm->ifa_index;
                a->address.prefix_len = ifm->ifa_prefixlen;
                switch (a->family) {
                case AF_INET:
                        if (rta_tb[IFA_LOCAL])
                                (void) rtnl_message_read_in_addr(rta_tb[IFA_LOCAL], &a->address.in);
                        else if (rta_tb[IFA_ADDRESS])
                                (void) rtnl_message_read_in_addr(rta_tb[IFA_ADDRESS], &a->address.in);

                        break;
                case AF_INET6:
                        if (rta_tb[IFA_LOCAL])
                                (void) rtnl_message_read_in6_addr(rta_tb[IFA_LOCAL], &a->address.in6);
                        else if (rta_tb[IFA_ADDRESS])
                                (void) rtnl_message_read_in6_addr(rta_tb[IFA_ADDRESS], &a->address.in6);

                        break;
                default:
                        break;
                }

                r = address_add(ret, a);
                if (r < 0)
                        return r;

                steal_pointer(a);
        }

        return 0;
}

static int acquire_link_address(int s, int ifindex, Addresses **ret) {
        _auto_cleanup_ IPAddressMessage *m = NULL;
        struct nlmsghdr *reply = NULL;
        int r;

        assert(s);
        assert(ret);

        r = ip_address_message_new(RTM_GETADDR, AF_UNSPEC, ifindex, &m);
        if (r < 0)
                return r;

        r = rtnl_message_request_dump(&m->hdr, true);
        if (r < 0)
                return r;

        r = rtnl_send_message(s, &m->hdr);
        if (r < 0)
                return r;

        r = rtnl_receive_message(s, m->buf, sizeof(m->buf), 0);
        if (r < 0)
                 return r;

        reply = (struct nlmsghdr *) m->buf;
        for (; r > 0;) {
                (void) fill_link_address(reply, r, ifindex, ret);

                r = rtnl_receive_message(s, m->buf, sizeof(m->buf), 0);
                if (r < 0)
                        return -errno;
                if (r == 0)
                         break;
         }

        return 0;
}

int manager_link_get_address(Addresses **ret) {
       _auto_cleanup_close_ int s = -1;
        int r;

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        return acquire_link_address(s, 0, ret);
}

int manager_get_one_link_address(int ifindex, Addresses **ret) {
        _auto_cleanup_close_ int s = -1;
        int r;

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        r = acquire_link_address(s, ifindex, ret);
        if (r < 0)
                return r;

        return 0;
}

static int link_add_address(int s, int ifindex, IPAddress *address, IPAddress *peer) {
        _auto_cleanup_ IPAddressMessage *m = NULL;
        int r;

        assert(s);
        assert(ifindex > 0);
        assert(address);

        r = ip_address_message_new(RTM_NEWADDR, address->family, ifindex, &m);
        if (r < 0)
                return r;

        m->ifm.ifa_prefixlen = address->prefix_len;

        if (address->family == AF_INET)
                r = rtnl_message_add_attribute(&m->hdr, IFA_LOCAL, &address->in, sizeof(struct in_addr));
        else
                r = rtnl_message_add_attribute(&m->hdr, IFA_LOCAL, &address->in6, sizeof(struct in6_addr));

        if (r < 0)
                return r;

        if (peer->family == AF_INET)
                r = rtnl_message_add_attribute(&m->hdr, IFA_ADDRESS, &peer->in, sizeof(struct in_addr));
        else
                r = rtnl_message_add_attribute(&m->hdr, IFA_ADDRESS, &peer->in6, sizeof(struct in6_addr));

        if (r < 0)
                return r;

        return netlink_call(s, &m->hdr, m->buf, sizeof(m->buf));
}

int manager_link_add_address(int ifindex, IPAddress *address, IPAddress *peer) {
       _auto_cleanup_close_ int s = -1;
       int r;

        assert(ifindex > 0);
        assert(address);

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        r = link_add_address(s, ifindex, address, peer);
        if (r < 0)
                return r;

        return 0;
}
