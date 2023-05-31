/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <linux/netlink.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if.h>

#include "alloc-util.h"
#include "log.h"
#include "macros.h"
#include "mnl_util.h"
#include "netlink-message.h"
#include "netlink.h"
#include "network-address.h"
#include "network-util.h"
#include "set.h"

static int addresses_new(Addresses **ret) {
        Addresses *h;
        int r;

        assert(ret);

        h = new0(Addresses, 1);
        if (!h)
                return log_oom();

        r = set_new(&h->addresses, g_direct_hash, g_direct_equal);
        if (r < 0)
                return r;

        *ret = steal_pointer(h);
        return 0;
}

int address_new(Address **ret) {
        Address *a;

        assert(ret);

        a = new0(Address, 1);
        if (!a)
                return log_oom();

        *ret = a;
        return 0;
}

void addresses_free(Addresses *a) {
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;
        Address *addr;

        if (!a)
                return;

        g_hash_table_iter_init(&iter, a->addresses->hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {

                addr = (Address *) g_bytes_get_data(key, &size);
                free(addr);

                g_bytes_unref(key);
                g_hash_table_iter_remove(&iter);
        }

        set_freep(&a->addresses);
        free(a);
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

static int validate_address_attributes(const struct nlattr *attr, void *data) {
        const struct nlattr **tb = data;
        int type = mnl_attr_get_type(attr);

        if (mnl_attr_type_valid(attr, IFA_MAX) < 0)
                return MNL_CB_OK;

        switch(type) {
        case IFA_ADDRESS:
                if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
                        return MNL_CB_ERROR;
                break;
        }
        tb[type] = attr;
        return MNL_CB_OK;
}

static int fill_link_address(const struct nlmsghdr *nlh, void *data) {
        struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
        struct nlattr *tb[IFA_MAX + 1] = {};
        _auto_cleanup_ Address *a = NULL;
        Addresses *addrs = data;
        int r;

        assert(nlh);
        assert(data);

        r = address_new(&a);
        if (r < 0)
                return r;

        *a = (Address) {
           .family = ifa->ifa_family,
           .flags = ifa->ifa_flags,
           .ifindex = ifa->ifa_index,
           .scope = ifa->ifa_scope,
           .address.prefix_len = ifa->ifa_prefixlen,
        };

        if (addrs->ifindex !=0 && addrs->ifindex != a->ifindex)
                return MNL_CB_OK;

        mnl_attr_parse(nlh, sizeof(*ifa), validate_address_attributes, tb);
        if (tb[IFA_ADDRESS]) {
                if (a->family == AF_INET)
                        memcpy(&a->address.in, mnl_attr_get_payload(tb[IFA_ADDRESS]), sizeof(struct in_addr));
                else
                        memcpy(&a->address.in6, mnl_attr_get_payload(tb[IFA_ADDRESS]), sizeof(struct in6_addr));
        }

        if (tb[IFA_LOCAL]) {
                if (a->family == AF_INET)
                        memcpy(&a->address.in, mnl_attr_get_payload(tb[IFA_ADDRESS]), sizeof(struct in_addr));
                else
                        memcpy(&a->address.in6, mnl_attr_get_payload(tb[IFA_ADDRESS]), sizeof(struct in6_addr));
        }

        if (tb[IFA_BROADCAST]) {
                if (a->family == AF_INET)
                        memcpy(&a->broadcast.in, mnl_attr_get_payload(tb[IFA_BROADCAST]), sizeof(struct in_addr));
                else
                        memcpy(&a->broadcast.in6, mnl_attr_get_payload(tb[IFA_BROADCAST]), sizeof(struct in6_addr));
        }

        if (tb[IFA_FLAGS])
                a->flags = mnl_attr_get_u32(tb[IFA_FLAGS]);

        if (tb[IFA_LABEL]) {
                a->label = strdup(mnl_attr_get_str(tb[IFA_LABEL]));
                if (!a->label)
                        return -ENOMEM;
        }

        if (tb[IFA_CACHEINFO])
                memcpy(&a->ci, mnl_attr_get_payload(tb[IFA_CACHEINFO]), sizeof(struct ifa_cacheinfo));

        r = address_add(&addrs, a);
        if (r < 0)
                return r;

        steal_pointer(a);
        return MNL_CB_OK;
}

static int acquire_link_address(int s, int ifindex, Addresses **ret) {
        _cleanup_(mnl_freep) Mnl *m = NULL;
        struct nlmsghdr *nlh;
        Addresses *a = NULL;
        int r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        nlh = mnl_nlmsg_put_header(m->buf);
        nlh->nlmsg_type = RTM_GETADDR;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
        m->nlh = nlh;

        r = addresses_new(&a);
        if (r < 0)
                return r;

        a->ifindex = ifindex;

        r = mnl_send(m, fill_link_address, a, NETLINK_ROUTE);
        if (r < 0)
                return r;

        *ret = a;
        return 0;
}

int manager_link_get_address(Addresses **ret) {
       _auto_cleanup_close_ int s = -1;
        int r;

        assert(ret);

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        return acquire_link_address(s, 0, ret);
}

int manager_get_one_link_address(int ifindex, Addresses **ret) {
        _auto_cleanup_close_ int s = -1;
        int r;

        assert(ifindex > 0);
        assert(ret);

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        return acquire_link_address(s, ifindex, ret);
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
        m->ifm.ifa_flags = address->flags;
        m->ifm.ifa_scope = address->scope;

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

        return link_add_address(s, ifindex, address, peer);
}
