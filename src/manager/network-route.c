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
#include "netlink.h"
#include "network-route.h"
#include "network-util.h"

static int route_news(Routes **ret) {
        Routes *h = NULL;

        h = new0(Routes, 1);
        if (!h)
                return log_oom();

        *ret = h;

        return 0;
}

int route_new(Route **ret) {
        Route *route = NULL;

        assert(ret);

        route = new0(Route, 1);
        if (!route)
                return log_oom();

        *route = (Route) {
                .family = AF_UNSPEC,
                .scope = RT_SCOPE_UNIVERSE,
                .protocol = RTPROT_UNSPEC,
                .type = RTN_UNICAST,
                .table = RT_TABLE_MAIN,
        };

        *ret = route;

        return 0;
}

static int route_add(Routes **h, Route *rt) {
        int r;

        assert(h);
        assert(rt);

        if (!*h) {
                r = route_news(h);
                if (r < 0)
                        return r;
        }

        (*h)->routes = g_list_append((*h)->routes, rt);

        return 0;
}

static int fill_link_route(struct nlmsghdr *h, size_t len, int ifindex, Routes **ret) {
        struct rtattr *rta_tb[RTA_MAX+1];
        struct nlmsghdr *p;
        struct rtmsg *rt;
        int r, l;

        assert(h);
        assert(ret);

        for (p = h; NLMSG_OK(p, len); p = NLMSG_NEXT(p, len)) {
                _auto_cleanup_ Route *a = NULL;

                rt = NLMSG_DATA(p);

                l = p->nlmsg_len;
                l -= NLMSG_LENGTH(sizeof(*rt));

                r = rtnl_message_parse_rtattr(rta_tb, IFA_MAX, RTM_RTA(rt), l);
                if (r < 0)
                        return r;

                r = route_new(&a);
                if (r < 0)
                        return r;

                a->family = rt->rtm_family;

                if (rta_tb[RTA_OIF])
                        a->ifindex = rtnl_message_get_attribute_u32(rta_tb[RTA_OIF]);
                else
                        continue;

                if (ifindex > 0 && ifindex != (int) a->ifindex)
                        continue;


                if (rt->rtm_dst_len != 0)
                        continue;

                if (rt->rtm_src_len != 0)
                        continue;

                switch (a->family) {
                case AF_INET:
                        if (rta_tb[RTA_GATEWAY])
                                (void) rtnl_message_get_in_addr(rta_tb[RTA_GATEWAY], &a->address.in);
                        break;
                case AF_INET6:
                        if (rta_tb[RTA_GATEWAY])
                                (void) rtnl_message_get_in6_addr(rta_tb[RTA_GATEWAY], &a->address.in6);
                        break;
                default:
                        break;
                }

                r = route_add(ret, a);
                if (r < 0)
                        return r;

                a = NULL;
        }

        return 0;
}

static int acquire_link_route(int s, int ifindex, Routes **ret) {
        _auto_cleanup_ IPRouteMessage *m = NULL;
        struct nlmsghdr *reply = NULL;
        int r;

        assert(s);
        assert(ret);

        r = ip_route_message_new(RTM_GETROUTE, AF_UNSPEC, 0, &m);
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
        for(; r > 0;) {
                fill_link_route(reply, r, ifindex, ret);

                r = rtnl_receive_message(s, m->buf, sizeof(m->buf), 0);
                if (r < 0)
                        return -errno;
                if (r == 0)
                         break;
         }

        return 0;
}

int manager_link_get_routes(Routes **ret) {
       _auto_cleanup_close_ int s = -1;
        int r;

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        return acquire_link_route(s, 0, ret);
}

int manager_get_one_link_route(int ifindex, Routes **ret) {
        _auto_cleanup_close_ int s = -1;
        int r, c;

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        c = acquire_link_route(s, ifindex, ret);
        if (c < 0)
                return c;

        return 0;
}

static int link_add_route(int s, Route *route) {
        _auto_cleanup_ IPRouteMessage *m = NULL;
        int r;

        assert(s);
        assert(route);
        assert(route->ifindex > 0);

        r = ip_route_message_new(RTM_NEWROUTE, route->family, RTPROT_STATIC, &m);
        if (r < 0)
                return r;

        if (route->onlink)
                m->rtm.rtm_flags |= RTNH_F_ONLINK;

        r = rtnl_message_add_attribute_uint32(&m->hdr, RTA_OIF, route->ifindex);
        if (r < 0)
                return r;

        if (ip_is_null(&route->gw) == 0) {
                if (route->gw.family == AF_INET)
                        r = rtnl_message_add_attribute(&m->hdr, RTA_GATEWAY, &route->gw.in, sizeof(struct in_addr));
                else
                        r = rtnl_message_add_attribute(&m->hdr, RTA_GATEWAY, &route->gw.in6, sizeof(struct in6_addr));

                if (r < 0)
                        return r;

        }

        if (route->destination.prefix_len > 0) {
                if (route->destination.family == AF_INET)
                        r = rtnl_message_add_attribute(&m->hdr, RTA_DST, &route->destination.in, sizeof(struct in_addr));
                else
                        r = rtnl_message_add_attribute(&m->hdr, RTA_DST, &route->destination.in6, sizeof(struct in6_addr));

                if (r < 0)
                        return r;

                m->rtm.rtm_dst_len = route->destination.prefix_len;
        }

        if (route->table != RT_TABLE_MAIN) {
                if (route->table < 256)
                        m->rtm.rtm_table = route->table;
                else {
                        m->rtm.rtm_table = RT_TABLE_UNSPEC;
                        r = rtnl_message_add_attribute_uint32(&m->hdr, RTA_TABLE, route->table);
                        if (r < 0)
                                return r;
                }
        }

        r = rtnl_message_add_attribute_uint32(&m->hdr, RTA_METRICS, route->metric);
        if (r < 0)
                return r;

        return netlink_call(s, &m->hdr, m->buf, sizeof(m->buf));
}

int manager_link_add_default_gateway(Route *route) {
       _auto_cleanup_close_ int s = -1;
       int r;

        assert(route);

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        r = link_add_route(s, route);
        if (r < 0)
                return r;

        return 0;
}

int manager_link_add_route(Route *route) {
       _auto_cleanup_close_ int s = -1;
       int r;

        assert(route);

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        r = link_add_route(s, route);
        if (r < 0)
                return r;

        return 0;
}
