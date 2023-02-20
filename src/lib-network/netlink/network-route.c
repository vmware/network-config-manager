/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "log.h"
#include "network-route.h"
#include "mnl_util.h"
#include "network-util.h"

int route_new(Route **ret) {
        Route *route;

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

static int routes_new(Routes **ret) {
        Routes *rt;
        int r;

        rt = new0(Routes, 1);
        if (!rt)
                return log_oom();

        r = set_new(&rt->routes, g_bytes_hash, g_bytes_equal);
        if (r < 0)
                return r;

        *ret = steal_pointer(rt);
        return 0;
}

void routes_unref(Routes *routes) {
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;

        if (!routes)
                return;

        g_hash_table_iter_init(&iter, routes->routes->hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                Route *rt;

                rt = (Route *) g_bytes_get_data(key, &size);
                free(rt);

                g_bytes_unref(key);
                g_hash_table_iter_remove(&iter);
        }

        set_unrefp(&routes->routes);
        free(routes);
}

static int route_add(Routes **rts, Route *rt) {
        GBytes *b = NULL;
        int r;

        assert(rts);
        assert(rt);

        if (!*rts) {
                r = routes_new(rts);
                if (r < 0)
                        return r;
        }

        b = g_bytes_new_with_free_func(rt, sizeof(Route), g_free, NULL);
        if (!b)
                return log_oom();

        if (!set_contains((*rts)->routes, b))
                return set_add((*rts)->routes, b);

        return -EEXIST;
}

static int validata_attr_mettrics(const struct nlattr *attr, void *data) {
        const struct nlattr **tb = data;

        if (mnl_attr_type_valid(attr, RTAX_MAX) < 0)
                return MNL_CB_OK;

        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
                return MNL_CB_ERROR;

        tb[mnl_attr_get_type(attr)] = attr;
        return MNL_CB_OK;
}

static int route_data_ipv4_attr_cb(const struct nlattr *attr, void *data) {
        int type = mnl_attr_get_type(attr);
        const struct nlattr **tb = data;

        if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
                return MNL_CB_OK;

        switch(type) {
        case RTA_TABLE:
        case RTA_DST:
        case RTA_SRC:
        case RTA_OIF:
        case RTA_FLOW:
        case RTA_PREFSRC:
        case RTA_GATEWAY:
        case RTA_PRIORITY:
                if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
                        return MNL_CB_ERROR;
                break;
        case RTA_METRICS:
                if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
                        return MNL_CB_ERROR;
                break;
        }
        tb[type] = attr;
        return MNL_CB_OK;
}

static int route_data_ipv6_attr_cb(const struct nlattr *attr, void *data) {
        int type = mnl_attr_get_type(attr);
        const struct nlattr **tb = data;

        if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
                return MNL_CB_OK;

        switch(type) {
        case RTA_TABLE:
        case RTA_OIF:
        case RTA_FLOW:
        case RTA_PRIORITY:
                if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
                        return MNL_CB_ERROR;
                break;
        case RTA_DST:
        case RTA_SRC:
        case RTA_PREFSRC:
        case RTA_GATEWAY:
                if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) < 0)
                        return MNL_CB_ERROR;
                break;
        case RTA_METRICS:
                if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
                        return MNL_CB_ERROR;
                break;
        }

        tb[type] = attr;
        return MNL_CB_OK;
}

static int fill_link_route_message(Route *rt, int ifindex , struct nlattr *tb[]) {
        if (tb[RTA_TABLE])
                rt->table = mnl_attr_get_u32(tb[RTA_TABLE]);

        if (tb[RTA_DST]) {
                if (rt->family == AF_INET)
                        memcpy(&rt->dst.in, mnl_attr_get_payload(tb[RTA_DST]), sizeof(struct in_addr));
                else
                        memcpy(&rt->dst.in6, mnl_attr_get_payload(tb[RTA_DST]), sizeof(struct in6_addr));

                rt->dst.family = rt->family;
        }

        if (tb[RTA_SRC]) {
                if (rt->family == AF_INET)
                        memcpy(&rt->src.in, mnl_attr_get_payload(tb[RTA_SRC]), sizeof(struct in_addr));
                else
                        memcpy(&rt->src.in6, mnl_attr_get_payload(tb[RTA_SRC]), sizeof(struct in6_addr));

                rt->src.family = rt->family;
        }

        if (tb[RTA_OIF])
                rt->ifindex = mnl_attr_get_u32(tb[RTA_OIF]);

        if (ifindex > 0 && ifindex != (int) rt->ifindex)
                return -EINVAL;

        if (tb[RTA_FLOW])
                rt->flow = mnl_attr_get_u32(tb[RTA_FLOW]);

        if (tb[RTA_PREFSRC]) {
                if (rt->family == AF_INET)
                        memcpy(&rt->prefsrc.in, mnl_attr_get_payload(tb[RTA_PREFSRC]), sizeof(struct in_addr));
                else
                        memcpy(&rt->prefsrc.in6, mnl_attr_get_payload(tb[RTA_PREFSRC]), sizeof(struct in6_addr));

                rt->prefsrc.family = rt->family;
        }

        if (tb[RTA_GATEWAY]) {
                if (rt->family == AF_INET)
                        memcpy(&rt->gw.in, mnl_attr_get_payload(tb[RTA_GATEWAY]), sizeof(struct in_addr));
                else
                        memcpy(&rt->gw.in6, mnl_attr_get_payload(tb[RTA_GATEWAY]), sizeof(struct in6_addr));

                rt->gw.family = rt->family;
        }

        if (tb[RTA_PRIORITY])
                rt->priority = mnl_attr_get_u32(tb[RTA_PRIORITY]);

        if (tb[RTA_METRICS]) {
                struct nlattr *tbx[RTAX_MAX+1] = {};
                int i;

                mnl_attr_parse_nested(tb[RTA_METRICS], validata_attr_mettrics, tbx);
                for (i=0; i<RTAX_MAX; i++) {
                        if (tbx[i])
                                rt->metric =  mnl_attr_get_u32(tbx[i]);
                }
        }

        return 0;
}

static int fill_link_route(const struct nlmsghdr *nlh, void *data) {
        struct nlattr *tb[RTA_MAX+1] = {};
        _auto_cleanup_ Route *rt = NULL;
        Routes *rts = (Routes *) data;
        struct rtmsg *rm;
        int r;

        assert(data);
        assert(nlh);

        rm = mnl_nlmsg_get_payload(nlh);

        r = route_new(&rt);
        if (r < 0)
                return r;

        *rt = (Route) {
               .family = rm->rtm_family,
               .dst_prefixlen = rm->rtm_dst_len,
               .src_prefixlen = rm->rtm_src_len,
               .tos = rm->rtm_tos,
               .table = rm->rtm_table,
               .type = rm->rtm_type,
               .scope = rm->rtm_scope,
               .protocol = rm->rtm_protocol,
               .flags = rm->rtm_flags,
        };

        switch(rm->rtm_family) {
        case AF_INET:
                mnl_attr_parse(nlh, sizeof(*rm), route_data_ipv4_attr_cb, tb);
                r = fill_link_route_message(rt, rts->ifindex, tb);
                if (r < 0)
                        return MNL_CB_OK;
                break;
        case AF_INET6:
                mnl_attr_parse(nlh, sizeof(*rm), route_data_ipv6_attr_cb, tb);
                fill_link_route_message(rt, rts->ifindex, tb);
                break;
        }

        r = route_add(&rts, rt);
        if (r < 0)
                return r;

        steal_pointer(rt);

        return MNL_CB_OK;
}

static int acquire_link_route(int ifindex, Routes **ret) {
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        struct nlmsghdr *nlh;
        Routes *rts = NULL;
        int r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        nlh = mnl_nlmsg_put_header(m->buf);
        nlh->nlmsg_type = RTM_GETROUTE;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        nlh->nlmsg_seq = time(NULL);
        mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
        m->nlh = nlh;

        r = routes_new(&rts);
        if (r < 0)
                return r;

        rts->ifindex = ifindex;

        r = mnl_send(m, fill_link_route, rts, NETLINK_ROUTE);
        if (r < 0)
                return r;

        *ret = rts;
        return 0;
}

int manager_link_get_routes(Routes **rt) {
        return acquire_link_route(0, rt);
}

int manager_get_one_link_route(int ifindex, Routes **ret) {
        return acquire_link_route(ifindex, ret);
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

        if (route->dst.prefix_len > 0) {
                if (route->dst.family == AF_INET)
                        r = rtnl_message_add_attribute(&m->hdr, RTA_DST, &route->dst.in, sizeof(struct in_addr));
                else
                        r = rtnl_message_add_attribute(&m->hdr, RTA_DST, &route->dst.in6, sizeof(struct in6_addr));

                if (r < 0)
                        return r;

                m->rtm.rtm_dst_len = route->dst.prefix_len;
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

        return link_add_route(s, route);
}

int manager_link_add_route(Route *route) {
       _auto_cleanup_close_ int s = -1;
       int r;

        assert(route);

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        return link_add_route(s, route);
}
