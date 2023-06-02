/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "macros.h"
#include "netlink-message.h"
#include "netlink.h"
#include "network-link.h"
#include "network-util.h"
#include "set.h"

#ifndef RTNH_F_TRAP
#define RTNH_F_TRAP             64      /* Nexthop is trapping packets */
#endif

#ifndef RTM_F_OFFLOAD_FAILED
#define RTM_F_OFFLOAD_FAILED    0x20000000 /* route offload failed, this value
                                            * is chosen to avoid conflicts with
                                            * other flags defined in
                                            * include/uapi/linux/ipv6_route.h
                                            */
#endif

typedef struct Route {
        unsigned char dst_prefixlen;
        unsigned char src_prefixlen;
        unsigned char protocol;
        unsigned char tos;
        unsigned char pref;

        uint32_t priority;
        uint32_t table;
        uint32_t mtu;
        uint32_t metric;
        uint32_t flags;
        uint32_t flow;
        uint32_t initcwnd;
        uint32_t initrwnd;

        int family;
        int ifindex;
        int iif;
        int type;
        int scope;

        int onlink;
        int quick_ack;
        int tfo;
        int ttl_propogate;
        bool to_default;

        IPAddress src;
        IPAddress dst;
        IPAddress gw;
        IPAddress prefsrc;
} Route;

typedef struct Routes {
        int ifindex;
        Set *routes;
} Routes;

int route_new(Route **ret);
void routes_free(Routes *rt);

DEFINE_CLEANUP(Routes *, routes_free);

int manager_link_get_routes(Routes **ret);
int manager_get_one_link_route(int ifindex, Routes **ret);

int manager_link_add_default_gateway(Route *route);
int manager_link_add_route(Route *route);
