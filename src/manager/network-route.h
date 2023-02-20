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

typedef struct Route {
        unsigned char dst_prefixlen;
        unsigned char src_prefixlen;
        unsigned char scope;
        unsigned char protocol;
        unsigned char type;
        unsigned char tos;

        uint32_t priority;
        uint32_t table;
        uint32_t mtu;
        uint32_t metric;
        uint32_t flags;
        uint32_t flow;

        int family;
        int ifindex;

        int onlink;

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
void routes_unref(Routes *rt);

DEFINE_CLEANUP(Routes *, routes_unref);

int manager_link_get_routes(Routes **ret);
int manager_get_one_link_route(int ifindex, Routes **ret);

int manager_link_add_default_gateway(Route *route);
int manager_link_add_route(Route *route);
