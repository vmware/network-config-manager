/* Copyright 2021 VMware, Inc.
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
        int family;
        int ifindex;
        int dst_prefixlen;

        char protocol;
        char type;

        unsigned char scope;

        uint32_t metric;
        uint32_t table;

        int onlink;

        IPAddress gw;
        IPAddress address;
        IPAddress destination;
} Route;

typedef struct Routes {
        Set *routes;
} Routes;

int route_new(Route **ret);
void routes_unref(Routes *rt);

DEFINE_CLEANUP(Routes *, routes_unref);

int manager_link_get_routes(Routes **ret);
int manager_get_one_link_route(int ifindex, Routes **ret);

int manager_link_add_default_gateway(Route *route);
int manager_link_add_route(Route *route);
