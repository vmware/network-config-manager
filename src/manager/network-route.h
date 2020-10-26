/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include "macros.h"
#include "netlink-message.h"
#include "netlink.h"
#include "network-link.h"
#include "network-util.h"

typedef struct Route {
        int family;
        int ifindex;
        int dst_prefixlen;

        char protocol;
        char type;

        unsigned char scope;

        uint32_t metric;
        uint32_t table;

        bool onlink;

        IPAddress gw;
        IPAddress address;
        IPAddress destination;
} Route;

typedef struct Routes {
        GList *routes;
} Routes;

static inline void routes_free(Routes **rt) {
        if (rt && *rt) {
                g_list_free_full((*rt)->routes, g_free);
                g_free(*rt);
        }
}

int route_new(Route **ret);

int manager_link_get_routes(Routes **ret);
int manager_get_one_link_route(int ifindex, Routes **ret);

int manager_link_add_default_gateway(Route *route);
int manager_link_add_route(Route *route);
