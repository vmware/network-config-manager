/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "macros.h"
#include "netlink-message.h"
#include "netlink.h"
#include "network-link.h"
#include "network-util.h"
#include "set.h"

/* iproute */
typedef enum RouteTable {
       ROUTE_TABLE_UNSPEC,
       ROUTE_TABLE_DEFAULT  = 253,
       ROUTE_TABLE_MAIN     = 254,
       ROUTE_TABLE_LOCAL    = 255,
       _ROUTE_TABLE_MAX,
       _ROUTE_TABLE_INVALID = -EINVAL
} RouteTable;

typedef enum RouteScope {
        ROUTE_SCOPE_UNIVERSE,
        ROUTE_SCOPE_SITE = RT_SCOPE_SITE,
        ROUTE_SCOPE_LINK = RT_SCOPE_LINK,
        ROUTE_SCOPE_HOST = RT_SCOPE_HOST,
        ROUTE_SCOPE_NOWHERE = RT_SCOPE_NOWHERE,
       _ROUTE_SCOPE_MAX,
       _ROUTE_SCOPE_INVALID = -EINVAL,
} RouteScope;

typedef enum IPv6RoutePreference {
        IPV6_ROUTE_PREFERENCE_LOW,
        IPV6_ROUTE_PREFERENCE_MEDIUM,
        IPV6_ROUTE_PREFERENCE_HIGH,
        _IPV6_ROUTE_PREFERENCE_MAX,
        _IPV6_ROUTE_PREFERENCE_INVALID = -EINVAL,
} IPv6RoutePreference;

typedef enum RouteProtcol {
       ROUTE_PROTOCOL_KERNEL,
       ROUTE_PROTOCOL_BOOT,
       ROUTE_PROTOCOL_STATIC,
       ROUTE_PRTOCOL_DHCP,
       _ROUTE_PROTOCOL_MAX,
       _ROUTE_PROTOCOL_INVALID = -EINVAL,
} RouteProtocol;

typedef enum RouteType {
       ROUTE_TYPE_UNSPEC,
       ROUTE_TYPE_UNICAST,
       ROUTE_TYPE_LOCAL,
       ROUTE_TYPE_BROADCAST,
       ROUTE_TYPE_ANYCAST,
       ROUTE_TYPE_MULTICAST,
       ROUTE_TYPE_BLACKHOLE,
       ROUTE_TYPE_UNREACHABLE,
       ROUTE_TYPE_PROHIBIT,
       ROUTE_TYPE_THROW,
       ROUTE_TYPE_NAT,
       ROUTE_TYPE_XRESOLVE,
       _ROUTE_TYPE_MAX,
       _ROUTE_TYPE_INVALID = -EINVAL
} RouteType;

typedef enum IPoIBMode {
        IP_OIB_MODE_DATAGRAM,
        IP_OIB_MODE_MODE_CONNECTED,
        _IP_OIB_MODE_MODE_MAX,
        _IP_OIB_MODE_MODE_INVALID = -EINVAL,
} IPoIBMode;

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

int netlink_acquire_all_link_routes(Routes **ret);
int netlink_get_one_link_route(int ifindex, Routes **ret);

int netlink_add_link_default_gateway(Route *route);
int netlink_add_link_route(Route *route);

int route_table_to_string(uint32_t table, char **ret);

const char *route_table_to_name(int id);
int route_table_to_mode(const char *name);

const char *route_scope_type_to_name(int id);
int route_scope_type_to_mode(const char *name);

const char *route_type_to_name(int id);
int route_type_to_mode(const char *name);

const char *ipv6_route_preference_to_name(int id);
int ipv6_route_preference_type_to_mode(const char *name);

const char *route_protocol_to_name(int id);
int route_protocol_to_mode(const char *name);

const char *ipoib_mode_to_name(int id);
int ipoib_name_to_mode(const char *name);
