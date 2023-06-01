/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "alloc-util.h"
#include "network-util.h"

#ifndef IFLA_PARENT_DEV_NAME
#define IFLA_PARENT_DEV_NAME 56
#define IFLA_PARENT_DEV_BUS_NAME 57
#define IFLA_GRO_MAX_SIZE 58
#define IFLA_TSO_MAX_SIZE 59
#define IFLA_TSO_MAX_SEGS 60
#define IFLA_ALLMULTI     61
#define IFLA_DEVLINK_PORT 62
#define IFLA_GSO_IPV4_MAX_SIZE 63
#define IFLA_GRO_IPV4_MAX_SIZE 64
#endif


typedef enum LinkState {
        LINK_STATE_DOWN,
        LINK_STATE_UP,
        _LINK_STATE_MAX,
        _LINK_STATE_INVALID,
} LinkState;

typedef enum IPv6AddressGenMode {
       IPV6_ADDRESSS_GEN_MODE_EUI64          = IN6_ADDR_GEN_MODE_EUI64,
       IPV6_ADDRESSS_GEN_MODE_NONE           = IN6_ADDR_GEN_MODE_NONE,
       IPV6_ADDRESSS_GEN_MODE_STABLE_PRIVACY = IN6_ADDR_GEN_MODE_STABLE_PRIVACY,
       IPV6_ADDRESSS_GEN_MODE_RANDOM         = IN6_ADDR_GEN_MODE_RANDOM,
       _IPV6_ADDRESS_GEN_MODE_MAX,
       _IPV6_ADDRESS_GEN_MODE_INVALID        = -EINVAL,
} IPv6lAddressGenMode;

typedef struct Link {
        struct ether_addr mac_address;
        struct ether_addr perm_address;

        unsigned short iftype;

        char name[IFNAMSIZ+1];
        char *qdisc;
        char *kind;
        char *parent_dev;
        char *parent_bus;

        int ifindex;

        uint8_t operstate;
        uint8_t ipv6_addr_gen_mode;

        uint32_t mtu;
        uint32_t master;
        uint32_t min_mtu;
        uint32_t max_mtu;
        uint32_t tx_queue_len;
        uint32_t n_tx_queues;
        uint32_t n_rx_queues;
        uint32_t gso_max_size;
        uint32_t gso_max_segments;
        uint32_t tso_max_size;
        uint32_t tso_max_segments;
        uint32_t gro_max_size;
        uint32_t gro_ipv4_max_size;
        uint32_t gso_ipv4_max_size;
        uint32_t flags;

        union {
                struct rtnl_link_stats64 stats64;
                struct rtnl_link_stats stats;
        };

        GPtrArray *alt_names;

        bool contains_mac_address:1;
        bool contains_perm_address:1;
        bool contains_mtu:1;
        bool contains_stats:1;
        bool contains_stats64:1;
} Link;

typedef struct Links {
         GList *links;
} Links;

void link_free(Link *l);
void links_free(Links *l);

DEFINE_CLEANUP(Link*, link_free);
DEFINE_CLEANUP(Links*, links_free);

int link_get_links(Links **ret);
int link_get_one_link(const char *ifname, Link **ret);

int link_read_sysfs_attribute(const char *ifname, const char *attribute, char **ret);
int link_set_mac_address(const IfNameIndex *ifidx, const char *mac_address);
int manager_link_get_link_mac_addr(const char *ifname, char **pmac);
int link_get_mtu(const char *ifname, uint32_t *mtu);
int link_update_mtu(const IfNameIndex *ifidx, uint32_t mtu);
int link_get_mac_address(const char *ifname, char **mac);
int link_set_state(const IfNameIndex *ifidx, LinkState state);
int link_get_operstate(const char *ifname, char **operstate);

int link_remove(const IfNameIndex *ifidx);

const char *link_operstates_to_name(int id);

const char *link_state_to_name(int id);
int link_name_to_state(char *name);

const char *ipv6_address_generation_mode_to_name(int mode);
