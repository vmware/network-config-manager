/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include "alloc-util.h"
#include "network-util.h"

typedef enum LinkState {
        LINK_STATE_DOWN,
        LINK_STATE_UP,
        _LINK_STATE_MAX,
        _LINK_STATE_INVALID,
} LinkState;

typedef struct Link {
        char name[IFNAMSIZ+1];
        int ifindex;
        unsigned short iftype;
        uint8_t operstate;
        struct ether_addr mac_address;
        uint32_t mtu;
        GPtrArray *alt_names;

        bool contains_mac_address:1;
        bool contains_mtu:1;
} Link;

typedef struct Links {
         GList *links;
} Links;

static inline void link_unref(Link **l) {
        if (l && *l) {
                if ((*l)->alt_names)
                        g_ptr_array_free((*l)->alt_names, true);

                free(*l);
        }
}

static inline void links_free(Links **l) {
        if (l && *l) {
                g_list_free_full(g_list_first((*l)->links), g_free);
                g_free(*l);
        }
}

int link_get_links(Links **ret);
int link_get_one_link(const char *ifname, Link **ret);

int link_read_sysfs_attribute(const char *ifname, const char *attribute, char **ret);
int link_set_mac_address(const IfNameIndex *ifnameidx, const char *mac_address);
int manager_link_get_link_mac_addr(const char *ifname, char **pmac);
int link_get_mtu(const char *ifname, uint32_t *mtu);
int link_update_mtu(const IfNameIndex *ifnameidx, uint32_t mtu);
int link_get_mac_address(const char *ifname, char **mac);
int link_set_state(const IfNameIndex *ifnameidx, LinkState state);
int link_get_operstate(const char *ifname, char **operstate);

const char *link_operstates_to_name(int id);

const char *link_state_to_name(int id);
int link_name_to_state(char *name);
