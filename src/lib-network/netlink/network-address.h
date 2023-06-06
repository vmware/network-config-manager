/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <assert.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "macros.h"
#include "netlink-message.h"
#include "netlink.h"
#include "network-link.h"
#include "network-util.h"
#include "set.h"

typedef struct Address {
        int family;
        int ifindex;

        unsigned char scope;
        unsigned char prefix_len;

        uint8_t proto;
        uint32_t flags;
        char *label;

        struct ifa_cacheinfo ci;

        IPAddress address;
        IPAddress broadcast;
        IPAddress peer;
} Address;

typedef struct Addresses {
       int ifindex;
       Set *addresses;
} Addresses;

void addresses_free(Addresses *a);
DEFINE_CLEANUP(Addresses*, addresses_free);

int address_new(Address **ret);
int address_add(Addresses **h, Address *a);

int netlink_acquire_all_link_addresses(Addresses **ret);
int netlink_get_one_link_address(int ifindex, Addresses **ret);

int netlink_add_link_address(int ifindex, IPAddress *address, IPAddress *peer);
