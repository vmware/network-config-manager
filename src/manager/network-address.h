/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
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

        uint32_t metric;

        IPAddress address;
        IPAddress peer;
} Address;

typedef struct Addresses {
       Set *addresses;
} Addresses;

void addresses_unref(Addresses **a);

int address_new(Address **ret);
int address_add(Addresses **h, Address *a);

int manager_link_get_address(Addresses **ret);
int manager_get_one_link_address(int ifindex, Addresses **ret);

int manager_link_add_address(int ifindex, IPAddress *address, IPAddress *peer);
