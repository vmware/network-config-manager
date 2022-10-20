/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "alloc-util.h"

typedef struct IPlinkMessage {
        struct nlmsghdr hdr;
        struct ifinfomsg ifi;

        char buf[32768];
} IPlinkMessage;

typedef struct IPAddressMessage {
        struct nlmsghdr hdr;
        struct ifaddrmsg ifm;

        char buf[32768];
} IPAddressMessage;

typedef struct IPRouteMessage {
        struct nlmsghdr hdr;
        struct rtmsg rtm;

        char buf[32768];
} IPRouteMessage;

int ip_link_message_new(int type, int family, int ifindex, IPlinkMessage **ret);
int ip_address_message_new(int type, int family, int ifindex, IPAddressMessage **ret);
int ip_route_message_new(int type, int family, char rtm_protocol, IPRouteMessage **ret);
