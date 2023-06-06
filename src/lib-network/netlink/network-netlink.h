/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <linux/if_link.h>

#pragma once

/* Link */

#ifndef IFLA_PERM_ADDRESS
#define IFLA_PERM_ADDRESS 54
#endif

#ifndef IFLA_PROTO_DOWN_REASON
#define IFLA_PROTO_DOWN_REASON 55
#endif

#ifndef IFLA_PARENT_DEV_NAME
#define IFLA_PARENT_DEV_NAME 56
#endif

#ifndef IFLA_PARENT_DEV_BUS_NAME
#define IFLA_PARENT_DEV_BUS_NAME 57
#endif

#ifndef IFLA_GRO_MAX_SIZE
#define IFLA_GRO_MAX_SIZE 58
#endif

#ifndef IFLA_TSO_MAX_SIZE
#define IFLA_TSO_MAX_SIZE 59
#endif

#ifndef IFLA_TSO_MAX_SEGS
#define IFLA_TSO_MAX_SEGS 60
#endif

#ifndef IFLA_ALLMULTI
#define IFLA_ALLMULTI     61
#endif

#ifndef IFLA_DEVLINK_PORT
#define IFLA_DEVLINK_PORT 62
#endif

#ifndef IFLA_GSO_IPV4_MAX_SIZE
#define IFLA_GSO_IPV4_MAX_SIZE 63
#endif

#ifndef IFLA_GRO_IPV4_MAX_SIZE
#define IFLA_GRO_IPV4_MAX_SIZE 64
#endif

/* Address  */

#ifndef IFA_PROTO
#define IFA_PROTO 11
#endif


/* Route */
#ifndef RTNH_F_TRAP
#define RTNH_F_TRAP             64      /* Nexthop is trapping packets */
#endif

/* rtm_flags */
#ifndef RTM_F_NOTIFY
#define RTM_F_NOTIFY            0x100   /* Notify user of route change  */
#endif

#ifndef RTM_F_CLONED
#define RTM_F_CLONED            0x200   /* This route is cloned         */
#endif

#ifndef RTM_F_EQUALIZE
#define RTM_F_EQUALIZE          0x400   /* Multipath equalizer: NI      */
#endif

#ifndef RTM_F_PREFIX
#define RTM_F_PREFIX            0x800   /* Prefix addresses             */
#endif

#ifndef RTM_F_LOOKUP_TABLE
#define RTM_F_LOOKUP_TABLE      0x1000  /* set rtm_table to FIB lookup result */
#endif

#ifndef RTM_F_FIB_MATCH
#define RTM_F_FIB_MATCH         0x2000  /* return full fib lookup match */
#endif

#ifndef RTM_F_OFFLOAD
#define RTM_F_OFFLOAD           0x4000  /* route is offloaded */
#endif

#ifndef RTM_F_TRAP
#define RTM_F_TRAP              0x8000  /* route is trapping packets */
#endif

#ifndef RTM_F_OFFLOAD_FAILED
#define RTM_F_OFFLOAD_FAILED    0x20000000 /* route offload failed, this value
                                            * is chosen to avoid conflicts with
                                            * other flags defined in
                                            * include/uapi/linux/ipv6_route.h
                                            */
#endif
