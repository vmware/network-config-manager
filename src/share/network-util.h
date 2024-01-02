/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <arpa/inet.h>
#include <assert.h>
#include <glib.h>
#include <net/if.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "macros.h"

#define ETHER_ADDR_FORMAT_STR "%02X%02X%02X%02X%02X%02X"
#define ETHER_ADDR_FORMAT_VAL(x) (x).ether_addr_octet[0], (x).ether_addr_octet[1], (x).ether_addr_octet[2], (x).ether_addr_octet[3], (x).ether_addr_octet[4], (x).ether_addr_octet[5]
#define ETHER_ADDR_TO_STRING_MAX (3*6)

#define parse_ether_address(mac) ether_aton(mac)

typedef enum AddressFamily {
        ADDRESS_FAMILY_NO             = 0,
        ADDRESS_FAMILY_IPV4           = 1 << 0,
        ADDRESS_FAMILY_IPV6           = 1 << 1,
        ADDRESS_FAMILY_YES            = ADDRESS_FAMILY_IPV4 | ADDRESS_FAMILY_IPV6,
        _ADDRESS_FAMILY_MAX,
        _ADDRESS_FAMILY_INVALID = -EINVAL,
} AddressFamily;

typedef enum ActivationPolicy {
        DEVICE_ACTIVATION_POLICY_UP,
        DEVICE_ACTIVATION_POLICY_ALWAYS_UP,
        DEVICE_ACTIVATION_POLICY_MANUAL,
        DEVICE_ACTIVATION_POLICY_ALWAYS_DOWN,
        DEVICE_ACTIVATION_POLICY_DOWN,
        DEVICE_ACTIVATION_POLICY_BOUND,
        _DEVICE_ACTIVATION_POLICY_MAX,
        _DEVICE_ACTIVATION_POLICY_INVALID = -EINVAL,
} ActivationPolicy;

typedef enum RequiredAddressFamilyForOnline {
        REQUIRED_ADDRESS_FAMILY_FOR_ONLINE_IPV4,
        REQUIRED_ADDRESS_FAMILY_FOR_ONLINE_IPV6,
        REQUIRED_ADDRESS_FAMILY_FOR_ONLINE_BOTH,
        REQUIRED_ADDRESS_FAMILY_FOR_ONLINE_ANY,
        _REQUIRED_ADDRESS_FAMILY_FOR_ONLINE_MAX,
        _REQUIRED_ADDRESS_FAMILY_FOR_ONLINE_INVALID = -EINVAL,
} RequiredAddressFamilyForOnline;

typedef struct IPAddress {
        struct in_addr in;
        struct in6_addr in6;

        int family;
        int prefix_len;
        unsigned char scope;
        unsigned char flags;

        char *label;
        char *lifetime;
} IPAddress;

typedef struct IfNameIndex {
        int ifindex;

        char ifname[IFNAMSIZ];
} IfNameIndex;

int ip_to_str(int family, const struct IPAddress *u, char **ret);
int ip_to_str_prefix(int family, const struct IPAddress *u, char **ret);

int parse_ipv4(const char *s, IPAddress **ret);
int parse_ipv6(const char *s, IPAddress **ret);
int parse_ip(const char *s, IPAddress **ret);
int parse_ip_port(const char *s, IPAddress **ret, uint16_t *port);

int parse_ip_from_str(const char *s, IPAddress **ret);
int ipv4_netmask_to_prefixlen(IPAddress *addr);

bool ip4_addr_is_null(const IPAddress *a);
int ip_is_null(const IPAddress *a);

int parse_ifname_or_index(const char *s, IfNameIndex **ret);
char *ether_addr_to_string(const struct ether_addr *addr, char *s);
bool ether_addr_is_not_null(const struct ether_addr *addr);

char *mac_addr_to_string(const char *addr, char *buf);

int parse_mtu(char *mtu, uint32_t *ret);

int parse_group(char *mtu, uint32_t *ret);

bool valid_hostname(const char *host);
bool valid_ifname(const char *s);

const char *address_family_type_to_name(int id);
int address_family_name_to_type(const char *name);

const char *device_activation_policy_type_to_name(int id);
int device_activation_policy_name_to_type(const char *name);

const char *required_address_family_for_online_type_to_name(int id);
int required_address_family_for_online_name_to_type(const char *name);
