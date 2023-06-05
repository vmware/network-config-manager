/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <linux/fib_rules.h>

#include "macros.h"
#include "netlink-message.h"
#include "netlink.h"
#include "network-link.h"
#include "network-util.h"
#include "set.h"

typedef struct RoutingPolicyRule {
        int family;

        bool invert_rule;
        bool priority_set;

        uint8_t tos;
        uint8_t action;
        uint8_t type;
        uint8_t ipproto; /* FRA_IP_PROTO */
        uint8_t protocol; /* FRA_PROTOCOL */
        uint8_t to_prefixlen;
        uint8_t from_prefixlen;
        uint8_t l3mdev; /* FRA_L3MDEV */

        uint32_t table;
        uint32_t fwmark;
        uint32_t fwmask;
        uint32_t priority;
        uint32_t flags;

        char *iif;
        char *oif;

        IPAddress to;
        IPAddress from;

        struct fib_rule_port_range sport;
        struct fib_rule_port_range dport;

        char *sport_str;
        char *dport_str;
        char *ipproto_str;

        struct fib_rule_uid_range uid_range;

        int suppress_prefixlen;
        int32_t suppress_ifgroup;
} RoutingPolicyRule;

typedef struct RoutingPolicyRules {
        int ifindex;
        Set *routing_policy_rules;
} RoutingPolicyRules;

void routing_policy_rules_free(RoutingPolicyRules *routing_policy_rules);
DEFINE_CLEANUP(RoutingPolicyRules *, routing_policy_rules_free);

int routing_policy_rule_new(RoutingPolicyRule **ret);
void routing_policy_rule_free(RoutingPolicyRule *rule);

DEFINE_CLEANUP(RoutingPolicyRule *, routing_policy_rule_free);
int acquire_routing_policy_rules(RoutingPolicyRules **ret);
