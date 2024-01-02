/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "log.h"
#include "network-routing-policy-rule.h"
#include "netlink-missing.h"
#include "mnl_util.h"
#include "network-util.h"

int routing_policy_rule_new(RoutingPolicyRule **ret) {
        RoutingPolicyRule *rule;

        assert(ret);

        rule = new(RoutingPolicyRule, 1);
        if (!rule)
                return log_oom();

        *rule = (RoutingPolicyRule) {
                .table = RT_TABLE_MAIN,
                .uid_range.start = ((uid_t) -1),
                .uid_range.end = ((uid_t) -1),
                .suppress_prefixlen = -1,
                .suppress_ifgroup = -1,
                .protocol = RTPROT_UNSPEC,
                .type = FR_ACT_TO_TBL,
                .priority = UINT_MAX,
                .tos = UINT8_MAX,
                .fwmark = UINT_MAX,
        };

        *ret = rule;
        return 0;
}

void routing_policy_rule_free(RoutingPolicyRule *rule) {
        if (!rule)
                return;

        free(rule->sport_str);
        free(rule->dport_str);
        free(rule->ipproto_str);
        free(rule);
}

static int routing_policy_rules_new(RoutingPolicyRules **ret) {
        RoutingPolicyRules *rule;
        int r;

        rule = new0(RoutingPolicyRules, 1);
        if (!rule)
                return log_oom();

        r = set_new(&rule->routing_policy_rules, g_direct_hash, g_direct_equal);
        if (r < 0)
                return r;

        *ret = steal_ptr(rule);
        return 0;
}

void routing_policy_rules_free(RoutingPolicyRules *routing_policy_rules) {
        GHashTableIter iter;
        gpointer key, value;
        unsigned long size;

        if (!routing_policy_rules)
                return;

        g_hash_table_iter_init(&iter, routing_policy_rules->routing_policy_rules->hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                RoutingPolicyRule *rule;

                rule = (RoutingPolicyRule *) g_bytes_get_data(key, &size);
                free(rule);

                g_bytes_unref(key);
                g_hash_table_iter_remove(&iter);
        }

        set_freep(&routing_policy_rules->routing_policy_rules);
        free(routing_policy_rules);
}

static int routing_policy_rule_add(RoutingPolicyRules **rules, RoutingPolicyRule *rule) {
        GBytes *b = NULL;
        int r;

        assert(rules);
        assert(rule);

        if (!*rules) {
                r = routing_policy_rules_new(rules);
                if (r < 0)
                        return r;
        }

        b = g_bytes_new_with_free_func(rule, sizeof(RoutingPolicyRule), g_free, NULL);
        if (!b)
                return log_oom();

        if (!set_contains((*rules)->routing_policy_rules, b))
                return set_add((*rules)->routing_policy_rules, b);

        return -EEXIST;
}

static int routing_policy_rule_data_attr_cb(const struct nlattr *attr, void *data) {
        int type = mnl_attr_get_type(attr);
        const struct nlattr **tb = data;

        if (mnl_attr_type_valid(attr, FRA_MAX) < 0)
                return MNL_CB_OK;

        tb[type] = attr;
        return MNL_CB_OK;
}

static int fill_link_routing_policy_rule_message(RoutingPolicyRule *rule, struct nlattr *tb[]) {
        assert(rule);
        assert(tb);

        if (tb[FRA_TABLE])
                rule->table = mnl_attr_get_u32(tb[FRA_TABLE]);

        if (tb[FRA_SUPPRESS_PREFIXLEN])
                rule->suppress_prefixlen = mnl_attr_get_u32(tb[FRA_SUPPRESS_PREFIXLEN]);

        if (tb[FRA_SUPPRESS_IFGROUP])
                rule->suppress_ifgroup = mnl_attr_get_u32(tb[FRA_SUPPRESS_IFGROUP]);

        if (tb[FRA_SRC]) {
                if (rule->family == AF_INET)
                        memcpy(&rule->from.in, mnl_attr_get_payload(tb[FRA_SRC]), sizeof(struct in_addr));
                else
                        memcpy(&rule->from.in6, mnl_attr_get_payload(tb[FRA_SRC]), sizeof(struct in6_addr));

                rule->from.family = rule->family;
        }

        if (tb[FRA_DST]) {
                if (rule->family == AF_INET)
                        memcpy(&rule->to.in, mnl_attr_get_payload(tb[FRA_DST]), sizeof(struct in_addr));
                else
                        memcpy(&rule->to.in6, mnl_attr_get_payload(tb[FRA_DST]), sizeof(struct in6_addr));

                rule->to.family = rule->family;
        }

        if (tb[FRA_PROTOCOL])
                rule->protocol = mnl_attr_get_u8(tb[FRA_PROTOCOL]);

        if (tb[FRA_L3MDEV])
                rule->l3mdev = mnl_attr_get_u8(tb[FRA_L3MDEV]);

        if (tb[FRA_IP_PROTO]) {
                rule->ipproto = mnl_attr_get_u8(tb[FRA_IP_PROTO]);
                rule->ipproto_set = true;
        }

        if (tb[FRA_FWMARK])
                rule->fwmark = mnl_attr_get_u32(tb[FRA_FWMARK]);

        if (tb[FRA_FWMASK])
                rule->fwmask = mnl_attr_get_u32(tb[FRA_FWMASK]);

        if (tb[FRA_PRIORITY])
                rule->priority = mnl_attr_get_u32(tb[FRA_PRIORITY]);

        if (tb[FRA_IFNAME]) {
                rule->iif = strdup(mnl_attr_get_str(tb[FRA_IFNAME]));
                if (!rule->iif)
                        return -ENOMEM;
        }

        if (tb[FRA_OIFNAME]) {
                rule->oif = strdup(mnl_attr_get_str(tb[FRA_OIFNAME]));
                if (!rule->oif)
                        return -ENOMEM;
        }

        if (tb[FRA_SPORT_RANGE])
                memcpy(&rule->sport, mnl_attr_get_payload(tb[FRA_SPORT_RANGE]), sizeof(struct fib_rule_port_range));


        if (tb[FRA_DPORT_RANGE])
                memcpy(&rule->dport, mnl_attr_get_payload(tb[FRA_DPORT_RANGE]), sizeof(struct fib_rule_port_range));

        return 0;
}

static int fill_routing_policy_rule(const struct nlmsghdr *nlh, void *data) {
        RoutingPolicyRules *rules = (RoutingPolicyRules *) data;
       _auto_cleanup_ RoutingPolicyRule *rule = NULL;
        struct nlattr *tb[FRA_MAX * 2] = {};
        struct fib_rule_hdr *rtm;
        int r;

        assert(data);
        assert(nlh);

        rtm = mnl_nlmsg_get_payload(nlh);
        r = routing_policy_rule_new(&rule);
        if (r < 0)
                return r;

        *rule = (RoutingPolicyRule) {
                .family = rtm->family,
                .table = rtm->table,
                .flags = rtm->flags,
                .to_prefixlen = rtm->dst_len,
                .from_prefixlen= rtm->src_len,
                .tos = rtm->tos,
                .action = rtm->action,
                .invert_rule = rtm->flags & FIB_RULE_INVERT,
             };

        mnl_attr_parse(nlh, sizeof(*rtm), routing_policy_rule_data_attr_cb, tb);
        fill_link_routing_policy_rule_message(rule, tb);

        r = routing_policy_rule_add(&rules, rule);
        if (r < 0)
                return r;

        steal_ptr(rule);
        return MNL_CB_OK;
}

int acquire_routing_policy_rules(RoutingPolicyRules **ret) {
        _cleanup_(mnl_freep) Mnl *m = NULL;
        RoutingPolicyRules *rules = NULL;
        struct nlmsghdr *nlh;
        int r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        nlh = mnl_nlmsg_put_header(m->buf);
        nlh->nlmsg_type = RTM_GETRULE;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        nlh->nlmsg_seq = time(NULL);
        mnl_nlmsg_put_extra_header(nlh, sizeof(struct fib_rule_hdr));
        m->nlh = nlh;

        r = routing_policy_rules_new(&rules);
        if (r < 0)
                return r;

        r = mnl_send(m, fill_routing_policy_rule, rules, NETLINK_ROUTE);
        if (r < 0)
                return r;

        *ret = rules;
        return 0;
}
