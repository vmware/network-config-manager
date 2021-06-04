/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "alloc-util.h"
#include "log.h"
#include "netlink-message.h"

int ip_link_message_new(int type, int family, int ifindex, IPlinkMessage **ret) {
        IPlinkMessage *m;

        m = new0(IPlinkMessage, 1);
        if (!m)
                return log_oom();

        *m = (IPlinkMessage) {
                .hdr.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
                .hdr.nlmsg_type  = type,
                .hdr.nlmsg_seq   = time(NULL),
                .hdr.nlmsg_pid   = getpid(),
                .ifi.ifi_family  = family,
                .ifi.ifi_index   = ifindex,
        };

        *ret = steal_pointer(m);

        return 0;
}

int ip_address_message_new(int type, int family, int ifindex, IPAddressMessage **ret) {
        IPAddressMessage *m;

        m = new0(IPAddressMessage, 1);
        if (!m)
                return log_oom();

        *m = (IPAddressMessage) {
                 .hdr.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
                 .hdr.nlmsg_type  = type,
                 .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
                 .hdr.nlmsg_seq   = time(NULL),
                 .hdr.nlmsg_pid   = getpid(),
                 .ifm.ifa_family  = family,
                 .ifm.ifa_index   = ifindex,
        };

        *ret = steal_pointer(m);

        return 0;
}

int ip_route_message_new(int type, int family, char rtm_protocol, IPRouteMessage **ret) {
        IPRouteMessage *m;

        m = new0(IPRouteMessage, 1);
        if (!m)
                return log_oom();

        *m = (IPRouteMessage) {
                .hdr.nlmsg_len    = NLMSG_LENGTH(sizeof(struct rtmsg)),
                .hdr.nlmsg_type   = type,
                .hdr.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK,
                .hdr.nlmsg_seq    = time(NULL),
                .hdr.nlmsg_pid    = getpid(),
                .rtm.rtm_family   = family,
                .rtm.rtm_scope    = RT_SCOPE_UNIVERSE,
                .rtm.rtm_type     = RTN_UNICAST,
                .rtm.rtm_table    = RT_TABLE_MAIN,
                .rtm.rtm_protocol = rtm_protocol,
        };

        if (type == RTM_NEWROUTE)
                m->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_APPEND;

        *ret = steal_pointer(m);

        return 0;
}
