/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "netlink-message.h"
#include "netlink.h"
#include "network-link.h"
#include "netlink-missing.h"
#include "parse-util.h"
#include "string-util.h"
#include "mnl_util.h"

static const char* const link_operstates_table[] = {
        [IF_OPER_UNKNOWN]        = "unknown",
        [IF_OPER_NOTPRESENT]     = "not-present",
        [IF_OPER_DOWN]           = "down",
        [IF_OPER_LOWERLAYERDOWN] = "lower-layerdown",
        [IF_OPER_TESTING]        = "testing",
        [IF_OPER_DORMANT]        = "dormant",
        [IF_OPER_UP]             = "up",
};

const char *link_operstates_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(link_operstates_table))
                return NULL;

        return link_operstates_table[id];
}

static const char* const link_states_table[_LINK_STATE_MAX] = {
        [LINK_STATE_DOWN] = "down",
        [LINK_STATE_UP]   = "up",
};

const char *link_state_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(link_states_table))
                return NULL;

        return link_states_table[id];
}

int link_name_to_state(char *name) {
        assert(name);

        for (size_t i = LINK_STATE_DOWN; i < (int) ELEMENTSOF(link_states_table); i++)
                if (streq_fold(name, link_states_table[i]))
                        return i;

        return _LINK_STATE_INVALID;
}

static const char* const ipv6_address_generation_mode_table[] = {
        [IPV6_ADDRESSS_GEN_MODE_EUI64]          = "eui64",
        [IPV6_ADDRESSS_GEN_MODE_NONE]           = "none",
        [IPV6_ADDRESSS_GEN_MODE_STABLE_PRIVACY] = "stable-privacy",
        [IPV6_ADDRESSS_GEN_MODE_RANDOM]         = "random",
};

const char *ipv6_address_generation_mode_to_name(int mode) {
        if (mode < 0)
                return NULL;

        if ((size_t) mode >= ELEMENTSOF(ipv6_address_generation_mode_table))
                return NULL;

        return ipv6_address_generation_mode_table[mode];
}

static int links_new(Links **ret) {
        Links *h = NULL;

        h = new0(Links, 1);
        if (!h)
                return log_oom();

        *ret = h;
        return 0;
}

static int link_new(Link **ret) {
        Link *link = NULL;

        link = new0(Link, 1);
        if (!link)
                return log_oom();

        *ret = link;
        return 0;
}

void link_free(Link *l) {
        if (!l)
                return;

        if (l->alt_names)
                g_ptr_array_free(l->alt_names, true);

        free(l->qdisc);
        free(l->kind);
        free(l->parent_dev);
        free(l->parent_bus);
        free(l);
}

void links_free(Links *l) {
        if (!l)
                return;

        g_list_free_full(g_list_first(l->links), g_free);
        free(l);
}

static int link_add(Links **h, Link *link) {
        int r;

        assert(h);
        assert(link);

        if (!*h) {
                r = links_new(h);
                if (r < 0)
                        return r;
        }

        (*h)->links = g_list_append((*h)->links, link);
        return 0;
}

static int parse_link_info_cb(const struct nlattr *attr, void *data) {
        const struct nlattr **tb = data;
        int type = mnl_attr_get_type(attr);

        if (mnl_attr_type_valid(attr, IFLA_INFO_SLAVE_DATA) < 0)
                return MNL_CB_OK;

        tb[type] = attr;
        return MNL_CB_OK;
}

static int parse_link_info(struct nlattr *nest, Link *l) {
        struct nlattr *tb[IFLA_INFO_MAX+1] = {};

        assert(l);

        mnl_attr_parse_nested(nest, parse_link_info_cb, tb);

        if (tb[IFLA_INFO_KIND]) {
                l->kind = strdup(mnl_attr_get_str(tb[IFLA_INFO_KIND]));
                if (!l->kind)
                        return -ENOMEM;
        }

        return 0;
}

static int data_attr_cb(const struct nlattr *attr, void *data) {
        int type = mnl_attr_get_type(attr);
        const struct nlattr **tb = data;

        if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
                return MNL_CB_OK;

        switch(type) {
        case IFLA_ADDRESS:
                if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
                        return MNL_CB_ERROR;
                break;
        case IFLA_MTU:
                if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
                        return MNL_CB_ERROR;
                break;
        case IFLA_IFNAME:
                if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
                        return MNL_CB_ERROR;
                break;
        }

        tb[type] = attr;
        return MNL_CB_OK;
}

static int fill_one_link_info(const struct nlmsghdr *nlh, void *data) {
        struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
        struct nlattr *tb[2 * IFLA_MAX] = {};
        _auto_cleanup_ Link *l = NULL;
        Links *links = data;
        int r;

        assert(nlh);
        assert(data);

        r = link_new(&l);
        if (r < 0)
                return r;

        *l = (Link) {
              .ifindex = ifm->ifi_index,
              .iftype = ifm->ifi_type,
              .flags = ifm->ifi_flags,
              .family = ifm->ifi_family,
        };

        if (links->ifindex != 0 && links->ifindex != l->ifindex)
                return MNL_CB_OK;

        log_debug("index=%d type=%d flags=%d family=%d", ifm->ifi_index, ifm->ifi_type, ifm->ifi_flags, ifm->ifi_family);

        mnl_attr_parse(nlh, sizeof(*ifm), data_attr_cb, tb);

        if (tb[IFLA_IFNAME])
                memcpy(l->name, mnl_attr_get_str(tb[IFLA_IFNAME]), IFNAMSIZ);

        if (tb[IFLA_IFALIAS])
                memcpy(l->alias, mnl_attr_get_str(tb[IFLA_IFALIAS]), IFNAMSIZ);

        if (tb[IFLA_MTU]) {
                l->mtu = mnl_attr_get_u32(tb[IFLA_MTU]);
                l->contains_mtu = true;
        }

        if (tb[IFLA_QDISC]) {
                l->qdisc = strdup(mnl_attr_get_str(tb[IFLA_QDISC]));
                if (!l->qdisc)
                        return log_oom();
        }

        if (tb[IFLA_PARENT_DEV_NAME]) {
                l->parent_dev = strdup(mnl_attr_get_str(tb[IFLA_PARENT_DEV_NAME]));
                if (!l->parent_dev)
                        return log_oom();
        }

        if (tb[IFLA_PARENT_DEV_BUS_NAME]) {
                l->parent_bus = strdup(mnl_attr_get_str(tb[IFLA_PARENT_DEV_BUS_NAME]));
                if (!l->parent_bus)
                        return log_oom();
        }

        if (tb[IFLA_LINK_NETNSID])
                l->netnsid = mnl_attr_get_u32(tb[IFLA_LINK_NETNSID]);

        if (tb[IFLA_NEW_NETNSID])
                l->new_netnsid = mnl_attr_get_u32(tb[IFLA_NEW_NETNSID]);

        if (tb[IFLA_NEW_IFINDEX])
                l->new_ifindex = mnl_attr_get_u32(tb[IFLA_NEW_IFINDEX]);

        if (tb[IFLA_GROUP])
                l->group = mnl_attr_get_u32(tb[IFLA_GROUP]);

        if (tb[IFLA_EVENT])
                l->event = mnl_attr_get_u32(tb[IFLA_EVENT]);

        if (tb[IFLA_MASTER])
                l->master = mnl_attr_get_u32(tb[IFLA_MASTER]);

        if (tb[IFLA_MIN_MTU])
                l->min_mtu = mnl_attr_get_u32(tb[IFLA_MIN_MTU]);

        if (tb[IFLA_MAX_MTU])
                l->max_mtu = mnl_attr_get_u32(tb[IFLA_MAX_MTU]);

        if (tb[IFLA_TXQLEN])
                l->tx_queue_len = mnl_attr_get_u32(tb[IFLA_TXQLEN]);

        if (tb[IFLA_NUM_TX_QUEUES])
                l->n_tx_queues = mnl_attr_get_u32(tb[IFLA_NUM_TX_QUEUES]);

        if (tb[IFLA_NUM_RX_QUEUES])
                l->n_rx_queues = mnl_attr_get_u32(tb[IFLA_NUM_RX_QUEUES]);

        if (tb[IFLA_GSO_MAX_SIZE])
                l->gso_max_size = mnl_attr_get_u32(tb[IFLA_GSO_MAX_SIZE]);

        if (tb[IFLA_GSO_MAX_SEGS])
                l->gso_max_segments = mnl_attr_get_u32(tb[IFLA_GSO_MAX_SEGS]);

        if (tb[IFLA_TSO_MAX_SIZE])
                l->tso_max_size = mnl_attr_get_u32(tb[IFLA_TSO_MAX_SIZE]);

        if (tb[IFLA_TSO_MAX_SEGS])
                l->tso_max_segments = mnl_attr_get_u32(tb[IFLA_TSO_MAX_SEGS]);

        if (tb[IFLA_GRO_MAX_SIZE])
                l->gro_max_size = mnl_attr_get_u32(tb[IFLA_GRO_MAX_SIZE]);

        if (tb[IFLA_GSO_IPV4_MAX_SIZE])
                l->gso_ipv4_max_size = mnl_attr_get_u32(tb[IFLA_GSO_IPV4_MAX_SIZE]);

        if (tb[IFLA_GRO_IPV4_MAX_SIZE])
                l->gro_ipv4_max_size = mnl_attr_get_u32(tb[IFLA_GRO_IPV4_MAX_SIZE]);

        if (tb[IFLA_OPERSTATE])
                l->operstate = mnl_attr_get_u8(tb[IFLA_OPERSTATE]);

        if (tb[IFLA_INET6_ADDR_GEN_MODE])
                l->ipv6_addr_gen_mode = mnl_attr_get_u8(tb[IFLA_INET6_ADDR_GEN_MODE]);

        if (tb[IFLA_ADDRESS]) {
                memcpy(&l->mac_address, mnl_attr_get_payload(tb[IFLA_ADDRESS]), sizeof(struct ether_addr));
                l->contains_mac_address = true;
        }

        if (tb[IFLA_PERM_ADDRESS]) {
                memcpy(&l->perm_address, mnl_attr_get_payload(tb[IFLA_PERM_ADDRESS]), sizeof(struct ether_addr));
                l->contains_perm_address = true;
        }

        if (tb[IFLA_STATS64]) {
                memcpy(&l->stats64, mnl_attr_get_payload(tb[IFLA_STATS64]), sizeof(struct rtnl_link_stats64));
                l->contains_stats64 = true;
        }

        if (tb[IFLA_STATS]) {
                memcpy(&l->stats, mnl_attr_get_payload(tb[IFLA_STATS]), sizeof(struct rtnl_link_stats));
                l->contains_stats = true;
        }

        if (tb[IFLA_PROP_LIST]) {
                struct rtattr *i, *j = (struct rtattr *) tb[IFLA_PROP_LIST];
                int k = RTA_PAYLOAD(j);
                GPtrArray *s;
                char *a;

                s = g_ptr_array_new();
                if (!s)
                        return log_oom();
                for (i = RTA_DATA(j); RTA_OK(i, k); i = RTA_NEXT(i, k)) {
                        a = strdup(rtnl_message_read_attribute_string(i));
                        if (!a)
                                return -ENOMEM;

                        g_ptr_array_add(s, a);
                }

                l->alt_names = steal_ptr(s);
        }

        if (tb[IFLA_LINKINFO]) {
                r = parse_link_info(tb[IFLA_LINKINFO], l);
                if (r < 0)
                        return r;
        }

        r = link_add(&links, l);
        if (r < 0)
                return r;

        steal_ptr(l);
        return MNL_CB_OK;
}

static int acquire_one_link_info(int ifindex, Links **ret) {
        _cleanup_(mnl_freep) Mnl *m = NULL;
        struct nlmsghdr *nlh;
        Links *links = NULL;
        int r;

        assert(ret);

        r = mnl_new(&m);
        if (r < 0)
                return r;

        nlh = mnl_nlmsg_put_header(m->buf);
        nlh->nlmsg_type = RTM_GETLINK;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
        m->nlh = nlh;

        r = links_new(&links);
        if (r < 0)
                return r;

        links->ifindex = ifindex;
        r = mnl_send(m, fill_one_link_info, links, NETLINK_ROUTE);
        if (r < 0)
                return r;

        *ret = steal_ptr(links);
        return 0;
}

int netlink_acqure_one_link(const char *ifname, Link **ret) {
        Links *links = NULL;
        int r, ifindex;

        assert(ifname);
        assert(ret);

        ifindex = (int) if_nametoindex(ifname);
        if (ifindex <= 0)
                return -errno;

        r = links_new(&links);
        if (r < 0)
                return r;

        r = acquire_one_link_info(ifindex, &links);
        if (r < 0)
                return r;

        *ret = g_list_first(links->links)->data;
        return 0;
}

int netlink_acquire_all_links(Links **ret) {
        _cleanup_(mnl_freep) Mnl *m = NULL;
        struct nlmsghdr *nlh;
        Links *links = NULL;
        int r;

        assert(ret);

        r = mnl_new(&m);
        if (r < 0)
                return r;

        nlh = mnl_nlmsg_put_header(m->buf);
        nlh->nlmsg_type = RTM_GETLINK;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
        m->nlh = nlh;

        r = links_new(&links);
        if (r < 0)
                return r;

        r = mnl_send(m, fill_one_link_info, links, NETLINK_ROUTE);
        if (r < 0)
                return r;

        *ret = links;
        return 0;
}

int netlink_remove_link(const IfNameIndex *ifidx) {
        _auto_cleanup_ IPlinkMessage *m = NULL;
        _auto_cleanup_close_ int s = -1;
        int r;

        assert(ifidx);

        r = ip_link_message_new(RTM_DELLINK, AF_UNSPEC, ifidx->ifindex, &m);
        if (r < 0)
                return r;

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        return netlink_call(s, &m->hdr, m->buf, sizeof(m->buf));
}

int link_read_sysfs_attribute(const char *ifname, const char *attribute, char **ret) {
        _auto_cleanup_ char *line = NULL, *path = NULL;
        int r;

        assert(ifname);
        assert(attribute);

        path = g_build_path("/", "/sys/class/net", ifname, attribute, NULL);
        if (!path)
                return log_oom();

        if (!g_file_test(path, G_FILE_TEST_EXISTS))
               return -ENOENT;

        r = read_one_line(path, &line);
        if (r < 0)
                return r;

        truncate_newline(line);

        *ret = steal_ptr(line);
        return 0;
}

int netlink_set_link_state(const IfNameIndex *ifidx, LinkState state) {
        _auto_cleanup_ IPlinkMessage *m = NULL;
        _auto_cleanup_ char *operstate = NULL;
        _auto_cleanup_close_ int s = -1;
        int r;

        assert(ifidx);

        r = netlink_acquire_link_operstate(ifidx->ifname, &operstate);
        if (r < 0) {
                log_warning("Failed to get link operstate: %s\n", ifidx->ifname);
                return r;
        }

        if ((int) state == link_name_to_state(operstate))
                return 0;

        r = ip_link_message_new(RTM_SETLINK, AF_UNSPEC, ifidx->ifindex, &m);
        if (r < 0)
                return r;

        switch (state) {
        case LINK_STATE_UP:
                SET_FLAG(m->ifi.ifi_change, IFF_UP, state);
                SET_FLAG(m->ifi.ifi_flags, IFF_UP, state);
                break;
        case LINK_STATE_DOWN:
                SET_FLAG(m->ifi.ifi_change, IFF_UP, IFF_UP);
                SET_FLAG(m->ifi.ifi_flags, ~IFF_UP, ~IFF_UP);
                break;
        default:
                assert(0);
        }

        r = rtnl_socket_open(0, &s);
        if (r < 0)
                return r;

        return netlink_call(s, &m->hdr, m->buf, sizeof(m->buf));
}

int netlink_acquire_link_mtu(const char *ifname, uint32_t *mtu) {
        _auto_cleanup_ Link *l = NULL;
        int r;

        r = netlink_acqure_one_link(ifname, &l);
        if (r < 0)
                return r;

        *mtu = l->mtu;
        return 0;
}

int netlink_acquire_link_mac_address(const char *ifname, char **mac) {
        _auto_cleanup_ Link *l = NULL;
        _auto_cleanup_ char *s = NULL;
        int r;

        r = netlink_acqure_one_link(ifname, &l);
        if (r < 0)
                return r;

        s = new0(char, ETHER_ADDR_TO_STRING_MAX);
        if (!s)
                return -ENOMEM;

        sprintf(s, ETHER_ADDR_FORMAT_STR, ETHER_ADDR_FORMAT_VAL(l->mac_address));
        *mac = steal_ptr(s);

        return 0;
}

int netlink_acquire_link_operstate(const char *ifname, char **operstate) {
        _auto_cleanup_ Link *l = NULL;
        int r;

        r = netlink_acqure_one_link(ifname, &l);
        if (r < 0)
                return r;

        *operstate = strdup(link_operstates_to_name(l->operstate));
        return 0;
}
