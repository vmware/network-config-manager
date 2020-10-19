/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <glib-object.h>
#include <gmodule.h>
#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>
#include <libnftnl/expr.h>
#include <libnftnl/table.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <linux/netfilter/nfnetlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <nftables/libnftables.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "alloc-util.h"
#include "file-util.h"
#include "macros.h"
#include "mnl_util.h"
#include "nftables.h"
#include "nft_rule_expr.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"

static const char* const nft_family_table[] = {
        [NF_PROTO_FAMILY_UNSPEC]   = "none",
        [NF_PROTO_FAMILY_INET]     = "ip",
        [NF_PROTO_FAMILY_IPV4]     = "ipv4",
        [NF_PROTO_FAMILY_ARP]      = "arp",
        [NF_PROTO_FAMILY_NETDEV]   = "netdev",
        [NF_PROTO_FAMILY_BRIDGE]   = "bridge",
        [NF_PROTO_FAMILY_IPV6]     = "ipv6",
};

const char *nft_family_to_name(int id) {
        if (id < 0)
                return "n/a";

        if ((size_t) id >= ELEMENTSOF(nft_family_table))
                return NULL;

        return nft_family_table[id];
}

int nft_family_name_to_type(char *name) {
        int i;

        assert(name);

        for (i = NF_PROTO_FAMILY_INET; i < (int) ELEMENTSOF(nft_family_table); i++)
                if (nft_family_table[i] && string_equal_fold(name, nft_family_table[i]))
                        return i;

        return _NF_PROTO_FAMILY_INVALID;
}

static const char* const nft_packet_action_table[] = {
        [NF_PACKET_ACTION_DROP]      = "drop",
        [NF_PACKET_ACTION_ACCEPT]    = "accept",
        [NF_PACKET_ACTION_NF_STOLEN] = "stolen",
        [NF_PACKET_ACTION_NF_QUEUE]  = "queue",
        [NF_PACKET_ACTION_NF_REPEAT] = "repeat",
        [NF_PACKET_ACTION_NF_STOP]   = "stop",
};

const char *nft_packet_action_to_name(int id) {
        if (id < 0)
                return "n/a";

        if ((size_t) id >= ELEMENTSOF(nft_packet_action_table))
                return NULL;

        return nft_packet_action_table[id];
}

int nft_packet_action_name_to_type(char *name) {
        int i;

        assert(name);

        for (i = NF_PACKET_ACTION_DROP; i < (int) ELEMENTSOF(nft_packet_action_table); i++)
                if (nft_packet_action_table[i] && string_equal_fold(name, nft_packet_action_table[i]))
                        return i;

        return _NF_PACKET_ACTION_INVALID;
}

static const char* const ip_packet_port_table[] = {
        [IP_PACKET_PORT_SPORT] = "sport",
        [IP_PACKET_PORT_DPORT] = "dport",
};

const char *ip_packet_port_type_to_name(int id) {
        if (id < 0)
                return "n/a";

        if ((size_t) id >= ELEMENTSOF(ip_packet_port_table))
                return NULL;

        return ip_packet_port_table[id];
}

int ip_packet_port_name_to_type(char *name) {
        int i;

        assert(name);

        for (i = IP_PACKET_PORT_SPORT; i < (int) ELEMENTSOF(ip_packet_port_table); i++)
                if (ip_packet_port_table[i] && string_equal_fold(name, ip_packet_port_table[i]))
                        return i;

        return _IP_PACKET_PORT_INVALID;
}

static const char* const ip_packet_protocol_table[] = {
        [IP_PACKET_PROTOCOL_TCP] = "tcp",
        [IP_PACKET_PROTOCOL_UDP] = "udp",
};

const char *ip_packet_protocol_type_to_name(int id) {
        if (id < 0)
                return "n/a";

        if ((size_t) id >= ELEMENTSOF(ip_packet_protocol_table))
                return NULL;

        return ip_packet_protocol_table[id];
}

void nft_ctx_unbuffer_output_unrefp(nft_ctx **t) {
        if (t && *t) {
                nft_ctx_unbuffer_output(*t);
                nft_ctx_free(*t);
        }
}

int ip_packet_protcol_name_to_type(char *name) {
        int i;

        assert(name);

        for (i = IP_PACKET_PROTOCOL_TCP; i < (int) ELEMENTSOF(ip_packet_protocol_table); i++)
                if (ip_packet_protocol_table[i] && string_equal_fold(name, ip_packet_protocol_table[i]))
                        return i;

        return _IP_PACKET_PROTOCOL_INVALID;
}

void nft_table_unrefp(NFTNLTable **t) {
        if (t && *t) {
                nftnl_table_free((*t)->table);
                free((*t)->name);
        }
}

int nft_table_new(int family, const char *name, NFTNLTable **ret) {
        _cleanup_(nft_table_unrefp) NFTNLTable *t = NULL;

        t = new(NFTNLTable, 1);
        if (!t)
                return -ENOMEM;

        *t = (NFTNLTable) {
                .family = family,
        };

        t->table = nftnl_table_alloc();
        if (!t->table)
                return -ENOMEM;

        nftnl_table_set_u32(t->table, NFTNL_TABLE_FAMILY, family);

        if (name) {
                nftnl_table_set_str(t->table, NFTNL_TABLE_NAME, name);
                t->name = strdup(name);
                if (!t->name)
                        return -ENOMEM;
        }

        *ret = steal_pointer(t);
        return 0;
}

void nft_chain_unrefp(NFTNLChain **c) {
        if (c && *c) {
                nftnl_chain_free((*c)->chain);

                free((*c)->name);
                free((*c)->table);
        }
}

int nft_chain_new(int family, const char *name, const char *table, NFTNLChain **ret) {
        _cleanup_(nft_chain_unrefp) NFTNLChain *c = NULL;

        c = new(NFTNLChain, 1);
        if (!c)
                return -ENOMEM;

        *c = (NFTNLChain) {
                .family = family,
        };

        c->chain = nftnl_chain_alloc();
        if (!c->chain)
                return -ENOMEM;

        if (table) {
                nftnl_chain_set_str(c->chain, NFTNL_CHAIN_TABLE, table);
                c->table = strdup(table);
                if (!c->table)
                        return -ENOMEM;
        }

        if (name) {
                nftnl_chain_set_str(c->chain, NFTNL_CHAIN_NAME, name);
                c->name = strdup(name);
                if (!c->name)
                        return -ENOMEM;
        }

        *ret = steal_pointer(c);
        return 0;
}

void nft_rule_unrefp(NFTNLRule **r) {
        if (r && *r) {
                nftnl_rule_free((*r)->rule);
                free((*r)->table);
                free((*r)->chain);
        }
}

int nft_rule_new(int family, const char *table, const char *chain, NFTNLRule **ret) {
        _cleanup_(nft_rule_unrefp) NFTNLRule *nf_rule = NULL;

        nf_rule = new(NFTNLRule, 1);
        if (!nf_rule)
                return -ENOMEM;

        *nf_rule = (NFTNLRule) {
                .family = family,
        };

        nf_rule->rule = nftnl_rule_alloc();
        if (!nf_rule->rule)
                return -ENOMEM;

        if (table) {
                nftnl_rule_set_str(nf_rule->rule, NFTNL_RULE_TABLE, table);
                nf_rule->table = strdup(table);
                if (!nf_rule->table)
                        return -ENOMEM;
        }

        if (chain) {
                nftnl_rule_set_str(nf_rule->rule, NFTNL_RULE_CHAIN, chain);
                nf_rule->table = strdup(table);
                if (!nf_rule->table)
                        return -ENOMEM;
        }

        nftnl_rule_set_u32(nf_rule->rule, NFTNL_RULE_FAMILY, family);

        *ret = steal_pointer(nf_rule);
        return 0;
}

static int generic_parser_data_attr_cb(const struct nlattr *attr, void *data) {
        const struct nlattr **tb;
        int type;

        assert(data);
        assert(attr);

        tb = data;
        type = mnl_attr_get_type(attr);

        tb[type] = attr;
        return MNL_CB_OK;
}

int nft_add_table(int family, const char *name) {
        _cleanup_(nft_table_unrefp) NFTNLTable *t = NULL;
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        int r;

        assert(name);

        r = nft_table_new(family, name, &t);
        if (r < 0)
                return r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        m->batch = mnl_nlmsg_batch_start(m->buf, MNL_SOCKET_BUFFER_SIZE);
        nftnl_batch_begin(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        m->nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(m->batch),
                                             NFT_MSG_NEWTABLE,
                                             family,
                                             NLM_F_CREATE|NLM_F_ACK, m->seq++);

        nftnl_table_nlmsg_build_payload(m->nlh, t->table);
        mnl_nlmsg_batch_next(m->batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        return mnl_send(m, 0, 0);
}

int nft_delete_table(int family, const char *name) {
        _cleanup_(nft_table_unrefp) NFTNLTable *t = NULL;
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        int r;

        assert(name);

        r = nft_table_new(family, name, &t);
        if (r < 0)
                return r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        m->batch = mnl_nlmsg_batch_start(m->buf, MNL_SOCKET_BUFFER_SIZE);
        nftnl_batch_begin(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        m->nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(m->batch),
                                             NFT_MSG_DELTABLE,
                                             family,
                                             NLM_F_CREATE|NLM_F_ACK, m->seq++);

        nftnl_table_nlmsg_build_payload(m->nlh, t->table);
        mnl_nlmsg_batch_next(m->batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        return mnl_send(m, 0, 0);
}

static int get_table_cb(const struct nlmsghdr *nlh, void *data) {
        struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
        _cleanup_(nft_table_unrefp) NFTNLTable *t = NULL;
        struct nlattr *tb[NFTA_TABLE_MAX+1] = {};
        const char *name = NULL;
        GPtrArray *s = data;
        int r;

        assert(nlh);
        assert(s);

        r = mnl_attr_parse(nlh, sizeof(*nfg), generic_parser_data_attr_cb, tb);
        if (r < 0)
                return MNL_CB_ERROR;

        if (tb[NFTA_TABLE_NAME])
                name = mnl_attr_get_str(tb[NFTA_TABLE_NAME]);

        r = nft_table_new(nfg->nfgen_family, name, &t);
        if (r < 0)
                return r;

        g_ptr_array_add(s, t);
        steal_pointer(t);

        return MNL_CB_OK;
}

int nft_get_tables(int family, GPtrArray **ret) {
        _cleanup_(g_ptr_array_unrefp) GPtrArray *s = NULL;
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        int r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        m->nlh = nftnl_table_nlmsg_build_hdr(m->buf, NFT_MSG_GETTABLE, family, NLM_F_DUMP, m->seq++);
        if (!m->nlh)
                return -ENOMEM;

        s = g_ptr_array_new();
        if (!s)
                return -ENOMEM;

        r = mnl_send(m, get_table_cb, s);
        if (r < 0)
                return r;

        *ret = steal_pointer(s);
        return 0;
}

int nft_add_chain(int family, const char *table, const char *name) {
        _cleanup_(nft_chain_unrefp) NFTNLChain *c = NULL;
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        int r;

        assert(name);
        assert(table);

        r = nft_chain_new(family, name, table, &c);
        if (r < 0)
                return r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        m->batch = mnl_nlmsg_batch_start(m->buf, MNL_SOCKET_BUFFER_SIZE);
        nftnl_batch_begin(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        m->nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(m->batch),
                                             NFT_MSG_NEWCHAIN,
                                             family,
                                             NLM_F_CREATE|NLM_F_ACK, m->seq++);

        nftnl_chain_nlmsg_build_payload(m->nlh, c->chain);
        mnl_nlmsg_batch_next(m->batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        return mnl_send(m, 0, 0);
}

static int get_chain_cb(const struct nlmsghdr *nlh, void *data) {
        struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
        _cleanup_(nft_chain_unrefp) NFTNLChain *c = NULL;
        struct nlattr *tb[NFTA_CHAIN_MAX+1] = {};
        const char *name = NULL, *table = NULL;
        GPtrArray *s = data;
        int r;

        assert(nlh);
        assert(s);

        r = mnl_attr_parse(nlh, sizeof(*nfg), generic_parser_data_attr_cb, tb);
        if (r < 0)
                return MNL_CB_ERROR;

        if (tb[NFTA_CHAIN_NAME])
                name = mnl_attr_get_str(tb[NFTA_CHAIN_NAME]);
        if (tb[NFTA_CHAIN_TABLE])
                table = mnl_attr_get_str(tb[NFTA_CHAIN_TABLE]);

        r = nft_chain_new(nfg->nfgen_family, name, table, &c);
        if (r < 0)
                return r;

        g_ptr_array_add(s, c);
        steal_pointer(c);

        return MNL_CB_OK;
}

int nft_get_chains(int family, GPtrArray **ret) {
        _cleanup_(g_ptr_array_unrefp) GPtrArray *s = NULL;
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        int r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        m->nlh = nftnl_chain_nlmsg_build_hdr(m->buf, NFT_MSG_GETCHAIN, family, NLM_F_DUMP, m->seq++);
        if (!m->nlh)
                return -ENOMEM;

        s = g_ptr_array_new();
        if (!s)
                return -ENOMEM;

        r = mnl_send(m, get_chain_cb, s);
        if (r < 0)
                return r;

        *ret = steal_pointer(s);
        return 0;
}

int nft_delete_chain(int family, const char *table, const char *name) {
        _cleanup_(nft_chain_unrefp) NFTNLChain *c = NULL;
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        int r;

        assert(name);
        assert(table);

        r = nft_chain_new(family, name, table, &c);
        if (r < 0)
                return r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        m->batch = mnl_nlmsg_batch_start(m->buf, MNL_SOCKET_BUFFER_SIZE);
        nftnl_batch_begin(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        m->nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(m->batch),
                                             NFT_MSG_DELCHAIN,
                                             family,
                                             NLM_F_CREATE|NLM_F_ACK, m->seq++);

        nftnl_chain_nlmsg_build_payload(m->nlh, c->chain);
        mnl_nlmsg_batch_next(m->batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        return mnl_send(m, 0, 0);
}

int nft_configure_rule_port(int family,
                            const char *table,
                            const char *chain,
                            IPPacketProtocol protocol,
                            IPPacketPort port_type,
                            uint16_t port,
                            NFPacketAction action) {

        _cleanup_(nft_rule_unrefp) NFTNLRule *nf_rule = NULL;
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        uint16_t k;
        int r;

        assert(table);
        assert(chain);
        assert(port);

        r = nft_rule_new(family, table, chain, &nf_rule);
        if (r < 0)
                return r;

        nf_add_payload(nf_rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, offsetof(struct iphdr, protocol), sizeof(uint8_t));
        nf_add_cmp(nf_rule, NFT_REG_1, NFT_CMP_EQ, &protocol, sizeof(uint8_t));

        k = htobe16(port);

        if (family == NF_PROTO_FAMILY_IPV4 || family == NF_PROTO_FAMILY_INET) {
                if (protocol == IP_PACKET_PROTOCOL_TCP) {
                        if (port_type == IP_PACKET_PORT_DPORT)
                                nf_add_payload(nf_rule, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1, offsetof(struct tcphdr, dest), sizeof(uint16_t));
                        else
                                nf_add_payload(nf_rule, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1, offsetof(struct tcphdr, source), sizeof(uint16_t));
                } else {
                        if (port_type == IP_PACKET_PORT_DPORT)
                                nf_add_payload(nf_rule, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1, offsetof(struct udphdr, dest), sizeof(uint16_t));
                        else
                                nf_add_payload(nf_rule, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1, offsetof(struct udphdr, source), sizeof(uint16_t));
                }
        }

        nf_add_cmp(nf_rule, NFT_REG_1, NFT_CMP_EQ, &k, sizeof(uint16_t));
        nf_add_counter(nf_rule);
        nf_add_immediate_verdict(nf_rule, action, chain);

        r = mnl_new(&m);
        if (r < 0)
                return r;

        m->batch = mnl_nlmsg_batch_start(m->buf, MNL_SOCKET_BUFFER_SIZE);
        nftnl_batch_begin(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        m->nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(m->batch),
                                             NFT_MSG_NEWRULE,
                                             family,
                                             NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, m->seq++);

        nftnl_rule_nlmsg_build_payload(m->nlh, nf_rule->rule);
        mnl_nlmsg_batch_next(m->batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        return mnl_send(m, 0, 0);
}

int nft_get_rules(const char *table, GString **ret) {
        _cleanup_(nft_ctx_unbuffer_output_unrefp) struct nft_ctx *nft = NULL;
        _cleanup_(g_string_unrefp) GString *o = NULL;
        _auto_cleanup_ char *c = NULL;
        const char *v = NULL;

        assert(table);

        c = string_join(" ", "list table", table, NULL);
        if (!c)
                return -ENOMEM;

        nft = nft_ctx_new(NFT_CTX_DEFAULT);
        if (!nft)
                return -ENOMEM;

        if (nft_ctx_buffer_output(nft) || nft_run_cmd_from_buffer(nft, c))
                return -ENODATA;

        v = nft_ctx_get_output_buffer(nft);
        if (isempty_string(v))
                return -ENODATA;

        o = g_string_new(v);
        if (!o)
                return -ENOMEM;

        *ret = steal_pointer(o);
        return 0;
}

int nft_delete_rule(int family, const char *table, const char *chain, int handle) {
        _cleanup_(nft_rule_unrefp) NFTNLRule *rl = NULL;
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        int r;

        assert(table);
        assert(chain);

        r = nft_rule_new(family, table, chain, &rl);
        if (r < 0)
                return r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        if (handle > 0)
                nftnl_rule_set_u64(rl->rule, NFTNL_RULE_HANDLE, handle);

        m->batch = mnl_nlmsg_batch_start(m->buf, MNL_SOCKET_BUFFER_SIZE);
        nftnl_batch_begin(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        m->nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(m->batch),
                                             NFT_MSG_DELRULE,
                                             family,
                                             NLM_F_CREATE|NLM_F_ACK, m->seq++);

        nftnl_rule_nlmsg_build_payload(m->nlh, rl->rule);
        mnl_nlmsg_batch_next(m->batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        return mnl_send(m, 0, 0);
}
