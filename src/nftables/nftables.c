/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <assert.h>
#include <string.h>
#include <time.h>
#include <glib-object.h>
#include <gmodule.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>
#include <libnftnl/table.h>

#include "alloc-util.h"
#include "file-util.h"
#include "macros.h"
#include "mnl_util.h"
#include "nftables.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"

static const char* const nft_family[] = {
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

        if ((size_t) id >= ELEMENTSOF(nft_family))
                return NULL;

        return nft_family[id];
}

int nft_family_name_to_type(char *name) {
        int i;

        assert(name);

        for (i = NF_PROTO_FAMILY_INET; i < (int) ELEMENTSOF(nft_family); i++)
                if (string_equal_fold(name, nft_family[i]))
                        return i;

        return _NF_PROTO_FAMILY_INVALID;
}

void nft_table_unref(NFTNLTable **t) {
        if (t && *t) {
                nftnl_table_free((*t)->table);
                free((*t)->name);
        }
}

int nft_table_new(int family, const char *name, NFTNLTable **ret) {
        _cleanup_(nft_table_unref) NFTNLTable *t = NULL;

        t = new(NFTNLTable, 1);
        if (!t)
                return -ENOMEM;

        *t = (NFTNLTable) {
                .family = family,
        };

        t->table = nftnl_table_alloc();
        if (!t->table)
                return log_oom();

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

void nft_chain_unref(struct nftnl_chain **c) {
        if (c && *c)
                nftnl_chain_free(*c);
}

int nft_chain_new(int family, const char *name, const char *table, struct nftnl_chain **ret) {
        struct nftnl_chain *c = NULL;

        c = nftnl_chain_alloc();
        if (!c)
                return log_oom();

        if (table)
                nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, table);
        if (name)
                nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, name);

        *ret = steal_pointer(c);
        return 0;
}

int nft_add_table(int family, const char *name) {
        _cleanup_(nft_table_unref) NFTNLTable *t = NULL;
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

static int generic_parrse_data_attr_cb(const struct nlattr *attr, void *data) {
        const struct nlattr **tb;
        int type;

        assert(data);
        assert(attr);

        tb = data;
        type = mnl_attr_get_type(attr);

        tb[type] = attr;
        return MNL_CB_OK;
}

static int get_table_cb(const struct nlmsghdr *nlh, void *data) {
        struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
        _cleanup_(nft_table_unref) NFTNLTable *t = NULL;
        struct nlattr *tb[NFTA_TABLE_MAX+1] = {};
        const char *name = NULL;
        GPtrArray *s = data;
        int r;

        assert(nlh);
        assert(s);

        r = mnl_attr_parse(nlh, sizeof(*nfg), generic_parrse_data_attr_cb, tb);
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
        _cleanup_(nft_chain_unref) struct nftnl_chain *c = NULL;
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

        nftnl_chain_nlmsg_build_payload(m->nlh, c);
        mnl_nlmsg_batch_next(m->batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        return mnl_send(m, 0, 0);
}
