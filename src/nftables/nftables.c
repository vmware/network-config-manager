/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <assert.h>
#include <string.h>
#include <time.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
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
        [NF_PROTO_FAMILY_INET]   = "ip",
        [NF_PROTO_FAMILY_IPV4]   = "ipv4",
        [NF_PROTO_FAMILY_ARP]    = "arp",
        [NF_PROTO_FAMILY_NETDEV] = "netdev",
        [NF_PROTO_FAMILY_BRIDGE] = "bridge",
        [NF_PROTO_FAMILY_IPV6]   = "ipv6",
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

void nft_tables_unref(struct nftnl_table **t) {
        if (t && *t)
                nftnl_table_free(*t);
}

int new_nft_table(int family, const char *name, struct nftnl_table **ret) {
        struct nftnl_table *t = NULL;

        t = nftnl_table_alloc();
        if (!t)
                return log_oom();

        nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);
        nftnl_table_set_str(t, NFTNL_TABLE_NAME, name);

        *ret = steal_pointer(t);

        return 0;
}

int nft_add_table(int family, const char *name) {
        _cleanup_(nft_tables_unref) struct nftnl_table *t = NULL;
        _cleanup_(mnl_unrefp) Mnl *m = NULL;
        int r;

        r = new_nft_table(family, name, &t);
        if (r < 0)
                return r;

        r = mnl_new(&m);
        if (r < 0)
                return r;

        m->batch = mnl_nlmsg_batch_start(m->buf, MNL_SOCKET_BUFFER_SIZE);
        nftnl_batch_begin(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        family = nftnl_table_get_u32(t, NFTNL_TABLE_FAMILY);
        m->nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(m->batch),
                                             NFT_MSG_NEWTABLE, family,
                                             NLM_F_CREATE|NLM_F_ACK, m->seq++);

        nftnl_table_nlmsg_build_payload(m->nlh, t);
        mnl_nlmsg_batch_next(m->batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(m->batch), m->seq++);
        mnl_nlmsg_batch_next(m->batch);

        return mnl_send(m);
}
