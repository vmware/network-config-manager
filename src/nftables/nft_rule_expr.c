/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <assert.h>

#include <asm-generic/errno-base.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>
#include <libnftnl/table.h>
#include <libnftnl/expr.h>

#include "nft_rule_expr.h"

int nf_add_counter(NFTNLRule *r) {
        struct nftnl_expr *e;

        assert(r);

        e = nftnl_expr_alloc("counter");
        if (!e)
                return -ENOMEM;

        nftnl_rule_add_expr(r->rule, e);

        return 0;
}

int nf_add_cmp(NFTNLRule *r, uint32_t sreg, uint32_t op, const void *data, uint32_t data_len) {
        struct nftnl_expr *e;

        assert(r);

        e = nftnl_expr_alloc("cmp");
        if (!e)
                return -ENOMEM;

        nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
        nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
        nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);

        nftnl_rule_add_expr(r->rule, e);
        return 0;
}

int nf_add_immediate_verdict(NFTNLRule *r, uint32_t verdict, const char *chain) {
        struct nftnl_expr *e;

        assert(r);

        e = nftnl_expr_alloc("immediate");
        if (!e)
                return -ENOMEM;

        nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
        if (chain)
                nftnl_expr_set_str(e, NFTNL_EXPR_IMM_CHAIN, chain);

        nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, verdict);

        nftnl_rule_add_expr(r->rule, e);
        return 0;
}

int nf_add_payload(NFTNLRule *r, uint32_t base, uint32_t dreg, uint32_t offset, uint32_t len) {
        struct nftnl_expr *e;

        assert(r);

        e = nftnl_expr_alloc("payload");
        if (!e)
                return -ENOMEM;

        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

        nftnl_rule_add_expr(r->rule, e);
        return 0;
}
