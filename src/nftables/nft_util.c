/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#if HAVE_NFTABLES

#include <assert.h>
#include <errno.h>
#include <libnftnl/table.h>
#include <libnftnl/expr.h>

#include "alloc-util.h"
#include "nft_util.h"

int nf_expr_new(const char *kind, struct nftnl_expr **ret) {
        struct nftnl_expr *e;

        assert(kind);

        e = nftnl_expr_alloc(kind);
        if (!e)
                return -ENOMEM;

        *ret = steal_ptr(e);
        return 0;
}

int nf_add_counter(NFTNLRule *rl) {
        struct nftnl_expr *e;
        int r;

        assert(rl);

        r = nf_expr_new("counter", &e);
        if (r < 0)
                return r;

        nftnl_rule_add_expr(rl->rule, e);
        return 0;
}

int nf_add_cmp(NFTNLRule *rl, uint32_t sreg, uint32_t op, const void *data, uint32_t data_len) {
        struct nftnl_expr *e;
        int r;

        assert(rl);

        r = nf_expr_new("cmp", &e);
        if (r < 0)
                return r;

        nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
        nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
        nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);

        nftnl_rule_add_expr(rl->rule, e);
        return 0;
}

int nf_add_immediate_verdict(NFTNLRule *rl, uint32_t verdict, const char *chain) {
        struct nftnl_expr *e;
        int r;

        assert(rl);

        r = nf_expr_new("immediate", &e);
        if (r < 0)
                return r;

        nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
        if (chain)
                nftnl_expr_set_str(e, NFTNL_EXPR_IMM_CHAIN, chain);

        nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, verdict);

        nftnl_rule_add_expr(rl->rule, e);
        return 0;
}

int nf_add_payload(NFTNLRule *rl, uint32_t base, uint32_t dreg, uint32_t offset, uint32_t len) {
        struct nftnl_expr *e;
        int r;

        assert(rl);

        r = nf_expr_new("payload", &e);
        if (r < 0)
                return r;

        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
        nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

        nftnl_rule_add_expr(rl->rule, e);
        return 0;
}

#endif
