/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2021 VMware, Inc.
 */

#pragma once

#include"nftables.h"

int nf_expr_new(const char *kind, struct nftnl_expr **ret);

int nf_add_counter(NFTNLRule *r) ;
int nf_add_cmp(NFTNLRule *r, uint32_t sreg, uint32_t op, const void *data, uint32_t data_len);
int nf_add_immediate_verdict(NFTNLRule *r, uint32_t verdict, const char *chain);
int nf_add_payload(NFTNLRule *r, uint32_t base, uint32_t dreg, uint32_t offset, uint32_t len);
