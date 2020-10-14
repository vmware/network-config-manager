/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/table.h>

typedef struct Mnl {
        struct nlmsghdr *nlh;

        uint32_t seq;
        struct mnl_nlmsg_batch *batch;
        char *buf;
} Mnl;

int mnl_new(Mnl **ret);
void mnl_unrefp(Mnl **m);

void unref_mnl_socket(struct mnl_socket **nl);
int mnl_send(struct Mnl *m);
