/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2021 VMware, Inc.
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

void mnl_unref(Mnl *m);
DEFINE_CLEANUP(Mnl*, mnl_unref);

int mnl_send(struct Mnl *m, mnl_cb_t cb, void *d);

void unref_mnl_socket(struct mnl_socket *nl);
DEFINE_CLEANUP(struct mnl_socket*, unref_mnl_socket);
