/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2021 VMware, Inc.
 */

#include <assert.h>
#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <linux/netfilter.h>

#include "alloc-util.h"
#include "file-util.h"
#include "macros.h"
#include "mnl_util.h"
#include "log.h"

void mnl_unref(Mnl *m) {
        if (!m)
                return;

        free(m->buf);
        free(m);
}

int mnl_new(Mnl **ret) {
        Mnl *m;

        m = new0(Mnl, 1);
        if (!m)
                return -ENOMEM;

        m->buf = new(char, MNL_SOCKET_BUFFER_SIZE);
        if (!m->buf)
                return -ENOMEM;

        m->seq = time(NULL);

        *ret = steal_pointer(m);

        return 0;
}

void unref_mnl_socket(struct mnl_socket *nl) {
        if (!nl)
                return;

        mnl_socket_close(nl);
}

int mnl_send(Mnl *m, mnl_cb_t cb, void *d) {
        _cleanup_(unref_mnl_socketp) struct mnl_socket *nl = NULL;
        uint32_t port_id;
        size_t k;
        int r;

        assert(m);

        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (!nl)
                return -errno;

        r = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
        if (r < 0)
                return -errno;

        port_id = mnl_socket_get_portid(nl);
        if (m->batch)
                k = mnl_nlmsg_batch_size(m->batch);
        else
                k = m->nlh->nlmsg_len;

        r = mnl_socket_sendto(nl, m->batch ? mnl_nlmsg_batch_head(m->batch) : m->nlh, k);
        if (r < 0)
                return -errno;

        if (m->batch)
                mnl_nlmsg_batch_stop(m->batch);

        r = mnl_socket_recvfrom(nl, m->buf, MNL_SOCKET_BUFFER_SIZE);
        while (r > 0) {
                r = mnl_cb_run(m->buf, r, 0, port_id, cb, d);
                if (r <= 0)
                        break;

                r = mnl_socket_recvfrom(nl, m->buf, MNL_SOCKET_BUFFER_SIZE);
        }
        if (r < 0)
                return -errno;

        return 0;
}
