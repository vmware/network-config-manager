/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <assert.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/table.h>

#include "alloc-util.h"
#include "file-util.h"
#include "macros.h"
#include "mnl_util.h"
#include "log.h"

void mnl_unrefp(Mnl **m) {
        if (m && *m) {
                free((*m)->buf);
                free(*m);
        }
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

void unref_mnl_socket(struct mnl_socket **nl) {
        if (nl && *nl)
                mnl_socket_close(*nl);
}

int mnl_send(Mnl *m) {
        _cleanup_(unref_mnl_socket) struct mnl_socket *nl = NULL;
        uint32_t port_id;
        int r;

        assert(m);

        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (!nl)
                return -errno;

        r = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
        if (r < 0)
                return -errno;

        port_id = mnl_socket_get_portid(nl);

        r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(m->batch), mnl_nlmsg_batch_size(m->batch));
        if (r < 0)
                return -errno;

        mnl_nlmsg_batch_stop(m->batch);

        r = mnl_socket_recvfrom(nl, m->buf, MNL_SOCKET_BUFFER_SIZE);
        while (r > 0) {
                r = mnl_cb_run(m->buf, r, 0, port_id, 0, 0);
                if (r <= 0)
                        break;

                r = mnl_socket_recvfrom(nl, m->buf, MNL_SOCKET_BUFFER_SIZE);
        }
        if (r < 0)
                return -errno;

        return 0;
}
