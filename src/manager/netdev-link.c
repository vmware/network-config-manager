/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "file-util.h"
#include "macros.h"
#include "log.h"
#include "netdev-link.h"
#include "network-util.h"
#include "parse-util.h"
#include "string-util.h"

static const Config link_ctl_to_config_table[] = {
                { "rx",   "ReceiveChecksumOffload"},
                { "tx",   "TransmitChecksumOffload"},
                { "tso",  "TCPSegmentationOffload" },
                { "t6so", "TCP6SegmentationOffload" },
                { "gso",  "GenericSegmentationOffload"},
                { "grso", "GenericReceiveOffload"},
                { "groh", "GenericReceiveOffloadHardware"},
                { "lro",  "LargeReceiveOffload" },
                {},
};

int netdev_link_new(NetDevLink **ret) {
        NetDevLink *n = NULL;
        int r;

        n = new0(NetDevLink, 1);
        if (!n)
                return log_oom();

        *n = (NetDevLink) {
                .receive_checksum_offload = -1,
                .transmit_checksum_offload = -1,
                .tcp_segmentation_offload = -1,
                .tcp6_segmentation_offload = -1,
                .generic_checksum_offload =-1,
                .generic_receive_offload = -1,
                .large_receive_offload = -1,
        };

        r = config_manager_new(link_ctl_to_config_table, &n->m);
        if (r < 0) {
                return r;
        }

        *ret = n;
        return 0;
}

void netdev_link_unref(NetDevLink *n) {
        if (!n)
                return;

        config_unref(n->m);
        g_free(n);
}

int create_or_parse_netdev_link_conf_file(const char *ifname, char **ret) {
        _auto_cleanup_ char *file = NULL, *link = NULL, *path = NULL, *s = NULL;
        int r;

        assert(ifname);

        s = string_join("-", "10", ifname, NULL);
        if (!s)
                return -ENOMEM;

        file = string_join(".", s, "link", NULL);
        if (!file)
                return -ENOMEM;

        path = g_build_path("/", "/etc/systemd/network", file, NULL);
        if (!path)
                 return log_oom();

        if (g_file_test(path, G_FILE_TEST_EXISTS)) {
                  *ret = steal_pointer(path);
                   return 0;
        }

        r = create_conf_file("/etc/systemd/network", s, "link", &file);
        if (r < 0)
                return r;

        r = set_config_file_string(path, "Match", "Name", ifname);
        if (r < 0)
                return r;


        *ret = steal_pointer(path);
        return 0;
}

int netdev_link_configure(const IfNameIndex *ifnameidx, NetDevLink *n) {
        _auto_cleanup_ char *path = NULL;
         int r;

        r = create_or_parse_netdev_link_conf_file(ifnameidx->ifname, &path);
        if (r < 0)
                return r;

        if (n->receive_checksum_offload != -1) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "rx"), bool_to_string(n->receive_checksum_offload));
                 if (r < 0)
                         return r;
        }
        if (n->transmit_checksum_offload != -1) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "tx"), bool_to_string(n->transmit_checksum_offload));
                 if (r < 0)
                         return r;
        }
        if (n->tcp_segmentation_offload != -1) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "tso"), bool_to_string(n->tcp_segmentation_offload));
                 if (r < 0)
                         return r;
        }
        if (n->tcp6_segmentation_offload!= -1) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "t6so"), bool_to_string(n->tcp6_segmentation_offload));
                 if (r < 0)
                         return r;
        }
        if (n->generic_checksum_offload != -1) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "gso"), bool_to_string(n->generic_checksum_offload));
                 if (r < 0)
                         return r;
        }
        if (n->generic_receive_offload != -1) {
                 r = set_config_file_string(path, "Link", ctl_to_config(n->m, "gro"), bool_to_string(n->generic_receive_offload));
                 if (r < 0)
                         return r;
        }
        if (n->large_receive_offload != -1) {
                r = set_config_file_string(path, "Link", ctl_to_config(n->m, "lro"), bool_to_string(n->large_receive_offload));
                if (r < 0)
                        return r;
        }


        return 0;
}
