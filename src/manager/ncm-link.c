/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <network-config-manager.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "arphrd-to-name.h"
#include "config-parser.h"
#include "ctl-display.h"
#include "ctl.h"
#include "dbus.h"
#include "log.h"
#include "macros.h"
#include "netdev-link.h"
#include "network-json.h"
#include "network-link.h"
#include "network-manager.h"
#include "network-util.h"
#include "parse-util.h"

_public_ int ncm_configure_link(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "alias")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_alias(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse alias='%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        n->alias = strdup(argv[i]);
                        if (!n->alias)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "desc")) {
                        parse_next_arg(argv, argc, i);

                        if (!argv[i]) {
                                log_warning("Failed to parse desc='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->desc = strdup(argv[i]);
                        if (!n->desc)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "mtub")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_link_bytes(argv[i])) {
                                log_warning("Failed to parse mtub='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->mtub = strdup(argv[i]);
                        if (!n->mtub)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "bps")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_link_bytes(argv[i])) {
                                log_warning("Failed to parse bps='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->bps = strdup(argv[i]);
                        if (!n->bps)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "duplex")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_duplex(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse duplex='%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        n->duplex = strdup(argv[i]);
                        if (!n->duplex)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "wol")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *w = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse wakeonlan '%s': %s", argv[i], strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_wakeonlan(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse wakeonlan '%s': %s", *d, strerror(EINVAL));
                                                return r;
                                        }
                                }

                                w = strv_join(" ", s);
                                if (!w) {
                                        log_warning("Failed to parse wakeonlan '%s': %s", *d, strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->wol = strdup(w);
                        } else {
                                r = parse_link_wakeonlan(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse wakeonlan '%s': %s", argv[i], strerror(EINVAL));
                                        return r;
                                }
                                n->wol = strdup(argv[i]);
                        }

                        if (!n->wol)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "wolp")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse wolp='%s': %s", argv[i], strerror(-r));
                                return -EINVAL;
                        }

                        n->wolp = strdup(argv[i]);
                        if (!n->wolp)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "port")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_port(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse port='%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        n->port = strdup(argv[i]);
                        if (!n->port)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "advertise")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *a = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse advertise '%s': %s", argv[i], strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_advertise(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse advertise '%s': %s", *d, strerror(EINVAL));
                                                return r;
                                        }
                                }

                                a = strv_join(" ", s);
                                if (!a) {
                                        log_warning("Failed to parse advertise '%s': %s", *d, strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->advertise = strdup(a);
                        } else {
                                r = parse_link_advertise(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse advertise '%s': %s", argv[i], strerror(EINVAL));
                                        return r;
                                }
                                n->advertise = strdup(argv[i]);
                        }

                        if (!n->advertise)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_features(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "auton")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse auton='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->auto_nego = r;
                        continue;
                } else if (string_equal_fold(argv[i], "rxcsumo")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxcsumo='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->rx_csum_off = r;
                        continue;
                } else if (string_equal_fold(argv[i], "txcsumo")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse txcsumo='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->tx_csum_off = r;
                        continue;
                } else if (string_equal_fold(argv[i], "tso")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse tso='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->tcp_seg_off = r;
                        continue;
                } else if (string_equal_fold(argv[i], "tso6")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse tso6='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->tcp6_seg_off = r;
                        continue;
                } else if (string_equal_fold(argv[i], "gso")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse gso='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->gen_seg_off = r;
                        continue;
                } else if (string_equal_fold(argv[i], "grxo")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse grxo='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->gen_rx_off = r;
                        continue;
                } else if (string_equal_fold(argv[i], "grxoh")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse grxoh='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->gen_rx_off_hw = r;
                        continue;
                } else if (string_equal_fold(argv[i], "lrxo")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse lrxo='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->large_rx_off = r;
                        continue;
                } else if (string_equal_fold(argv[i], "rxvtha")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxvtha='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->rx_vlan_ctag_hw_acl = r;
                        continue;
                } else if (string_equal_fold(argv[i], "txvtha")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse txvtha='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->tx_vlan_ctag_hw_acl = r;
                        continue;
                } else if (string_equal_fold(argv[i], "rxvtf")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxvtf='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->rx_vlan_ctag_fltr = r;
                        continue;
                } else if (string_equal_fold(argv[i], "txvstha")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse txvstha='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->tx_vlan_stag_hw_acl = r;
                        continue;
                } else if (string_equal_fold(argv[i], "ntf")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse ntf='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->n_tpl_fltr = r;
                        continue;
                } else if (string_equal_fold(argv[i], "uarxc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse uarxc='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->use_adpt_rx_coal = r;
                        continue;
                } else if (string_equal_fold(argv[i], "uatxc")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse uatxc='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->use_adpt_tx_coal = r;
                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_buf_size(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "rxbuf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxbuf='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_buf = strdup(argv[i]);
                        if (!n->rx_buf) {
                                return log_oom();
                        }
                        continue;
                } else if (string_equal_fold(argv[i], "rxminbuf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxminbuf='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }
                        n->rx_mini_buf = strdup(argv[i]);
                        continue;
                } else if (string_equal_fold(argv[i], "rxjumbobuf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxjumbobuf='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }
                        n->rx_jumbo_buf = strdup(argv[i]);
                        continue;
                } else if (string_equal_fold(argv[i], "txbuf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txbuf='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }
                        n->tx_buf = strdup(argv[i]);
                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_queue_size(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                unsigned v;

                if (string_equal_fold(argv[i], "txq")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_link_queue(argv[i], &v)) {
                                log_warning("Failed to parse txq='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_queues = v;
                        continue;
                } else if (string_equal_fold(argv[i], "rxq")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_link_queue(argv[i], &v)) {
                                log_warning("Failed to parse rxq='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }
                        n->rx_queues = v;
                        continue;
                } else if (string_equal_fold(argv[i], "txqlen")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to parse txqlen='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->tx_queue_len = v;
                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_flow_control(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "rxflowctrl")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxflowctrl='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->rx_flow_ctrl = r;
                        continue;
                } else if (string_equal_fold(argv[i], "txflowctrl")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse rxflowctrl='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->tx_flow_ctrl = r;
                        continue;
                } else if (string_equal_fold(argv[i], "autoflowctrl")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse autoflowctrl='%s': %s", argv[i], strerror(-r));
                                return r;
                        }
                        n->auto_flow_ctrl = r;
                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_gso(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "gsob")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_gso(argv[i], &n->gen_seg_off_bytes);
                        if (r < 0) {
                                log_warning("Failed to parse gsob='%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        continue;
                } else if (string_equal_fold(argv[i], "gsos")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_gso(argv[i], &n->gen_seg_off_seg);
                        if (r < 0) {
                                log_warning("Failed to parse gsos='%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_channel(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "rxch")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxch='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_chnl = strdup(argv[i]);
                        if (!n->rx_chnl)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "txch")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txch='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_chnl = strdup(argv[i]);
                        if (!n->tx_chnl)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "otrch")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse otrch='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->otr_chnl = strdup(argv[i]);
                        if (!n->rx_chnl)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "combch")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse combch='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->comb_chnl = strdup(argv[i]);
                        if (!n->rx_chnl)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_coalesce(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "rxcs")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxcs='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coal_sec = strdup(argv[i]);
                        if (!n->rx_coal_sec)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "rxcsirq")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxcsirq='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coal_irq_sec = strdup(argv[i]);
                        if (!n->rx_coal_irq_sec)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "rxcslow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxcslow='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coal_low_sec = strdup(argv[i]);
                        if (!n->rx_coal_low_sec)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "rxcshigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxcshigh='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coal_high_sec = strdup(argv[i]);
                        if (!n->rx_coal_high_sec)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "txcs")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txcs='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coal_sec = strdup(argv[i]);
                        if (!n->tx_coal_sec)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "txcsirq")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txcsirq='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coal_irq_sec = strdup(argv[i]);
                        if (!n->rx_coal_irq_sec)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "txcslow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txcslow='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coal_low_sec = strdup(argv[i]);
                        if (!n->tx_coal_low_sec)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "txcshigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txcshigh='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coal_high_sec = strdup(argv[i]);
                        if (!n->tx_coal_high_sec)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_coald_frames(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "rxmcf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxmcf='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coald_frames = strdup(argv[i]);
                        if (!n->rx_coald_frames)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "rxmcfirq")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxmcfirq='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coald_irq_frames = strdup(argv[i]);
                        if (!n->rx_coald_irq_frames)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "rxmcflow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxmcflow='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coald_low_frames = strdup(argv[i]);
                        if (!n->rx_coald_low_frames)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "rxmcfhigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse rxmcfhigh='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->rx_coald_high_frames = strdup(argv[i]);
                        if (!n->rx_coald_high_frames)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "txmcf")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txmcf='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coald_frames = strdup(argv[i]);
                        if (!n->tx_coald_frames)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "txmcfirq")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txmcfirq='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coald_irq_frames = strdup(argv[i]);
                        if (!n->tx_coald_irq_frames)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "txmcflow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txmcflow='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coald_low_frames = strdup(argv[i]);
                        if (!n->tx_coald_low_frames)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "txmcfhigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse txmcfhigh='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->tx_coald_high_frames = strdup(argv[i]);
                        if (!n->tx_coald_high_frames)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_coal_pkt(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "cprlow")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse cprlow='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->coal_pkt_rate_low = strdup(argv[i]);
                        if (!n->coal_pkt_rate_low)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "cprhigh")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse cprhigh='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->coal_pkt_rate_high = strdup(argv[i]);
                        if (!n->coal_pkt_rate_high)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "cprsis")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse cprsis='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->coal_pkt_rate_smpl_itrvl = strdup(argv[i]);
                        if (!n->coal_pkt_rate_smpl_itrvl)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "sbcs")) {
                        parse_next_arg(argv, argc, i);

                        if (!is_uint32_or_max(argv[i])) {
                                log_warning("Failed to parse sbcs='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->sts_blk_coal_sec = strdup(argv[i]);
                        if (!n->sts_blk_coal_sec)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_altname(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "altnamepolicy")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *altnm = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse altnamepolicy '%s': %s", argv[i], strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_altnamepolicy(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse altnamepolicy '%s': %s", *d, strerror(EINVAL));
                                                return r;
                                        }
                                }

                                altnm = strv_join(" ", s);
                                if (!altnm) {
                                        log_warning("Failed to parse altnamepolicy '%s': %s", *d, strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->altnamepolicy = strdup(altnm);
                        } else {
                                r = parse_link_altnamepolicy(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse altnamepolicy '%s': %s", argv[i], strerror(EINVAL));
                                        return r;
                                }
                                n->altnamepolicy = strdup(argv[i]);
                        }

                        if (!n->altnamepolicy)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "altname")) {
                        parse_next_arg(argv, argc, i);

                        if (!argv[i]) {
                                log_warning("Failed to parse altname '%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        n->altname = strdup(argv[i]);
                        if (!n->altname)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_name(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "namepolicy")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *nm = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse namepolicy '%s': %s", argv[i], strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_namepolicy(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse namepolicy '%s': %s", *d, strerror(EINVAL));
                                                return r;
                                        }
                                }

                                nm = strv_join(" ", s);
                                if (!nm) {
                                        log_warning("Failed to parse namepolicy '%s': %s", *d, strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->namepolicy = strdup(nm);
                        } else {
                                r = parse_link_namepolicy(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse namepolicy '%s': %s", argv[i], strerror(EINVAL));
                                        return r;
                                }
                                n->namepolicy = strdup(argv[i]);
                        }

                        if (!n->namepolicy)
                                return log_oom();

                        continue;
                }

                if (string_equal_fold(argv[i], "name")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_link_name(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse name '%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        n->name = strdup(argv[i]);
                        if (!n->name)
                                return log_oom();

                        continue;
                }

                log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                return -EINVAL;
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}

_public_ int ncm_configure_link_mac(int argc, char *argv[]) {
        _cleanup_(netdev_link_unrefp) NetDevLink *n = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        int r;

        r = parse_ifname_or_index(argv[1], &p);
        if (r < 0) {
                log_warning("Failed to find device '%s': %s", argv[1], strerror(-r));
                return r;
        }

        r = netdev_link_new(&n);
        if (r < 0)
                return log_oom();

        for (int i = 2; i < argc; i++) {
                if (string_equal_fold(argv[i], "macpolicy")) {
                        parse_next_arg(argv, argc, i);

                        if (strchr(argv[i], ',')) {
                                _auto_cleanup_strv_ char **s = NULL;
                                _auto_cleanup_ char *pcy = NULL;
                                char **d;

                                s = strsplit(argv[i], ",", -1);
                                if (!s) {
                                        log_warning("Failed to parse macpolicy '%s': %s", argv[i], strerror(EINVAL));
                                        return -EINVAL;
                                }

                                strv_foreach(d, s) {
                                        r = parse_link_macpolicy(*d);
                                        if (r < 0) {
                                                log_warning("Failed to parse macpolicy '%s': %s", *d, strerror(EINVAL));
                                                return r;
                                        }
                                }

                                pcy = strv_join(" ", s);
                                if (!pcy) {
                                        log_warning("Failed to parse macpolicy '%s': %s", *d, strerror(EINVAL));
                                        return -EINVAL;
                                }
                                n->macpolicy = strdup(pcy);
                        } else {
                                r = parse_link_macpolicy(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse macpolicy '%s': %s", argv[i], strerror(EINVAL));
                                        return r;
                                }
                                n->macpolicy = strdup(argv[i]);
                        }

                        if (!n->macpolicy)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "macaddr") || string_equal_fold(argv[i], "mac")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse macaddr='%s': %s", argv[i], strerror(-r));
                                return -EINVAL;
                        }

                        n->macaddr = strdup(argv[i]);
                        if (!n->macaddr)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        r = netdev_link_configure(p, n);
        if (r < 0) {
                log_warning("Failed to configure device: %s", strerror(-r));
                return r;
        }

        return 0;
}
