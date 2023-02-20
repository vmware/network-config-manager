/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <net/if.h>
#include <linux/if.h>
#include <net/ethernet.h>

#include <network-config-manager.h>

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "dbus.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "netdev-link.h"
#include "network-sriov.h"
#include "network-util.h"
#include "network.h"
#include "parse-util.h"

int sriov_new(SRIOV **ret) {
        _cleanup_(sriov_freep) SRIOV *s = NULL;

        s = new0(SRIOV, 1);
        if (!s)
                return log_oom();

        *s = (SRIOV) {
                .family = AF_UNSPEC,
                .macspoofck = -1,
                .qrss = -1,
                .trust = -1,
        };

        *ret = steal_pointer(s);
        return 0;
}

void sriov_free(SRIOV *s) {
        if (!s)
                return;

        free(s->vf);
        free(s->vlanid);
        free(s->qos);
        free(s->vlanproto);
        free(s->macaddr);
        free(s->linkstate);

        free(s);
}

int sriov_configure(const IfNameIndex *ifidx, SRIOV *s, bool link) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        _auto_cleanup_ char *network = NULL;
         int r;

        assert(ifidx);
        assert(s);

        if (!link) {
                r = create_or_parse_network_file(ifidx, &network);
                if (r < 0)
                        return r;
        } else {
                r = create_or_parse_netdev_link_conf_file(ifidx->ifname, &network);
                if (r < 0)
                        return r;
        }

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = section_new("SR-IOV", &section);
        if (r < 0)
                return r;

        if (s->vf)
                add_key_to_section(section, "VirtualFunction", s->vf);

        if (s->vlanid)
                add_key_to_section(section, "VLANId", s->vlanid);

        if (s->qos)
                add_key_to_section(section, "QualityOfService", s->qos);

        if (s->vlanproto)
                add_key_to_section(section, "VLANProtocol", s->vlanproto);

        if (s->macspoofck >= 0)
                add_key_to_section(section, "MACSpoofCheck", bool_to_string(s->macspoofck));

        if (s->qrss >= 0)
                add_key_to_section(section, "QueryReceiveSideScaling", bool_to_string(s->qrss));

        if (s->trust >= 0)
                add_key_to_section(section, "Trust", bool_to_string(s->trust));

        if (s->linkstate)
                add_key_to_section(section, "LinkState", s->linkstate);

        if (s->macaddr)
                add_key_to_section(section, "MACAddress", s->macaddr);

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_pointer(section);

        r = key_file_save (key_file);
        if (r < 0) {
                log_warning("Failed to write to '%s': %s", key_file->name, strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}

_public_ int ncm_configure_sr_iov(int argc, char *argv[]) {
        _cleanup_(sriov_freep) SRIOV *s = NULL;
        _auto_cleanup_ IfNameIndex *p = NULL;
        bool have_vf = false, link = false;
        int r;

        if (string_equal(argv[0], "add-link-sr-iov") || string_equal(argv[0], "lsriov"))
                link = true;

        r = sriov_new(&s);
        if (r < 0)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                unsigned v;

                if (string_equal_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;

                } else if (string_equal_fold(argv[i], "vf")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to configure sriov vf ='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        s->vf = strdup(argv[i]);
                        if (!s->vf)
                                return log_oom();

                        have_vf = true;
                        continue;
                } else if (string_equal_fold(argv[i], "vlanid")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to configure sriov vlanid ='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        s->vlanid = strdup(argv[i]);
                        if (!s->vlanid)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "qos")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &v);
                        if (r < 0) {
                                log_warning("Failed to configure sriov qos ='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        s->qos = strdup(argv[i]);
                        if (!s->qos)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "vlanproto")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_sriov_vlanprotocol(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to configure sriov vlanproto ='%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        s->vlanproto = strdup(argv[i]);
                        if (!s->vlanproto)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "macspoofck")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov macspoofck '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        s->macspoofck = r;
                        continue;
                } else if (string_equal_fold(argv[i], "qrss")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov qrss '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        s->qrss = r;
                        continue;
                } else  if (string_equal_fold(argv[i], "trust")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_boolean(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov trust '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        s->trust = r;
                        continue;
                } else if (string_equal_fold(argv[i], "linkstate")) {
                        parse_next_arg(argv, argc, i);

                        if (!string_equal_fold(argv[i], "auto")) {
                                r = parse_boolean(argv[i]);
                                if (r < 0) {
                                        log_warning("Failed to parse sriov linkstate '%s': %s", argv[i], strerror(-r));
                                        return r;
                                }
                        }

                        s->linkstate = strdup(argv[i]);
                        if (!s->linkstate)
                                return log_oom();

                        continue;
                } else if (string_equal_fold(argv[i], "macaddr")) {
                        parse_next_arg(argv, argc, i);

                        if (!parse_ether_address(argv[i])) {
                                log_warning("Failed to parse sriov macaddr='%s': %s", argv[i], strerror(-r));
                                return -EINVAL;
                        }

                        s->macaddr = strdup(argv[i]);
                        if (!s->macaddr)
                                return log_oom();

                        continue;
                } else {
                        log_warning("Failed to parse '%s': %s", argv[i], strerror(EINVAL));
                        return -EINVAL;
                }
        }

        if (!p) {
                log_warning("Failed to find device: %s",  strerror(EINVAL));
                return -EINVAL;
        }

        if (!have_vf) {
                log_warning("Failed to configure sriov missing VirtualFunction : %s", strerror(EINVAL));
                return -EINVAL;
        }

        r = sriov_configure(p, s, link);
        if (r < 0) {
                log_warning("Failed to configure sriov: %s", strerror(-r));
                return r;
        }

        return 0;
}
