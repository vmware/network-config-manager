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

static const char *const sriov_link_state_table[_SR_IOV_LINK_STATE_MAX] = {
       [SR_IOV_LINK_STATE_DISABLE] = "no",
       [SR_IOV_LINK_STATE_ENABLE]  = "yes",
       [SR_IOV_LINK_STATE_AUTO]    = "auto",
};

static const char *sriov_link_state_to_name(int id) {
        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(sriov_link_state_table))
                return NULL;

        return sriov_link_state_table[id];
}

int parse_sriov_link_state(const char *s) {
        int r;

        assert(s);

        if (str_eq(s, "auto"))
                return SR_IOV_LINK_STATE_AUTO;

        r = parse_bool(s);
        if (r < 0)
                return -EINVAL;

        return r;
}

int sriov_new(SRIOV **ret) {
        _cleanup_(sriov_freep) SRIOV *s = NULL;

        s = new(SRIOV, 1);
        if (!s)
                return log_oom();

        *s = (SRIOV) {
                .vf = UINT32_MAX,
                .family = AF_UNSPEC,
                .query_rss = -1,
                .vf_spoof_check_setting = -1,
                .trust = -1,
                .link_state = -1,
        };

        *ret = steal_ptr(s);
        return 0;
}

void sriov_free(SRIOV *s) {
        if (!s)
                return;

        free(s->macaddr);
        free(s);
}

int sriov_add_new_section(KeyFile *key_file, SRIOV *s) {
        _cleanup_(section_freep) Section *section = NULL;
        int r;

        r = section_new("SR-IOV", &section);
        if (r < 0)
                return r;

        if (s->vf != UINT32_MAX)
                add_key_to_section_uint(section, "VirtualFunction", s->vf);

        if (s->vlan > 0)
                add_key_to_section_uint(section, "VLANId", s->vlan);

        if (s->qos > 0)
                add_key_to_section_uint(section, "QualityOfService", s->qos);

        if (s->vlan_proto)
                add_key_to_section(section, "VLANProtocol", s->vlan_proto);

        if (s->vf_spoof_check_setting >= 0)
                add_key_to_section(section, "MACSpoofCheck", bool_to_str(s->vf_spoof_check_setting));

        if (s->query_rss >= 0)
                add_key_to_section(section, "QueryReceiveSideScaling", bool_to_str(s->query_rss));

        if (s->trust >= 0)
                add_key_to_section(section, "Trust", bool_to_str(s->trust));

        if (s->link_state >= 0)
                add_key_to_section(section, "LinkState", sriov_link_state_to_name(s->link_state));

        if (s->macaddr)
                add_key_to_section(section, "MACAddress", s->macaddr);

        r = add_section_to_key_file(key_file, section);
        if (r < 0)
                return r;

        steal_ptr(section);

        return 0;
}

int sriov_configure(const IfNameIndex *i, SRIOV *s, bool link) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _auto_cleanup_ char *network = NULL;
         int r;

        assert(i);
        assert(s);

        if (!link)
                r = create_or_parse_network_file(i, &network);
        else
                r = create_or_parse_netdev_link_conf_file(i->ifname, &network);
        if (r < 0)
                return r;

        r = parse_key_file(network, &key_file);
        if (r < 0)
                return r;

        r = sriov_add_new_section(key_file, s);
        if (r < 0)
                return r;

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

        if (str_eq(argv[0], "add-link-sr-iov") || str_eq(argv[0], "lsriov"))
                link = true;

        r = sriov_new(&s);
        if (r < 0)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                if (str_eq_fold(argv[i], "dev")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_ifname_or_index(argv[i], &p);
                        if (r < 0) {
                                log_warning("Failed to find device: %s", argv[i]);
                                return r;
                        }
                        continue;

                } else if (str_eq_fold(argv[i], "vf")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &s->vf);
                        if (r < 0) {
                                log_warning("Failed to configure sriov vf='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        have_vf = true;
                        continue;
                } else if (str_eq_fold(argv[i], "vlanid")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &s->vlan);
                        if (r < 0) {
                                log_warning("Failed to configure sriov vlan='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "qos")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_uint32(argv[i], &s->qos);
                        if (r < 0) {
                                log_warning("Failed to configure sriov qos='%s': %s", argv[i], strerror(EINVAL));
                                return -EINVAL;
                        }

                        continue;
                } else if (str_eq_fold(argv[i], "vlanproto")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_sriov_vlan_protocol(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to configure sriov vlan proto ='%s': %s", argv[i], strerror(EINVAL));
                                return r;
                        }

                        s->vlan_proto = strdup(argv[i]);
                        if (!s->vlan_proto)
                                return log_oom();

                        continue;
                } else if (str_eq_fold(argv[i], "macspoofck")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov macspoofck '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        s->vf_spoof_check_setting = r;
                        continue;
                } else if (str_eq_fold(argv[i], "qrss")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov qrss '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        s->query_rss = r;
                        continue;
                } else  if (str_eq_fold(argv[i], "trust")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_bool(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov trust '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        s->trust = r;
                        continue;
                } else if (str_eq_fold(argv[i], "linkstate")) {
                        parse_next_arg(argv, argc, i);

                        r = parse_sriov_link_state(argv[i]);
                        if (r < 0) {
                                log_warning("Failed to parse sriov link_state '%s': %s", argv[i], strerror(-r));
                                return r;
                        }

                        s->link_state = r;

                        continue;
                } else if (str_eq_fold(argv[i], "macaddr")) {
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
                log_warning("Failed to configure sriov. Missing VirtualFunction: %s", strerror(EINVAL));
                return -EINVAL;
        }

        r = sriov_configure(p, s, link);
        if (r < 0) {
                log_warning("Failed to configure sriov: %s", strerror(-r));
                return r;
        }

        return 0;
}
