/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <net/if.h>
#include <linux/if.h>
#include <net/ethernet.h>

#include "alloc-util.h"
#include "log.h"
#include "macros.h"
#include "netlink.h"
#include "file-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "network.h"
#include "dbus.h"
#include "network-sriov.h"
#include "network-util.h"

static const Config sriov_ctl_to_config_table[] = {
                { "vf",           "VirtualFunction" },
                { "vlanid",       "VLANId" },
                { "qos",          "QualityOfService" },
                { "vlanproto",    "VLANProtocol" },
                { "macspoofck",   "MACSpoofCheck" },
                { "qrss",         "QueryReceiveSideScaling" },
                { "trust",        "Trust" },
                { "linkstate",    "LinkState" },
                { "macaddr",      "MACAddress" },
                {},
};

int netdev_sriov_new(SRIOV **ret) {
        SRIOV *s = NULL;
        int r;

        s = new0(SRIOV, 1);
        if (!s)
                return log_oom();

        *s = (SRIOV) {
                .family = AF_UNSPEC,
                .macspoofck = -1,
                .qrss = -1,
                .trust = -1,
        };

        r = config_manager_new(sriov_ctl_to_config_table, &s->m);
        if (r < 0)
                return r;

        *ret = s;
        return 0;
}

void netdev_sriov_unref(SRIOV *s) {
        if (!s)
                return;

        config_manager_unref(s->m);

        free(s->vf);
        free(s->vlanid);
        free(s->qos);
        free(s->vlanproto);
        free(s->macaddr);
        free(s->linkstate);

        g_free(s);
}

int netdev_sriov_configure(const IfNameIndex *ifnameidx, SRIOV *s) {
        _cleanup_(key_file_freep) KeyFile *key_file = NULL;
        _cleanup_(section_freep) Section *section = NULL;
        _auto_cleanup_ char *network = NULL;
         int r;

        assert(ifnameidx);
        assert(s);

        r = create_or_parse_network_file(ifnameidx, &network);
        if (r < 0)
                return r;

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
                log_warning("Failed to write to '%s': %s", key_file->name, g_strerror(-r));
                return r;
        }

        r = set_file_permisssion(network, "systemd-network");
        if (r < 0)
                return r;

        return dbus_network_reload();
}
