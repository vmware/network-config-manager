/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <linux/if_arp.h>
#include <string.h>

#include "arphrd-to-name.h"
#include "macros.h"

#define add_arp_head_to_name(id, n) { .type = id, .name = n }

struct ARPHeaderToName {
        int type;
        const char *name;
} arphrd_names[] = {
        add_arp_head_to_name(ARPHRD_NETROM,             "netrom"),
        add_arp_head_to_name(ARPHRD_ETHER,              "ether"),
        add_arp_head_to_name(ARPHRD_EETHER,             "eether"),
        add_arp_head_to_name(ARPHRD_AX25,               "ax25"),
        add_arp_head_to_name(ARPHRD_PRONET,             "pronet"),
        add_arp_head_to_name(ARPHRD_CHAOS,              "chaos"),
        add_arp_head_to_name(ARPHRD_IEEE802,            "ieee802"),
        add_arp_head_to_name(ARPHRD_ARCNET,             "arcnet"),
        add_arp_head_to_name(ARPHRD_APPLETLK,           "atalk"),
        add_arp_head_to_name(ARPHRD_DLCI,               "dlci"),
        add_arp_head_to_name(ARPHRD_ATM,                "atm"),
        add_arp_head_to_name(ARPHRD_METRICOM,           "metricom"),
        add_arp_head_to_name(ARPHRD_IEEE1394,           "ieee1394"),
        add_arp_head_to_name(ARPHRD_INFINIBAND,         "infiniband"),
        add_arp_head_to_name(ARPHRD_SLIP,               "slip"),
        add_arp_head_to_name(ARPHRD_CSLIP,              "cslip"),
        add_arp_head_to_name(ARPHRD_SLIP6,              "slip6"),
        add_arp_head_to_name(ARPHRD_CSLIP6,             "cslip6"),
        add_arp_head_to_name(ARPHRD_RSRVD,              "rsrvd"),
        add_arp_head_to_name(ARPHRD_ADAPT,              "adapt"),
        add_arp_head_to_name(ARPHRD_ROSE,               "rose"),
        add_arp_head_to_name(ARPHRD_X25,                "x25"),
        add_arp_head_to_name(ARPHRD_HWX25,              "hwx25"),
        add_arp_head_to_name(ARPHRD_CAN,                "can"),
        add_arp_head_to_name(ARPHRD_PPP,                "ppp"),
        add_arp_head_to_name(ARPHRD_HDLC,               "hdlc"),
        add_arp_head_to_name(ARPHRD_LAPB,               "lapb"),
        add_arp_head_to_name(ARPHRD_DDCMP,              "ddcmp"),
        add_arp_head_to_name(ARPHRD_RAWHDLC,            "rawhdlc"),
        add_arp_head_to_name(ARPHRD_TUNNEL,             "ipip"),
        add_arp_head_to_name(ARPHRD_TUNNEL6,            "tunnel6"),
        add_arp_head_to_name(ARPHRD_FRAD,               "frad"),
        add_arp_head_to_name(ARPHRD_SKIP,               "skip"),
        add_arp_head_to_name(ARPHRD_LOOPBACK,           "loopback"),
        add_arp_head_to_name(ARPHRD_LOCALTLK,           "ltalk"),
        add_arp_head_to_name(ARPHRD_FDDI,               "fddi"),
        add_arp_head_to_name(ARPHRD_BIF,                "bif"),
        add_arp_head_to_name(ARPHRD_SIT,                "sit"),
        add_arp_head_to_name(ARPHRD_IPDDP,              "ip/ddp"),
        add_arp_head_to_name(ARPHRD_IPGRE,              "gre"),
        add_arp_head_to_name(ARPHRD_PIMREG,             "pimreg"),
        add_arp_head_to_name(ARPHRD_HIPPI,              "hippi"),
        add_arp_head_to_name(ARPHRD_ASH,                "ash"),
        add_arp_head_to_name(ARPHRD_ECONET,             "econet"),
        add_arp_head_to_name(ARPHRD_IRDA,               "irda"),
        add_arp_head_to_name(ARPHRD_IRDA,               "irda"),
        add_arp_head_to_name(ARPHRD_FCPP,               "fcpp"),
        add_arp_head_to_name(ARPHRD_FCAL,               "fcal"),
        add_arp_head_to_name(ARPHRD_FCPL,               "fcpl"),
        add_arp_head_to_name(ARPHRD_FCFABRIC,           "fcfb0"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+1,         "fcfb1"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+2,         "fcfb2"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+3,         "fcfb3"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+4,         "fcfb4"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+5,         "fcfb5"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+6,         "fcfb6"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+7,         "fcfb7"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+8,         "fcfb8"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+9,         "fcfb9"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+10,        "fcfb10"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+11,        "fcfb11"),
        add_arp_head_to_name(ARPHRD_FCFABRIC+12,        "fcfb12"),
        add_arp_head_to_name(ARPHRD_IEEE802_TR,         "tr"),
        add_arp_head_to_name(ARPHRD_IEEE80211,          "ieee802.11"),
        add_arp_head_to_name(ARPHRD_IEEE80211_PRISM,    "ieee802.11/prism"),
        add_arp_head_to_name(ARPHRD_IEEE80211_RADIOTAP, "ieee802.11/radiotap"),
        add_arp_head_to_name(ARPHRD_IEEE802154,         "ieee802.15.4"),
        add_arp_head_to_name(ARPHRD_IEEE802154_MONITOR, "ieee802.15.4/monitor"),
        add_arp_head_to_name(ARPHRD_PHONET,             "phonet"),
        add_arp_head_to_name(ARPHRD_PHONET_PIPE,        "phonet_pipe"),
        add_arp_head_to_name(ARPHRD_CAIF,               "caif"),
        add_arp_head_to_name(ARPHRD_IP6GRE,             "gre6"),
        add_arp_head_to_name(ARPHRD_NETLINK,            "netlink"),
        add_arp_head_to_name(ARPHRD_6LOWPAN,            "6lowpan"),
        add_arp_head_to_name(ARPHRD_NONE,               "none"),
};

const char *arphrd_to_name(int id) {
        size_t i;

        if (id <= 0)
                return NULL;

        for (i = 0; i <= ELEMENTSOF(arphrd_names); i++) {
                if (id == arphrd_names[i].type)
                        return arphrd_names[i].name;
        }

        return NULL;
}
