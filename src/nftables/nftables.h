/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2021 VMware, Inc.
 */
#pragma once

#include <gmodule.h>

#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/table.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

typedef struct nft_ctx nft_ctx;

typedef enum NfProtoFamily {
        NF_PROTO_FAMILY_UNSPEC = NFPROTO_UNSPEC,
        NF_PROTO_FAMILY_INET   = NFPROTO_INET,
        NF_PROTO_FAMILY_IPV4   = NFPROTO_IPV4,
        NF_PROTO_FAMILY_ARP    = NFPROTO_ARP,
        NF_PROTO_FAMILY_NETDEV = NFPROTO_NETDEV,
        NF_PROTO_FAMILY_BRIDGE = NFPROTO_BRIDGE,
        NF_PROTO_FAMILY_IPV6   = NFPROTO_IPV6,
        NF_PROTO_FAMILY_DECNET = NFPROTO_DECNET,
        _NF_PROTO_FAMILY_MAX,
        _NF_PROTO_FAMILY_INVALID = -1
} NfProtoFamily;

typedef enum NFPacketAction {
        NF_PACKET_ACTION_DROP      = NF_DROP,
        NF_PACKET_ACTION_ACCEPT    = NF_ACCEPT,
        NF_PACKET_ACTION_NF_STOLEN = NF_STOLEN,
        NF_PACKET_ACTION_NF_QUEUE  = NF_QUEUE,
        NF_PACKET_ACTION_NF_REPEAT = NF_REPEAT,
        NF_PACKET_ACTION_NF_STOP   = NF_STOP,
        _NF_PACKET_ACTION_MAX,
        _NF_PACKET_ACTION_INVALID = -1
} NFPacketAction;

typedef enum IPPacketPort {
        IP_PACKET_PORT_SPORT,
        IP_PACKET_PORT_DPORT,
        _IP_PACKET_PORT_MAX,
        _IP_PACKET_PORT_INVALID = -1
} IPPacketPort;

typedef enum IPPacketProtocol {
        IP_PACKET_PROTOCOL_TCP = IPPROTO_TCP,
        IP_PACKET_PROTOCOL_UDP = IPPROTO_UDP,
        _IP_PACKET_PROTOCOL_MAX,
        _IP_PACKET_PROTOCOL_INVALID = -1
} IPPacketProtocol;

typedef struct NFTNLTable {
        struct nftnl_table *table;

        char *name;
        int family;
} NFTNLTable;

typedef struct NFTNLChain {
        struct nftnl_chain *chain;

        char *name;
        char *table;

        int family;
} NFTNLChain;

typedef struct NFTNLRule {
        struct nftnl_rule *rule;

        char *table;
        char *chain;

        int family;
} NFTNLRule;

void nft_ctx_unbuffer_output_unref(nft_ctx *t);
DEFINE_CLEANUP(nft_ctx*, nft_ctx_unbuffer_output_unref);

int nft_table_new(int family, const char *name, NFTNLTable **ret);
int nft_add_table(int family, const char *name);
int nft_get_tables(int family, const char *name, GPtrArray **ret);
int nft_delete_table(int family, const char *name);

void nft_table_unref(NFTNLTable *t);
DEFINE_CLEANUP(NFTNLTable *, nft_table_unref);

int nft_chain_new(int family, const char *name, const char *table, NFTNLChain **ret);
int nft_add_chain(int family, const char *table, const char *name);
int nft_get_chains(int family, const char *table, const char *chain, GPtrArray **ret);
int nft_delete_chain(int family, const char *table, const char *name);

void nft_chain_unref(NFTNLChain *c);
DEFINE_CLEANUP(NFTNLChain*, nft_chain_unref);

int nft_rule_new(int family, const char *table, const char *chain, NFTNLRule **ret);
void nft_rule_unref(NFTNLRule *c);
DEFINE_CLEANUP(NFTNLRule*, nft_rule_unref);

int nft_configure_rule_port(int family, const char *table, const char *chain,
                            IPPacketProtocol protocol, IPPacketPort port_type,
                            uint16_t port, NFPacketAction action);
int nft_run_command(char **command, GString **ret);

int nft_get_rules(const char *table, GString **ret);
int nft_delete_rule(int family, const char *table, const char *chain, int handle);

const char *nft_packet_action_to_name(int id);
int nft_packet_action_name_to_type(char *name);

const char *ip_packet_port_type_to_name(int id);
int ip_packet_port_name_to_type(char *name);

const char *ip_packet_protocol_type_to_name(int id);
int ip_packet_protcol_name_to_type(char *name);

const char *nft_family_to_name(int id);
int nft_family_name_to_type(const char *name);
