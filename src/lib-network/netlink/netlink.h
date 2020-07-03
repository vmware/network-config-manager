/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#pragma once

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "defines.h"

#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((char *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

int rtnl_message_add_attribute(struct nlmsghdr *hdr, int type, const void *value, int len);
struct rtattr *rtnl_message_add_attribute_nested(struct nlmsghdr *hdr, int type, const void *value, int len);
int addattr_nest_end(struct nlmsghdr *hdr, struct rtattr *nested);
int rtnl_message_add_attribute_uint8(struct nlmsghdr *hdr, int type, uint8_t value);
int rtnl_message_add_attribute_uint16(struct nlmsghdr *hdr, int type, uint16_t value);
int rtnl_message_add_attribute_uint32(struct nlmsghdr *hdr, int type, uint32_t value);
int rtnl_message_add_attribute_uint64(struct nlmsghdr *hdr, int type, uint64_t value);
int rtnl_message_add_attribute_string(struct nlmsghdr *hdr, int type, const char *attribute);

int rtnl_message_is_error(struct nlmsghdr *hdr);
int rtnl_message_get_errno(struct nlmsghdr *hdr);
bool rtnl_message_is_done(struct nlmsghdr *hdr);
int rtnl_message_request_dump(struct nlmsghdr *hdr, int dump);

int rtnl_socket_open(unsigned int group, int *ret);

int rtnl_send_message(int fd, struct nlmsghdr *hdr);
size_t rtnl_receive_message(int fd, char *buf, int len, int flags);
int netlink_call(int fd, struct nlmsghdr *hdr, char *ret, size_t len);

int rtnl_message_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, int len);
struct rtattr *rtnl_message_parse_rtattr_one(int type, struct rtattr *rta, int len);

uint8_t rtnl_message_read_attribute_u8(const struct rtattr *rta);
uint16_t rtnl_message_read_attribute_u16(const struct rtattr *rta);
be16_t rtnl_message_read_attribute_be16(const struct rtattr *rta);
uint32_t rtnl_message_read_attribute_u32(const struct rtattr *rta);
be32_t rtnl_message_read_attribute_be32(const struct rtattr *rta);
uint64_t rtnl_message_read_attribute_u64(const struct rtattr *rta);
int rtnl_message_read_attribute_s32(const struct rtattr *rta);
const char *rtnl_message_read_attribute_string(const struct rtattr *rta);
int rtnl_message_read_attribute_ether_address(const struct rtattr *rta, struct ether_addr *data);
int rtnl_message_read_in_addr(const struct rtattr *rta, struct in_addr *data);
int rtnl_message_read_in6_addr(const struct rtattr *rta, struct in6_addr *data);
