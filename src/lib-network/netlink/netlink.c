/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "alloc-util.h"
#include "macros.h"
#include "log.h"
#include "netlink.h"

int rtnl_message_add_attribute(struct nlmsghdr *hdr, int type, const void *data, int len) {
        struct rtattr *attr;
        int l;

        assert(hdr);

        l = RTA_LENGTH(len);

        attr = NLMSG_TAIL(hdr);
        attr->rta_type = type;
        attr->rta_len = l;
        if (len)
                memcpy(RTA_DATA(attr), data, len);

        hdr->nlmsg_len = NLMSG_ALIGN(hdr->nlmsg_len) + RTA_ALIGN(l);

        return 0;
}

struct rtattr *rtnl_message_add_attribute_nested(struct nlmsghdr *hdr, int type, const void *value, int len) {
        struct rtattr *nest;
        int r;

        assert(hdr);

        nest = NLMSG_TAIL(hdr);

        r = rtnl_message_add_attribute(hdr, type, NULL, len);
        if (r < 0)
                return NULL;

        return nest;
}

int addattr_nest_end(struct nlmsghdr *hdr, struct rtattr *nested) {
        assert(hdr);
        assert(nested);

        nested->rta_len = (char *) NLMSG_TAIL(hdr) - (char *) nested;

        return hdr->nlmsg_len;
}

int rtnl_message_add_attribute_uint8(struct nlmsghdr *hdr, int type, uint8_t value) {
        assert(hdr);

        return rtnl_message_add_attribute(hdr, type, &value, sizeof(uint8_t));
}

int rtnl_message_add_attribute_uint16(struct nlmsghdr *hdr, int type, uint16_t value) {
        assert(hdr);

        return rtnl_message_add_attribute(hdr, type, &value, sizeof(uint16_t));
}

int rtnl_message_add_attribute_uint32(struct nlmsghdr *hdr, int type, uint32_t value) {
        assert(hdr);

        return rtnl_message_add_attribute(hdr, type, &value, sizeof(uint32_t));
}

int rtnl_message_add_attribute_uint64(struct nlmsghdr *hdr, int type, uint64_t value) {
        assert(hdr);

        return rtnl_message_add_attribute(hdr, type, &value, sizeof(uint64_t));
}

int rtnl_message_add_attribute_string(struct nlmsghdr *hdr, int type, const char *attribute) {
        assert(hdr);

        return rtnl_message_add_attribute(hdr, type, attribute, strlen(attribute) + 1);
}

int rtnl_message_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, int len) {
        unsigned short type;

        for (;RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
                type = rta->rta_type & ~NLA_F_NESTED;

                if ((type <= max) && (tb + type))
                        *(tb + type) = rta;
        }

        return 0;
}

struct rtattr *rtnl_message_parse_rtattr_one(int type, struct rtattr *rta, int len) {
         assert(rta);

         for (;RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
                if (rta->rta_type == type)
                        return rta;

        return NULL;
}

uint8_t rtnl_message_read_attribute_u8(const struct rtattr *rta) {
        assert(rta);

        return *(uint8_t *) RTA_DATA(rta);
}

uint16_t rtnl_message_read_attribute_u16(const struct rtattr *rta) {
        assert(rta);

        return *(uint16_t *) RTA_DATA(rta);
}

be16_t rtnl_message_read_attribute_be16(const struct rtattr *rta) {
         assert(rta);

        return ntohs(rtnl_message_read_attribute_u16(rta));
}

uint32_t rtnl_message_read_attribute_u32(const struct rtattr *rta) {
        assert(rta);

        return *(uint32_t *) RTA_DATA(rta);
}

be32_t rtnl_message_read_attribute_be32(const struct rtattr *rta) {
        assert(rta);

        return ntohl(rtnl_message_read_attribute_u32(rta));
}

uint64_t rtnl_message_read_attribute_u64(const struct rtattr *rta) {
        uint64_t tmp;

        assert(rta);

        memcpy(&tmp, RTA_DATA(rta), sizeof(__u64));
        return tmp;
 }

int rtnl_message_read_attribute_s32(const struct rtattr *rta) {
        assert(rta);

        return *(int *) RTA_DATA(rta);
}

const char *rtnl_message_read_attribute_string(const struct rtattr *rta) {
        assert(rta);

        return (const char *) RTA_DATA(rta);
}

int rtnl_message_read_attribute_ether_address(const struct rtattr *rta, struct ether_addr *data) {
        assert(rta);
        assert(data);

        memcpy(data, RTA_DATA(rta), sizeof(struct ether_addr));
        return 0;
}

int rtnl_message_read_in_addr(const struct rtattr *rta, struct in_addr *data) {
        assert(rta);

        if (data)
                memcpy(data, RTA_DATA(rta), sizeof(struct in_addr));

        return 0;
}

int rtnl_message_read_in6_addr(const struct rtattr *rta, struct in6_addr *data) {
        assert(rta);

        if (data)
                memcpy(data, RTA_DATA(rta), sizeof(struct in6_addr));

        return 0;
}


int rtnl_message_is_error(struct nlmsghdr *hdr) {
        assert(hdr);

        return hdr->nlmsg_type == NLMSG_ERROR;
}

int rtnl_message_get_errno(struct nlmsghdr *hdr) {
        struct nlmsgerr *err;

        assert(hdr);

        if (!rtnl_message_is_error(hdr))
                return 0;

        err = NLMSG_DATA(hdr);

        return err->error;
}

bool rtnl_message_is_done(struct nlmsghdr *hdr) {
        assert(hdr);

        return hdr->nlmsg_type == NLMSG_DONE;
}

int rtnl_message_request_dump(struct nlmsghdr *hdr, int dump) {
        assert(hdr);

        SET_FLAG(hdr->nlmsg_flags, NLM_F_DUMP, dump);

        return 0;
}

int rtnl_socket_open(unsigned int group, int *ret) {
        _auto_cleanup_close_ int fd = -1;
        struct sockaddr_nl addr = {
                        .nl_family = AF_NETLINK,
                        .nl_pid = getpid(),
                        .nl_groups = group
        };
        int sndbuf = 32768, rcvbuf = 1024 * 1024;
        struct sockaddr_nl local;
        socklen_t addr_len;

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0)
                return -errno;

        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0)
                return -errno;

        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
                return -errno;

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
                 return -errno;

        addr_len = sizeof(local);
        if (getsockname(fd, (struct sockaddr *)&local, &addr_len) < 0)
                return -errno;

        if (addr_len != sizeof(local))
                return -EINVAL;

        if (local.nl_family != AF_NETLINK)
                return -EINVAL;

        *ret = steal_fd(fd);

        return 0;
}

int rtnl_send_message(int fd, struct nlmsghdr *hdr) {
        struct sockaddr_nl nladdr = {
                        .nl_family = AF_NETLINK
        };
        struct iovec iov = {
                        .iov_base = hdr,
                        .iov_len = hdr->nlmsg_len,
        };
        struct msghdr msg = {
                        .msg_name = &nladdr,
                        .msg_namelen = sizeof(nladdr),
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
        };
        int r;

        assert(hdr);

        r = sendmsg(fd, &msg, 0);
        if (r < 0)
                return -errno;

        return 0;
}

size_t rtnl_receive_message(int fd, char *buf, int len, int flags) {
        struct sockaddr_nl sender = {
                        .nl_family = AF_NETLINK,
        };
        struct iovec iov = {
                        .iov_base = buf,
                        .iov_len  = len,
        };
        struct msghdr msg = {
                        .msg_name       = &sender,
                        .msg_namelen    = sizeof(struct sockaddr_nl),
                        .msg_iov        = &iov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = 0,
        };
        size_t k;

        assert(fd >=0);
        assert(buf);
        assert(len > 0);

        k = recvmsg(fd, &msg, flags);
        if (k <= 0)
                return k;

        if (msg.msg_flags & MSG_TRUNC)
                return -ENOSPC;

        if (msg.msg_namelen != sizeof(struct sockaddr_nl))
                return -EINVAL;

        if (rtnl_message_is_done((struct nlmsghdr *) buf))
                return 0;

        /* drop the message as not sent by the kernel */
        if (sender.nl_pid != 0)
                return 0;

        return k;
}

int netlink_call(int fd, struct nlmsghdr *hdr, char *ret, size_t len) {
        struct nlmsghdr *reply;
        uint32_t sequence;
        pid_t pid;
        size_t l;
        int r;

        assert(hdr);
        assert(ret);

        sequence = hdr->nlmsg_seq = random();
        pid = hdr->nlmsg_pid = getpid();

        r = rtnl_send_message(fd, hdr);
        if (r < 0)
                return r;

        l = rtnl_receive_message(fd, ret, len, 0);
        if (l == 0)
                return -ENODATA;

        reply = (struct nlmsghdr *) ret;
        if ((reply->nlmsg_seq != sequence) || (reply->nlmsg_pid != (uint32_t) pid))
                return -errno;

        if ((NLMSG_OK(reply, l) == 0) || (reply->nlmsg_type == NLMSG_ERROR)) {
                struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(reply);

                if (reply->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                        log_warning("netlink message truncated");
                else
                        errno = err->error;

                return errno;
        }

        return 0;
}
