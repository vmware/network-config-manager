/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

typedef uint16_t __bitwise le16_t;
typedef uint16_t __bitwise be16_t;
typedef uint32_t __bitwise le32_t;
typedef uint32_t __bitwise be32_t;
typedef uint64_t __bitwise le64_t;
typedef uint64_t __bitwise be64_t;

typedef uint64_t usec_t;

#define MSEC_PER_SEC  1000ULL
#define USEC_PER_SEC  ((usec_t) 1000000ULL)
#define USEC_PER_MSEC ((usec_t) 1000ULL)
#define NSEC_PER_SEC  ((nsec_t) 1000000000ULL)
#define NSEC_PER_MSEC ((nsec_t) 1000000ULL)
#define NSEC_PER_USEC ((nsec_t) 1000ULL)
