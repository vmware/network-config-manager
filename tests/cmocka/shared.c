/* Copyright 2024 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "alloc-util.h"
#include "config-file.h"
#include "config-parser.h"
#include "file-util.h"
#include "log.h"
#include "macros.h"
#include "parse-util.h"
#include "shared.h"
#include "string-util.h"

int link_add(const char *s) {
    _auto_cleanup_ char *c = NULL;

    c = strjoin(" ", "/usr/sbin/ip", "link", "add", "dev", s, "type", "dummy", NULL);
    if (!c)
        return -ENOMEM;

    system(c);

    return 0;
}

int link_remove (const char *s) {
    _auto_cleanup_ char *c = NULL;

    c = strjoin(" ", "/usr/sbin/ip", "link", "del", s, NULL);
    if (!c)
        return -ENOMEM;

    system(c);

    return 0;
}

int reload_networkd (const char *s) {
    _auto_cleanup_ char *c = NULL;

    system("networkctl reload");
    system("sleep 30");

    c = strjoin(" ", "/lib/systemd/systemd-networkd-wait-online", "-i", s, NULL);
    if (!c)
        return -ENOMEM;

    system(c);

    return 0;
}

int apply_yaml_file(const char *y) {
    _auto_cleanup_ char *c = NULL, *yaml_file = NULL;

    assert(y);

    yaml_file = strjoin("", "/run/network-config-manager-ci/yaml/", y, NULL);
    if (!yaml_file)
        return -ENOMEM;

    c = strjoin(" ", "/usr/bin/nmctl", "apply-file", yaml_file, NULL);
    if (!c)
        return -ENOMEM;

    assert_true(system(c) >= 0);

    return 0;
}
