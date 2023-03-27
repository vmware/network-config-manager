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
#include "string-util.h"

static int apply_yaml_file(const char *y) {
    _auto_cleanup_ char *c = NULL, *yaml_file = NULL;

    assert(y);

    yaml_file = string_join("", "/run/network-config-manager-ci/yaml/", y, NULL);
    if (!yaml_file)
        return -ENOMEM;

    c = string_join(" ", "/usr/bin/nmctl", "apply-file", yaml_file, NULL);
    if (!c)
        return -ENOMEM;

    assert_true(system(c) >= 0);

    return 0;
}

static void multiple_routes_address(void **state) {
    _cleanup_(key_file_freep) KeyFile *key_file = NULL;
    char *dns = NULL;
    int r;

    apply_yaml_file("multiple-rt.yml");

    r = parse_key_file("/etc/systemd/network/10-test99.network", &key_file);
    assert_true(r >= 0);

    display_key_file(key_file);
    assert_true(key_file_config_exists(key_file, "Match", "Name", "test99"));

    assert_true(dns=key_file_config_get(key_file, "Network", "DNS"));
    assert_true(g_strrstr(dns, "192.168.1.1"));
    assert_true(g_strrstr(dns, "8.8.4.4"));
    assert_true(g_strrstr(dns, "8.8.8.8"));

    assert_true(key_file_config_exists(key_file, "Network", "Domains", "testdomain1.com testdomain2.com"));
    assert_true(key_file_config_exists(key_file, "Network", "NTP", "ntp1.com ntp2.com"));

    assert_true(key_file_config_exists(key_file, "Address", "Address", "11.0.0.11/24"));
    assert_true(key_file_config_exists(key_file, "Address", "Address", "10.0.0.10/24"));

    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "10.0.0.1"));
    assert_true(key_file_config_exists(key_file, "Route", "RouteMetric", "200"));
    assert_true(key_file_config_exists(key_file, "Route", "Gateway", "11.0.0.1"));
    assert_true(key_file_config_exists(key_file, "Route", "RouteMetric", "300"));
}

static int setup(void **state) {
    system("/usr/sbin/ip link add dev test99 type dummy");

    return 0;
}

static int teardown (void **state) {
    system("/usr/sbin/ip link del test99 ");

    return 0;
}

int main(void) {
    const struct CMUnitTest tests [] = {
        cmocka_unit_test (multiple_routes_address),
    };

    int count_fail_tests = cmocka_run_group_tests (tests, setup, teardown);

    return count_fail_tests;
}
