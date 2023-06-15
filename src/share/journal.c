/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <systemd/sd-journal.h>

#include "alloc-util.h"
#include "ctl-display.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "journal.h"

int add_matches_for_unit(sd_journal *j, const char *unit) {
        const char *match_systemd_unit, *match_coredump_unit, *match_unit, *match_object_systemd_unit;
        int r;

        assert(j);
        assert(unit);

        match_systemd_unit = strjoin("_SYSTEMD_UNIT=", unit, NULL);
        match_coredump_unit = strjoin("COREDUMP_UNIT", unit, NULL);
        match_unit = strjoin("UNIT=", unit, NULL);
        match_object_systemd_unit = strjoin("OBJECT_SYSTEMD_UNIT=", unit, NULL);

        r = sd_journal_add_match(j, match_systemd_unit, 0);
        r = sd_journal_add_match(j, match_coredump_unit, 0);
        r = sd_journal_add_disjunction(j);
        r = sd_journal_add_match(j, "_PID=1", 0);
        r = sd_journal_add_match(j, match_unit, 0);

        /* Look for messages from authorized daemons about this service */
        r = sd_journal_add_disjunction(j);
        r = sd_journal_add_match(j, "_UID=0", 0);
        r = sd_journal_add_match(j, match_object_systemd_unit, 0);

        return r;
}

int add_match_current_boot(sd_journal *j) {
        char match[strlen("_BOOT_ID=") + SD_ID128_STRING_MAX];
        sd_id128_t boot_id;
        int r;

        assert(j);

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return r;

        sd_id128_to_string(boot_id, stpcpy(match, "_BOOT_ID="));
        r = sd_journal_add_match(j, match, strlen(match));
        if (r < 0)
                return r;

        return sd_journal_add_conjunction(j);
}

int display_network_logs(int ifindex, char *ifname) {
        sd_journal *j = NULL;
        int r;

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0) {
                log_error("Failed to open journal: %s", strerror(-r));
                return r;
        }

        r = add_match_current_boot(j);
        if (r < 0) {
                log_warning("Failed to add boot matches: %s", strerror(-r));
                return r;
        }
        if (ifindex > 0 && ifname) {
                _auto_cleanup_ char *device = NULL, *kernel_device = NULL;
                char interface[256] = {};

                device = strjoin("", "INTERFACE=", ifname, NULL);
                if (!device)
                        return log_oom();

                kernel_device = strjoin("", "DEVICE=", ifname, NULL);
                sprintf(interface, "_KERNEL_DEVICE=n%i", ifindex);

                r = sd_journal_add_match(j, interface, 0);
                r = sd_journal_add_disjunction(j);
                r = sd_journal_add_match(j, device, 0);
                r = sd_journal_add_disjunction(j);
                r = sd_journal_add_match(j, kernel_device, 0);
                if (r < 0) {
                        log_warning("Failed to add link matches: %s", strerror(-r));
                        return r;
                }

        } else {
                r = add_matches_for_unit(j, "systemd-networkd.service");
                if (r < 0) {
                        log_warning("Failed to add unit matches: %s", strerror(-r));
                        return r;
                }

                r = add_matches_for_unit(j, "systemd-networkd-wait-online.service");
                if (r < 0) {
                        log_warning("Failed to add unit matches: %s", strerror(-r));
                        return r;
                }
        }

        r = sd_journal_seek_tail(j);
        if (r < 0) {
                log_warning("Failed to iterate to next entry: %s", strerror(-r));
                return r;
        }

        r = sd_journal_previous_skip(j, get_log_line());
        if (r < 0) {
                log_warning("Failed to skip previous: %s", strerror(-r));
                return r;
        }

        printf("\n");
        SD_JOURNAL_FOREACH (j)  {
                _auto_cleanup_ char *p = NULL, *s = NULL, *a = NULL, *b = NULL, *c = NULL, *e = NULL, *f = NULL, *g = NULL;
                size_t l, pid_len, syslog_indentifier_len, host_name_len;
                const void *d, *pid, *syslog_indentifier, *host_name;
                char buf[128] = {};
                uint64_t x;
                time_t t;

                r = sd_journal_next(j);
                if (r < 0) {
                        log_warning("Failed to iterate to next entry: %s", strerror(-r));
                        break;
                }
                if (r == 0) {
                        r = sd_journal_wait(j, (uint64_t) -1);
                        if (r < 0) {
                                log_warning("Failed to wait for changes: %s", strerror(-r));
                                break;
                        }
                        continue;
                }

                r = sd_journal_get_realtime_usec(j, &x);
                if (r < 0)
                        continue;

                t = x / 1000000;
                strftime(buf, 16, "%b %d %H:%M:%S", localtime(&t));

                r = sd_journal_get_data(j, "MESSAGE", &d, &l);
                if (r < 0) {
                        log_warning("Failed to read message field: %s", strerror(-r));
                        continue;
                }

                r = sd_journal_get_data(j, "_PID", (const void **) &pid, &pid_len);
                if (r < 0)
                        continue;

                r = sd_journal_get_data(j, "SYSLOG_IDENTIFIER", (const void **) &syslog_indentifier, &syslog_indentifier_len);
                if (r < 0)
                        continue;

                r = sd_journal_get_data(j, "_HOSTNAME", (const void **) &host_name, &host_name_len);
                if (r < 0)
                        continue;

                split_pair((char *) d, "=", &p, &s);
                split_pair((char *) pid, "=", &a, &b);
                split_pair((char *) syslog_indentifier, "=", &c, &e);
                split_pair((char *) host_name, "=", &f, &g);
                printf("%s %s %s [%.*s] %.*s\n", buf, g, e, (int) (strlen(a) + 1), b, (int) l, s);
        }

        sd_journal_close(j);
        return 0;
}
