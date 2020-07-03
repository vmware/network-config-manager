/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2020 VMware, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "alloc-util.h"
#include "cli.h"
#include "macros.h"
#include "log.h"

int cli_manager_new(const Cli *cli_commands, CliManager **ret) {
        _auto_cleanup_ CliManager *m = NULL;
        int i;

        assert(cli_commands);

        m = new0(CliManager, 1);
        if (!m)
                return log_oom();

        *m = (CliManager) {
               .hash = g_hash_table_new(g_str_hash, g_str_equal),
               .commands = (Cli *) cli_commands,
        };

        if (!m->hash)
                return log_oom();

        for (i = 0;; i++) {
                if (cli_commands[i].name) {
                        if (!g_hash_table_insert(m->hash, (gpointer *) cli_commands[i].name, (gpointer *) &cli_commands[i]))
                                continue;
                } else
                        break;
        }

        *ret = steal_pointer(m);

        return 0;
}

void cli_unrefp(CliManager **m) {
        if (m && *m) {
                g_hash_table_unref((*m)->hash);
                free(*m);
        }
}

static Cli *cli_get_command(const CliManager *m, const char *name) {
        assert(m);
        assert(name);

        return g_hash_table_lookup(m->hash, name);
}

int cli_run_command(const CliManager *m, int argc, char *argv[]) {
        Cli *command = NULL;
        int remaining_argc;
        char *name;

        assert(m);

        remaining_argc = argc - optind;

        argv += optind;
        optind = 0;
        name = argv[0];

        /* run default if no command specified */
        if (!name) {
                int i;

                for (i = 0;; i++) {
                        if (m->commands[i].default_command)
                                command = m->commands;
                        remaining_argc = 1;
                        return command->run(remaining_argc, argv);
                }
        }

        command = cli_get_command(m, name);
        if (!command) {
                log_warning("Unknown cli command %s.", name);
                return -EINVAL;
        }

        if (command->min_args != WORD_ANY && (unsigned) remaining_argc <= command->min_args) {
                log_warning("Too few arguments.");
                return -EINVAL;
        }

        if (command->max_args != WORD_ANY && (unsigned) remaining_argc > command->max_args) {
                log_warning("Too many arguments.");
                return -EINVAL;
        }

        return command->run(remaining_argc, argv);
}
