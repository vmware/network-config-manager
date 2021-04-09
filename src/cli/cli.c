/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2021 VMware, Inc.
 */

#include "alloc-util.h"
#include "cli.h"
#include "macros.h"
#include "log.h"

int cli_manager_new(const Cli *cli_commands, CliManager **ret) {
        _auto_cleanup_ CliManager *m = NULL;
        size_t i;

        assert(cli_commands);
        assert(ret);

        m = new0(CliManager, 1);
        if (!m)
                return log_oom();

        *m = (CliManager) {
               .hash = g_hash_table_new(g_str_hash, g_str_equal),
               .commands = (Cli *) cli_commands,
        };
        if (!m->hash)
                return log_oom();

        for (i = 0; cli_commands[i].name; i++)
                g_hash_table_insert(m->hash, (gpointer *) cli_commands[i].name, (gpointer *) &cli_commands[i]);

        *ret = steal_pointer(m);
        return 0;
}

void cli_unref(CliManager *m) {
        if (!m)
                return;

        g_hash_table_unref(m->hash);
        free(m);
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
                log_warning("Unknown cli command '%s'.", name);
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
