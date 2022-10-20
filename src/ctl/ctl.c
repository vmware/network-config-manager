/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "alloc-util.h"
#include "ctl.h"
#include "macros.h"
#include "log.h"

int ctl_manager_new(const Ctl *ctl_commands, CtlManager **ret) {
        _auto_cleanup_ CtlManager *m = NULL;

        assert(ctl_commands);
        assert(ret);

        m = new0(CtlManager, 1);
        if (!m)
                return log_oom();

        *m = (CtlManager) {
               .hash = g_hash_table_new(g_str_hash, g_str_equal),
               .commands = (Ctl *) ctl_commands,
        };
        if (!m->hash)
                return log_oom();

        for (size_t i = 0; ctl_commands[i].name; i++)
                g_hash_table_insert(m->hash, (gpointer *) ctl_commands[i].name, (gpointer *) &ctl_commands[i]);

        *ret = steal_pointer(m);
        return 0;
}

void ctl_unref(CtlManager *m) {
        if (!m)
                return;

        g_hash_table_unref(m->hash);
        free(m);
}

static Ctl *ctl_get_command(const CtlManager *m, const char *name) {
        assert(m);
        assert(name);

        return g_hash_table_lookup(m->hash, name);
}

int ctl_run_command(const CtlManager *m, int argc, char *argv[]) {
        Ctl *command = NULL;
        int remaining_argc;
        char *name;

        assert(m);

        remaining_argc = argc - optind;

        argv += optind;
        optind = 0;
        name = argv[0];

        /* run default if no command specified */
        if (!name) {
                for (size_t i = 0;; i++) {
                        if (m->commands[i].default_command)
                                command = m->commands;
                        remaining_argc = 1;
                        return command->run(remaining_argc, argv);
                }
        }

        command = ctl_get_command(m, name);
        if (!command) {
                log_warning("Unknown ctl command '%s'.", name);
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
