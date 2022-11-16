/* Copyright 2022 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "macros.h"
#include "string-util.h"

#define WORD_ANY ((unsigned) -1)

typedef int (*CommandRunFunction)(int argc, char **argv);

typedef struct Ctl {
        const char *name;
        const char *alias;
        unsigned min_args, max_args;
        bool default_command;

        CommandRunFunction run;
} Ctl;

typedef struct CtlManager {
        GHashTable *table;
        GHashTable *table_alias;

        Ctl *commands;
} CtlManager;

void ctl_unref(CtlManager *m);
DEFINE_CLEANUP(CtlManager*, ctl_unref);

int ctl_manager_new(const Ctl *ctl_commands, CtlManager **ret);
int ctl_run_command(const CtlManager *m, int argc, char *argv[]);
