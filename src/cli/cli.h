/* Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "macros.h"
#include "string-util.h"

#define WORD_ANY ((unsigned) -1)

typedef int (*CommandRunFunction)(int argc, char **argv);

typedef struct Cli {
        const char *name;
        unsigned min_args, max_args;
        bool default_command;

        CommandRunFunction run;
} Cli;

typedef struct CliManager {
        GHashTable *hash;

        Cli *commands;
} CliManager;

void cli_unref(CliManager *m);
DEFINE_CLEANUP(CliManager*, cli_unref);

int cli_manager_new(const Cli *cli_commands, CliManager **ret);
int cli_run_command(const CliManager *m, int argc, char *argv[]);
