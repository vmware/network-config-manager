/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2019 VMware, Inc.
 */

#include <getopt.h>
#include <glib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

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

void cli_unrefp(CliManager **m);

int cli_manager_new(const Cli *cli_commands, CliManager **ret);
int cli_run_command(const CliManager *m, int argc, char *argv[]);
