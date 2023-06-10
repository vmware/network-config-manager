/* Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "edit.h"
#include "alloc-util.h"
#include "string-util.h"
#include "log.h"

int edit_file(const char *file) {
        pid_t pid;
        int r;

        assert(file);

        pid = fork();
        if (pid < 0)
                return -errno;

        if (pid == 0) {
                _auto_cleanup_strv_ char **editors = NULL;
                char **d;

                editors = strv_new("vim");
                if (!editors)
                        return log_oom();

                r = strv_add(&editors, "vi");
                if (r < 0)
                        return r;

                strv_foreach(d, editors) {
                        const char *args[] = {*d, file, NULL};

                        execvp(*d, (char* const*) args);
                        if (errno != ENOENT) {
                                log_warning("Failed to edit %s via editor %s: %s",  file, *d, strerror(-errno));
                                _exit(EXIT_FAILURE);
                        }
                }

                _exit(EXIT_SUCCESS);
        } else {
                int status;

                waitpid(pid, &status, 0);
        }

        return 0;
}
