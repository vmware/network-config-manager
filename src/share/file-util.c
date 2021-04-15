/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2021 VMware, Inc.
 */

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "file-util.h"
#include "macros.h"
#include "string-util.h"

int safe_mkdir_p_dir(const char* file_path) {
    _auto_cleanup_  char* dir = g_path_get_dirname(file_path);

    if (g_mkdir_with_parents(dir, 0755) < 0)
            return -errno;

    return 0;
}

int set_file_permisssion(const char *path, const char *user) {
        struct passwd *pw = NULL;
        int r;

        assert(path);
        assert(user);

        pw = getpwnam(user);
        if (!pw)
                return -errno;

        r = chown(path, pw->pw_uid, pw->pw_gid);
        if (r < 0)
                return -errno;

        return 0;
}


int create_conf_file(const char *path, const char *ifname, const char *extension, char **ret) {
        _auto_cleanup_ char *p = NULL, *f = NULL;
        _auto_cleanup_close_ int fd = -1;
        int r;

        assert(path);
        assert(ifname);
        assert(extension);

        f = string_join(".", ifname, extension, NULL);
        if (!f)
                return -ENOMEM;

        p = g_build_path("/", path, f, NULL);
        if (!p)
                return -ENOMEM;

        fd = creat(p, 0644 | S_ISUID | S_ISGID);
        if (fd < 0)
                return -errno;

        r = set_file_permisssion(path, "systemd-network");
        if (r < 0)
                return r;

        *ret = steal_pointer(p);

        return 0;
}

int read_one_line(const char *path, char **v) {
        _auto_cleanup_fclose_ FILE *fp = NULL;
        _auto_cleanup_ char *line = NULL;
        size_t len = LINE_MAX;
        int l;

        assert(path);
        assert(v);

        fp = fopen(path, "r");
        if (!fp)
                return -errno;

        line = new(char, LINE_MAX);
        if (!line)
                return -ENOMEM;

        l = getline(&line, &len, fp);
        if (l < 0)
                return -errno;

        *v = steal_pointer(line);

        return 0;
}

int write_one_line(const char *path, const char *v) {
        _auto_cleanup_fclose_ FILE *f = NULL;

        assert(path);
        assert(v);

        f = fopen(path, "w");
        if (!f)
                return -errno;

        if (fputs(v, f) == EOF)
                return -1;

        return 0;
}

int glob_files(const char *path, int flags, glob_t *ret) {
        int r;

        assert(path);

        errno = 0;
        r = glob(path, flags, NULL, ret);
        if (r == GLOB_NOSPACE)
                return -ENOMEM;
        if (r == GLOB_NOMATCH)
                return -ENOENT;
        if (r != 0)
                return -EIO;

        if (g_strv_length(ret->gl_pathv))
                return -ENOENT;

        return 0;
}
