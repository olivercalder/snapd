/*
 * Copyright (C) 2015-2018 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "../libsnap-confine-private/error.h"
#include "../libsnap-confine-private/locking.h"
#include "../libsnap-confine-private/snap.h"
#include "../libsnap-confine-private/string-utils.h"
#include "../libsnap-confine-private/utils.h"

#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: snap-discard-ns <SNAP-INSTANCE-NAME>\n");
		return 0;
	}

	const char *snap_instance_name = argv[1];
	struct sc_error *err = NULL;
	sc_instance_name_validate(snap_instance_name, &err);
	sc_die_on_error(err);

	/* Grab the lock holding the snap instance. This prevents races from
	 * concurrently executing snap-confine. The lock is explicitly released
	 * during normal operation but it is not preserved across the life-cycle of
	 * the process anyway so no attempt is made to unlock it ahead of any call
	 * to die() */
	int snap_lock_fd = sc_lock_snap(snap_instance_name);
	debug("discarding mount namespaces of snap %s", snap_instance_name);

	const char *ns_dir_path = "/run/snapd/ns";
	int ns_dir_fd = open(ns_dir_path, O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (ns_dir_fd < 0) {
		/* The directory may legitimately not exist if no snap has started to
		 * prepare it. This is not an error condition. */
		if (errno == ENOENT) {
			return 0;
		}
		die("cannot open path %s", ns_dir_path);
	}

	/* Move to the namespace directory. This is used so that we don't need to
	 * traverse the path over and over in our upcoming unmount2(2) calls. */
	if (fchdir(ns_dir_fd) < 0) {
		die("cannot move to directory %s", ns_dir_path);
	}

	/* Create shell patterns that describe the things we are interested in:
	 *
	 * Preserved mount namespaces to unmount and unlink:
	 * - "$SNAP_INSTANCE_NAME.mnt"
	 * - "$SNAP_INSTANCE_NAME.[0-9]+.mnt"
	 *
	 * Applied mount profiles to unlink:
	 * - "snap.$SNAP_INSTANCE_NAME.fstab"
	 * - "snap.$SNAP_INSTANCE_NAME.[0-9]+.fstab" */
	char sys_fstab_pattern[PATH_MAX];
	char usr_fstab_pattern[PATH_MAX];
	char sys_mnt_pattern[PATH_MAX];
	char usr_mnt_pattern[PATH_MAX];
	sc_must_snprintf(sys_fstab_pattern, sizeof sys_fstab_pattern,
			 "snap\\.%s\\.fstab", snap_instance_name);
	sc_must_snprintf(usr_fstab_pattern, sizeof usr_fstab_pattern,
			 "snap\\.%s\\.*\\.fstab", snap_instance_name);
	sc_must_snprintf(sys_mnt_pattern, sizeof sys_mnt_pattern,
			 "%s\\.mnt", snap_instance_name);
	sc_must_snprintf(usr_mnt_pattern, sizeof usr_mnt_pattern,
			 "%s\\.*\\.mnt", snap_instance_name);

	DIR *ns_dir = fdopendir(ns_dir_fd);
	if (ns_dir == NULL) {
		die("cannot fdopendir");
	}
	/* ns_dir_fd is now owned by ns_dir and will not be closed. */

	while (true) {
		/* Reset errno ahead of any call to readdir to differentiate errors
		 * from legitimate end of directory. */
		errno = 0;
		struct dirent *dent = readdir(ns_dir);
		if (dent == NULL) {
			if (errno != 0) {
				die("cannot read next directory entry");
			}
			/* We've seen the whole directory. */
			break;
		}

		/* We use dnet->d_name a lot so let's shorten it. */
		const char *dname = dent->d_name;

		/* Check the four patterns that we have against the name and set the
		 * two should flags to decide further actions. Note that we always
		 * unlink matching files so that is not reflected in the structure. */
		bool should_unmount = false;
		bool should_unlink = false;
		struct variant {
			const char *pattern;
			bool unmount;
		};
		struct variant variants[4] = {
			{.pattern = sys_mnt_pattern,.unmount = true},
			{.pattern = usr_mnt_pattern,.unmount = true},
			{.pattern = sys_fstab_pattern},
			{.pattern = usr_fstab_pattern},
		};
		for (size_t i = 0; i < sizeof variants / sizeof *variants; ++i) {
			struct variant *v = &variants[i];
			debug("checking if %s matches %s", dname, v->pattern);
			int match_result = fnmatch(v->pattern, dname, 0);
			if (match_result == FNM_NOMATCH) {
				continue;
			} else if (match_result == 0) {
				should_unmount |= v->unmount;
				should_unlink = true;
				debug("file %s matches pattern %s", dname,
				      v->pattern);
				/* One match is enough. */
				break;
			} else if (match_result < 0) {
				die("cannot execute match against pattern %s",
				    v->pattern);
			}
		}

		/* Stat the candidate directory entry to know what we are dealing with. */
		struct stat file_info;
		if (fstatat(ns_dir_fd, dname, &file_info,
			    AT_SYMLINK_NOFOLLOW) < 0) {
			die("cannot inspect file %s", dname);
		}

		/* We are only interested in regular files. The .mnt files, even if
		 * bind-mounted, appear as regular files and not as symbolic links due
		 * to the peculiarities of the Linux kernel. */
		if (!S_ISREG(file_info.st_mode)) {
			continue;
		}

		if (should_unmount) {
			/* If we are asked to unmount the file double check that it is
			 * really a preserved mount namespace since the error code from
			 * umount2(2) is inconclusive. */
			int path_fd = openat(ns_dir_fd, dname,
					     O_PATH | O_CLOEXEC | O_NOFOLLOW);
			if (path_fd < 0) {
				die("cannot open path %s", dname);
			}
			struct statfs fs_info;
			if (fstatfs(path_fd, &fs_info) < 0) {
				die("cannot inspect file-system at %s", dname);
			}
			close(path_fd);
			if (fs_info.f_type == NSFS_MAGIC
			    || fs_info.f_type == PROC_SUPER_MAGIC) {
				debug("unmounting %s", dname);
				if (umount2(dname, MNT_DETACH | UMOUNT_NOFOLLOW)
				    < 0) {
					die("cannot unmount %s", dname);
				}
			}
		}

		if (should_unlink) {
			debug("unlinking %s", dname);
			if (unlinkat(ns_dir_fd, dname, 0) < 0) {
				die("cannot unlink %s", dname);
			}
		}
	}

	/* Close the directory and release the lock, we're done. */
	if (closedir(ns_dir) < 0) {
		die("cannot close directory");
	}
	sc_unlock(snap_lock_fd);
	return 0;
}
