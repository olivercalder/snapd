/*
 * Copyright (C) 2018 Canonical Ltd
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include "config.h"

#include "../libsnap-confine-private/cleanup-funcs.h"
#include "../libsnap-confine-private/mountinfo.h"
#include "../libsnap-confine-private/string-utils.h"

static sc_mountinfo_entry *find_root_mountinfo(sc_mountinfo * mounts)
{
	sc_mountinfo_entry *cur, *root = NULL;
	for (cur = sc_first_mountinfo_entry(mounts); cur != NULL;
	     cur = sc_next_mountinfo_entry(cur)) {
		// Look for the mount info entry for the root file-system.
		if (sc_streq("/", cur->mount_dir)) {
			root = cur;
		}
	}
	return root;
}

int ensure_root_fs_shared(const char *normal_dir)
{
	// Load /proc/self/mountinfo so that we can inspect the root filesystem.
	sc_mountinfo *mounts SC_CLEANUP(sc_cleanup_mountinfo) = NULL;
	mounts = sc_parse_mountinfo(NULL);
	if (!mounts) {
		fprintf(stderr, "cannot open or parse /proc/self/mountinfo\n");
		return 1;
	}

	sc_mountinfo_entry *root = find_root_mountinfo(mounts);
	if (!root) {
		fprintf(stderr,
			"cannot find mountinfo entry of the root filesystem\n");
		return 1;
	}
	// Check if the root file-system is mounted with shared option.
	if (strstr(root->optional_fields, "shared:") != NULL) {
		// The workaround is not needed, everything is good as-is.
		return 0;
	}
	// Construct the file name for a new systemd mount unit.
	char fname[PATH_MAX + 1] = { 0 };
	sc_must_snprintf(fname, sizeof fname,
			 "%s/" SNAP_MOUNT_DIR_SYSTEMD_UNIT ".mount", normal_dir);

	// Open the mount unit and write the contents.
	FILE *f SC_CLEANUP(sc_cleanup_file) = NULL;
	f = fopen(fname, "wt");
	if (!f) {
		fprintf(stderr, "cannot open %s: %m\n", fname);
		return 1;
	}
	fprintf(f,
		"# Ensure that snap mount directory is mounted \"shared\" "
		"so snaps can be refreshed correctly (LP: #1668759).\n");
	fprintf(f, "[Unit]\n");
	fprintf(f,
		"Description=Ensure that the snap directory "
		"shares mount events.\n");
	fprintf(f, "[Mount]\n");
	fprintf(f, "What=" SNAP_MOUNT_DIR "\n");
	fprintf(f, "Where=" SNAP_MOUNT_DIR "\n");
	fprintf(f, "Type=none\n");
	fprintf(f, "Options=bind,shared\n");
	fprintf(f, "[Install]\n");
	fprintf(f, "WantedBy=local-fs.target\n");
	return 0;
}

int ensure_fusesquashfs_inside_container(const char *normal_dir)
{
	// check if we are running inside a container
	if (system("systemd-detect-virt --container --quiet") != 0) {
		return 0;
	}

	char *fstype = NULL;
	if (system("which squashfuse > /dev/null") == 0) {
		fstype = "fuse.squashfuse";
	} else if (system("which snapfuse > /dev/null") == 0) {
		fstype = "fuse.snapfuse";
	} else {
		fprintf(stderr,
			"cannot find squashfuse or snapfuse executable\n");
		return 2;
	}

	DIR *units_dir SC_CLEANUP(sc_cleanup_closedir) = NULL;
    units_dir = opendir("/etc/systemd/system");
    if (units_dir == NULL) {
		fprintf(stderr,
			"cannot open /etc/systemd/system directory: %m\n");
        return 2;
    }

	char fname[PATH_MAX + 1] = { 0 };

    struct dirent *ent;
    while (ent = readdir(units_dir)) {
		if (!(sc_startswith(ent->d_name, "snap-") && sc_endswith(ent->d_name, ".mount"))) {
			continue;
		}
		sc_must_snprintf(fname, sizeof fname,
			"%s/%s.d", normal_dir, ent->d_name);
		if (mkdir(fname, 0755) != 0) {
			// generators are run over clean directory, no need to handle EEXIST
			fprintf(stderr,
				"cannot create %s directory: %m\n", fname);
			return 2;
		}

		sc_must_snprintf(fname, sizeof fname,
			"%s/%s.d/container.conf", normal_dir, ent->d_name);

		FILE *f SC_CLEANUP(sc_cleanup_file) = NULL;
		f = fopen(fname, "w");
		if (!f) {
			fprintf(stderr, "cannot open %s: %m\n", fname);
			return 1;
		}
		fprintf(f, "[Mount]\n");
		fprintf(f, "Type=%s\n", fstype);
    }
	
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		printf("usage: snapd-workaround-generator "
		       "normal-dir early-dir late-dir\n");
		return 1;
	}
	const char *normal_dir = argv[1];
	// For reference, but we don't use those variables here.
	// const char *early_dir = argv[2];
	// const char *late_dir = argv[3];

	int status = 0;
	status = ensure_root_fs_shared(normal_dir);
	status |= ensure_fusesquashfs_inside_container(normal_dir);

	return status;
}
