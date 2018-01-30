/*
 * Copyright (C) 2015 Canonical Ltd
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

#include "config.h"
#include "mount-support-nvidia.h"

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../libsnap-confine-private/classic.h"
#include "../libsnap-confine-private/cleanup-funcs.h"
#include "../libsnap-confine-private/string-utils.h"
#include "../libsnap-confine-private/utils.h"

#define SC_NVIDIA_DRIVER_VERSION_FILE "/sys/module/nvidia/version"

// note: if the parent dir changes to something other than
// the current /var/lib/snapd/lib then sc_mkdir_and_mount_and_bind
// and sc_mkdir_and_mount_and_bind need updating.
#define SC_LIBGL_DIR   "/var/lib/snapd/lib/gl"
#define SC_LIBGL32_DIR "/var/lib/snapd/lib/gl32"
#define SC_VULKAN_DIR  "/var/lib/snapd/lib/vulkan"

#define SC_VULKAN_SOURCE_DIR "/usr/share/vulkan"

// Location for NVIDIA vulkan files (including _wayland)
static const char *vulkan_globs[] = {
	"icd.d/*nvidia*.json",
};

static const size_t vulkan_globs_len =
    sizeof vulkan_globs / sizeof *vulkan_globs;

#ifdef NVIDIA_BIARCH

// List of globs that describe nvidia userspace libraries.
// This list was compiled from the following packages.
//
// https://www.archlinux.org/packages/extra/x86_64/nvidia-304xx-libgl/files/
// https://www.archlinux.org/packages/extra/x86_64/nvidia-304xx-utils/files/
// https://www.archlinux.org/packages/extra/x86_64/nvidia-340xx-libgl/files/
// https://www.archlinux.org/packages/extra/x86_64/nvidia-340xx-utils/files/
// https://www.archlinux.org/packages/extra/x86_64/nvidia-libgl/files/
// https://www.archlinux.org/packages/extra/x86_64/nvidia-utils/files/
//
// FIXME: this doesn't yet work with libGLX and libglvnd redirector
// FIXME: this still doesn't work with the 361 driver
static const char *nvidia_globs[] = {
	"libEGL.so*",
	"libEGL_nvidia.so*",
	"libGL.so*",
	"libOpenGL.so*",
	"libGLESv1_CM.so*",
	"libGLESv1_CM_nvidia.so*",
	"libGLESv2.so*",
	"libGLESv2_nvidia.so*",
	"libGLX_indirect.so*",
	"libGLX_nvidia.so*",
	"libGLX.so*",
	"libGLdispatch.so*",
	"libGLU.so*",
	"libXvMCNVIDIA.so*",
	"libXvMCNVIDIA_dynamic.so*",
	"libcuda.so*",
	"libnvcuvid.so*",
	"libnvidia-cfg.so*",
	"libnvidia-compiler.so*",
	"libnvidia-eglcore.so*",
	"libnvidia-egl-wayland*",
	"libnvidia-encode.so*",
	"libnvidia-fatbinaryloader.so*",
	"libnvidia-fbc.so*",
	"libnvidia-glcore.so*",
	"libnvidia-glsi.so*",
	"libnvidia-ifr.so*",
	"libnvidia-ml.so*",
	"libnvidia-ptxjitcompiler.so*",
	"libnvidia-tls.so*",
	"vdpau/libvdpau_nvidia.so*",
};

static const size_t nvidia_globs_len =
    sizeof nvidia_globs / sizeof *nvidia_globs;

#endif				// ifdef NVIDIA_BIARCH

// Populate libgl_dir with a symlink farm to files matching glob_list.
//
// The symbolic links are made in one of two ways. If the library found is a
// file a regular symlink "$libname" -> "/path/to/hostfs/$libname" is created.
// If the library is a symbolic link then relative links are kept as-is but
// absolute links are translated to have "/path/to/hostfs" up front so that
// they work after the pivot_root elsewhere.
//
// The glob list passed to us is produced with paths relative to source dir,
// to simplify the various tie-in points with this function.
static void sc_populate_libgl_with_hostfs_symlinks(const char *libgl_dir,
						   const char *source_dir,
						   const char *glob_list[],
						   size_t glob_list_len)
{
	glob_t glob_res SC_CLEANUP(globfree) = {
	.gl_pathv = NULL};
	// Find all the entries matching the list of globs
	for (size_t i = 0; i < glob_list_len; ++i) {
		const char *glob_pattern = glob_list[i];
		char glob_pattern_full[512] = { 0 };
		sc_must_snprintf(glob_pattern_full, sizeof glob_pattern_full,
				 "%s/%s", source_dir, glob_pattern);

		int err = glob(glob_pattern_full, i ? GLOB_APPEND : 0, NULL,
			       &glob_res);
		// Not all of the files have to be there (they differ depending on the
		// driver version used). Ignore all errors that are not GLOB_NOMATCH.
		if (err != 0 && err != GLOB_NOMATCH) {
			die("cannot search using glob pattern %s: %d",
			    glob_pattern_full, err);
		}
	}
	// Symlink each file found
	for (size_t i = 0; i < glob_res.gl_pathc; ++i) {
		char symlink_name[512] = { 0 };
		char symlink_target[512] = { 0 };
		const char *pathname = glob_res.gl_pathv[i];
		char *pathname_copy
		    SC_CLEANUP(sc_cleanup_string) = strdup(pathname);
		char *filename = basename(pathname_copy);
		struct stat stat_buf;
		int err = lstat(pathname, &stat_buf);
		if (err != 0) {
			die("cannot stat file %s", pathname);
		}
		switch (stat_buf.st_mode & S_IFMT) {
		case S_IFLNK:;
			// Read the target of the symbolic link
			char hostfs_symlink_target[512];
			ssize_t num_read;
			hostfs_symlink_target[0] = 0;
			num_read =
			    readlink(pathname, hostfs_symlink_target,
				     sizeof hostfs_symlink_target);
			if (num_read == -1) {
				die("cannot read symbolic link %s", pathname);
			}
			hostfs_symlink_target[num_read] = 0;
			if (hostfs_symlink_target[0] == '/') {
				sc_must_snprintf(symlink_target,
						 sizeof symlink_target,
						 "/var/lib/snapd/hostfs%s",
						 hostfs_symlink_target);
			} else {
				// Keep relative symlinks as-is, so that they point to -> libfoo.so.0.123
				sc_must_snprintf(symlink_target,
						 sizeof symlink_target, "%s",
						 hostfs_symlink_target);
			}
			break;
		case S_IFREG:
			sc_must_snprintf(symlink_target,
					 sizeof symlink_target,
					 "/var/lib/snapd/hostfs%s", pathname);
			break;
		default:
			debug("ignoring unsupported entry: %s", pathname);
			continue;
		}
		sc_must_snprintf(symlink_name, sizeof symlink_name,
				 "%s/%s", libgl_dir, filename);
		debug("creating symbolic link %s -> %s", symlink_name,
		      symlink_target);

		// Make sure we don't have some link already (merged GLVND systems)
		if (lstat(symlink_name, &stat_buf) == 0) {
			if (unlink(symlink_name) != 0) {
				die("cannot remove symbolic link target %s",
				    symlink_name);
			}
		}

		if (symlink(symlink_target, symlink_name) != 0) {
			die("cannot create symbolic link %s -> %s",
			    symlink_name, symlink_target);
		}
	}
}

static void sc_mkdir_and_mount_and_glob_files(const char *rootfs_dir,
					      const char *source_dir,
					      const char *tgt_dir,
					      const char *glob_list[],
					      size_t glob_list_len)
{
	// Bind mount a tmpfs on $rootfs_dir/$tgt_dir (i.e. /var/lib/snapd/lib/gl)
	char buf[512] = { 0 };
	sc_must_snprintf(buf, sizeof(buf), "%s%s", rootfs_dir, tgt_dir);
	const char *libgl_dir = buf;

	int res = mkdir(libgl_dir, 0755);
	if (res != 0 && errno != EEXIST) {
		die("cannot create tmpfs target %s", libgl_dir);
	}

	debug("mounting tmpfs at %s", libgl_dir);
	if (mount("none", libgl_dir, "tmpfs", MS_NODEV | MS_NOEXEC, NULL) != 0) {
		die("cannot mount tmpfs at %s", libgl_dir);
	};
	// Populate libgl_dir with symlinks to libraries from hostfs
	sc_populate_libgl_with_hostfs_symlinks(libgl_dir, source_dir, glob_list,
					       glob_list_len);
	// Remount $tgt_dir (i.e. .../lib/gl) read only
	debug("remounting tmpfs as read-only %s", libgl_dir);
	if (mount(NULL, buf, NULL, MS_REMOUNT | MS_RDONLY, NULL) != 0) {
		die("cannot remount %s as read-only", buf);
	}
}

#ifdef NVIDIA_BIARCH

// Copy the symlink farm to an already mounted/constructed target
static void sc_glob_files_only(const char *rootfs_dir,
			       const char *source_dir,
			       const char *tgt_dir,
			       const char *glob_list[], size_t glob_list_len)
{
	char buf[512] = { 0 };
	sc_must_snprintf(buf, sizeof(buf), "%s%s", rootfs_dir, tgt_dir);
	const char *libgl_dir = buf;

	// Populate libgl_dir with symlinks to libraries from hostfs
	sc_populate_libgl_with_hostfs_symlinks(libgl_dir, source_dir, glob_list,
					       glob_list_len);
}

// Expose host NVIDIA drivers to the snap on biarch systems.
//
// Order is absolutely imperative here. We'll attempt to find the
// primary files for the architecture in the main directory, and end
// up copying any files across. However it is possible we're using a
// GLVND enabled host, in which case we copied libGL* to the farm.
// The next step in the list is to look within the private nvidia
// directory, exposed using ld.so.conf tricks within the host OS.
// In some distros (i.e. Solus) only the private libGL/libEGL files
// may be found here, and they'll clobber the existing GLVND files from
// the previous run.
// In other distros (like Fedora) all NVIDIA libraries are contained
// within the private directory, so we clobber the GLVND files and we
// also grab all the private NVIDIA libraries.
//
// In non GLVND cases we just copy across the exposed libGLs and NVIDIA
// libraries from wherever we find, and clobbering is also harmless.
static void sc_mount_nvidia_driver_biarch(const char *rootfs_dir)
{
	// Primary arch
	sc_mkdir_and_mount_and_glob_files(rootfs_dir, "/usr/lib", SC_LIBGL_DIR,
					  nvidia_globs, nvidia_globs_len);
	sc_glob_files_only(rootfs_dir, "/usr/lib/nvidia*",
			   SC_LIBGL_DIR, nvidia_globs, nvidia_globs_len);

	// Alternative 32-bit support
	sc_mkdir_and_mount_and_glob_files(rootfs_dir, "/usr/lib32",
					  SC_LIBGL32_DIR, nvidia_globs,
					  nvidia_globs_len);
	sc_glob_files_only(rootfs_dir, "/usr/lib32/nvidia*",
			   SC_LIBGL32_DIR, nvidia_globs, nvidia_globs_len);
}

#endif				// ifdef NVIDIA_BIARCH

#ifdef NVIDIA_MULTIARCH

struct sc_nvidia_driver {
	int major_version;
	int minor_version;
};

static void sc_probe_nvidia_driver(struct sc_nvidia_driver *driver)
{
	FILE *file SC_CLEANUP(sc_cleanup_file) = NULL;
	debug("opening file describing nvidia driver version");
	file = fopen(SC_NVIDIA_DRIVER_VERSION_FILE, "rt");
	if (file == NULL) {
		if (errno == ENOENT) {
			debug("nvidia driver version file doesn't exist");
			driver->major_version = 0;
			driver->minor_version = 0;
			return;
		}
		die("cannot open file describing nvidia driver version");
	}
	// Driver version format is MAJOR.MINOR where both MAJOR and MINOR are
	// integers. We can use sscanf to parse this data.
	if (fscanf
	    (file, "%d.%d", &driver->major_version,
	     &driver->minor_version) != 2) {
		die("cannot parse nvidia driver version string");
	}
	debug("parsed nvidia driver version: %d.%d", driver->major_version,
	      driver->minor_version);
}

static void sc_mkdir_and_mount_and_bind(const char *rootfs_dir,
					const char *src_dir,
					const char *tgt_dir)
{
	struct sc_nvidia_driver driver;

	// Probe sysfs to get the version of the driver that is currently inserted.
	sc_probe_nvidia_driver(&driver);

	// If there's driver in the kernel then don't mount userspace.
	if (driver.major_version == 0) {
		return;
	}
	// Construct the paths for the driver userspace libraries
	// and for the gl directory.
	char src[PATH_MAX] = { 0 };
	char dst[PATH_MAX] = { 0 };
	sc_must_snprintf(src, sizeof src, "%s-%d", src_dir,
			 driver.major_version);
	sc_must_snprintf(dst, sizeof dst, "%s%s", rootfs_dir, tgt_dir);

	// If there is no userspace driver available then don't try to mount it.
	// This can happen for any number of reasons but one interesting one is
	// that that snapd runs in a lxd container on a host that uses nvidia. In
	// that case the container may not have the userspace library installed but
	// the kernel will still have the module around.
	if (access(src, F_OK) != 0) {
		return;
	}
	int res = mkdir(dst, 0755);
	if (res != 0 && errno != EEXIST) {
		die("cannot create directory %s", dst);
	}
	// Bind mount the binary nvidia driver into $tgt_dir (i.e. /var/lib/snapd/lib/gl).
	debug("bind mounting nvidia driver %s -> %s", src, dst);
	if (mount(src, dst, NULL, MS_BIND, NULL) != 0) {
		die("cannot bind mount nvidia driver %s -> %s", src, dst);
	}
}

static void sc_mount_nvidia_driver_multiarch(const char *rootfs_dir)
{
	// Attempt mount of both the native and 32-bit variants of the driver if they exist
	sc_mkdir_and_mount_and_bind(rootfs_dir, "/usr/lib/nvidia",
				    SC_LIBGL_DIR);
	sc_mkdir_and_mount_and_bind(rootfs_dir, "/usr/lib32/nvidia",
				    SC_LIBGL32_DIR);
}

#endif				// ifdef NVIDIA_MULTIARCH

void sc_mount_nvidia_driver(const char *rootfs_dir)
{
	/* If NVIDIA module isn't loaded, don't attempt to mount the drivers */
	if (access(SC_NVIDIA_DRIVER_VERSION_FILE, F_OK) != 0) {
		return;
	}
#ifdef NVIDIA_MULTIARCH
	sc_mount_nvidia_driver_multiarch(rootfs_dir);
#endif				// ifdef NVIDIA_MULTIARCH
#ifdef NVIDIA_BIARCH
	sc_mount_nvidia_driver_biarch(rootfs_dir);
#endif				// ifdef NVIDIA_BIARCH

	// Common for both driver mechanisms
	sc_mkdir_and_mount_and_glob_files(rootfs_dir, SC_VULKAN_SOURCE_DIR,
					  SC_VULKAN_DIR, vulkan_globs,
					  vulkan_globs_len);
}
