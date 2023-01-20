// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package osutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func resolvePathInSysrootRec(sysroot, path string, symlinkRecursion int) (string, error) {
	if path == "" || path == "/" {
		// Relative paths are taken from sysroot
		return "/", nil
	}

	if strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}

	dir, file := filepath.Split(path)
	resolvedDir, err := resolvePathInSysrootRec(sysroot, dir, symlinkRecursion)
	if err != nil {
		return "", err
	}
	if file == "" {
		return resolvedDir, nil
	}
	if file == "." {
		return resolvedDir, nil
	}
	if file == ".." {
		upperDir, _ := filepath.Split(resolvedDir)
		return upperDir, nil
	}

	fileInResolvedDir := filepath.Join(resolvedDir, file)

	realPath := filepath.Join(sysroot, fileInResolvedDir)
	st, err := os.Lstat(realPath)
	if err != nil {
		return "", err
	}

	if st.Mode()&os.ModeSymlink != 0 {
		if symlinkRecursion < 0 {
			return "", fmt.Errorf("maximum recursion reached when reading symlinks")
		}
		target, err := os.Readlink(realPath)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			return resolvePathInSysrootRec(sysroot, target, symlinkRecursion-1)
		} else {
			return resolvePathInSysrootRec(sysroot, filepath.Join(resolvedDir, target), symlinkRecursion-1)
		}
	}

	return fileInResolvedDir, nil
}

// ResolvePathInSysroot resolves a path within a sysroot
//
// In a sysroot, abolute symlinks should be relative to the sysroot
// rather than `/`. Also paths with multiple `..` that would escape
// the sysroot should not do so.
//
// The path must point to a file that exists.
//
// Example 1:
//   - /sysroot/path1/a is a symlink pointing to /path2/b
//   - /sysroot/path2/b is a symlink pointing to /path3/c
//   - /sysroot/path3/c is a file
//     ResolvePathInSysroot("/sysroot", "/path1/a") will return "/path3/c"
//
// Example 2:
//   - /sysroot/path1/a  is a symlink pointing to ../../../path2/b
//   - /sysroot/path2/b  is a symlink pointing to ../../../path3/c
//   - /sysroot/path3/c  is a file
//     ResolvePathInSysroot("/sysroot", "../../../path1/a") will return "/path3/c"
//
// Example 3:
//   - /sysroot/path1/a is a symlink pointing to /path2/b
//   - /sysroot/path2/b does not exist
//     ResolvePathInSysroot("/sysroot", "/path1/a") will fail (IsNotExist)
//
// Example 4:
//   - /sysroot/foo is a file or a directory
//   - ResolvePathInSysroot("/sysroot", "/../../../../foo") will return "/foo"
//
// The return path is the path within the sysroot. filepath.Join() has
// to be used to get the path in the sysroot.
func ResolvePathInSysroot(sysroot, path string) (string, error) {
	return resolvePathInSysrootRec(sysroot, path, 255)
}
