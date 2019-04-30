// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package wrappers

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"
)

func findIconFiles(rootDir string, iconGlob string) (icons []string, err error) {
	if !osutil.IsDirectory(rootDir) {
		return nil, nil
	}
	forbiddenDirGlob := "snap.*"
	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		base := filepath.Base(path)
		if info.IsDir() {
			// Ignore directories that could match an icon glob
			if ok, err := filepath.Match(forbiddenDirGlob, base); ok || err != nil {
				return filepath.SkipDir
			}
		} else {
			if ok, err := filepath.Match(iconGlob, base); err != nil {
				return err
			} else if ok {
				ext := filepath.Ext(base)
				if ext == ".png" || ext == ".svg" {
					icons = append(icons, rel)
				}
			}
		}
		return nil
	})
	return icons, err
}

func deriveIconContent(rootDir string, icons []string) (content map[string]map[string]*osutil.FileState, err error) {
	content = make(map[string]map[string]*osutil.FileState)

	for _, iconFile := range icons {
		dir := filepath.Dir(iconFile)
		base := filepath.Base(iconFile)
		dirContent := content[dir]
		if dirContent == nil {
			dirContent = make(map[string]*osutil.FileState)
			content[dir] = dirContent
		}
		data, err := ioutil.ReadFile(filepath.Join(rootDir, iconFile))
		if err != nil {
			return nil, err
		}
		dirContent[base] = &osutil.FileState{
			Content: data,
			Mode:    0644,
		}
	}
	return content, nil
}

func AddSnapIcons(s *snap.Info) error {
	if err := os.MkdirAll(dirs.SnapDesktopIconsDir, 0755); err != nil {
		return err
	}

	rootDir := filepath.Join(s.MountDir(), "meta", "gui", "icons")
	iconGlob := fmt.Sprintf("snap.%s.*", s.SnapName())
	icons, err := findIconFiles(rootDir, iconGlob)
	if err != nil {
		return err
	}

	content, err := deriveIconContent(rootDir, icons)
	if err != nil {
		return err
	}
	_, _, err = osutil.EnsureTreeState(dirs.SnapDesktopIconsDir, []string{iconGlob}, content)
	return err
}

func RemoveSnapIcons(s *snap.Info) error {
	if !osutil.IsDirectory(dirs.SnapDesktopIconsDir) {
		return nil
	}
	iconGlob := fmt.Sprintf("snap.%s.*", s.SnapName())
	_, _, err := osutil.EnsureTreeState(dirs.SnapDesktopIconsDir, []string{iconGlob}, nil)
	return err
}
