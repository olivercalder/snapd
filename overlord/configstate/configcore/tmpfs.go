// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package configcore

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/overlord/configstate/config"
	"github.com/snapcore/snapd/sysconfig"
)

const (
	mntStaticOptions         = "mode=1777,strictatime,nosuid,nodev"
	tmpfsMountPoint          = "/tmp"
	tmpMntServOverrideSubDir = "tmp.mount.d"
	tmpMntServOverrideFile   = "override.conf"
)

func init() {
	// add supported configuration of this module
	supportedConfigurations["core.tmpfs.size"] = true
}

// Regex matches what is specified by tmpfs(5) for the size option
var validTmpfsSizeRe = regexp.MustCompile(`^[0-9]+[kmgKMG%]?$`).MatchString

func validTmpfsSize(sizeStr string) error {
	if !validTmpfsSizeRe(sizeStr) {
		return fmt.Errorf("cannot set tmpfs size %q: invalid size", sizeStr)
	}

	postfix := sizeStr[len(sizeStr)-1:]
	mult := uint64(1)
	isPercentage := false
	numberLen := len(sizeStr) - 1
	switch postfix {
	case "k", "K":
		mult = 1024
	case "m", "M":
		mult = 1024 * 1024
	case "g", "G":
		mult = 1024 * 1024 * 1024 * 1024
	case "%":
		isPercentage = true
	default:
		numberLen += 1
	}

	size, err := strconv.ParseUint(sizeStr[0:numberLen], 10, 64)
	if err != nil {
		return err
	}
	if isPercentage {
		sysinfo := &syscall.Sysinfo_t{}
		if err := syscall.Sysinfo(sysinfo); err != nil {
			return err
		}
		size = (sysinfo.Totalram * uint64(sysinfo.Unit) * size) / 100
	} else {
		size *= mult
	}

	// Do not allow less than 16mb
	// 0 is special and means unlimited
	if size > 0 && size < 16*1024*1024 {
		return fmt.Errorf("size is less than 16Mb")
	}

	return nil
}

func validateTmpfsSettings(tr config.ConfGetter) error {
	tmpfsSz, err := coreCfg(tr, "tmpfs.size")
	if err != nil {
		return err
	}
	if tmpfsSz == "" {
		return nil
	}
	if err := validTmpfsSize(tmpfsSz); err != nil {
		return err
	}

	return nil
}

func handleTmpfsConfiguration(_ sysconfig.Device, tr config.ConfGetter, opts *fsOnlyContext) error {
	tmpfsSz, err := coreCfg(tr, "tmpfs.size")
	if err != nil {
		return err
	}

	// Create override configuration file for tmp.mount service

	// Create /etc/systemd/system/tmp.mount.d if needed
	var overrDir string
	if opts == nil {
		// runtime system
		overrDir = dirs.SnapServicesDir
	} else {
		overrDir = dirs.SnapServicesDirUnder(opts.RootDir)
	}
	overrDir = filepath.Join(overrDir, tmpMntServOverrideSubDir)

	// Write service config override if needed
	options := mntStaticOptions
	dirContent := make(map[string]osutil.FileState, 1)
	cfgFilePath := filepath.Join(overrDir, tmpMntServOverrideFile)
	modify := true
	if tmpfsSz != "" {
		if err := os.MkdirAll(overrDir, 0755); err != nil {
			return err
		}
		options = fmt.Sprintf("%s,size=%s", options, tmpfsSz)
		content := fmt.Sprintf("[Mount]\nOptions=%s\n", options)
		dirContent[tmpMntServOverrideFile] = &osutil.MemoryFileState{
			Content: []byte(content),
			Mode:    0644,
		}
		oldContent, err := ioutil.ReadFile(cfgFilePath)
		if err == nil && content == string(oldContent) {
			modify = false
		}
	} else {
		// Use default tmpfs size if empty setting (50%, see tmpfs(5))
		options = fmt.Sprintf("%s,size=50%%", options)
		// In this case, we are removing the file, so we will
		// not do anything if the file is not there alreay.
		if _, err := os.Stat(cfgFilePath); errors.Is(err, os.ErrNotExist) {
			modify = false
		}
	}

	// Re-starting the tmp.mount service will fail if some process
	// is using a file in /tmp, so instead of doing that we use
	// the remount option for the mount command, which will not
	// fail in that case. There is however the possibility of a
	// failure in case we are reducing the size to something
	// smaller than the currently used space in the mount. We
	// return an error in that case.
	if opts == nil && modify {
		output, err := exec.Command("mount", "-o", "remount,"+options, tmpfsMountPoint).CombinedOutput()
		if err != nil {
			return fmt.Errorf("cannot remount tmpfs with new size: %s (%s)", err.Error(), output)
		}
	}

	glob := tmpMntServOverrideFile
	_, _, err = osutil.EnsureDirState(overrDir, glob, dirContent)
	if err != nil {
		return err
	}

	return nil
}
