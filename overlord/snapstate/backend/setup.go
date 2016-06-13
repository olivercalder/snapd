// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2016 Canonical Ltd
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

package backend

import (
	"fmt"
	"os"

	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/progress"
	"github.com/snapcore/snapd/snap"
)

// SetupSnap does prepare and mount the snap for further processing.
func (b Backend) SetupSnap(snapFilePath string, sideInfo *snap.SideInfo, meter progress.Meter) error {
	// This assumes that the snap was already verified or devmode was requested.

	s, snapf, err := OpenSnapFile(snapFilePath, sideInfo)
	if err != nil {
		return err
	}
	instdir := s.MountDir()

	if err := os.MkdirAll(instdir, 0755); err != nil {
		return err
	}

	if err := snapf.Install(s.MountFile(), instdir); err != nil {
		return err
	}

	// generate the mount unit for the squashfs
	if err := addMountUnit(s, meter); err != nil {
		return err
	}

	// FIXME: special handling is bad 'mkay
	if s.Type == snap.TypeKernel {
		if err := boot.ExtractKernelAssets(s, meter); err != nil {
			return fmt.Errorf("cannot install kernel: %s", err)
		}
	}

	return err
}

// RemoveSnapFiles removes the snap files from the disk after unmounting the snap.
func (b Backend) RemoveSnapFiles(s snap.PlaceInfo, meter progress.Meter) error {
	mountDir := s.MountDir()

	// this also ensures that the mount unit stops
	if err := removeMountUnit(mountDir, meter); err != nil {
		return err
	}

	if err := os.RemoveAll(mountDir); err != nil {
		return err
	}

	snapPath := s.MountFile()

	if osutil.FileExists(snapPath) {
		// XXX: would be better if this information was in the state directly
		info, _, err := OpenSnapFile(snapPath, nil)
		if err != nil {
			return fmt.Errorf("cannot read snap file %q to determine snap type: %v", snapPath, err)
		}

		// remove the kernel assets (if any)
		if info.Type == snap.TypeKernel {
			if err := boot.RemoveKernelAssets(s, meter); err != nil {
				return err
			}
		}

		// remove the snap
		if err := os.RemoveAll(snapPath); err != nil {
			return err
		}
	}

	return nil
}

// UndoSetupSnap undoes the work of SetupSnap using RemoveSnapFiles.
func (b Backend) UndoSetupSnap(s snap.PlaceInfo, meter progress.Meter) error {
	return b.RemoveSnapFiles(s, meter)
}
