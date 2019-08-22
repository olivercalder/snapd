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
	"path/filepath"

	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/progress"
	"github.com/snapcore/snapd/snap"
)

// InstallUndoContext keeps information about what needs to be undone in case of install failure
type InstallUndoContext struct {
	// KeepTargetSnap indicates that the target .snap file under /var/lib/snapd/snap already existed when the
	// backend attempted SetupSnap() through squashfs Install() and should be kept.
	KeepTargetSnap bool `json:"keep-target-snap,omitempty"`
}

// SetupSnap does prepare and mount the snap for further processing.
func (b Backend) SetupSnap(snapFilePath, instanceName string, sideInfo *snap.SideInfo, meter progress.Meter) (snapType snap.Type, undoCtx *InstallUndoContext, err error) {
	// This assumes that the snap was already verified or --dangerous was used.

	s, snapf, oErr := OpenSnapFile(snapFilePath, sideInfo)
	if oErr != nil {
		return snapType, nil, oErr
	}

	// update instance key to what was requested
	_, s.InstanceKey = snap.SplitInstanceName(instanceName)

	instdir := s.MountDir()

	defer func() {
		if err == nil {
			return
		}

		// XXX: this will also remove the snap from /var/lib/snapd/snaps
		if e := b.RemoveSnapFiles(s, s.GetType(), undoCtx, meter); e != nil {
			meter.Notify(fmt.Sprintf("while trying to clean up due to previous failure: %v", e))
		}
	}()

	if err := os.MkdirAll(instdir, 0755); err != nil {
		return snapType, nil, err
	}

	if s.InstanceKey != "" {
		err := os.MkdirAll(snap.BaseDir(s.SnapName()), 0755)
		if err != nil && !os.IsExist(err) {
			return snapType, nil, err
		}
	}

	var nothingToDo bool
	if nothingToDo, err = snapf.Install(s.MountFile(), instdir); err != nil {
		return snapType, nil, err
	}

	// generate the mount unit for the squashfs
	if err := addMountUnit(s, meter); err != nil {
		return snapType, nil, err
	}

	if s.GetType() == snap.TypeKernel {
		if err := boot.ExtractKernelAssets(s, snapf); err != nil {
			return snapType, nil, fmt.Errorf("cannot install kernel: %s", err)
		}
	}

	undoCtx = &InstallUndoContext{KeepTargetSnap: nothingToDo}
	return s.GetType(), undoCtx, err
}

// RemoveSnapFiles removes the snap files from the disk after unmounting the snap.
func (b Backend) RemoveSnapFiles(s snap.PlaceInfo, typ snap.Type, undoCtx *InstallUndoContext, meter progress.Meter) error {
	mountDir := s.MountDir()

	// this also ensures that the mount unit stops
	if err := removeMountUnit(mountDir, meter); err != nil {
		return err
	}

	if err := os.RemoveAll(mountDir); err != nil {
		return err
	}

	// snapPath may either be a file or a (broken) symlink to a dir
	snapPath := s.MountFile()
	if _, err := os.Lstat(snapPath); err == nil {
		// remove the kernel assets (if any)
		if typ == snap.TypeKernel {
			if err := boot.RemoveKernelAssets(s); err != nil {
				return err
			}
		}

		// don't remove snap path if it existed before snap installation was attempted
		if undoCtx == nil || !undoCtx.KeepTargetSnap {
			// remove the snap
			if err := os.RemoveAll(snapPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func (b Backend) RemoveSnapDir(s snap.PlaceInfo, hasOtherInstances bool) error {
	mountDir := s.MountDir()

	snapName, instanceKey := snap.SplitInstanceName(s.InstanceName())
	if instanceKey != "" {
		// always ok to remove instance specific one, failure to remove
		// is ok, there may be other revisions
		os.Remove(filepath.Dir(mountDir))
	}
	if !hasOtherInstances {
		// remove only if not used by other instances of the same snap,
		// failure to remove is ok, there may be other revisions
		os.Remove(snap.BaseDir(snapName))
	}
	return nil
}

// UndoSetupSnap undoes the work of SetupSnap using RemoveSnapFiles.
func (b Backend) UndoSetupSnap(s snap.PlaceInfo, typ snap.Type, undoCtx *InstallUndoContext, meter progress.Meter) error {
	return b.RemoveSnapFiles(s, typ, undoCtx, meter)
}
