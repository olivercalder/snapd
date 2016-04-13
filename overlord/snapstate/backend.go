// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016 Canonical Ltd
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

package snapstate

import (
	"path/filepath"
	"strconv"

	"github.com/ubuntu-core/snappy/dirs"
	"github.com/ubuntu-core/snappy/progress"
	"github.com/ubuntu-core/snappy/snap"
	"github.com/ubuntu-core/snappy/snappy"
)

type managerBackend interface {
	// install releated
	Download(name, channel string, meter progress.Meter) (*snap.Info, string, error)
	CheckSnap(snapFilePath string, flags int) error
	SetupSnap(snapFilePath string, si *snap.SideInfo, flags int) error
	CopySnapData(newSnap, oldSnap *snap.Info, flags int) error
	LinkSnap(info *snap.Info) error
	GarbageCollect(snap string, flags int, meter progress.Meter) error
	// the undoers for install
	UndoSetupSnap(s snap.PlaceInfo) error
	UndoCopySnapData(instSnapPath string, flags int) error

	// remove releated
	CanRemove(info *snap.Info, active bool) bool
	UnlinkSnap(info *snap.Info, meter progress.Meter) error
	RemoveSnapFiles(s snap.PlaceInfo, meter progress.Meter) error
	RemoveSnapData(name string, revision int) error

	// TODO: need to be split into fine grained tasks
	Activate(name string, active bool, meter progress.Meter) error
	// XXX: this one needs to be revno based as well
	Rollback(name, ver string, meter progress.Meter) (string, error)

	// info
	SnapByNameAndVersion(name, version string) *snap.Info

	// testing helpers
	Candidate(sideInfo *snap.SideInfo)
}

type defaultBackend struct{}

func (b *defaultBackend) Candidate(*snap.SideInfo) {}

func (b *defaultBackend) SnapByNameAndVersion(name, version string) *snap.Info {
	// XXX: use snapstate stuff!
	installed, err := (&snappy.Overlord{}).Installed()
	if err != nil {
		return nil
	}
	found := snappy.FindSnapsByNameAndVersion(name, version, installed)
	if len(found) == 0 {
		return nil
	}
	// XXX: could be many now, pick one for now
	return found[0].Info()
}

func (b *defaultBackend) Rollback(name, ver string, meter progress.Meter) (string, error) {
	return snappy.Rollback(name, ver, meter)
}

func (b *defaultBackend) Activate(name string, active bool, meter progress.Meter) error {
	return snappy.SetActive(name, active, meter)
}

func (b *defaultBackend) Download(name, channel string, meter progress.Meter) (*snap.Info, string, error) {
	mStore := snappy.NewConfiguredUbuntuStoreSnapRepository()
	snap, err := mStore.Snap(name, channel)
	if err != nil {
		return nil, "", err
	}

	downloadedSnapFile, err := mStore.Download(snap, meter)
	if err != nil {
		return nil, "", err
	}

	return snap, downloadedSnapFile, nil
}

func (b *defaultBackend) CheckSnap(snapFilePath string, flags int) error {
	meter := &progress.NullProgress{}
	return snappy.CheckSnap(snapFilePath, snappy.InstallFlags(flags), meter)
}

func (b *defaultBackend) SetupSnap(snapFilePath string, sideInfo *snap.SideInfo, flags int) error {
	meter := &progress.NullProgress{}
	_, err := snappy.SetupSnap(snapFilePath, sideInfo, snappy.InstallFlags(flags), meter)
	return err
}

func (b *defaultBackend) CopySnapData(newInfo, oldInfo *snap.Info, flags int) error {
	meter := &progress.NullProgress{}
	return snappy.CopyData(newInfo, oldInfo, snappy.InstallFlags(flags), meter)
}

func (b *defaultBackend) LinkSnap(info *snap.Info) error {
	meter := &progress.NullProgress{}
	return snappy.LinkSnap(info, meter)
}

func (b *defaultBackend) UndoSetupSnap(s snap.PlaceInfo) error {
	meter := &progress.NullProgress{}
	snappy.UndoSetupSnap(s, meter)
	return nil
}

func (b *defaultBackend) UndoCopySnapData(instSnapPath string, flags int) error {
	sn, err := snappy.NewInstalledSnap(filepath.Join(instSnapPath, "meta", "snap.yaml"))
	if err != nil {
		return err
	}
	meter := &progress.NullProgress{}
	snappy.UndoCopyData(sn.Info(), snappy.InstallFlags(flags), meter)
	return nil
}

func (b *defaultBackend) CanRemove(info *snap.Info, active bool) bool {
	return snappy.CanRemove(info, active)
}

func (b *defaultBackend) UnlinkSnap(info *snap.Info, meter progress.Meter) error {
	return snappy.UnlinkSnap(info, meter)
}

func (b *defaultBackend) RemoveSnapFiles(s snap.PlaceInfo, meter progress.Meter) error {
	return snappy.RemoveSnapFiles(s, meter)
}

func (b *defaultBackend) RemoveSnapData(name string, revision int) error {
	// XXX: hack for now
	sn, err := snappy.NewInstalledSnap(filepath.Join(dirs.SnapSnapsDir, name, strconv.Itoa(revision), "meta", "snap.yaml"))
	if err != nil {
		return err
	}

	return snappy.RemoveSnapData(sn.Info())
}

func (b *defaultBackend) GarbageCollect(snap string, flags int, meter progress.Meter) error {
	return snappy.GarbageCollect(snap, snappy.InstallFlags(flags), meter)
}
