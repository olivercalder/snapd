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
	"github.com/ubuntu-core/snappy/progress"
	"github.com/ubuntu-core/snappy/snappy"
)

type defaultBackend struct{}

func (s *defaultBackend) InstallLocal(snap, developer string, flags snappy.InstallFlags, meter progress.Meter) error {
	// FIXME: the name `snappy.Overlord` is confusing :/
	_, err := (&snappy.Overlord{}).Install(snap, developer, flags, meter)
	return err
}

func (s *defaultBackend) Update(name, channel string, flags snappy.InstallFlags, meter progress.Meter) error {
	// FIXME: support "channel" in snappy.Update()
	_, err := snappy.Update(name, flags, meter)
	return err
}

func (s *defaultBackend) Remove(name string, flags snappy.RemoveFlags, meter progress.Meter) error {
	return snappy.Remove(name, flags, meter)
}

func (s *defaultBackend) Purge(name string, flags snappy.PurgeFlags, meter progress.Meter) error {
	return snappy.Purge(name, flags, meter)
}

func (s *defaultBackend) Rollback(name, ver string, meter progress.Meter) (string, error) {
	return snappy.Rollback(name, ver, meter)
}

func (s *defaultBackend) Activate(name string, active bool, meter progress.Meter) error {
	return snappy.SetActive(name, active, meter)
}

func (s *defaultBackend) Download(name, channel string, meter progress.Meter) (string, string, error) {
	mStore := snappy.NewUbuntuStoreSnapRepository()
	snap, err := mStore.Snap(name, channel)
	if err != nil {
		return "", "", err
	}

	downloadedSnapFile, err := mStore.Download(snap, meter)
	if err != nil {
		return "", "", err
	}

	if err := snap.SaveStoreManifest(); err != nil {
		return "", "", err
	}

	return downloadedSnapFile, snap.Developer(), nil
}
