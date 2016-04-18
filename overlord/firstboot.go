// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2015 Canonical Ltd
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

package overlord

import (
	"github.com/ubuntu-core/snappy/dirs"
	"github.com/ubuntu-core/snappy/overlord/snapstate"
	"github.com/ubuntu-core/snappy/overlord/state"
	"github.com/ubuntu-core/snappy/snappy"
)

func populateStateFromInstalled() error {
	all, err := (&snappy.Overlord{}).Installed()
	if err != nil {
		return err
	}

	st := state.New(&overlordStateBackend{
		path: dirs.SnapStateFile,
	})
	st.Lock()
	defer st.Unlock()

	for _, sn := range all {
		// no need to do a snapstate.Get() because this is firstboot
		info := sn.Info()

		var snapst snapstate.SnapState
		snapst.Sequence = append(snapst.Sequence, &info.SideInfo)
		snapst.Channel = info.Channel
		snapstate.Set(st, sn.Name(), &snapst)
	}

	return nil
}

func FirstBoot() error {
	if err := snappy.FirstBoot(); err != nil {
		return err
	}

	return populateStateFromInstalled()
}
