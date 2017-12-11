// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017 Canonical Ltd
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

package snapstate_test

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
)

type prereqSuite struct {
	state     *state.State
	snapmgr   *snapstate.SnapManager
	fakeStore *fakeStore

	fakeBackend *fakeSnappyBackend

	reset func()
}

var _ = Suite(&prereqSuite{})

func (s *prereqSuite) SetUpTest(c *C) {
	s.fakeBackend = &fakeSnappyBackend{}
	s.state = state.New(nil)
	s.state.Lock()
	defer s.state.Unlock()

	s.fakeStore = &fakeStore{
		state:       s.state,
		fakeBackend: s.fakeBackend,
	}
	snapstate.ReplaceStore(s.state, s.fakeStore)

	var err error
	s.snapmgr, err = snapstate.Manager(s.state)
	c.Assert(err, IsNil)
	s.snapmgr.AddForeignTaskHandlers(s.fakeBackend)

	snapstate.SetSnapManagerBackend(s.snapmgr, s.fakeBackend)

	s.reset = snapstate.MockReadInfo(s.fakeBackend.ReadInfo)
}

func (s *prereqSuite) TearDownTest(c *C) {
	s.reset()
}

func (s *prereqSuite) TestDoPrereqSuccess(c *C) {
	s.state.Lock()
	t := s.state.NewTask("prerequisites", "test")
	t.Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "foo",
			Revision: snap.R(33),
		},
		Channel: "beta",
		Base:    "some-base",
		Prereq:  []string{"prereq1", "prereq2"},
	})
	s.state.NewChange("dummy", "...").AddTask(t)
	s.state.Unlock()

	s.snapmgr.Ensure()
	s.snapmgr.Wait()

	s.state.Lock()
	defer s.state.Unlock()
	c.Assert(s.fakeBackend.ops, DeepEquals, fakeOps{
		{
			op:    "storesvc-snap",
			name:  "prereq1",
			revno: snap.R(11),
		},
		{
			op:    "storesvc-snap",
			name:  "prereq2",
			revno: snap.R(11),
		},
		{
			op:    "storesvc-snap",
			name:  "some-base",
			revno: snap.R(11),
		},
	})
	c.Check(t.Status(), Equals, state.DoneStatus)
}
