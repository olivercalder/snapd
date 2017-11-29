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

package configstate_test

import (
	"time"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/corecfg"
	"github.com/snapcore/snapd/overlord"
	"github.com/snapcore/snapd/overlord/configstate"
	"github.com/snapcore/snapd/overlord/hookstate"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
)

type tasksetsSuite struct {
	state *state.State
}

var _ = Suite(&tasksetsSuite{})
var _ = Suite(&coreCfgHijackSuite{})

func (s *tasksetsSuite) SetUpTest(c *C) {
	s.state = state.New(nil)
}

var configureTests = []struct {
	patch       map[string]interface{}
	optional    bool
	ignoreError bool
	useDefaults bool
}{{
	patch:       nil,
	optional:    true,
	ignoreError: false,
}, {
	patch:       map[string]interface{}{},
	optional:    true,
	ignoreError: false,
}, {
	patch:       map[string]interface{}{"foo": "bar"},
	optional:    false,
	ignoreError: false,
}, {
	patch:       nil,
	optional:    true,
	ignoreError: true,
}, {
	patch:       nil,
	optional:    true,
	ignoreError: true,
	useDefaults: true,
}}

func (s *tasksetsSuite) TestConfigure(c *C) {
	for _, test := range configureTests {
		var flags int
		if test.ignoreError {
			flags |= snapstate.IgnoreHookError
		}
		if test.useDefaults {
			flags |= snapstate.UseConfigDefaults
		}

		s.state.Lock()
		taskset := configstate.Configure(s.state, "test-snap", test.patch, flags)
		s.state.Unlock()

		tasks := taskset.Tasks()
		c.Assert(tasks, HasLen, 1)
		task := tasks[0]

		c.Assert(task.Kind(), Equals, "run-hook")

		summary := `Run configure hook of "test-snap" snap`
		if test.optional {
			summary += " if present"
		}
		c.Assert(task.Summary(), Equals, summary)

		var hooksup hookstate.HookSetup
		s.state.Lock()
		err := task.Get("hook-setup", &hooksup)
		s.state.Unlock()
		c.Check(err, IsNil)

		c.Assert(hooksup.Snap, Equals, "test-snap")
		c.Assert(hooksup.Hook, Equals, "configure")
		c.Assert(hooksup.Optional, Equals, test.optional)
		c.Assert(hooksup.IgnoreError, Equals, test.ignoreError)
		c.Assert(hooksup.Timeout, Equals, 5*time.Minute)

		context, err := hookstate.NewContext(task, task.State(), &hooksup, nil, "")
		c.Check(err, IsNil)
		c.Check(context.SnapName(), Equals, "test-snap")
		c.Check(context.SnapRevision(), Equals, snap.Revision{})
		c.Check(context.HookName(), Equals, "configure")

		var patch map[string]interface{}
		var useDefaults bool
		context.Lock()
		context.Get("use-defaults", &useDefaults)
		err = context.Get("patch", &patch)
		context.Unlock()
		if len(test.patch) > 0 {
			c.Check(err, IsNil)
			c.Check(patch, DeepEquals, test.patch)
		} else {
			c.Check(err, Equals, state.ErrNoState)
			c.Check(patch, IsNil)
		}
		c.Check(useDefaults, Equals, test.useDefaults)
	}
}

type coreCfgHijackSuite struct {
	o     *overlord.Overlord
	state *state.State
}

func (s *coreCfgHijackSuite) SetUpTest(c *C) {
	s.o = overlord.Mock()
	s.state = s.o.State()
	hookMgr, err := hookstate.Manager(s.state)
	c.Assert(err, IsNil)
	s.o.AddManager(hookMgr)
	configMgr, err := configstate.Manager(s.state, hookMgr)
	c.Assert(err, IsNil)
	s.o.AddManager(configMgr)
}

func (s *coreCfgHijackSuite) TestHijack(c *C) {
	coreCfgRan := false
	witnessCoreCfgRun := func(conf corecfg.Conf) error {
		// called with no state lock!
		conf.State().Lock()
		defer conf.State().Unlock()
		coreCfgRan = true
		return nil
	}
	r := configstate.MockCorecfgRun(witnessCoreCfgRun)
	defer r()

	s.state.Lock()
	defer s.state.Unlock()
	snapstate.Set(s.state, "core", &snapstate.SnapState{
		Sequence: []*snap.SideInfo{{RealName: "core", Revision: snap.R(1)}},
		Active:   true,
		Current:  snap.R(1),
	})

	ts := configstate.Configure(s.state, "core", nil, 0)

	chg := s.state.NewChange("configure-core", "configure core")
	chg.AddAll(ts)

	s.state.Unlock()
	err := s.o.Settle(5 * time.Second)
	s.state.Lock()
	c.Assert(err, IsNil)

	c.Check(chg.Err(), IsNil)
	c.Check(coreCfgRan, Equals, true)
}
