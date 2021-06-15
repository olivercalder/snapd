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

package hookstate_test

import (
	"fmt"
	"time"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/cmd/snaplock/runinhibit"
	"github.com/snapcore/snapd/overlord/configstate/config"
	"github.com/snapcore/snapd/overlord/hookstate"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
	"gopkg.in/tomb.v2"
)

const snapaYaml = `name: snap-a
version: 1
hooks:
    gate-auto-refresh:
`

const snapbYaml = `name: snap-b
version: 1
`

type gateAutoRefreshHookSuite struct {
	baseHookManagerSuite
}

var _ = Suite(&gateAutoRefreshHookSuite{})

func (s *gateAutoRefreshHookSuite) SetUpTest(c *C) {
	s.commonSetUpTest(c)

	s.state.Lock()
	defer s.state.Unlock()

	si := &snap.SideInfo{RealName: "snap-a", SnapID: "snap-a-id1", Revision: snap.R(1)}
	snaptest.MockSnap(c, snapaYaml, si)
	snapstate.Set(s.state, "snap-a", &snapstate.SnapState{
		Active:   true,
		Sequence: []*snap.SideInfo{si},
		Current:  snap.R(1),
	})

	si2 := &snap.SideInfo{RealName: "snap-b", SnapID: "snap-b-id1", Revision: snap.R(1)}
	snaptest.MockSnap(c, snapbYaml, si2)
	snapstate.Set(s.state, "snap-b", &snapstate.SnapState{
		Active:   true,
		Sequence: []*snap.SideInfo{si2},
		Current:  snap.R(1),
	})
}

func (s *gateAutoRefreshHookSuite) TearDownTest(c *C) {
	s.commonTearDownTest(c)
}

func (s *gateAutoRefreshHookSuite) settle(c *C) {
	err := s.o.Settle(5 * time.Second)
	c.Assert(err, IsNil)
}

func checkIsHeld(c *C, st *state.State, heldSnap, gatingSnap string) {
	var held map[string]map[string]interface{}
	c.Assert(st.Get("snaps-hold", &held), IsNil)
	c.Check(held[heldSnap][gatingSnap], NotNil)
}

func checkIsNotHeld(c *C, st *state.State, heldSnap string) {
	var held map[string]map[string]interface{}
	c.Assert(st.Get("snaps-hold", &held), IsNil)
	c.Check(held[heldSnap], IsNil)
}

func (s *gateAutoRefreshHookSuite) TestGateAutorefreshHookProceedRuninhibitLock(c *C) {
	hookInvoke := func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
		c.Check(ctx.HookName(), Equals, "gate-auto-refresh")
		c.Check(ctx.InstanceName(), Equals, "snap-a")
		ctx.Lock()
		defer ctx.Unlock()

		// check that runinhibit hint has been set by Before() hook handler.
		hint, err := runinhibit.IsLocked("snap-a")
		c.Assert(err, IsNil)
		c.Check(hint, Equals, runinhibit.HintInhibitedGateRefresh)

		// action is normally set via snapctl; pretend it is --proceed.
		action := snapstate.GateAutoRefreshProceed
		ctx.Cache("action", action)
		return nil, nil
	}
	restore := hookstate.MockRunHook(hookInvoke)
	defer restore()

	st := s.state
	st.Lock()
	defer st.Unlock()

	// enable refresh-app-awareness
	tr := config.NewTransaction(st)
	tr.Set("core", "experimental.refresh-app-awareness", true)
	tr.Commit()

	task := hookstate.SetupGateAutoRefreshHook(st, "snap-a", false, false, map[string]bool{"snap-b": true})
	change := st.NewChange("kind", "summary")
	change.AddTask(task)

	st.Unlock()
	s.settle(c)
	st.Lock()

	c.Assert(change.Err(), IsNil)
	c.Assert(change.Status(), Equals, state.DoneStatus)

	hint, err := runinhibit.IsLocked("snap-a")
	c.Assert(err, IsNil)
	c.Check(hint, Equals, runinhibit.HintInhibitedForRefresh)
}

func (s *gateAutoRefreshHookSuite) TestGateAutorefreshHookHoldUnlocksRuninhibit(c *C) {
	hookInvoke := func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
		c.Check(ctx.HookName(), Equals, "gate-auto-refresh")
		c.Check(ctx.InstanceName(), Equals, "snap-a")
		ctx.Lock()
		defer ctx.Unlock()

		// check that runinhibit hint has been set by Before() hook handler.
		hint, err := runinhibit.IsLocked("snap-a")
		c.Assert(err, IsNil)
		c.Check(hint, Equals, runinhibit.HintInhibitedGateRefresh)

		// action is normally set via snapctl; pretend it is --hold.
		action := snapstate.GateAutoRefreshHold
		ctx.Cache("action", action)
		return nil, nil
	}
	restore := hookstate.MockRunHook(hookInvoke)
	defer restore()

	st := s.state
	st.Lock()
	defer st.Unlock()

	// enable refresh-app-awareness
	tr := config.NewTransaction(st)
	tr.Set("core", "experimental.refresh-app-awareness", true)
	tr.Commit()

	task := hookstate.SetupGateAutoRefreshHook(st, "snap-a", false, false, map[string]bool{"snap-b": true})
	change := st.NewChange("kind", "summary")
	change.AddTask(task)

	st.Unlock()
	s.settle(c)
	st.Lock()

	c.Assert(change.Err(), IsNil)
	c.Assert(change.Status(), Equals, state.DoneStatus)

	hint, err := runinhibit.IsLocked("snap-a")
	c.Assert(err, IsNil)
	c.Check(hint, Equals, runinhibit.HintNotInhibited)
}

// Test that if gate-auto-refresh hook does nothing, the hook handler
// assumes --proceed.
func (s *gateAutoRefreshHookSuite) TestGateAutorefreshHookDefaultProceed(c *C) {
	hookInvoke := func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
		// no runinhibit because the refresh-app-awareness feature is disabled.
		hint, err := runinhibit.IsLocked("snap-a")
		c.Assert(err, IsNil)
		c.Check(hint, Equals, runinhibit.HintNotInhibited)

		// this hook does nothing (action not set to proceed/hold).
		c.Check(ctx.HookName(), Equals, "gate-auto-refresh")
		c.Check(ctx.InstanceName(), Equals, "snap-a")
		return nil, nil
	}
	restore := hookstate.MockRunHook(hookInvoke)
	defer restore()

	st := s.state
	st.Lock()
	defer st.Unlock()

	// pretend that snap-b is initially held by snap-a.
	c.Assert(snapstate.HoldRefresh(st, "snap-a", 0, "snap-b"), IsNil)
	// sanity
	checkIsHeld(c, st, "snap-b", "snap-a")

	task := hookstate.SetupGateAutoRefreshHook(st, "snap-a", false, false, map[string]bool{"snap-b": true})
	change := st.NewChange("kind", "summary")
	change.AddTask(task)

	st.Unlock()
	s.settle(c)
	st.Lock()

	c.Assert(change.Err(), IsNil)
	c.Assert(change.Status(), Equals, state.DoneStatus)

	checkIsNotHeld(c, st, "snap-b")

	// no runinhibit because the refresh-app-awareness feature is disabled.
	hint, err := runinhibit.IsLocked("snap-a")
	c.Assert(err, IsNil)
	c.Check(hint, Equals, runinhibit.HintNotInhibited)
}

// Test that if gate-auto-refresh hook errors out, the hook handler
// assumes --hold.
func (s *gateAutoRefreshHookSuite) TestGateAutorefreshHookError(c *C) {
	hookInvoke := func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
		// no runinhibit because the refresh-app-awareness feature is disabled.
		hint, err := runinhibit.IsLocked("snap-a")
		c.Assert(err, IsNil)
		c.Check(hint, Equals, runinhibit.HintNotInhibited)

		// this hook does nothing (action not set to proceed/hold).
		c.Check(ctx.HookName(), Equals, "gate-auto-refresh")
		c.Check(ctx.InstanceName(), Equals, "snap-a")
		return []byte("fail"), fmt.Errorf("boom")
	}
	restore := hookstate.MockRunHook(hookInvoke)
	defer restore()

	st := s.state
	st.Lock()
	defer st.Unlock()

	task := hookstate.SetupGateAutoRefreshHook(st, "snap-a", false, false, map[string]bool{"snap-b": true})
	change := st.NewChange("kind", "summary")
	change.AddTask(task)

	st.Unlock()
	s.settle(c)
	st.Lock()

	c.Assert(change.Err(), ErrorMatches, `cannot perform the following tasks:\n- Run hook gate-auto-refresh of snap "snap-a" \(run hook "gate-auto-refresh": fail\)`)
	c.Assert(change.Status(), Equals, state.ErrorStatus)

	// and snap-b is now held.
	checkIsHeld(c, st, "snap-b", "snap-a")

	// no runinhibit because the refresh-app-awareness feature is disabled.
	hint, err := runinhibit.IsLocked("snap-a")
	c.Assert(err, IsNil)
	c.Check(hint, Equals, runinhibit.HintNotInhibited)
}

func (s *gateAutoRefreshHookSuite) TestGateAutorefreshHookErrorHoldErrorLogged(c *C) {
	hookInvoke := func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
		// no runinhibit because the refresh-app-awareness feature is disabled.
		hint, err := runinhibit.IsLocked("snap-a")
		c.Assert(err, IsNil)
		c.Check(hint, Equals, runinhibit.HintNotInhibited)

		// this hook does nothing (action not set to proceed/hold).
		c.Check(ctx.HookName(), Equals, "gate-auto-refresh")
		c.Check(ctx.InstanceName(), Equals, "snap-a")

		// simulate failing hook
		return []byte("fail"), fmt.Errorf("boom")
	}
	restore := hookstate.MockRunHook(hookInvoke)
	defer restore()

	st := s.state
	st.Lock()
	defer st.Unlock()

	task := hookstate.SetupGateAutoRefreshHook(st, "snap-a", false, false, map[string]bool{"snap-b": true})
	change := st.NewChange("kind", "summary")
	change.AddTask(task)

	// pretend snap-b wasn't updated for a very long time.
	var snapst snapstate.SnapState
	c.Assert(snapstate.Get(st, "snap-b", &snapst), IsNil)
	t := time.Now().Add(-365 * 24 * time.Hour)
	snapst.LastRefreshTime = &t
	snapstate.Set(st, "snap-b", &snapst)

	st.Unlock()
	s.settle(c)
	st.Lock()

	c.Assert(change.Err(), ErrorMatches, `cannot perform the following tasks:
- Run hook gate-auto-refresh of snap "snap-a" \(error: cannot hold some snaps:
 - snap "snap-a" cannot hold snap "snap-b" anymore, maximum refresh postponement exceeded \(while handling previous hook error\)\)
- Run hook gate-auto-refresh of snap "snap-a" \(run hook \"gate-auto-refresh\": fail\)`)
	c.Assert(change.Status(), Equals, state.ErrorStatus)

	// and snap-b is not held (due to hold error).
	var held map[string]map[string]interface{}
	c.Assert(st.Get("snaps-hold", &held), Equals, state.ErrNoState)

	// no runinhibit because the refresh-app-awareness feature is disabled.
	hint, err := runinhibit.IsLocked("snap-a")
	c.Assert(err, IsNil)
	c.Check(hint, Equals, runinhibit.HintNotInhibited)
}
