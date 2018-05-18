// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016-2017 Canonical Ltd
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

// Package ifacestate implements the manager and state aspects
// responsible for the maintenance of interfaces the system.
package ifacestate

import (
	"fmt"
	"sync"
	"time"

	"github.com/snapcore/snapd/i18n"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/policy"
	"github.com/snapcore/snapd/overlord/assertstate"
	"github.com/snapcore/snapd/overlord/hookstate"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
)

var noConflictOnConnectTasks = func(task *state.Task) bool {
	// TODO: reconsider this check with regard to interface hooks
	return task.Kind() != "connect" && task.Kind() != "disconnect"
}

var connectRetryTimeout = time.Second * 5

func checkConnectConflicts(st *state.State, change *state.Change, plugSnap, slotSnap string, installedSnapTask *state.Task) error {
	if installedSnapTask == nil {
		for _, chg := range st.Changes() {
			if chg.Kind() == "transition-ubuntu-core" {
				return fmt.Errorf("ubuntu-core to core transition in progress, no other changes allowed until this is done")
			}
		}
	}

	var installedSnap string
	if installedSnapTask != nil {
		snapsup, err := snapstate.TaskSnapSetup(installedSnapTask)
		if err != nil {
			return fmt.Errorf("internal error: cannot obtain snap setup from task: %s", installedSnapTask.Summary())
		}
		installedSnap = snapsup.Name()
	}

	for _, task := range st.Tasks() {
		if task.Status().Ready() || installedSnapTask == task {
			continue
		}

		k := task.Kind()
		if k == "connect" || k == "disconnect" {
			continue
		}

		snapsup, err := snapstate.TaskSnapSetup(task)
		// e.g. hook tasks don't have task snap setup
		if err != nil {
			continue
		}

		snapName := snapsup.Name()

		if installedSnapTask != nil && installedSnap == snapName {
			continue
		}

		// different snaps - no conflict
		if snapName != plugSnap && snapName != slotSnap {
			continue
		}

		if k == "unlink-snap" || k == "link-snap" || k == "setup-profiles" {
			if installedSnapTask != nil {
				// if snap is getting removed, we will retry but the snap will be gone and auto-connect becomes no-op
				// if snap is getting installed/refreshed - temporary conflict, retry later
				return &state.Retry{After: connectRetryTimeout}
			}
			// for connect it's a conflict
			return snapstate.ChangeConflictError(snapName, task.Change().Kind())
		}
	}
	return nil
}

// AutoConnect returns a set of tasks for connecting an interface as part of snap installation
// and auto-connect handling.
func AutoConnect(st *state.State, change *state.Change, autoConnectTask *state.Task, plugSnap, plugName, slotSnap, slotName string) (*state.TaskSet, error) {
	return connect(st, change, autoConnectTask, plugSnap, plugName, slotSnap, slotName)
}

// Reconnect returns a set of tasks for reconnecting an interface as part of snap installation.
func Reconnect(st *state.State, change *state.Change, reconnectTask *state.Task, plugSnap, plugName, slotSnap, slotName string) (*state.TaskSet, error) {
	return connect(st, change, reconnectTask, plugSnap, plugName, slotSnap, slotName)
}

// Connect returns a set of tasks for connecting an interface.
//
func Connect(st *state.State, plugSnap, plugName, slotSnap, slotName string) (*state.TaskSet, error) {
	return connect(st, nil, nil, plugSnap, plugName, slotSnap, slotName)
}

func connect(st *state.State, change *state.Change, installedSnapTask *state.Task, plugSnap, plugName, slotSnap, slotName string) (*state.TaskSet, error) {
	if err := checkConnectConflicts(st, change, plugSnap, slotSnap, installedSnapTask); err != nil {
		return nil, err
	}

	// TODO: Store the intent-to-connect in the state so that we automatically
	// try to reconnect on reboot (reconnection can fail or can connect with
	// different parameters so we cannot store the actual connection details).

	// Create a series of tasks:
	//  - prepare-plug-<plug> hook
	//  - prepare-slot-<slot> hook
	//  - connect task
	//  - connect-slot-<slot> hook
	//  - connect-plug-<plug> hook
	// The tasks run in sequence (are serialized by WaitFor).
	// The prepare- hooks collect attributes via snapctl set.
	// 'snapctl set' can only modify own attributes (plug's attributes in the *-plug-* hook and
	// slot's attributes in the *-slot-* hook).
	// 'snapctl get' can read both slot's and plug's attributes.
	summary := fmt.Sprintf(i18n.G("Connect %s:%s to %s:%s"),
		plugSnap, plugName, slotSnap, slotName)
	connectInterface := st.NewTask("connect", summary)

	initialContext := make(map[string]interface{})
	initialContext["attrs-task"] = connectInterface.ID()

	plugHookSetup := &hookstate.HookSetup{
		Snap:     plugSnap,
		Hook:     "prepare-plug-" + plugName,
		Optional: true,
	}

	summary = fmt.Sprintf(i18n.G("Run hook %s of snap %q"), plugHookSetup.Hook, plugHookSetup.Snap)
	preparePlugConnection := hookstate.HookTask(st, summary, plugHookSetup, initialContext)

	slotHookSetup := &hookstate.HookSetup{
		Snap:     slotSnap,
		Hook:     "prepare-slot-" + slotName,
		Optional: true,
	}

	summary = fmt.Sprintf(i18n.G("Run hook %s of snap %q"), slotHookSetup.Hook, slotHookSetup.Snap)
	prepareSlotConnection := hookstate.HookTask(st, summary, slotHookSetup, initialContext)
	prepareSlotConnection.WaitFor(preparePlugConnection)

	connectInterface.Set("slot", interfaces.SlotRef{Snap: slotSnap, Name: slotName})
	connectInterface.Set("plug", interfaces.PlugRef{Snap: plugSnap, Name: plugName})
	connectInterface.Set("auto", installedSnapTask != nil && installedSnapTask.Kind() == "auto-connect")

	// Expose a copy of all plug and slot attributes coming from yaml to interface hooks. The hooks will be able
	// to modify them but all attributes will be checked against assertions after the hooks are run.
	if err := setInitialConnectAttributes(connectInterface, plugSnap, plugName, slotSnap, slotName); err != nil {
		return nil, err
	}
	connectInterface.WaitFor(prepareSlotConnection)

	connectSlotHookSetup := &hookstate.HookSetup{
		Snap:     slotSnap,
		Hook:     "connect-slot-" + slotName,
		Optional: true,
	}

	summary = fmt.Sprintf(i18n.G("Run hook %s of snap %q"), connectSlotHookSetup.Hook, connectSlotHookSetup.Snap)
	connectSlotConnection := hookstate.HookTask(st, summary, connectSlotHookSetup, initialContext)
	connectSlotConnection.WaitFor(connectInterface)

	connectPlugHookSetup := &hookstate.HookSetup{
		Snap:     plugSnap,
		Hook:     "connect-plug-" + plugName,
		Optional: true,
	}

	summary = fmt.Sprintf(i18n.G("Run hook %s of snap %q"), connectPlugHookSetup.Hook, connectPlugHookSetup.Snap)
	connectPlugConnection := hookstate.HookTask(st, summary, connectPlugHookSetup, initialContext)
	connectPlugConnection.WaitFor(connectSlotConnection)

	return state.NewTaskSet(preparePlugConnection, prepareSlotConnection, connectInterface, connectSlotConnection, connectPlugConnection), nil
}

func setInitialConnectAttributes(ts *state.Task, plugSnap string, plugName string, slotSnap string, slotName string) error {
	// Set initial interface attributes for the plug and slot snaps in connect task.
	var snapst snapstate.SnapState
	var err error

	st := ts.State()
	if err = snapstate.Get(st, plugSnap, &snapst); err != nil {
		return err
	}
	snapInfo, err := snapst.CurrentInfo()
	if err != nil {
		return err
	}

	emptyDynamicAttrs := make(map[string]interface{})
	if plug, ok := snapInfo.Plugs[plugName]; ok {
		ts.Set("plug-static", plug.Attrs)
		ts.Set("plug-dynamic", emptyDynamicAttrs)
	} else {
		return fmt.Errorf("snap %q has no plug named %q", plugSnap, plugName)
	}

	if err = snapstate.Get(st, slotSnap, &snapst); err != nil {
		return err
	}
	snapInfo, err = snapst.CurrentInfo()
	if err != nil {
		return err
	}
	addImplicitSlots(snapInfo)
	if slot, ok := snapInfo.Slots[slotName]; ok {
		ts.Set("slot-static", slot.Attrs)
		ts.Set("slot-dynamic", emptyDynamicAttrs)
	} else {
		return fmt.Errorf("snap %q has no slot named %q", slotSnap, slotName)
	}

	return nil
}

// Disconnect returns a set of tasks for  disconnecting an interface.
func Disconnect(st *state.State, conn *interfaces.Connection) (*state.TaskSet, error) {
	plugSnap := conn.Plug.Snap().Name()
	slotSnap := conn.Slot.Snap().Name()
	plugName := conn.Plug.Name()
	slotName := conn.Slot.Name()

	if err := snapstate.CheckChangeConflict(st, plugSnap, noConflictOnConnectTasks, nil); err != nil {
		return nil, err
	}
	if err := snapstate.CheckChangeConflict(st, slotSnap, noConflictOnConnectTasks, nil); err != nil {
		return nil, err
	}

	summary := fmt.Sprintf(i18n.G("Disconnect %s:%s from %s:%s"),
		plugSnap, plugName, slotSnap, slotName)
	disconnectTask := st.NewTask("disconnect", summary)
	disconnectTask.Set("slot", interfaces.SlotRef{Snap: slotSnap, Name: slotName})
	disconnectTask.Set("plug", interfaces.PlugRef{Snap: plugSnap, Name: plugName})

	hooks, err := DisconnectHooks(st, conn)
	if err != nil {
		return nil, err
	}
	disconnectTask.WaitAll(hooks)

	ts := state.NewTaskSet(hooks.Tasks()...)
	ts.AddTask(disconnectTask)
	return ts, nil
}

// DisconnectHooks returns a set of tasks for running disconnect- hooks for an interface.
func DisconnectHooks(st *state.State, conn *interfaces.Connection) (*state.TaskSet, error) {
	plugSnap := conn.Plug.Snap().Name()
	slotSnap := conn.Slot.Snap().Name()
	plugName := conn.Plug.Name()
	slotName := conn.Slot.Name()

	ts := state.NewTaskSet()

	var snapst snapstate.SnapState
	if err := snapstate.Get(st, slotSnap, &snapst); err != nil {
		return nil, err
	}

	// do not run slot hooks if slotSnap is not active
	if snapst.Active {
		disconnectSlotHookSetup := &hookstate.HookSetup{
			Snap:     slotSnap,
			Hook:     "disconnect-slot-" + slotName,
			Optional: true,
		}
		summary := fmt.Sprintf(i18n.G("Run hook %s of snap %q"), disconnectSlotHookSetup.Hook, disconnectSlotHookSetup.Snap)
		disconnectSlot := hookstate.HookTask(st, summary, disconnectSlotHookSetup, nil)

		ts.AddTask(disconnectSlot)
	}

	if err := snapstate.Get(st, plugSnap, &snapst); err != nil {
		return nil, err
	}

	// do not run plug hooks if plugSnap is not active
	if snapst.Active {
		disconnectPlugHookSetup := &hookstate.HookSetup{
			Snap:     plugSnap,
			Hook:     "disconnect-plug-" + plugName,
			Optional: true,
		}
		summary := fmt.Sprintf(i18n.G("Run hook %s of snap %q"), disconnectPlugHookSetup.Hook, disconnectPlugHookSetup.Snap)
		disconnectPlug := hookstate.HookTask(st, summary, disconnectPlugHookSetup, nil)
		disconnectPlug.WaitAll(ts)

		ts.AddTask(disconnectPlug)
	}

	// expose plug/slot attributes to the hooks
	for _, task := range ts.Tasks() {
		task.Set("slot", interfaces.SlotRef{Snap: slotSnap, Name: slotName})
		task.Set("plug", interfaces.PlugRef{Snap: plugSnap, Name: plugName})

		task.Set("slot-static", conn.Slot.StaticAttrs())
		task.Set("slot-dynamic", conn.Slot.DynamicAttrs())
		task.Set("plug-static", conn.Plug.StaticAttrs())
		task.Set("plug-dynamic", conn.Plug.DynamicAttrs())
	}

	return ts, nil
}

// CheckInterfaces checks whether plugs and slots of snap are allowed for installation.
func CheckInterfaces(st *state.State, snapInfo *snap.Info) error {
	// XXX: addImplicitSlots is really a brittle interface
	addImplicitSlots(snapInfo)

	if snapInfo.SnapID == "" {
		// no SnapID means --dangerous was given, so skip interface checks
		return nil
	}

	baseDecl, err := assertstate.BaseDeclaration(st)
	if err != nil {
		return fmt.Errorf("internal error: cannot find base declaration: %v", err)
	}

	snapDecl, err := assertstate.SnapDeclaration(st, snapInfo.SnapID)
	if err != nil {
		return fmt.Errorf("cannot find snap declaration for %q: %v", snapInfo.Name(), err)
	}

	ic := policy.InstallCandidate{
		Snap:            snapInfo,
		SnapDeclaration: snapDecl,
		BaseDeclaration: baseDecl,
	}

	return ic.Check()
}

var once sync.Once

func delayedCrossMgrInit() {
	// hook interface checks into snapstate installation logic
	once.Do(func() {
		snapstate.AddCheckSnapCallback(func(st *state.State, snapInfo, _ *snap.Info, _ snapstate.Flags) error {
			return CheckInterfaces(st, snapInfo)
		})
	})
}
