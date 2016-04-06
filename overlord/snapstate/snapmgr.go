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

// Package snapstate implements the manager and state aspects responsible for the installation and removal of snaps.
package snapstate

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/tomb.v2"

	"github.com/ubuntu-core/snappy/dirs"
	"github.com/ubuntu-core/snappy/overlord/state"
	"github.com/ubuntu-core/snappy/snap"
	"github.com/ubuntu-core/snappy/snappy"
)

// SnapManager is responsible for the installation and removal of snaps.
type SnapManager struct {
	state   *state.State
	backend managerBackend

	runner *state.TaskRunner
}

type installState struct {
	Name    string              `json:"name"`
	Channel string              `json:"channel"`
	Flags   snappy.InstallFlags `json:"flags,omitempty"`

	DownloadTaskID string `json:"download-task-id,omitempty"`
	SnapPath       string `json:"snap-path,omitempty"`
}

type downloadState struct {
	Developer string `json:"developer"`
	SnapPath  string `json:"snap-path,omitempty"`
}

type removeState struct {
	Name  string             `json:"name"`
	Flags snappy.RemoveFlags `json:"flags,omitempty"`
}

type rollbackState struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type activateState struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

// Manager returns a new snap manager.
func Manager(s *state.State) (*SnapManager, error) {
	runner := state.NewTaskRunner(s)
	backend := &defaultBackend{}
	m := &SnapManager{
		state:   s,
		backend: backend,
		runner:  runner,
	}

	runner.AddHandler("download-snap", m.doDownloadSnap, nil)
	runner.AddHandler("install-snap", m.doInstallLocalSnap, nil)
	runner.AddHandler("update-snap", m.doUpdateSnap, nil)
	runner.AddHandler("remove-snap", m.doRemoveSnap, nil)
	runner.AddHandler("rollback-snap", m.doRollbackSnap, nil)
	runner.AddHandler("activate-snap", m.doActivateSnap, nil)

	// test handlers
	runner.AddHandler("fake-install-snap", func(t *state.Task, _ *tomb.Tomb) error {
		return nil
	}, nil)
	runner.AddHandler("fake-install-snap-error", func(t *state.Task, _ *tomb.Tomb) error {
		return fmt.Errorf("fake-install-snap-error errored")
	}, nil)

	return m, nil
}

func (m *SnapManager) doDownloadSnap(t *state.Task, _ *tomb.Tomb) error {
	var inst installState
	var dl downloadState

	t.State().Lock()
	if err := t.Get("install-state", &inst); err != nil {
		return err
	}
	t.State().Unlock()

	pb := &TaskProgressAdapter{task: t}
	downloadedSnapFile, developer, err := m.backend.Download(inst.Name, inst.Channel, pb)
	if err != nil {
		return err
	}
	dl.SnapPath = downloadedSnapFile
	dl.Developer = developer

	// update instState for the next task
	t.State().Lock()
	t.Set("download-state", dl)
	t.State().Unlock()

	return nil
}

func (m *SnapManager) doInstallLocalSnap(t *state.Task, _ *tomb.Tomb) error {
	var inst installState
	var dl downloadState

	t.State().Lock()
	if err := t.Get("install-state", &inst); err != nil {
		return err
	}
	t.State().Unlock()

	// local snaps are special
	var snapPath string
	if inst.SnapPath != "" {
		snapPath = inst.SnapPath
	} else if inst.DownloadTaskID != "" {
		t.State().Lock()
		tDl := t.State().Task(inst.DownloadTaskID)
		if err := tDl.Get("download-state", &dl); err != nil {
			return err
		}
		t.State().Unlock()
		defer os.Remove(dl.SnapPath)
		snapPath = dl.SnapPath
	} else {
		return fmt.Errorf("internal error: install-snap created without a snap path source")
	}

	pb := &TaskProgressAdapter{task: t}
	return m.backend.InstallLocal(snapPath, inst.Flags, pb)
}

func (m *SnapManager) doUpdateSnap(t *state.Task, _ *tomb.Tomb) error {
	var inst installState
	t.State().Lock()
	if err := t.Get("update-state", &inst); err != nil {
		return err
	}
	t.State().Unlock()

	pb := &TaskProgressAdapter{task: t}
	err := m.backend.Update(inst.Name, inst.Channel, inst.Flags, pb)
	return err
}

func (m *SnapManager) doRemoveSnap(t *state.Task, _ *tomb.Tomb) error {
	var rm removeState

	t.State().Lock()
	if err := t.Get("remove-state", &rm); err != nil {
		return err
	}
	t.State().Unlock()

	pb := &TaskProgressAdapter{task: t}
	name, _ := snappy.SplitDeveloper(rm.Name)
	err := m.backend.Remove(name, rm.Flags, pb)
	return err
}

func (m *SnapManager) doRollbackSnap(t *state.Task, _ *tomb.Tomb) error {
	var rollback rollbackState

	t.State().Lock()
	if err := t.Get("rollback-state", &rollback); err != nil {
		return err
	}
	t.State().Unlock()

	pb := &TaskProgressAdapter{task: t}
	name, _ := snappy.SplitDeveloper(rollback.Name)
	_, err := m.backend.Rollback(name, rollback.Version, pb)
	return err
}

func (m *SnapManager) doActivateSnap(t *state.Task, _ *tomb.Tomb) error {
	var activate activateState

	t.State().Lock()
	if err := t.Get("activate-state", &activate); err != nil {
		return err
	}
	t.State().Unlock()

	pb := &TaskProgressAdapter{task: t}
	name, _ := snappy.SplitDeveloper(activate.Name)
	return m.backend.Activate(name, activate.Active, pb)
}

// Ensure implements StateManager.Ensure.
func (m *SnapManager) Ensure() error {
	m.runner.Ensure()
	return nil
}

// Wait implements StateManager.Wait.
func (m *SnapManager) Wait() {
	m.runner.Wait()
}

// Stop implements StateManager.Stop.
func (m *SnapManager) Stop() {
	m.runner.Stop()
}

// SnapInfo returns the snap.Info for a snap in the system.
//
// Today this function is looking at data directly from the mounted snap, but soon it will
// be changed so it looks first at the state for the snap details (Revision, Developer, etc),
// and then complements it with information from the snap itself.
func SnapInfo(state *state.State, snapName, snapVersion string) (*snap.Info, error) {
	fname := filepath.Join(dirs.SnapSnapsDir, snapName, snapVersion, "meta", "snap.yaml")
	yamlData, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	info, err := snap.InfoFromSnapYaml(yamlData)
	if err != nil {
		return nil, err
	}
	// Overwrite the name which doesn't belong in snap.yaml and is actually
	// defined by snap declaration assertion.
	// TODO: use a full SideInfo
	info.OfficialName = snapName
	// TODO: use state to retrieve additional information
	return info, nil
}
