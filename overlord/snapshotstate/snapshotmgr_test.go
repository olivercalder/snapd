// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2018 Canonical Ltd
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

package snapshotstate_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/check.v1"
	"gopkg.in/tomb.v2"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/snapshotstate"
	"github.com/snapcore/snapd/overlord/snapshotstate/backend"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
)

func (snapshotSuite) TestManager(c *check.C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()
	runner := state.NewTaskRunner(st)
	mgr := snapshotstate.Manager(st, runner)
	c.Assert(mgr, check.NotNil)
	kinds := runner.KnownTaskKinds()
	sort.Strings(kinds)
	c.Check(kinds, check.DeepEquals, []string{
		"check-snapshot",
		"forget-snapshot",
		"restore-snapshot",
		"save-snapshot",
	})
}

func mockDummySnapshot(c *check.C) (restore func()) {
	shotfile, err := os.Create(filepath.Join(c.MkDir(), "foo.zip"))
	c.Assert(err, check.IsNil)

	fakeIter := func(_ context.Context, f func(*backend.Reader) error) error {
		c.Assert(f(&backend.Reader{
			Snapshot: client.Snapshot{SetID: 1, Snap: "a-snap", SnapID: "a-id", Epoch: snap.Epoch{Read: []uint32{42}, Write: []uint32{17}}},
			File:     shotfile,
		}), check.IsNil)
		return nil
	}

	restoreBackendIter := snapshotstate.MockBackendIter(fakeIter)

	return func() {
		shotfile.Close()
		restoreBackendIter()
	}
}

func (snapshotSuite) TestEnsureForgetsSnapshots(c *check.C) {
	var removedSnapshot string
	restoreOsRemove := snapshotstate.MockOsRemove(func(fileName string) error {
		removedSnapshot = fileName
		return nil
	})
	defer restoreOsRemove()

	restore := mockDummySnapshot(c)
	defer restore()

	st := state.New(nil)
	runner := state.NewTaskRunner(st)
	mgr := snapshotstate.Manager(st, runner)
	c.Assert(mgr, check.NotNil)

	st.Lock()
	defer st.Unlock()

	st.Set("snapshots-expiry", map[uint64]interface{}{
		1: "2001-03-11T11:24:00Z",
		2: "2037-02-12T12:50:00Z",
	})

	st.Unlock()
	c.Assert(mgr.Ensure(), check.IsNil)
	st.Lock()

	// verify expired snapshots were removed
	var expirations map[uint64]interface{}
	c.Assert(st.Get("snapshots-expiry", &expirations), check.IsNil)
	c.Check(expirations, check.DeepEquals, map[uint64]interface{}{2: "2037-02-12T12:50:00Z"})
	c.Check(removedSnapshot, check.Matches, ".*/foo.zip")
}

func (snapshotSuite) testEnsureForgetSnapshotsConflict(c *check.C, snapshotTaskKind string) {
	removeCalled := 0
	restoreOsRemove := snapshotstate.MockOsRemove(func(string) error {
		removeCalled++
		return nil
	})
	defer restoreOsRemove()

	restore := mockDummySnapshot(c)
	defer restore()

	st := state.New(nil)
	runner := state.NewTaskRunner(st)
	mgr := snapshotstate.Manager(st, runner)
	c.Assert(mgr, check.NotNil)

	st.Lock()
	defer st.Unlock()

	st.Set("snapshots-expiry", map[uint64]interface{}{1: "2001-03-11T11:24:00Z"})

	chg := st.NewChange("snapshot-change", "...")
	tsk := st.NewTask(snapshotTaskKind, "...")
	tsk.SetStatus(state.DoingStatus)
	tsk.Set("snapshot-setup", map[string]int{"set-id": 1})
	chg.AddTask(tsk)

	st.Unlock()
	c.Assert(mgr.Ensure(), check.IsNil)
	st.Lock()

	var expirations map[uint64]interface{}
	c.Assert(st.Get("snapshots-expiry", &expirations), check.IsNil)
	c.Check(expirations, check.DeepEquals, map[uint64]interface{}{
		1: "2001-03-11T11:24:00Z",
	})
	c.Check(removeCalled, check.Equals, 0)

	// sanity check of the test setup: snapshot gets removed once conflict goes away
	tsk.SetStatus(state.DoneStatus)
	st.Unlock()
	c.Assert(mgr.Ensure(), check.IsNil)
	st.Lock()

	expirations = nil
	c.Assert(st.Get("snapshots-expiry", &expirations), check.IsNil)
	c.Check(removeCalled, check.Equals, 1)
	c.Check(expirations, check.HasLen, 0)
}

func (s *snapshotSuite) TestEnsureForgetSnapshotsConflictWithCheckSnapshot(c *check.C) {
	s.testEnsureForgetSnapshotsConflict(c, "check-snapshot")
}

func (s *snapshotSuite) TestEnsureForgetSnapshotsConflictWithRestoreSnapshot(c *check.C) {
	s.testEnsureForgetSnapshotsConflict(c, "restore-snapshot")
}

func (snapshotSuite) TestFilename(c *check.C) {
	si := &snap.Info{
		SideInfo: snap.SideInfo{
			RealName: "a-snap",
			Revision: snap.R(-1),
		},
		Version: "1.33",
	}
	filename := snapshotstate.Filename(42, si)
	c.Check(filepath.Dir(filename), check.Equals, dirs.SnapshotsDir)
	c.Check(filepath.Base(filename), check.Equals, "42_a-snap_1.33_x1.zip")
}

func (snapshotSuite) TestDoSave(c *check.C) {
	snapInfo := snap.Info{
		SideInfo: snap.SideInfo{
			RealName: "a-snap",
			Revision: snap.R(-1),
		},
		Version: "1.33",
	}
	defer snapshotstate.MockSnapstateCurrentInfo(func(_ *state.State, snapname string) (*snap.Info, error) {
		c.Check(snapname, check.Equals, "a-snap")
		return &snapInfo, nil
	})()
	defer snapshotstate.MockConfigGetSnapConfig(func(_ *state.State, snapname string) (*json.RawMessage, error) {
		c.Check(snapname, check.Equals, "a-snap")
		buf := json.RawMessage(`{"hello": "there"}`)
		return &buf, nil
	})()
	defer snapshotstate.MockBackendSave(func(_ context.Context, id uint64, si *snap.Info, cfg map[string]interface{}, usernames []string, auto bool) (*client.Snapshot, error) {
		c.Check(id, check.Equals, uint64(42))
		c.Check(si, check.DeepEquals, &snapInfo)
		c.Check(cfg, check.DeepEquals, map[string]interface{}{"hello": "there"})
		c.Check(usernames, check.DeepEquals, []string{"a-user", "b-user"})
		c.Check(auto, check.Equals, false)
		return nil, nil
	})()

	st := state.New(nil)
	st.Lock()
	task := st.NewTask("save-snapshot", "...")
	task.Set("snapshot-setup", map[string]interface{}{
		"set-id": 42,
		"snap":   "a-snap",
		"users":  []string{"a-user", "b-user"},
	})
	st.Unlock()
	err := snapshotstate.DoSave(task, &tomb.Tomb{})
	c.Assert(err, check.IsNil)
}

func (snapshotSuite) TestDoSaveFailsWithNoSnap(c *check.C) {
	defer snapshotstate.MockSnapstateCurrentInfo(func(*state.State, string) (*snap.Info, error) {
		return nil, errors.New("bzzt")
	})()
	defer snapshotstate.MockConfigGetSnapConfig(func(*state.State, string) (*json.RawMessage, error) { return nil, nil })()
	defer snapshotstate.MockBackendSave(func(_ context.Context, id uint64, si *snap.Info, cfg map[string]interface{}, usernames []string, auto bool) (*client.Snapshot, error) {
		return nil, nil
	})()

	st := state.New(nil)
	st.Lock()
	task := st.NewTask("save-snapshot", "...")
	task.Set("snapshot-setup", map[string]interface{}{
		"set-id": 42,
		"snap":   "a-snap",
		"users":  []string{"a-user", "b-user"},
	})
	st.Unlock()
	err := snapshotstate.DoSave(task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, "bzzt")
}

func (snapshotSuite) TestDoSaveFailsWithNoSnapshot(c *check.C) {
	snapInfo := snap.Info{
		SideInfo: snap.SideInfo{
			RealName: "a-snap",
			Revision: snap.R(-1),
		},
		Version: "1.33",
	}
	defer snapshotstate.MockSnapstateCurrentInfo(func(*state.State, string) (*snap.Info, error) { return &snapInfo, nil })()
	defer snapshotstate.MockConfigGetSnapConfig(func(*state.State, string) (*json.RawMessage, error) { return nil, nil })()
	defer snapshotstate.MockBackendSave(func(_ context.Context, id uint64, si *snap.Info, cfg map[string]interface{}, usernames []string, auto bool) (*client.Snapshot, error) {
		return nil, nil
	})()

	st := state.New(nil)
	st.Lock()
	task := st.NewTask("save-snapshot", "...")
	// NOTE no task.Set("snapshot-setup", ...)
	st.Unlock()
	err := snapshotstate.DoSave(task, &tomb.Tomb{})
	c.Assert(err, check.NotNil)
	c.Assert(err.Error(), check.Equals, "internal error: task 1 (save-snapshot) is missing snapshot information")
}

func (snapshotSuite) TestDoSaveFailsBackendError(c *check.C) {
	snapInfo := snap.Info{
		SideInfo: snap.SideInfo{
			RealName: "a-snap",
			Revision: snap.R(-1),
		},
		Version: "1.33",
	}
	defer snapshotstate.MockSnapstateCurrentInfo(func(*state.State, string) (*snap.Info, error) { return &snapInfo, nil })()
	defer snapshotstate.MockConfigGetSnapConfig(func(*state.State, string) (*json.RawMessage, error) { return nil, nil })()
	defer snapshotstate.MockBackendSave(func(_ context.Context, id uint64, si *snap.Info, cfg map[string]interface{}, usernames []string, auto bool) (*client.Snapshot, error) {
		return nil, errors.New("bzzt")
	})()

	st := state.New(nil)
	st.Lock()
	task := st.NewTask("save-snapshot", "...")
	task.Set("snapshot-setup", map[string]interface{}{
		"set-id": 42,
		"snap":   "a-snap",
		"users":  []string{"a-user", "b-user"},
	})
	st.Unlock()
	err := snapshotstate.DoSave(task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, "bzzt")
}

func (snapshotSuite) TestDoSaveFailsConfigError(c *check.C) {
	snapInfo := snap.Info{
		SideInfo: snap.SideInfo{
			RealName: "a-snap",
			Revision: snap.R(-1),
		},
		Version: "1.33",
	}
	defer snapshotstate.MockSnapstateCurrentInfo(func(*state.State, string) (*snap.Info, error) { return &snapInfo, nil })()
	defer snapshotstate.MockConfigGetSnapConfig(func(*state.State, string) (*json.RawMessage, error) {
		return nil, errors.New("bzzt")
	})()
	defer snapshotstate.MockBackendSave(func(_ context.Context, id uint64, si *snap.Info, cfg map[string]interface{}, usernames []string, auto bool) (*client.Snapshot, error) {
		return nil, nil
	})()

	st := state.New(nil)
	st.Lock()
	task := st.NewTask("save-snapshot", "...")
	task.Set("snapshot-setup", map[string]interface{}{
		"set-id": 42,
		"snap":   "a-snap",
		"users":  []string{"a-user", "b-user"},
	})
	st.Unlock()
	err := snapshotstate.DoSave(task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, "bzzt")
}

func (snapshotSuite) TestDoSaveFailsBadConfig(c *check.C) {
	snapInfo := snap.Info{
		SideInfo: snap.SideInfo{
			RealName: "a-snap",
			Revision: snap.R(-1),
		},
		Version: "1.33",
	}
	defer snapshotstate.MockSnapstateCurrentInfo(func(*state.State, string) (*snap.Info, error) { return &snapInfo, nil })()
	defer snapshotstate.MockConfigGetSnapConfig(func(*state.State, string) (*json.RawMessage, error) {
		// returns something that's not a JSON object
		buf := json.RawMessage(`"hello-there"`)
		return &buf, nil
	})()
	defer snapshotstate.MockBackendSave(func(_ context.Context, id uint64, si *snap.Info, cfg map[string]interface{}, usernames []string, auto bool) (*client.Snapshot, error) {
		return nil, nil
	})()

	st := state.New(nil)
	st.Lock()
	task := st.NewTask("save-snapshot", "...")
	task.Set("snapshot-setup", map[string]interface{}{
		"set-id": 42,
		"snap":   "a-snap",
		"users":  []string{"a-user", "b-user"},
	})
	st.Unlock()
	err := snapshotstate.DoSave(task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, ".* cannot unmarshal .*")
}

type readerSuite struct {
	task     *state.Task
	calls    []string
	restores []func()
}

var _ = check.Suite(&readerSuite{})

func (rs *readerSuite) SetUpTest(c *check.C) {
	st := state.New(nil)
	st.Lock()
	rs.task = st.NewTask("restore-snapshot", "...")
	rs.task.Set("snapshot-setup", map[string]interface{}{
		// interestingly restore doesn't use the set-id
		"snap":     "a-snap",
		"filename": "/some/file.zip",
		"users":    []string{"a-user", "b-user"},
	})
	st.Unlock()

	rs.calls = nil
	rs.restores = []func(){
		snapshotstate.MockOsRemove(func(string) error {
			rs.calls = append(rs.calls, "remove")
			return nil
		}),
		snapshotstate.MockConfigGetSnapConfig(func(*state.State, string) (*json.RawMessage, error) {
			rs.calls = append(rs.calls, "get config")
			return nil, nil
		}),
		snapshotstate.MockConfigSetSnapConfig(func(*state.State, string, *json.RawMessage) error {
			rs.calls = append(rs.calls, "set config")
			return nil
		}),
		snapshotstate.MockBackendOpen(func(string) (*backend.Reader, error) {
			rs.calls = append(rs.calls, "open")
			return &backend.Reader{}, nil
		}),
		snapshotstate.MockBackendRestore(func(*backend.Reader, context.Context, snap.Revision, []string, backend.Logf) (*backend.RestoreState, error) {
			rs.calls = append(rs.calls, "restore")
			return &backend.RestoreState{}, nil
		}),
		snapshotstate.MockBackendCheck(func(*backend.Reader, context.Context, []string) error {
			rs.calls = append(rs.calls, "check")
			return nil
		}),
		snapshotstate.MockBackendRevert(func(*backend.RestoreState) {
			rs.calls = append(rs.calls, "revert")
		}),
		snapshotstate.MockBackendCleanup(func(*backend.RestoreState) {
			rs.calls = append(rs.calls, "cleanup")
		}),
	}
}

func (rs *readerSuite) TearDownTest(c *check.C) {
	for _, restore := range rs.restores {
		restore()
	}
}

func (rs *readerSuite) TestDoRestore(c *check.C) {
	defer snapshotstate.MockConfigGetSnapConfig(func(_ *state.State, snapname string) (*json.RawMessage, error) {
		rs.calls = append(rs.calls, "get config")
		c.Check(snapname, check.Equals, "a-snap")
		buf := json.RawMessage(`{"old": "conf"}`)
		return &buf, nil
	})()
	defer snapshotstate.MockBackendOpen(func(filename string) (*backend.Reader, error) {
		rs.calls = append(rs.calls, "open")
		c.Check(filename, check.Equals, "/some/file.zip")
		return &backend.Reader{
			Snapshot: client.Snapshot{Conf: map[string]interface{}{"hello": "there"}},
		}, nil
	})()
	defer snapshotstate.MockBackendRestore(func(_ *backend.Reader, _ context.Context, _ snap.Revision, users []string, _ backend.Logf) (*backend.RestoreState, error) {
		rs.calls = append(rs.calls, "restore")
		c.Check(users, check.DeepEquals, []string{"a-user", "b-user"})
		return &backend.RestoreState{}, nil
	})()
	defer snapshotstate.MockConfigSetSnapConfig(func(_ *state.State, snapname string, conf *json.RawMessage) error {
		rs.calls = append(rs.calls, "set config")
		c.Check(snapname, check.Equals, "a-snap")
		c.Check(string(*conf), check.Equals, `{"hello":"there"}`)
		return nil
	})()

	err := snapshotstate.DoRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.IsNil)
	c.Check(rs.calls, check.DeepEquals, []string{"get config", "open", "restore", "set config"})

	st := rs.task.State()
	st.Lock()
	var v map[string]interface{}
	rs.task.Get("restore-state", &v)
	st.Unlock()
	c.Check(v, check.DeepEquals, map[string]interface{}{"config": map[string]interface{}{"old": "conf"}})
}

func (rs *readerSuite) TestDoRestoreFailsNoTaskSnapshot(c *check.C) {
	rs.task.State().Lock()
	rs.task.Clear("snapshot-setup")
	rs.task.State().Unlock()

	err := snapshotstate.DoRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.NotNil)
	c.Assert(err.Error(), check.Equals, "internal error: task 1 (restore-snapshot) is missing snapshot information")
	c.Check(rs.calls, check.HasLen, 0)
}

func (rs *readerSuite) TestDoRestoreFailsOnGetConfigError(c *check.C) {
	defer snapshotstate.MockConfigGetSnapConfig(func(*state.State, string) (*json.RawMessage, error) {
		rs.calls = append(rs.calls, "get config")
		return nil, errors.New("bzzt")
	})()

	err := snapshotstate.DoRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, "internal error: cannot obtain current snap config for snapshot restore: bzzt")
	c.Check(rs.calls, check.DeepEquals, []string{"get config"})
}

func (rs *readerSuite) TestDoRestoreFailsOnBadConfig(c *check.C) {
	defer snapshotstate.MockConfigGetSnapConfig(func(*state.State, string) (*json.RawMessage, error) {
		rs.calls = append(rs.calls, "get config")
		buf := json.RawMessage(`42`)
		return &buf, nil
	})()

	err := snapshotstate.DoRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, ".* cannot unmarshal .*")
	c.Check(rs.calls, check.DeepEquals, []string{"get config"})
}

func (rs *readerSuite) TestDoRestoreFailsOpenError(c *check.C) {
	defer snapshotstate.MockBackendOpen(func(string) (*backend.Reader, error) {
		rs.calls = append(rs.calls, "open")
		return nil, errors.New("bzzt")
	})()

	err := snapshotstate.DoRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, "cannot open snapshot: bzzt")
	c.Check(rs.calls, check.DeepEquals, []string{"get config", "open"})
}

func (rs *readerSuite) TestDoRestoreFailsUnserialisableSnapshotConfigError(c *check.C) {
	defer snapshotstate.MockBackendOpen(func(string) (*backend.Reader, error) {
		rs.calls = append(rs.calls, "open")
		return &backend.Reader{
			Snapshot: client.Snapshot{Conf: map[string]interface{}{"hello": func() {}}},
		}, nil
	})()

	err := snapshotstate.DoRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, "cannot marshal saved config: json.*")
	c.Check(rs.calls, check.DeepEquals, []string{"get config", "open", "restore", "revert"})
}

func (rs *readerSuite) TestDoRestoreFailsOnRestoreError(c *check.C) {
	defer snapshotstate.MockBackendRestore(func(*backend.Reader, context.Context, snap.Revision, []string, backend.Logf) (*backend.RestoreState, error) {
		rs.calls = append(rs.calls, "restore")
		return nil, errors.New("bzzt")
	})()

	err := snapshotstate.DoRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, "bzzt")
	c.Check(rs.calls, check.DeepEquals, []string{"get config", "open", "restore"})
}

func (rs *readerSuite) TestDoRestoreFailsAndRevertsOnSetConfigError(c *check.C) {
	defer snapshotstate.MockConfigSetSnapConfig(func(*state.State, string, *json.RawMessage) error {
		rs.calls = append(rs.calls, "set config")
		return errors.New("bzzt")
	})()

	err := snapshotstate.DoRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.ErrorMatches, "cannot set snap config: bzzt")
	c.Check(rs.calls, check.DeepEquals, []string{"get config", "open", "restore", "set config", "revert"})
}

func (rs *readerSuite) TestUndoRestore(c *check.C) {
	st := rs.task.State()
	st.Lock()
	var v map[string]interface{}
	rs.task.Set("restore-state", &v)
	st.Unlock()

	err := snapshotstate.UndoRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.IsNil)
	c.Check(rs.calls, check.DeepEquals, []string{"set config", "revert"})
}

func (rs *readerSuite) TestCleanupRestore(c *check.C) {
	st := rs.task.State()
	st.Lock()
	var v map[string]interface{}
	rs.task.Set("restore-state", &v)
	st.Unlock()

	err := snapshotstate.CleanupRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.IsNil)
	c.Check(rs.calls, check.HasLen, 0)

	st.Lock()
	rs.task.SetStatus(state.DoneStatus)
	st.Unlock()

	err = snapshotstate.CleanupRestore(rs.task, &tomb.Tomb{})
	c.Assert(err, check.IsNil)
	c.Check(rs.calls, check.DeepEquals, []string{"cleanup"})
}

func (rs *readerSuite) TestDoCheck(c *check.C) {
	defer snapshotstate.MockBackendOpen(func(filename string) (*backend.Reader, error) {
		rs.calls = append(rs.calls, "open")
		c.Check(filename, check.Equals, "/some/file.zip")
		return &backend.Reader{
			Snapshot: client.Snapshot{Conf: map[string]interface{}{"hello": "there"}},
		}, nil
	})()
	defer snapshotstate.MockBackendCheck(func(_ *backend.Reader, _ context.Context, users []string) error {
		rs.calls = append(rs.calls, "check")
		c.Check(users, check.DeepEquals, []string{"a-user", "b-user"})
		return nil
	})()

	err := snapshotstate.DoCheck(rs.task, &tomb.Tomb{})
	c.Assert(err, check.IsNil)
	c.Check(rs.calls, check.DeepEquals, []string{"open", "check"})

}

func (rs *readerSuite) TestDoRemove(c *check.C) {
	defer snapshotstate.MockOsRemove(func(filename string) error {
		c.Check(filename, check.Equals, "/some/file.zip")
		rs.calls = append(rs.calls, "remove")
		return nil
	})()
	err := snapshotstate.DoForget(rs.task, &tomb.Tomb{})
	c.Assert(err, check.IsNil)
	c.Check(rs.calls, check.DeepEquals, []string{"remove"})
}
