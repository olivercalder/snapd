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

package ifacestate_test

import (
	"strings"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/overlord/assertstate"
	"github.com/snapcore/snapd/overlord/ifacestate"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
)

func TestInterfaceManager(t *testing.T) { TestingT(t) }

var (
	rootKey, _  = assertstest.GenerateKey(752)
	storeKey, _ = assertstest.GenerateKey(752)
)

type interfaceManagerSuite struct {
	state           *state.State
	db              *asserts.Database
	privateMgr      *ifacestate.InterfaceManager
	extraIfaces     []interfaces.Interface
	secBackend      *interfaces.TestSecurityBackend
	restoreBackends func()

	storeSigning *assertstest.StoreStack
}

var _ = Suite(&interfaceManagerSuite{})

func (s *interfaceManagerSuite) SetUpTest(c *C) {
	s.storeSigning = assertstest.NewStoreStack("canonical", rootKey, storeKey)

	dirs.SetRootDir(c.MkDir())
	state := state.New(nil)
	s.state = state
	db, err := asserts.OpenDatabase(&asserts.DatabaseConfig{
		Backstore: asserts.NewMemoryBackstore(),
		Trusted:   s.storeSigning.Trusted,
	})
	c.Assert(err, IsNil)
	s.db = db
	err = db.Add(s.storeSigning.StoreAccountKey(""))
	c.Assert(err, IsNil)

	s.state.Lock()
	assertstate.ReplaceDB(state, s.db)
	s.state.Unlock()

	s.privateMgr = nil
	s.extraIfaces = nil
	s.secBackend = &interfaces.TestSecurityBackend{}
	s.restoreBackends = ifacestate.MockSecurityBackends([]interfaces.SecurityBackend{s.secBackend})
}

func (s *interfaceManagerSuite) TearDownTest(c *C) {
	if s.privateMgr != nil {
		s.privateMgr.Stop()
	}
	dirs.SetRootDir("")
	s.restoreBackends()
}

func (s *interfaceManagerSuite) manager(c *C) *ifacestate.InterfaceManager {
	if s.privateMgr == nil {
		mgr, err := ifacestate.Manager(s.state, s.extraIfaces)
		c.Assert(err, IsNil)
		s.privateMgr = mgr
	}
	return s.privateMgr
}

func (s *interfaceManagerSuite) TestSmoke(c *C) {
	mgr := s.manager(c)
	mgr.Ensure()
	mgr.Wait()
}

func (s *interfaceManagerSuite) TestConnectTask(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	ts, err := ifacestate.Connect(s.state, "consumer", "plug", "producer", "slot")
	c.Assert(err, IsNil)

	task := ts.Tasks()[0]
	c.Assert(task.Kind(), Equals, "connect")
	var plug interfaces.PlugRef
	err = task.Get("plug", &plug)
	c.Assert(err, IsNil)
	c.Assert(plug.Snap, Equals, "consumer")
	c.Assert(plug.Name, Equals, "plug")
	var slot interfaces.SlotRef
	err = task.Get("slot", &slot)
	c.Assert(err, IsNil)
	c.Assert(slot.Snap, Equals, "producer")
	c.Assert(slot.Name, Equals, "slot")
}

func (s *interfaceManagerSuite) TestEnsureProcessesConnectTask(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	change := s.state.NewChange("kind", "summary")
	ts, err := ifacestate.Connect(s.state, "consumer", "plug", "producer", "slot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change.AddAll(ts)
	s.state.Unlock()

	mgr := s.manager(c)
	mgr.Ensure()
	mgr.Wait()

	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(change.Err(), IsNil)
	task := change.Tasks()[0]
	c.Check(task.Kind(), Equals, "connect")
	c.Check(task.Status(), Equals, state.DoneStatus)
	c.Check(change.Status(), Equals, state.DoneStatus)

	repo := mgr.Repository()
	plug := repo.Plug("consumer", "plug")
	slot := repo.Slot("producer", "slot")
	c.Assert(plug.Connections, HasLen, 1)
	c.Assert(slot.Connections, HasLen, 1)
	c.Check(plug.Connections[0], DeepEquals, interfaces.SlotRef{Snap: "producer", Name: "slot"})
	c.Check(slot.Connections[0], DeepEquals, interfaces.PlugRef{Snap: "consumer", Name: "plug"})
}

func (s *interfaceManagerSuite) TestConnectTaskCheckInterfaceMismatch(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test2"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	change := s.state.NewChange("kind", "summary")
	ts, err := ifacestate.Connect(s.state, "consumer", "otherplug", "producer", "slot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change.AddAll(ts)
	s.state.Unlock()

	mgr := s.manager(c)
	mgr.Ensure()
	mgr.Wait()

	s.state.Lock()
	defer s.state.Unlock()

	c.Check(change.Err(), ErrorMatches, `(?s).*cannot connect mismatched plug interface "test2" to slot interface "test.*`)
	task := change.Tasks()[0]
	c.Check(task.Kind(), Equals, "connect")
	c.Check(task.Status(), Equals, state.ErrorStatus)
	c.Check(change.Status(), Equals, state.ErrorStatus)
}

func (s *interfaceManagerSuite) TestConnectTaskNoSuchSlot(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	change := s.state.NewChange("kind", "summary")
	ts, err := ifacestate.Connect(s.state, "consumer", "plug", "producer", "whatslot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change.AddAll(ts)
	s.state.Unlock()

	mgr := s.manager(c)
	mgr.Ensure()
	mgr.Wait()

	s.state.Lock()
	defer s.state.Unlock()

	c.Check(change.Err(), ErrorMatches, `(?s).*Connect consumer:plug to producer:whatslot \(no such slot\).*`)
	c.Check(change.Status(), Equals, state.ErrorStatus)
}

func (s *interfaceManagerSuite) TestConnectTaskNoSuchPlug(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	change := s.state.NewChange("kind", "summary")
	ts, err := ifacestate.Connect(s.state, "consumer", "whatplug", "producer", "slot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change.AddAll(ts)
	s.state.Unlock()

	mgr := s.manager(c)
	mgr.Ensure()
	mgr.Wait()

	s.state.Lock()
	defer s.state.Unlock()

	c.Check(change.Err(), ErrorMatches, `(?s).*no such plug.*`)
	c.Check(change.Status(), Equals, state.ErrorStatus)
}

func (s *interfaceManagerSuite) TestConnectTaskCheckNotAllowed(c *C) {
	restore := assertstest.MockBuiltinBaseDeclaration([]byte(`
type: base-declaration
authority-id: canonical
series: 16
slots:
  test:
    allow-connection:
      plug-publisher-id:
        - $slot-publisher-id
`))
	defer restore()
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnapDecl(c, "consumer", "consumer-publisher")
	s.mockSnap(c, consumerYaml)
	s.mockSnapDecl(c, "producer", "producer-publisher")
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	change := s.state.NewChange("kind", "summary")
	ts, err := ifacestate.Connect(s.state, "consumer", "plug", "producer", "slot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change.AddAll(ts)
	s.state.Unlock()

	mgr := s.manager(c)
	mgr.Ensure()
	mgr.Wait()

	s.state.Lock()
	defer s.state.Unlock()

	c.Check(change.Err(), ErrorMatches, `(?s).*connection not allowed by slot rule of interface "test".*`)
	c.Check(change.Status(), Equals, state.ErrorStatus)
}

func (s *interfaceManagerSuite) TestConnectTaskCheckAllowed(c *C) {
	restore := assertstest.MockBuiltinBaseDeclaration([]byte(`
type: base-declaration
authority-id: canonical
series: 16
slots:
  test:
    allow-connection:
      plug-publisher-id:
        - $slot-publisher-id
`))
	defer restore()
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnapDecl(c, "consumer", "one-publisher")
	s.mockSnap(c, consumerYaml)
	s.mockSnapDecl(c, "producer", "one-publisher")
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	change := s.state.NewChange("kind", "summary")
	ts, err := ifacestate.Connect(s.state, "consumer", "plug", "producer", "slot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change.AddAll(ts)
	s.state.Unlock()

	mgr := s.manager(c)
	mgr.Ensure()
	mgr.Wait()

	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(change.Err(), IsNil)
	c.Check(change.Status(), Equals, state.DoneStatus)

	repo := mgr.Repository()
	plug := repo.Plug("consumer", "plug")
	slot := repo.Slot("producer", "slot")
	c.Assert(plug.Connections, HasLen, 1)
	c.Check(plug.Connections[0], DeepEquals, interfaces.SlotRef{Snap: "producer", Name: "slot"})
	c.Check(slot.Connections[0], DeepEquals, interfaces.PlugRef{Snap: "consumer", Name: "plug"})
}

func (s *interfaceManagerSuite) TestDisconnectTask(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	ts, err := ifacestate.Disconnect(s.state, "consumer", "plug", "producer", "slot")
	c.Assert(err, IsNil)

	task := ts.Tasks()[0]
	c.Assert(task.Kind(), Equals, "disconnect")
	var plug interfaces.PlugRef
	err = task.Get("plug", &plug)
	c.Assert(err, IsNil)
	c.Assert(plug.Snap, Equals, "consumer")
	c.Assert(plug.Name, Equals, "plug")
	var slot interfaces.SlotRef
	err = task.Get("slot", &slot)
	c.Assert(err, IsNil)
	c.Assert(slot.Snap, Equals, "producer")
	c.Assert(slot.Name, Equals, "slot")
}

func (s *interfaceManagerSuite) TestEnsureProcessesDisconnectTask(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	s.state.Set("conns", map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
	s.state.Unlock()

	s.state.Lock()
	change := s.state.NewChange("kind", "summary")
	ts, err := ifacestate.Disconnect(s.state, "consumer", "plug", "producer", "slot")
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})
	c.Assert(err, IsNil)
	change.AddAll(ts)
	s.state.Unlock()

	mgr := s.manager(c)
	mgr.Ensure()
	mgr.Wait()

	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(change.Err(), IsNil)
	task := change.Tasks()[0]
	c.Check(task.Kind(), Equals, "disconnect")
	c.Check(task.Status(), Equals, state.DoneStatus)
	c.Check(change.Status(), Equals, state.DoneStatus)

	// The connection is gone
	repo := mgr.Repository()
	plug := repo.Plug("consumer", "plug")
	slot := repo.Slot("producer", "slot")
	c.Assert(plug.Connections, HasLen, 0)
	c.Assert(slot.Connections, HasLen, 0)
}

func (s *interfaceManagerSuite) mockIface(c *C, iface interfaces.Interface) {
	s.extraIfaces = append(s.extraIfaces, iface)
}

func (s *interfaceManagerSuite) mockSnapDecl(c *C, name, publisher string) {
	_, err := s.db.Find(asserts.AccountType, map[string]string{
		"account-id": publisher,
	})
	if err == asserts.ErrNotFound {
		acct := assertstest.NewAccount(s.storeSigning, publisher, map[string]interface{}{
			"account-id": publisher,
		}, "")
		err = s.db.Add(acct)
	}
	c.Assert(err, IsNil)

	snapDecl, err := s.storeSigning.Sign(asserts.SnapDeclarationType, map[string]interface{}{
		"series":       "16",
		"snap-name":    name,
		"publisher-id": publisher,
		"snap-id":      (name + strings.Repeat("id", 16))[:32],
		"timestamp":    time.Now().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	err = s.db.Add(snapDecl)
	c.Assert(err, IsNil)
}

func (s *interfaceManagerSuite) mockSnap(c *C, yamlText string) *snap.Info {
	sideInfo := &snap.SideInfo{
		Revision: snap.R(1),
	}
	snapInfo := snaptest.MockSnap(c, yamlText, sideInfo)
	sideInfo.RealName = snapInfo.Name()

	a, err := s.db.FindMany(asserts.SnapDeclarationType, map[string]string{
		"snap-name": sideInfo.RealName,
	})
	if err == nil {
		decl := a[0].(*asserts.SnapDeclaration)
		sideInfo.SnapID = decl.SnapID()
	} else if err == asserts.ErrNotFound {
		err = nil
	}
	c.Assert(err, IsNil)

	s.state.Lock()
	defer s.state.Unlock()

	// Put a side info into the state
	snapstate.Set(s.state, snapInfo.Name(), &snapstate.SnapState{
		Active:   true,
		Sequence: []*snap.SideInfo{sideInfo},
		Current:  sideInfo.Revision,
	})
	return snapInfo
}

func (s *interfaceManagerSuite) mockUpdatedSnap(c *C, yamlText string, revision int) *snap.Info {
	sideInfo := &snap.SideInfo{Revision: snap.R(revision)}
	snapInfo := snaptest.MockSnap(c, yamlText, sideInfo)
	sideInfo.RealName = snapInfo.Name()

	s.state.Lock()
	defer s.state.Unlock()

	// Put the new revision (stored in SideInfo) into the state
	var snapst snapstate.SnapState
	err := snapstate.Get(s.state, snapInfo.Name(), &snapst)
	c.Assert(err, IsNil)
	snapst.Sequence = append(snapst.Sequence, sideInfo)
	snapstate.Set(s.state, snapInfo.Name(), &snapst)

	return snapInfo
}

func (s *interfaceManagerSuite) addSetupSnapSecurityChange(c *C, ss *snapstate.SnapSetup) *state.Change {
	s.state.Lock()
	defer s.state.Unlock()

	task := s.state.NewTask("setup-profiles", "")
	task.Set("snap-setup", ss)
	taskset := state.NewTaskSet(task)
	change := s.state.NewChange("test", "")
	change.AddAll(taskset)
	return change
}

func (s *interfaceManagerSuite) addRemoveSnapSecurityChange(c *C, snapName string) *state.Change {
	s.state.Lock()
	defer s.state.Unlock()

	task := s.state.NewTask("remove-profiles", "")
	ss := snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapName,
		},
	}
	task.Set("snap-setup", ss)
	taskset := state.NewTaskSet(task)
	change := s.state.NewChange("test", "")
	change.AddAll(taskset)
	return change
}

func (s *interfaceManagerSuite) addDiscardConnsChange(c *C, snapName string) *state.Change {
	s.state.Lock()
	defer s.state.Unlock()

	task := s.state.NewTask("discard-conns", "")
	ss := snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapName,
		},
	}
	task.Set("snap-setup", ss)
	taskset := state.NewTaskSet(task)
	change := s.state.NewChange("test", "")
	change.AddAll(taskset)
	return change
}

var osSnapYaml = `
name: ubuntu-core
version: 1
type: os
`

var sampleSnapYaml = `
name: snap
version: 1
apps:
 app:
   command: foo
plugs:
 network:
  interface: network
`

var consumerYaml = `
name: consumer
version: 1
plugs:
 plug:
  interface: test
 otherplug:
  interface: test2
`

var producerYaml = `
name: producer
version: 1
slots:
 slot:
  interface: test
`

// The setup-profiles task will not auto-connect an plug that was previously
// explicitly disconnected by the user.
func (s *interfaceManagerSuite) TestDoSetupSnapSecurityHonorsDisconnect(c *C) {
	// Add an OS snap as well as a sample snap with a "network" plug.
	// The plug is normally auto-connected.
	s.mockSnap(c, osSnapYaml)
	snapInfo := s.mockSnap(c, sampleSnapYaml)

	// Initialize the manager. This registers the two snaps.
	mgr := s.manager(c)

	// Run the setup-snap-security task and let it finish.
	change := s.addSetupSnapSecurityChange(c, &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapInfo.Name(),
			Revision: snapInfo.Revision,
		},
	})
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	// Ensure that the task succeeded
	c.Assert(change.Status(), Equals, state.DoneStatus)

	// Ensure that "network" is not saved in the state as auto-connected.
	var conns map[string]interface{}
	err := s.state.Get("conns", &conns)
	c.Assert(err, IsNil)
	c.Check(conns, HasLen, 0)

	// Ensure that "network" is really disconnected.
	repo := mgr.Repository()
	plug := repo.Plug("snap", "network")
	c.Assert(plug, Not(IsNil))
	c.Check(plug.Connections, HasLen, 0)
}

// The setup-profiles task will auto-connect plugs with viable candidates.
func (s *interfaceManagerSuite) TestDoSetupSnapSecuirtyAutoConnects(c *C) {
	// Add an OS snap.
	s.mockSnap(c, osSnapYaml)

	// Initialize the manager. This registers the OS snap.
	mgr := s.manager(c)

	// Add a sample snap with a "network" plug which should be auto-connected.
	snapInfo := s.mockSnap(c, sampleSnapYaml)

	// Run the setup-snap-security task and let it finish.
	change := s.addSetupSnapSecurityChange(c, &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapInfo.Name(),
			Revision: snapInfo.Revision,
		},
	})
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	// Ensure that the task succeeded.
	c.Assert(change.Status(), Equals, state.DoneStatus)

	// Ensure that "network" is now saved in the state as auto-connected.
	var conns map[string]interface{}
	err := s.state.Get("conns", &conns)
	c.Assert(err, IsNil)
	c.Check(conns, DeepEquals, map[string]interface{}{
		"snap:network ubuntu-core:network": map[string]interface{}{
			"interface": "network", "auto": true,
		},
	})

	// Ensure that "network" is really connected.
	repo := mgr.Repository()
	plug := repo.Plug("snap", "network")
	c.Assert(plug, Not(IsNil))
	c.Check(plug.Connections, HasLen, 1)
}

// The setup-profiles task will only touch connection state for the task it
// operates on or auto-connects to and will leave other state intact.
func (s *interfaceManagerSuite) TestDoSetupSnapSecuirtyKeepsExistingConnectionState(c *C) {
	// Add an OS snap in place.
	s.mockSnap(c, osSnapYaml)

	// Initialize the manager. This registers the two snaps.
	mgr := s.manager(c)

	// Add a sample snap with a "network" plug which should be auto-connected.
	snapInfo := s.mockSnap(c, sampleSnapYaml)

	// Put fake information about connections for another snap into the state.
	s.state.Lock()
	s.state.Set("conns", map[string]interface{}{
		"other-snap:network ubuntu-core:network": map[string]interface{}{
			"interface": "network",
		},
	})
	s.state.Unlock()

	// Run the setup-snap-security task and let it finish.
	change := s.addSetupSnapSecurityChange(c, &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapInfo.Name(),
			Revision: snapInfo.Revision,
		},
	})
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	// Ensure that the task succeeded.
	c.Assert(change.Status(), Equals, state.DoneStatus)

	var conns map[string]interface{}
	err := s.state.Get("conns", &conns)
	c.Assert(err, IsNil)
	c.Check(conns, DeepEquals, map[string]interface{}{
		// The sample snap was auto-connected, as expected.
		"snap:network ubuntu-core:network": map[string]interface{}{
			"interface": "network", "auto": true,
		},
		// Connection state for the fake snap is preserved.
		// The task didn't alter state of other snaps.
		"other-snap:network ubuntu-core:network": map[string]interface{}{
			"interface": "network",
		},
	})
}

// The setup-profiles task will add implicit slots necessary for the OS snap.
func (s *interfaceManagerSuite) TestDoSetupProfilesAddsImplicitSlots(c *C) {
	// Initialize the manager.
	mgr := s.manager(c)

	// Add an OS snap.
	snapInfo := s.mockSnap(c, osSnapYaml)

	// Run the setup-profiles task and let it finish.
	change := s.addSetupSnapSecurityChange(c, &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapInfo.Name(),
			Revision: snapInfo.Revision,
		},
	})
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	// Ensure that the task succeeded.
	c.Assert(change.Status(), Equals, state.DoneStatus)

	// Ensure that we have slots on the OS snap.
	repo := mgr.Repository()
	slots := repo.Slots(snapInfo.Name())
	// NOTE: This is not an exact test as it duplicates functionality elsewhere
	// and is was a pain to update each time. This is correctly handled by the
	// implicit slot tests in snap/implicit_test.go
	c.Assert(len(slots) > 18, Equals, true)
}

func (s *interfaceManagerSuite) TestDoSetupSnapSecuirtyReloadsConnectionsWhenInvokedOnPlugSide(c *C) {
	snapInfo := s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)
	s.testDoSetupSnapSecuirtyReloadsConnectionsWhenInvokedOn(c, snapInfo.Name(), snapInfo.Revision)
}

func (s *interfaceManagerSuite) TestDoSetupSnapSecuirtyReloadsConnectionsWhenInvokedOnSlotSide(c *C) {
	s.mockSnap(c, consumerYaml)
	snapInfo := s.mockSnap(c, producerYaml)
	s.testDoSetupSnapSecuirtyReloadsConnectionsWhenInvokedOn(c, snapInfo.Name(), snapInfo.Revision)
}

func (s *interfaceManagerSuite) testDoSetupSnapSecuirtyReloadsConnectionsWhenInvokedOn(c *C, snapName string, revision snap.Revision) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})

	s.state.Lock()
	s.state.Set("conns", map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
	s.state.Unlock()

	mgr := s.manager(c)

	// Run the setup-profiles task
	change := s.addSetupSnapSecurityChange(c, &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapName,
			Revision: revision,
		},
	})
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	// Change succeeds
	s.state.Lock()
	defer s.state.Unlock()
	c.Check(change.Status(), Equals, state.DoneStatus)

	repo := mgr.Repository()

	// Repository shows the connection
	plug := repo.Plug("consumer", "plug")
	slot := repo.Slot("producer", "slot")
	c.Assert(plug.Connections, HasLen, 1)
	c.Assert(slot.Connections, HasLen, 1)
	c.Check(plug.Connections[0], DeepEquals, interfaces.SlotRef{Snap: "producer", Name: "slot"})
	c.Check(slot.Connections[0], DeepEquals, interfaces.PlugRef{Snap: "consumer", Name: "plug"})
}

// The setup-profiles task will honor snapstate.DevMode flag by storing it
// in the SnapState.Flags and by actually setting up security
// using that flag. Old copy of SnapState.Flag's DevMode is saved for the undo
// handler under `old-devmode`.
func (s *interfaceManagerSuite) TestSetupProfilesHonorsDevMode(c *C) {
	// Put the OS snap in place.
	mgr := s.manager(c)

	// Initialize the manager. This registers the OS snap.
	snapInfo := s.mockSnap(c, sampleSnapYaml)

	// Run the setup-profiles task and let it finish.
	// Note that the task will see SnapSetup.Flags equal to DeveloperMode.
	change := s.addSetupSnapSecurityChange(c, &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapInfo.Name(),
			Revision: snapInfo.Revision,
		},
		Flags: snapstate.DevMode,
	})
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	// Ensure that the task succeeded.
	c.Check(change.Status(), Equals, state.DoneStatus)

	// The snap was setup with DevMode equal to true.
	c.Assert(s.secBackend.SetupCalls, HasLen, 1)
	c.Assert(s.secBackend.RemoveCalls, HasLen, 0)
	c.Check(s.secBackend.SetupCalls[0].SnapInfo.Name(), Equals, "snap")
	c.Check(s.secBackend.SetupCalls[0].DevMode, Equals, true)
}

// setup-profiles uses the new snap.Info when setting up security for the new
// snap when it had prior connections and DisconnectSnap() returns it as a part
// of the affected set.
func (s *interfaceManagerSuite) TestSetupProfilesUsesFreshSnapInfo(c *C) {
	// Put the OS and the sample snaps in place.
	coreSnapInfo := s.mockSnap(c, osSnapYaml)
	oldSnapInfo := s.mockSnap(c, sampleSnapYaml)

	// Put connection information between the OS snap and the sample snap.
	// This is done so that DisconnectSnap returns both snaps as "affected"
	// and so that the previously broken code path is exercised.
	s.state.Lock()
	s.state.Set("conns", map[string]interface{}{
		"snap:network ubuntu-core:network": map[string]interface{}{"interface": "network"},
	})
	s.state.Unlock()

	// Initialize the manager. This registers both of the snaps and reloads the
	// connection between them.
	mgr := s.manager(c)

	// Put a new revision of the sample snap in place.
	newSnapInfo := s.mockUpdatedSnap(c, sampleSnapYaml, 42)

	// Sanity check, the revisions are different.
	c.Assert(oldSnapInfo.Revision, Not(Equals), 42)
	c.Assert(newSnapInfo.Revision, Equals, snap.R(42))

	// Run the setup-profiles task for the new revision and let it finish.
	change := s.addSetupSnapSecurityChange(c, &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: newSnapInfo.Name(),
			Revision: newSnapInfo.Revision,
		},
	})
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	// Ensure that the task succeeded.
	c.Assert(change.Err(), IsNil)
	c.Check(change.Status(), Equals, state.DoneStatus)

	// Ensure that both snaps were setup correctly.
	c.Assert(s.secBackend.SetupCalls, HasLen, 2)
	c.Assert(s.secBackend.RemoveCalls, HasLen, 0)
	// The sample snap was setup, with the correct new revision.
	c.Check(s.secBackend.SetupCalls[0].SnapInfo.Name(), Equals, newSnapInfo.Name())
	c.Check(s.secBackend.SetupCalls[0].SnapInfo.Revision, Equals, newSnapInfo.Revision)
	// The OS snap was setup (because it was affected).
	c.Check(s.secBackend.SetupCalls[1].SnapInfo.Name(), Equals, coreSnapInfo.Name())
	c.Check(s.secBackend.SetupCalls[1].SnapInfo.Revision, Equals, coreSnapInfo.Revision)
}

func (s *interfaceManagerSuite) TestDoDiscardConnsPlug(c *C) {
	s.testDoDicardConns(c, "consumer")
}

func (s *interfaceManagerSuite) TestDoDiscardConnsSlot(c *C) {
	s.testDoDicardConns(c, "producer")
}

func (s *interfaceManagerSuite) TestUndoDiscardConnsPlug(c *C) {
	s.testUndoDicardConns(c, "consumer")
}

func (s *interfaceManagerSuite) TestUndoDiscardConnsSlot(c *C) {
	s.testUndoDicardConns(c, "producer")
}

func (s *interfaceManagerSuite) testDoDicardConns(c *C, snapName string) {
	s.state.Lock()
	// Store information about a connection in the state.
	s.state.Set("conns", map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
	// Store empty snap state. This snap has an empty sequence now.
	snapstate.Set(s.state, snapName, &snapstate.SnapState{})
	s.state.Unlock()

	mgr := s.manager(c)

	// Run the discard-conns task and let it finish
	change := s.addDiscardConnsChange(c, snapName)
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()
	c.Check(change.Status(), Equals, state.DoneStatus)

	// Information about the connection was removed
	var conns map[string]interface{}
	err := s.state.Get("conns", &conns)
	c.Assert(err, IsNil)
	c.Check(conns, DeepEquals, map[string]interface{}{})

	// But removed connections are preserved in the task for undo.
	var removed map[string]interface{}
	err = change.Tasks()[0].Get("removed", &removed)
	c.Assert(err, IsNil)
	c.Check(removed, DeepEquals, map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
}

func (s *interfaceManagerSuite) testUndoDicardConns(c *C, snapName string) {
	s.state.Lock()
	// Store information about a connection in the state.
	s.state.Set("conns", map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
	// Store empty snap state. This snap has an empty sequence now.
	snapstate.Set(s.state, snapName, &snapstate.SnapState{})
	s.state.Unlock()

	mgr := s.manager(c)

	// Run the discard-conns task and let it finish
	change := s.addDiscardConnsChange(c, snapName)

	// Add a dummy task just to hold the change not ready.
	s.state.Lock()
	dummy := s.state.NewTask("dummy", "")
	change.AddTask(dummy)
	s.state.Unlock()

	mgr.Ensure()
	mgr.Wait()

	s.state.Lock()
	c.Check(change.Status(), Equals, state.DoStatus)
	change.Abort()
	s.state.Unlock()

	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()
	c.Assert(change.Status(), Equals, state.UndoneStatus)

	// Information about the connection is intact
	var conns map[string]interface{}
	err := s.state.Get("conns", &conns)
	c.Assert(err, IsNil)
	c.Check(conns, DeepEquals, map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})

	var removed map[string]interface{}
	err = change.Tasks()[0].Get("removed", &removed)
	c.Assert(err, IsNil)
	c.Check(removed, HasLen, 0)
}

func (s *interfaceManagerSuite) TestDoRemove(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	s.state.Set("conns", map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
	s.state.Unlock()

	mgr := s.manager(c)

	// Run the remove-security task
	change := s.addRemoveSnapSecurityChange(c, "consumer")
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	// Change succeeds
	s.state.Lock()
	defer s.state.Unlock()
	c.Check(change.Status(), Equals, state.DoneStatus)

	repo := mgr.Repository()

	// Snap is removed from repository
	c.Check(repo.Plug("consumer", "slot"), IsNil)

	// Security of the snap was removed
	c.Check(s.secBackend.RemoveCalls, DeepEquals, []string{"consumer"})

	// Security of the related snap was configured
	c.Check(s.secBackend.SetupCalls, HasLen, 1)
	c.Check(s.secBackend.SetupCalls[0].SnapInfo.Name(), Equals, "producer")

	// Connection state was left intact
	var conns map[string]interface{}
	err := s.state.Get("conns", &conns)
	c.Assert(err, IsNil)
	c.Check(conns, DeepEquals, map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
}

func (s *interfaceManagerSuite) TestConnectTracksConnectionsInState(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	mgr := s.manager(c)

	s.state.Lock()
	ts, err := ifacestate.Connect(s.state, "consumer", "plug", "producer", "slot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change := s.state.NewChange("connect", "")
	change.AddAll(ts)
	s.state.Unlock()

	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(change.Err(), IsNil)
	c.Check(change.Status(), Equals, state.DoneStatus)
	var conns map[string]interface{}
	err = s.state.Get("conns", &conns)
	c.Assert(err, IsNil)
	c.Check(conns, DeepEquals, map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{
			"interface": "test",
		},
	})
}

func (s *interfaceManagerSuite) TestConnectSetsUpSecurity(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	mgr := s.manager(c)

	s.state.Lock()
	ts, err := ifacestate.Connect(s.state, "consumer", "plug", "producer", "slot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change := s.state.NewChange("connect", "")
	change.AddAll(ts)
	s.state.Unlock()

	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(change.Err(), IsNil)
	c.Check(change.Status(), Equals, state.DoneStatus)

	c.Assert(s.secBackend.SetupCalls, HasLen, 2)
	c.Assert(s.secBackend.RemoveCalls, HasLen, 0)
	c.Check(s.secBackend.SetupCalls[0].SnapInfo.Name(), Equals, "consumer")
	c.Check(s.secBackend.SetupCalls[1].SnapInfo.Name(), Equals, "producer")

	c.Check(s.secBackend.SetupCalls[0].DevMode, Equals, false)
	c.Check(s.secBackend.SetupCalls[1].DevMode, Equals, false)
}

func (s *interfaceManagerSuite) TestDisconnectSetsUpSecurity(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	s.state.Set("conns", map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
	s.state.Unlock()

	mgr := s.manager(c)

	s.state.Lock()
	ts, err := ifacestate.Disconnect(s.state, "consumer", "plug", "producer", "slot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change := s.state.NewChange("disconnect", "")
	change.AddAll(ts)
	s.state.Unlock()

	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(change.Err(), IsNil)
	c.Check(change.Status(), Equals, state.DoneStatus)

	c.Assert(s.secBackend.SetupCalls, HasLen, 2)
	c.Assert(s.secBackend.RemoveCalls, HasLen, 0)
	c.Check(s.secBackend.SetupCalls[0].SnapInfo.Name(), Equals, "consumer")
	c.Check(s.secBackend.SetupCalls[1].SnapInfo.Name(), Equals, "producer")

	c.Check(s.secBackend.SetupCalls[0].DevMode, Equals, false)
	c.Check(s.secBackend.SetupCalls[1].DevMode, Equals, false)
}

func (s *interfaceManagerSuite) TestDisconnectTracksConnectionsInState(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)
	s.state.Lock()
	s.state.Set("conns", map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
	s.state.Unlock()

	mgr := s.manager(c)

	s.state.Lock()
	ts, err := ifacestate.Disconnect(s.state, "consumer", "plug", "producer", "slot")
	c.Assert(err, IsNil)
	ts.Tasks()[0].Set("snap-setup", &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "consumer",
		},
	})

	change := s.state.NewChange("disconnect", "")
	change.AddAll(ts)
	s.state.Unlock()

	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(change.Err(), IsNil)
	c.Check(change.Status(), Equals, state.DoneStatus)
	var conns map[string]interface{}
	err = s.state.Get("conns", &conns)
	c.Assert(err, IsNil)
	c.Check(conns, DeepEquals, map[string]interface{}{})
}

func (s *interfaceManagerSuite) TestManagerReloadsConnections(c *C) {
	s.mockIface(c, &interfaces.TestInterface{InterfaceName: "test"})
	s.mockSnap(c, consumerYaml)
	s.mockSnap(c, producerYaml)

	s.state.Lock()
	s.state.Set("conns", map[string]interface{}{
		"consumer:plug producer:slot": map[string]interface{}{"interface": "test"},
	})
	s.state.Unlock()

	mgr := s.manager(c)
	repo := mgr.Repository()

	plug := repo.Plug("consumer", "plug")
	slot := repo.Slot("producer", "slot")
	c.Assert(plug.Connections, HasLen, 1)
	c.Assert(slot.Connections, HasLen, 1)
	c.Check(plug.Connections[0], DeepEquals, interfaces.SlotRef{Snap: "producer", Name: "slot"})
	c.Check(slot.Connections[0], DeepEquals, interfaces.PlugRef{Snap: "consumer", Name: "plug"})
}

func (s *interfaceManagerSuite) TestSetupProfilesDevModeMultiple(c *C) {
	mgr := s.manager(c)
	repo := mgr.Repository()

	// setup two snaps that are connected
	siP := s.mockSnap(c, producerYaml)
	siC := s.mockSnap(c, consumerYaml)
	err := repo.AddInterface(&interfaces.TestInterface{
		InterfaceName: "test",
	})
	c.Assert(err, IsNil)
	err = repo.AddSlot(&interfaces.Slot{
		SlotInfo: &snap.SlotInfo{
			Snap:      siC,
			Name:      "slot",
			Interface: "test",
		},
	})
	c.Assert(err, IsNil)
	err = repo.AddPlug(&interfaces.Plug{
		PlugInfo: &snap.PlugInfo{
			Snap:      siP,
			Name:      "plug",
			Interface: "test",
		},
	})
	c.Assert(err, IsNil)
	err = repo.Connect(siP.Name(), "plug", siC.Name(), "slot")
	c.Assert(err, IsNil)

	change := s.addSetupSnapSecurityChange(c, &snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: siC.Name(),
			Revision: siC.Revision,
		},
		Flags: snapstate.DevMode,
	})
	mgr.Ensure()
	mgr.Wait()
	mgr.Stop()

	s.state.Lock()
	defer s.state.Unlock()

	// Ensure that the task succeeded.
	c.Check(change.Err(), IsNil)
	c.Check(change.Status(), Equals, state.DoneStatus)

	// The first snap is setup in devmode, the second is not
	c.Assert(s.secBackend.SetupCalls, HasLen, 2)
	c.Assert(s.secBackend.RemoveCalls, HasLen, 0)
	c.Check(s.secBackend.SetupCalls[0].SnapInfo.Name(), Equals, siC.Name())
	c.Check(s.secBackend.SetupCalls[0].DevMode, Equals, true)
	c.Check(s.secBackend.SetupCalls[1].SnapInfo.Name(), Equals, siP.Name())
	c.Check(s.secBackend.SetupCalls[1].DevMode, Equals, false)
}
