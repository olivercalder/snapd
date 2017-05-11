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

package builtin_test

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/interfaces/dbus"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/interfaces/udev"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/testutil"
)

type ModemManagerInterfaceSuite struct {
	iface interfaces.Interface
	slot  *interfaces.Slot
	plug  *interfaces.Plug
}

const modemmgrMockSlotSnapInfoYaml = `name: modem-manager
version: 1.0
apps:
 mm:
  command: foo
  slots: [modem-manager]
`

const modemmgrMockPlugSnapInfoYaml = `name: modem-manager
version: 1.0
plugs:
 modem-manager:
  interface: modem-manager
apps:
 mmcli:
  command: foo
  plugs:
   - modem-manager
`

var _ = Suite(&ModemManagerInterfaceSuite{})

func (s *ModemManagerInterfaceSuite) SetUpTest(c *C) {
	s.iface = &builtin.ModemManagerInterface{}
	s.plug = &interfaces.Plug{
		PlugInfo: &snap.PlugInfo{
			Snap:      &snap.Info{SuggestedName: "modem-manager"},
			Name:      "mmcli",
			Interface: "modem-manager",
		},
	}
	slotSnap := snaptest.MockInfo(c, modemmgrMockSlotSnapInfoYaml, nil)
	s.slot = &interfaces.Slot{SlotInfo: slotSnap.Slots["modem-manager"]}
}

func (s *ModemManagerInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "modem-manager")
}

// The label glob when all apps are bound to the modem-manager slot
func (s *ModemManagerInterfaceSuite) TestConnectedPlugSnippetUsesSlotLabelAll(c *C) {
	app1 := &snap.AppInfo{Name: "app1"}
	app2 := &snap.AppInfo{Name: "app2"}
	slot := &interfaces.Slot{
		SlotInfo: &snap.SlotInfo{
			Snap: &snap.Info{
				SuggestedName: "modem-manager-prod",
				Apps:          map[string]*snap.AppInfo{"app1": app1, "app2": app2},
			},
			Name:      "modem-manager",
			Interface: "modem-manager",
			Apps:      map[string]*snap.AppInfo{"app1": app1, "app2": app2},
		},
	}
	release.OnClassic = false

	plugSnap := snaptest.MockInfo(c, modemmgrMockPlugSnapInfoYaml, nil)
	plug := &interfaces.Plug{PlugInfo: plugSnap.Plugs["modem-manager"]}

	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, plug, nil, slot, nil)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.modem-manager.mmcli"})
	c.Assert(apparmorSpec.SnippetForTag("snap.modem-manager.mmcli"), testutil.Contains, `peer=(label="snap.modem-manager-prod.*"),`)
}

// The label uses alternation when some, but not all, apps is bound to the modem-manager slot
func (s *ModemManagerInterfaceSuite) TestConnectedPlugSnippetUsesSlotLabelSome(c *C) {
	app1 := &snap.AppInfo{Name: "app1"}
	app2 := &snap.AppInfo{Name: "app2"}
	app3 := &snap.AppInfo{Name: "app3"}
	slot := &interfaces.Slot{
		SlotInfo: &snap.SlotInfo{
			Snap: &snap.Info{
				SuggestedName: "modem-manager",
				Apps:          map[string]*snap.AppInfo{"app1": app1, "app2": app2, "app3": app3},
			},
			Name:      "modem-manager",
			Interface: "modem-manager",
			Apps:      map[string]*snap.AppInfo{"app1": app1, "app2": app2},
		},
	}
	release.OnClassic = false

	plugSnap := snaptest.MockInfo(c, modemmgrMockPlugSnapInfoYaml, nil)
	plug := &interfaces.Plug{PlugInfo: plugSnap.Plugs["modem-manager"]}

	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, plug, nil, slot, nil)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.modem-manager.mmcli"})
	c.Assert(apparmorSpec.SnippetForTag("snap.modem-manager.mmcli"), testutil.Contains, `peer=(label="snap.modem-manager.{app1,app2}"),`)
}

// The label uses short form when exactly one app is bound to the modem-manager slot
func (s *ModemManagerInterfaceSuite) TestConnectedPlugSnippetUsesSlotLabelOne(c *C) {
	app := &snap.AppInfo{Name: "app"}
	slot := &interfaces.Slot{
		SlotInfo: &snap.SlotInfo{
			Snap: &snap.Info{
				SuggestedName: "modem-manager",
				Apps:          map[string]*snap.AppInfo{"app": app},
			},
			Name:      "modem-manager",
			Interface: "modem-manager",
			Apps:      map[string]*snap.AppInfo{"app": app},
		},
	}
	release.OnClassic = false

	plugSnap := snaptest.MockInfo(c, modemmgrMockPlugSnapInfoYaml, nil)
	plug := &interfaces.Plug{PlugInfo: plugSnap.Plugs["modem-manager"]}

	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, plug, nil, slot, nil)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.modem-manager.mmcli"})
	c.Assert(apparmorSpec.SnippetForTag("snap.modem-manager.mmcli"), testutil.Contains, `peer=(label="snap.modem-manager.app"),`)
}

func (s *ModemManagerInterfaceSuite) TestConnectedPlugSnippetUsesUnconfinedLabelNot(c *C) {
	release.OnClassic = false
	plugSnap := snaptest.MockInfo(c, modemmgrMockPlugSnapInfoYaml, nil)
	plug := &interfaces.Plug{PlugInfo: plugSnap.Plugs["modem-manager"]}

	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, plug, nil, s.slot, nil)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.modem-manager.mmcli"})
	snippet := apparmorSpec.SnippetForTag("snap.modem-manager.mmcli")
	c.Assert(snippet, Not(testutil.Contains), "peer=(label=unconfined),")
	c.Assert(snippet, testutil.Contains, "org/freedesktop/ModemManager1")
}

func (s *ModemManagerInterfaceSuite) TestConnectedPlugSnippetUsesUnconfinedLabelOnClassic(c *C) {
	release.OnClassic = true

	plugSnap := snaptest.MockInfo(c, modemmgrMockPlugSnapInfoYaml, nil)
	plug := &interfaces.Plug{PlugInfo: plugSnap.Plugs["modem-manager"]}
	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, plug, nil, s.slot, nil)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.modem-manager.mmcli"})
	c.Assert(apparmorSpec.SnippetForTag("snap.modem-manager.mmcli"), testutil.Contains, "peer=(label=unconfined),")
}

func (s *ModemManagerInterfaceSuite) TestUsedSecuritySystems(c *C) {
	plugSnap := snaptest.MockInfo(c, modemmgrMockPlugSnapInfoYaml, nil)
	plug := &interfaces.Plug{PlugInfo: plugSnap.Plugs["modem-manager"]}
	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, plug, nil, s.slot, nil)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), HasLen, 1)

	dbusSpec := &dbus.Specification{}
	err = dbusSpec.AddConnectedPlug(s.iface, plug, nil, s.slot, nil)
	c.Assert(err, IsNil)
	c.Assert(dbusSpec.SecurityTags(), HasLen, 1)

	dbusSpec = &dbus.Specification{}
	err = dbusSpec.AddPermanentSlot(s.iface, s.slot)
	c.Assert(err, IsNil)
	c.Assert(dbusSpec.SecurityTags(), HasLen, 1)

	udevSpec := &udev.Specification{}
	c.Assert(udevSpec.AddPermanentSlot(s.iface, s.slot), IsNil)
	c.Assert(udevSpec.Snippets(), HasLen, 1)
	c.Assert(udevSpec.Snippets()[0], testutil.Contains, `SUBSYSTEMS=="usb"`)
}

func (s *ModemManagerInterfaceSuite) TestPermanentSlotDBus(c *C) {
	dbusSpec := &dbus.Specification{}
	err := dbusSpec.AddPermanentSlot(s.iface, s.slot)
	c.Assert(err, IsNil)
	c.Assert(dbusSpec.SecurityTags(), DeepEquals, []string{"snap.modem-manager.mm"})
	snippet := dbusSpec.SnippetForTag("snap.modem-manager.mm")
	c.Assert(snippet, testutil.Contains, "allow own=\"org.freedesktop.ModemManager1\"")
	c.Assert(snippet, testutil.Contains, "allow send_destination=\"org.freedesktop.ModemManager1\"")
}

func (s *ModemManagerInterfaceSuite) TestPermanentSlotSecComp(c *C) {
	seccompSpec := &seccomp.Specification{}
	err := seccompSpec.AddPermanentSlot(s.iface, s.slot)
	c.Assert(err, IsNil)
	c.Assert(seccompSpec.SecurityTags(), DeepEquals, []string{"snap.modem-manager.mm"})
	c.Check(seccompSpec.SnippetForTag("snap.modem-manager.mm"), testutil.Contains, "listen\n")
}

func (s *ModemManagerInterfaceSuite) TestConnectedPlugDBus(c *C) {
	plugSnap := snaptest.MockInfo(c, modemmgrMockPlugSnapInfoYaml, nil)
	plug := &interfaces.Plug{PlugInfo: plugSnap.Plugs["modem-manager"]}

	dbusSpec := &dbus.Specification{}
	err := dbusSpec.AddConnectedPlug(s.iface, plug, nil, s.slot, nil)
	c.Assert(err, IsNil)
	c.Assert(dbusSpec.SecurityTags(), DeepEquals, []string{"snap.modem-manager.mmcli"})
	snippet := dbusSpec.SnippetForTag("snap.modem-manager.mmcli")
	c.Assert(snippet, testutil.Contains, "deny own=\"org.freedesktop.ModemManager1\"")
	c.Assert(snippet, testutil.Contains, "deny send_destination=\"org.freedesktop.ModemManager1\"")
}

func (s *ModemManagerInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
