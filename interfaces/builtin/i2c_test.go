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
	"github.com/snapcore/snapd/interfaces/udev"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/testutil"
)

type I2cInterfaceSuite struct {
	testutil.BaseTest
	iface interfaces.Interface

	// OS Snap
	testSlot1     *interfaces.ConnectedSlot
	testSlot1Info *snap.SlotInfo

	// Gadget Snap
	testUDev1                 *interfaces.ConnectedSlot
	testUDev1Info             *snap.SlotInfo
	testUDev2                 *interfaces.ConnectedSlot
	testUDev2Info             *snap.SlotInfo
	testUDev3                 *interfaces.ConnectedSlot
	testUDev3Info             *snap.SlotInfo
	testUDevBadValue1         *interfaces.ConnectedSlot
	testUDevBadValue1Info     *snap.SlotInfo
	testUDevBadValue2         *interfaces.ConnectedSlot
	testUDevBadValue2Info     *snap.SlotInfo
	testUDevBadValue3         *interfaces.ConnectedSlot
	testUDevBadValue3Info     *snap.SlotInfo
	testUDevBadValue4         *interfaces.ConnectedSlot
	testUDevBadValue4Info     *snap.SlotInfo
	testUDevBadValue5         *interfaces.ConnectedSlot
	testUDevBadValue5Info     *snap.SlotInfo
	testUDevBadValue6         *interfaces.ConnectedSlot
	testUDevBadValue6Info     *snap.SlotInfo
	testUDevBadValue7         *interfaces.ConnectedSlot
	testUDevBadValue7Info     *snap.SlotInfo
	testUDevBadInterface1     *interfaces.ConnectedSlot
	testUDevBadInterface1Info *snap.SlotInfo

	// Consuming Snap
	testPlugPort1     *interfaces.ConnectedPlug
	testPlugPort1Info *snap.PlugInfo
}

var _ = Suite(&I2cInterfaceSuite{
	iface: builtin.MustInterface("i2c"),
})

func (s *I2cInterfaceSuite) SetUpTest(c *C) {
	// Mock for OS Snap
	osSnapInfo := snaptest.MockInfo(c, `
name: ubuntu-core
type: os
slots:
  test-port-1:
    interface: i2c
    path: /dev/i2c-0
`, nil)
	s.testSlot1Info = osSnapInfo.Slots["test-port-1"]

	// Mock for Gadget Snap
	gadgetSnapInfo := snaptest.MockInfo(c, `
name: some-device
type: gadget
slots:
  test-udev-1:
    interface: i2c
    path: /dev/i2c-1
  test-udev-2:
    interface: i2c
    path: /dev/i2c-11
  test-udev-3:
    interface: i2c
    path: /dev/i2c-0
  test-udev-bad-value-1:
    interface: i2c
    path: /dev/i2c
  test-udev-bad-value-2:
    interface: i2c
    path: /dev/i2c-a
  test-udev-bad-value-3:
    interface: i2c
    path: /dev/i2c-2a
  test-udev-bad-value-4:
    interface: i2c
    path: /dev/foo-0
  test-udev-bad-value-5:
    interface: i2c
    path: /dev/i2c-foo
  test-udev-bad-value-6:
    interface: i2c
    path: ""
  test-udev-bad-value-7:
    interface: i2c
  test-udev-bad-interface-1:
    interface: other-interface
`, nil)
	s.testUDev1Info = gadgetSnapInfo.Slots["test-udev-1"]
	s.testUDev1 = interfaces.NewConnectedSlot(s.testUDev1Info, nil)
	s.testUDev2Info = gadgetSnapInfo.Slots["test-udev-2"]
	s.testUDev2 = interfaces.NewConnectedSlot(s.testUDev2Info, nil)
	s.testUDev3Info = gadgetSnapInfo.Slots["test-udev-3"]
	s.testUDev3 = interfaces.NewConnectedSlot(s.testUDev3Info, nil)
	s.testUDevBadValue1Info = gadgetSnapInfo.Slots["test-udev-bad-value-1"]
	s.testUDevBadValue1 = interfaces.NewConnectedSlot(s.testUDevBadValue1Info, nil)
	s.testUDevBadValue2Info = gadgetSnapInfo.Slots["test-udev-bad-value-2"]
	s.testUDevBadValue2 = interfaces.NewConnectedSlot(s.testUDevBadValue2Info, nil)
	s.testUDevBadValue3Info = gadgetSnapInfo.Slots["test-udev-bad-value-3"]
	s.testUDevBadValue3 = interfaces.NewConnectedSlot(s.testUDevBadValue3Info, nil)
	s.testUDevBadValue4Info = gadgetSnapInfo.Slots["test-udev-bad-value-4"]
	s.testUDevBadValue4 = interfaces.NewConnectedSlot(s.testUDevBadValue4Info, nil)
	s.testUDevBadValue5Info = gadgetSnapInfo.Slots["test-udev-bad-value-5"]
	s.testUDevBadValue5 = interfaces.NewConnectedSlot(s.testUDevBadValue5Info, nil)
	s.testUDevBadValue6Info = gadgetSnapInfo.Slots["test-udev-bad-value-6"]
	s.testUDevBadValue6 = interfaces.NewConnectedSlot(s.testUDevBadValue6Info, nil)
	s.testUDevBadValue7Info = gadgetSnapInfo.Slots["test-udev-bad-value-7"]
	s.testUDevBadValue7 = interfaces.NewConnectedSlot(s.testUDevBadValue7Info, nil)
	s.testUDevBadInterface1Info = gadgetSnapInfo.Slots["test-udev-bad-interface-1"]

	// Snap Consumers
	consumingSnapInfo := snaptest.MockInfo(c, `
name: client-snap
plugs:
  plug-for-port-1:
    interface: i2c
apps:
  app-accessing-1-port:
    command: foo
    plugs: [i2c]
`, nil)
	s.testPlugPort1Info = consumingSnapInfo.Plugs["plug-for-port-1"]
	s.testPlugPort1 = interfaces.NewConnectedPlug(s.testPlugPort1Info, nil)
}

func (s *I2cInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "i2c")
}

func (s *I2cInterfaceSuite) TestSanitizeCoreSnapSlot(c *C) {
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testSlot1Info), IsNil)
}

func (s *I2cInterfaceSuite) TestSanitizeGadgetSnapSlot(c *C) {
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDev1Info), IsNil)
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDev2Info), IsNil)
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDev3Info), IsNil)
}

func (s *I2cInterfaceSuite) TestSanitizeBadGadgetSnapSlot(c *C) {
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDevBadValue1Info), ErrorMatches, "i2c path attribute must be a valid device node")
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDevBadValue2Info), ErrorMatches, "i2c path attribute must be a valid device node")
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDevBadValue3Info), ErrorMatches, "i2c path attribute must be a valid device node")
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDevBadValue4Info), ErrorMatches, "i2c path attribute must be a valid device node")
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDevBadValue5Info), ErrorMatches, "i2c path attribute must be a valid device node")
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDevBadValue6Info), ErrorMatches, "i2c slot must have a path attribute")
	c.Assert(interfaces.SanitizeSlot(s.iface, s.testUDevBadValue7Info), ErrorMatches, "i2c slot must have a path attribute")
}

func (s *I2cInterfaceSuite) TestUDevSpec(c *C) {
	spec := &udev.Specification{}
	c.Assert(spec.AddConnectedPlug(s.iface, s.testPlugPort1, s.testUDev1), IsNil)
	c.Assert(spec.Snippets(), HasLen, 1)
	c.Assert(spec.Snippets(), testutil.Contains, `# i2c
KERNEL=="i2c-1", TAG+="snap_client-snap_app-accessing-1-port"`)
}

func (s *I2cInterfaceSuite) TestAppArmorSpec(c *C) {
	spec := &apparmor.Specification{}
	c.Assert(spec.AddConnectedPlug(s.iface, s.testPlugPort1, s.testUDev1), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.client-snap.app-accessing-1-port"})
	c.Assert(spec.SnippetForTag("snap.client-snap.app-accessing-1-port"), testutil.Contains, `/dev/i2c-1 rw,`)
	c.Assert(spec.SnippetForTag("snap.client-snap.app-accessing-1-port"), testutil.Contains, `/sys/devices/platform/{*,**.i2c}/i2c-1/** rw,`)
}

func (s *I2cInterfaceSuite) TestAutoConnect(c *C) {
	c.Check(s.iface.AutoConnect(nil, nil), Equals, true)
}

func (s *I2cInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
