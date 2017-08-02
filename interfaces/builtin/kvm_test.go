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

type kvmInterfaceSuite struct {
	iface interfaces.Interface
	slot  *interfaces.Slot
	plug  *interfaces.Plug
}

var _ = Suite(&kvmInterfaceSuite{
	iface: builtin.MustInterface("kvm"),
})

func (s *kvmInterfaceSuite) SetUpTest(c *C) {
	// Mock for OS Snap
	osSnapInfo := snaptest.MockInfo(c, `
name: ubuntu-core
type: os
slots:
  test-kvm:
    interface: kvm
`, nil)
	s.slot = &interfaces.Slot{SlotInfo: osSnapInfo.Slots["test-kvm"]}

	// Snap Consumers
	consumingSnapInfo := snaptest.MockInfo(c, `
name: client-snap
apps:
  app-accessing-kvm:
    command: foo
    plugs: [kvm]
`, nil)
	s.plug = &interfaces.Plug{PlugInfo: consumingSnapInfo.Plugs["kvm"]}
}

func (s *kvmInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "kvm")
}

func (s *kvmInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(s.slot.Sanitize(s.iface), IsNil)
	slot := &interfaces.Slot{SlotInfo: &snap.SlotInfo{
		Snap:      &snap.Info{SuggestedName: "some-snap"},
		Name:      "kvm",
		Interface: "kvm",
	}}
	c.Assert(slot.Sanitize(s.iface), ErrorMatches,
		"kvm slots only allowed on core snap")
}

func (s *kvmInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(s.plug.Sanitize(s.iface), IsNil)
}

func (s *kvmInterfaceSuite) TestUsedSecuritySystems(c *C) {
	expectedSnippet1 := `
# Description: Allow write access to kvm.
# See 'man kvm' for details.

/dev/kvm rw,
`
	expectedSnippet3 := `KERNEL=="kvm", TAG+="snap_client-snap_app-accessing-kvm"`
	// connected plugs have a non-nil security snippet for apparmor
	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, s.plug, nil, s.slot, nil)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.client-snap.app-accessing-kvm"})
	aasnippet := apparmorSpec.SnippetForTag("snap.client-snap.app-accessing-kvm")
	c.Assert(aasnippet, Equals, expectedSnippet1, Commentf("\nexpected:\n%s\nfound:\n%s", expectedSnippet1, aasnippet))

	udevSpec := &udev.Specification{}
	c.Assert(udevSpec.AddConnectedPlug(s.iface, s.plug, nil, s.slot, nil), IsNil)
	c.Assert(udevSpec.Snippets(), HasLen, 1)
	snippet := udevSpec.Snippets()[0]
	c.Assert(snippet, Equals, expectedSnippet3)
}

func (s *kvmInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
