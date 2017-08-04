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
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type AvahiObserveInterfaceSuite struct {
	iface    interfaces.Interface
	plug     *interfaces.Plug
	appSlot  *interfaces.Slot
	coreSlot *interfaces.Slot
}

var _ = Suite(&AvahiObserveInterfaceSuite{
	iface: builtin.MustInterface("avahi-observe"),
})

const avahiObserveConsumerYaml = `name: consumer
apps:
 app:
  plugs: [avahi-observe]
`

const avahiObserveProducerYaml = `name: producer
apps:
 app:
  slots: [avahi-observe]
`

const avahiObserveCoreYaml = `name: core
slots:
  avahi-observe:
`

func (s *AvahiObserveInterfaceSuite) SetUpTest(c *C) {
	s.plug = MockPlug(c, avahiObserveConsumerYaml, nil, "avahi-observe")
	s.appSlot = MockSlot(c, avahiObserveProducerYaml, nil, "avahi-observe")
	s.coreSlot = MockSlot(c, avahiObserveCoreYaml, nil, "avahi-observe")
}

func (s *AvahiObserveInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "avahi-observe")
}

func (s *AvahiObserveInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(s.coreSlot.Sanitize(s.iface), IsNil)
	c.Assert(s.appSlot.Sanitize(s.iface), IsNil)
	// avahi-observe slot can now be used on snap other than core.
	slot := &interfaces.Slot{SlotInfo: &snap.SlotInfo{
		Snap:      &snap.Info{SuggestedName: "some-snap"},
		Name:      "avahi-observe",
		Interface: "avahi-observe",
	}}
	c.Assert(slot.Sanitize(s.iface), IsNil)
}

func (s *AvahiObserveInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(s.plug.Sanitize(s.iface), IsNil)
}

func (s *AvahiObserveInterfaceSuite) TestAppArmorSpec(c *C) {
	// on a core system with avahi slot coming from a regular app snap.
	restore := release.MockOnClassic(false)
	defer restore()

	// connected plug to app slot
	spec := &apparmor.Specification{}
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, nil, s.appSlot, nil), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "name=org.freedesktop.Avahi")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `peer=(label="snap.producer.app"),`)

	// connected app slot to plug
	spec = &apparmor.Specification{}
	c.Assert(spec.AddConnectedSlot(s.iface, s.plug, nil, s.appSlot, nil), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.producer.app"})
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `interface=org.freedesktop.Avahi`)
	c.Assert(spec.SnippetForTag("snap.producer.app"), testutil.Contains, `peer=(label="snap.consumer.app"),`)

	// on a classic system with avahi slot coming from the core snap.
	restore = release.MockOnClassic(true)
	defer restore()

	// connected plug to core slot
	spec = &apparmor.Specification{}
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, nil, s.coreSlot, nil), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "name=org.freedesktop.Avahi")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "peer=(label=unconfined),")

	// connected app slot to plug
	spec = &apparmor.Specification{}
	c.Assert(spec.AddConnectedSlot(s.iface, s.plug, nil, s.coreSlot, nil), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)
}

func (s *AvahiObserveInterfaceSuite) TestStaticInfo(c *C) {
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.ImplicitOnCore, Equals, false)
	c.Assert(si.ImplicitOnClassic, Equals, true)
	c.Assert(si.Summary, Equals, `allows discovering local domains, hostnames and services`)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "avahi-observe")
}

func (s *AvahiObserveInterfaceSuite) TestAutoConnect(c *C) {
	c.Assert(s.iface.AutoConnect(s.plug, s.coreSlot), Equals, true)
	c.Assert(s.iface.AutoConnect(s.plug, s.appSlot), Equals, true)
}

func (s *AvahiObserveInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
