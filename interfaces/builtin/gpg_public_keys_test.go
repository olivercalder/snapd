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
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type GpgPublicKeysInterfaceSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

var _ = Suite(&GpgPublicKeysInterfaceSuite{
	iface: builtin.MustInterface("gpg-public-keys"),
})

const gpgPublicKeysConsumerYaml = `name: consumer
apps:
 app:
   plugs: [gpg-public-keys]
   `

const gpgPublicKeysCoreYaml = `name: core
type: os
slots:
  gpg-public-keys:
`

func (s *GpgPublicKeysInterfaceSuite) SetUpTest(c *C) {
	s.plug, s.plugInfo = MockConnectedPlug(c, gpgPublicKeysConsumerYaml, nil, "gpg-public-keys")
	s.slot, s.slotInfo = MockConnectedSlot(c, gpgPublicKeysCoreYaml, nil, "gpg-public-keys")
}

func (s *GpgPublicKeysInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "gpg-public-keys")
}

func (s *GpgPublicKeysInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.SanitizeSlot(s.iface, s.slotInfo), IsNil)
	slotInfo := &snap.SlotInfo{
		Snap:      &snap.Info{SuggestedName: "some-snap"},
		Name:      "gpg-public-keys",
		Interface: "gpg-public-keys",
	}
	c.Assert(interfaces.SanitizeSlot(s.iface, slotInfo), ErrorMatches,
		"gpg-public-keys slots are reserved for the core snap")
}

func (s *GpgPublicKeysInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.SanitizePlug(s.iface, s.plugInfo), IsNil)
}

func (s *GpgPublicKeysInterfaceSuite) TestAppArmorSpec(c *C) {
	spec := &apparmor.Specification{}
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, `owner @{HOME}/.gnupg/gpg.conf r,`)
}

func (s *GpgPublicKeysInterfaceSuite) TestStaticInfo(c *C) {
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.ImplicitOnCore, Equals, true)
	c.Assert(si.ImplicitOnClassic, Equals, true)
	c.Assert(si.Summary, Equals, `allows reading gpg public keys and non-sensitive configuration`)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "gpg-public-keys")
}

func (s *GpgPublicKeysInterfaceSuite) TestAutoConnect(c *C) {
	// FIXME: fix AutoConnect
	c.Assert(s.iface.AutoConnect(&interfaces.Plug{PlugInfo: s.plugInfo}, &interfaces.Slot{SlotInfo: s.slotInfo}), Equals, true)
}

func (s *GpgPublicKeysInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
