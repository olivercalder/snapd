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
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/snap"
)

type PulseAudioInterfaceSuite struct {
	iface interfaces.Interface
	slot  *interfaces.Slot
	plug  *interfaces.Plug
}

var _ = Suite(&PulseAudioInterfaceSuite{
	iface: &builtin.PulseAudioInterface{},
	slot: &interfaces.Slot{
		SlotInfo: &snap.SlotInfo{
			Snap:      &snap.Info{SuggestedName: "pulseaudio"},
			Name:      "pulseaudio",
			Interface: "pulseaudio",
		},
	},
	plug: &interfaces.Plug{
		PlugInfo: &snap.PlugInfo{
			Snap:      &snap.Info{SuggestedName: "other"},
			Name:      "pulseaudio",
			Interface: "pulseaudio",
		},
	},
})

func (s *PulseAudioInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "pulseaudio")
}

func (s *PulseAudioInterfaceSuite) TestSanitizeSlot(c *C) {
	err := s.iface.SanitizeSlot(s.slot)
	c.Assert(err, IsNil)
}

func (s *PulseAudioInterfaceSuite) TestSanitizePlug(c *C) {
	err := s.iface.SanitizePlug(s.plug)
	c.Assert(err, IsNil)
}

func (s *PulseAudioInterfaceSuite) TestUnusedSecuritySystems(c *C) {
	systems := [...]interfaces.SecuritySystem{interfaces.SecurityAppArmor,
		interfaces.SecuritySecComp, interfaces.SecurityDBus,
		interfaces.SecurityUDev}
	for _, system := range systems {
		snippet, err := s.iface.PermanentPlugSnippet(s.plug, system)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
		snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.slot, system)
		c.Assert(err, IsNil)
		c.Assert(snippet, IsNil)
	}
	snippet, err := s.iface.ConnectedPlugSnippet(s.plug, s.slot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	snippet, err = s.iface.PermanentSlotSnippet(s.slot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	snippet, err = s.iface.ConnectedPlugSnippet(s.plug, s.slot, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
	snippet, err = s.iface.ConnectedPlugSnippet(s.plug, s.slot, interfaces.SecurityMount)
	c.Assert(err, IsNil)
	c.Assert(snippet, IsNil)
}

func (s *PulseAudioInterfaceSuite) TestUnexpectedSecuritySystems(c *C) {
	snippet, err := s.iface.PermanentPlugSnippet(s.plug, "foo")
	c.Assert(err, Equals, interfaces.ErrUnknownSecurity)
	c.Assert(snippet, IsNil)
	snippet, err = s.iface.ConnectedPlugSnippet(s.plug, s.slot, "foo")
	c.Assert(err, Equals, interfaces.ErrUnknownSecurity)
	c.Assert(snippet, IsNil)
	snippet, err = s.iface.PermanentSlotSnippet(s.slot, "foo")
	c.Assert(err, Equals, interfaces.ErrUnknownSecurity)
	c.Assert(snippet, IsNil)
	snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.slot, "foo")
	c.Assert(err, Equals, interfaces.ErrUnknownSecurity)
	c.Assert(snippet, IsNil)

	snippet, err = s.iface.PermanentSlotSnippet(s.slot, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	snippet, err = s.iface.PermanentSlotSnippet(s.slot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	snippet, err = s.iface.PermanentSlotSnippet(s.slot, interfaces.SecurityMount)
	c.Assert(err, IsNil)
	snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.slot, interfaces.SecurityDBus)
	c.Assert(err, IsNil)
	snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.slot, interfaces.SecurityAppArmor)
	c.Assert(err, IsNil)
	snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.slot, interfaces.SecuritySecComp)
	c.Assert(err, IsNil)
	snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.slot, interfaces.SecurityUDev)
	c.Assert(err, IsNil)
	snippet, err = s.iface.ConnectedSlotSnippet(s.plug, s.slot, interfaces.SecurityMount)
	c.Assert(err, IsNil)
}
