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

package udev_test

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/ifacetest"
	"github.com/snapcore/snapd/interfaces/udev"
	"github.com/snapcore/snapd/snap/snaptest"
)

type specSuite struct {
	iface *ifacetest.TestInterface
	spec  *udev.Specification
	plug  *interfaces.Plug
	slot  *interfaces.Slot
}

var _ = Suite(&specSuite{
	iface: &ifacetest.TestInterface{
		InterfaceName: "test",
		UDevConnectedPlugCallback: func(spec *udev.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
			spec.AddSnippet("connected-plug")
			return nil
		},
		UDevConnectedSlotCallback: func(spec *udev.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
			spec.AddSnippet("connected-slot")
			return nil
		},
		UDevPermanentPlugCallback: func(spec *udev.Specification, plug *interfaces.Plug) error {
			spec.AddSnippet("permanent-plug")
			return nil
		},
		UDevPermanentSlotCallback: func(spec *udev.Specification, slot *interfaces.Slot) error {
			spec.AddSnippet("permanent-slot")
			return nil
		},
	},
})

func (s *specSuite) SetUpSuite(c *C) {
	info1 := snaptest.MockInfo(c, `name: snap1
plugs:
    name:
        interface: test
apps:
    foo:
        command: bin/foo
hooks:
    configure:
`, nil)
	info2 := snaptest.MockInfo(c, `name: snap2
slots:
    name:
        interface: test
`, nil)
	s.plug = &interfaces.Plug{PlugInfo: info1.Plugs["name"]}
	s.slot = &interfaces.Slot{SlotInfo: info2.Slots["name"]}
}

func (s *specSuite) SetUpTest(c *C) {
	s.spec = &udev.Specification{}
}

func (s *specSuite) TestAddSnippte(c *C) {
	s.spec.AddSnippet("foo")
	c.Assert(s.spec.Snippets(), DeepEquals, []string{"foo"})
}

func (s *specSuite) TestTagDevice(c *C) {
	// TagDevice acts in the scope of the plug/slot (as appropriate) and
	// affects all of the apps and hooks related to the given plug or slot
	// (with the exception that slots cannot have hooks).
	iface := &ifacetest.TestInterface{
		InterfaceName: "iface-1",
		UDevConnectedPlugCallback: func(spec *udev.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
			spec.TagDevice(`kernel="voodoo"`)
			return nil
		},
	}
	c.Assert(s.spec.AddConnectedPlug(iface, s.plug, nil, s.slot, nil), IsNil)

	iface = &ifacetest.TestInterface{
		InterfaceName: "iface-2",
		UDevConnectedPlugCallback: func(spec *udev.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
			spec.TagDevice(`kernel="hoodoo"`)
			return nil
		},
	}
	c.Assert(s.spec.AddConnectedPlug(iface, s.plug, nil, s.slot, nil), IsNil)

	c.Assert(s.spec.Snippets(), DeepEquals, []string{
		`# iface-1
kernel="voodoo", TAG+="snap_snap1_foo"`,
		`# iface-2
kernel="hoodoo", TAG+="snap_snap1_foo"`,
		`# iface-1
kernel="voodoo", TAG+="snap_snap1_hook_configure"`,
		`# iface-2
kernel="hoodoo", TAG+="snap_snap1_hook_configure"`,
	})
}

// The spec.Specification can be used through the interfaces.Specification interface
func (s *specSuite) TestSpecificationIface(c *C) {
	var r interfaces.Specification = s.spec
	c.Assert(r.AddConnectedPlug(s.iface, s.plug, nil, s.slot, nil), IsNil)
	c.Assert(r.AddConnectedSlot(s.iface, s.plug, nil, s.slot, nil), IsNil)
	c.Assert(r.AddPermanentPlug(s.iface, s.plug), IsNil)
	c.Assert(r.AddPermanentSlot(s.iface, s.slot), IsNil)
	c.Assert(s.spec.Snippets(), DeepEquals, []string{"connected-plug", "connected-slot", "permanent-plug", "permanent-slot"})
}
