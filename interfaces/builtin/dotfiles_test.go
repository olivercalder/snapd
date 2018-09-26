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

package builtin_test

import (
	"strings"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/testutil"
)

type dotfilesInterfaceSuite struct {
	iface    interfaces.Interface
	slot     *interfaces.ConnectedSlot
	slotInfo *snap.SlotInfo
	plug     *interfaces.ConnectedPlug
	plugInfo *snap.PlugInfo
}

var _ = Suite(&dotfilesInterfaceSuite{
	iface: builtin.MustInterface("dotfiles"),
})

func (s *dotfilesInterfaceSuite) SetUpTest(c *C) {
	const mockPlugSnapInfo = `name: other
version: 1.0
plugs:
 dotfiles:
  read: [$HOME/.read-dir1/, /etc/read-dir2, $HOME/.read-file2, /etc/read-file2]
  write:  [$HOME/.write-dir1/, /etc/write-dir2, $HOME/.write-file2, /etc/write-file2]
apps:
 app:
  command: foo
  plugs: [dotfiles]
`
	s.slotInfo = &snap.SlotInfo{
		Snap:      &snap.Info{SuggestedName: "core", Type: snap.TypeOS},
		Name:      "dotfiles",
		Interface: "dotfiles",
	}
	s.slot = interfaces.NewConnectedSlot(s.slotInfo, nil, nil)
	plugSnap := snaptest.MockInfo(c, mockPlugSnapInfo, nil)
	s.plugInfo = plugSnap.Plugs["dotfiles"]
	s.plug = interfaces.NewConnectedPlug(s.plugInfo, nil, nil)
}

func (s *dotfilesInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "dotfiles")
}

func (s *dotfilesInterfaceSuite) TestConnectedPlugAppArmor(c *C) {
	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.other.app"})
	c.Check(apparmorSpec.SnippetForTag("snap.other.app"), Equals, `
# Description: Can access specific files or directories.
# This is restricted because it gives file access to arbitrary locations.

/etc/read-dir2 rkl,
/etc/read-file2 rkl,
/etc/write-dir2 rwkl,
/etc/write-file2 rwkl,
owner @${HOME}/.read-dir1 rkl,
owner @${HOME}/.read-file2 rkl,
owner @${HOME}/.write-dir1 rwkl,
owner @${HOME}/.write-file2 rwkl,`)
}

func (s *dotfilesInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
	slot := &snap.SlotInfo{
		Snap:      &snap.Info{SuggestedName: "some-snap"},
		Name:      "dotfiles",
		Interface: "dotfiles",
	}
	c.Assert(interfaces.BeforePrepareSlot(s.iface, slot), ErrorMatches,
		"dotfiles slots are reserved for the core snap")
}

func (s *dotfilesInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *dotfilesInterfaceSuite) TestSanitizePlugHappy(c *C) {
	const mockSnapYaml = `name: dotfiles-plug-snap
version: 1.0
plugs:
 dotfiles:
  read: ["$HOME/.file1"]
  write: ["$HOME/.dir1/"]
`
	info := snaptest.MockInfo(c, mockSnapYaml, nil)
	plug := info.Plugs["dotfiles"]
	c.Assert(interfaces.BeforePreparePlug(s.iface, plug), IsNil)
}

func (s *dotfilesInterfaceSuite) TestSanitizePlugUnhappy(c *C) {
	const mockSnapYaml = `name: dotfiles-plug-snap
version: 1.0
plugs:
 dotfiles:
  $t
`
	errPrefix := `cannot add dotfiles plug: `
	var testCases = []struct {
		inp    string
		errStr string
	}{
		{`read: ""`, `"read" must be a list of strings`},
		{`read: [ 123 ]`, `"read" must be a list of strings`},
		{`read: [ "/foo/./bar" ]`, `"/foo/./bar" must be clean`},
		{`read: [ "../foo" ]`, `"../foo" must start with "/" or "\$HOME"`},
		{`read: [ "/foo[" ]`, `"/foo\[" contains a reserved apparmor char from .*`},
		{`write: ""`, `"write" must be a list of strings`},
		{`write: bar`, `"write" must be a list of strings`},
		{`read: [ "~/foo" ]`, `"~/foo" must start with "/" or "\$HOME"`},
	}

	for _, t := range testCases {
		yml := strings.Replace(mockSnapYaml, "$t", t.inp, -1)
		info := snaptest.MockInfo(c, yml, nil)
		plug := info.Plugs["dotfiles"]

		c.Check(interfaces.BeforePreparePlug(s.iface, plug), ErrorMatches, errPrefix+t.errStr, Commentf("unexpected error for %q", t.inp))
	}
}

func (s *dotfilesInterfaceSuite) TestConnectedPlugAppArmorInternalError(c *C) {
	const mockPlugSnapInfo = `name: other
version: 1.0
plugs:
 dotfiles:
  read: [ 123 , 345 ]
apps:
 app:
  command: foo
  plugs: [dotfiles]
`
	s.slotInfo = &snap.SlotInfo{
		Snap:      &snap.Info{SuggestedName: "core", Type: snap.TypeOS},
		Name:      "dotfiles",
		Interface: "dotfiles",
	}
	s.slot = interfaces.NewConnectedSlot(s.slotInfo, nil, nil)
	plugSnap := snaptest.MockInfo(c, mockPlugSnapInfo, nil)
	s.plugInfo = plugSnap.Plugs["dotfiles"]
	s.plug = interfaces.NewConnectedPlug(s.plugInfo, nil, nil)

	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot)
	c.Assert(err, ErrorMatches, `cannot connect plug dotfiles: 123 \(int64\) is not a string`)
}

func (s *dotfilesInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
