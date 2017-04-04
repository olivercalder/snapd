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

package kmod_test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/snapcore/snapd/testutil"
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/ifacetest"
	"github.com/snapcore/snapd/interfaces/kmod"
	"github.com/snapcore/snapd/osutil"
)

func Test(t *testing.T) {
	TestingT(t)
}

type backendSuite struct {
	ifacetest.BackendSuite
	modprobeCmd *testutil.MockCmd
}

var _ = Suite(&backendSuite{})

var testedConfinementOpts = []interfaces.ConfinementOptions{
	{},
	{DevMode: true},
	{JailMode: true},
	{Classic: true},
}

func (s *backendSuite) SetUpTest(c *C) {
	s.Backend = &kmod.Backend{}
	s.BackendSuite.SetUpTest(c)
	c.Assert(s.Repo.AddBackend(s.Backend), IsNil)
	s.modprobeCmd = testutil.MockCommand(c, "modprobe", "")
}

func (s *backendSuite) TearDownTest(c *C) {
	s.modprobeCmd.Restore()
	s.BackendSuite.TearDownTest(c)
}

func (s *backendSuite) TestName(c *C) {
	c.Check(s.Backend.Name(), Equals, interfaces.SecurityKMod)
}

func (s *backendSuite) TestInstallingSnapCreatesModulesConf(c *C) {
	// NOTE: Hand out a permanent snippet so that .conf file is generated.
	s.Iface.KModPermanentSlotCallback = func(spec *kmod.Specification, slot *interfaces.Slot) error {
		spec.AddModule("module1")
		spec.AddModule("module2")
		return nil
	}

	path := filepath.Join(dirs.SnapKModModulesDir, "snap.samba.conf")
	c.Assert(osutil.FileExists(path), Equals, false)

	for _, opts := range testedConfinementOpts {
		s.modprobeCmd.ForgetCalls()
		snapInfo := s.InstallSnap(c, opts, ifacetest.SambaYamlV1, 0)

		c.Assert(osutil.FileExists(path), Equals, true)
		modfile, err := ioutil.ReadFile(path)
		c.Assert(err, IsNil)
		c.Assert(string(modfile), Equals, "# This file is automatically generated.\nmodule1\nmodule2\n")

		c.Assert(s.modprobeCmd.Calls(), DeepEquals, [][]string{
			{"modprobe", "--syslog", "module1"},
			{"modprobe", "--syslog", "module2"},
		})
		s.RemoveSnap(c, snapInfo)
	}
}

func (s *backendSuite) TestRemovingSnapRemovesModulesConf(c *C) {
	// NOTE: Hand out a permanent snippet so that .conf file is generated.
	s.Iface.KModPermanentSlotCallback = func(spec *kmod.Specification, slot *interfaces.Slot) error {
		spec.AddModule("module1")
		spec.AddModule("module2")
		return nil
	}

	path := filepath.Join(dirs.SnapKModModulesDir, "snap.samba.conf")
	c.Assert(osutil.FileExists(path), Equals, false)

	for _, opts := range testedConfinementOpts {
		snapInfo := s.InstallSnap(c, opts, ifacetest.SambaYamlV1, 0)
		c.Assert(osutil.FileExists(path), Equals, true)
		s.RemoveSnap(c, snapInfo)
		c.Assert(osutil.FileExists(path), Equals, false)
	}
}

func (s *backendSuite) TestSecurityIsStable(c *C) {
	// NOTE: Hand out a permanent snippet so that .conf file is generated.
	s.Iface.KModPermanentSlotCallback = func(spec *kmod.Specification, slot *interfaces.Slot) error {
		spec.AddModule("module1")
		spec.AddModule("module2")
		return nil
	}

	for _, opts := range testedConfinementOpts {
		snapInfo := s.InstallSnap(c, opts, ifacetest.SambaYamlV1, 0)
		s.modprobeCmd.ForgetCalls()
		err := s.Backend.Setup(snapInfo, opts, s.Repo)
		c.Assert(err, IsNil)
		// modules conf is not re-loaded when nothing changes
		c.Check(s.modprobeCmd.Calls(), HasLen, 0)
		s.RemoveSnap(c, snapInfo)
	}
}
