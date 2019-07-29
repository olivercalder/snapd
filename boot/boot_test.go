// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2019 Canonical Ltd
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

package boot_test

import (
	"errors"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/boot/boottest"
	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

// set up gocheck
func TestBoot(t *testing.T) { TestingT(t) }

// baseBootSuite is used to setup the common test environment
type baseBootSetSuite struct {
	testutil.BaseTest

	bootdir string
}

func (s *baseBootSetSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	dirs.SetRootDir(c.MkDir())
	s.AddCleanup(func() { dirs.SetRootDir("") })
	restore := snap.MockSanitizePlugsSlots(func(snapInfo *snap.Info) {})
	s.AddCleanup(restore)

	s.bootdir = filepath.Join(dirs.GlobalRootDir, "boot")
}

// bootSetSuite tests the abstract BootSet interface, and tools that
// don't depend on a specific BootSet implementation
type bootSetSuite struct {
	baseBootSetSuite

	loader *boottest.MockBootloader
}

var _ = Suite(&bootSetSuite{})

func (s *bootSetSuite) SetUpTest(c *C) {
	s.baseBootSetSuite.SetUpTest(c)

	s.loader = boottest.NewMockBootloader("mock", c.MkDir())
	bootloader.Force(s.loader)
	s.AddCleanup(func() { bootloader.Force(nil) })
}

func (s *bootSetSuite) TestNameAndRevnoFromSnapValid(c *C) {
	info, err := boot.NameAndRevnoFromSnap("foo_2.snap")
	c.Assert(err, IsNil)
	c.Assert(info.Name, Equals, "foo")
	c.Assert(info.Revision, Equals, snap.R(2))
}

func (s *bootSetSuite) TestNameAndRevnoFromSnapInvalidFormat(c *C) {
	_, err := boot.NameAndRevnoFromSnap("invalid")
	c.Assert(err, ErrorMatches, `input "invalid" has invalid format \(not enough '_'\)`)
	_, err = boot.NameAndRevnoFromSnap("invalid_xxx.snap")
	c.Assert(err, ErrorMatches, `invalid snap revision: "xxx"`)
}

func BenchmarkNameAndRevno(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for _, sn := range []string{
			"core_21.snap",
			"kernel_41.snap",
			"some-long-kernel-name-kernel_82.snap",
			"what-is-this-core_111.snap",
		} {
			boot.NameAndRevnoFromSnap(sn)
		}
	}
}

func (s *bootSetSuite) TestInUse(c *C) {
	for _, t := range []struct {
		bootVarKey   string
		bootVarValue string

		snapName string
		snapRev  snap.Revision

		inUse bool
	}{
		// in use
		{"snap_kernel", "kernel_41.snap", "kernel", snap.R(41), true},
		{"snap_try_kernel", "kernel_82.snap", "kernel", snap.R(82), true},
		{"snap_core", "core_21.snap", "core", snap.R(21), true},
		{"snap_try_core", "core_42.snap", "core", snap.R(42), true},
		// not in use
		{"snap_core", "core_111.snap", "core", snap.R(21), false},
		{"snap_try_core", "core_111.snap", "core", snap.R(21), false},
		{"snap_kernel", "kernel_111.snap", "kernel", snap.R(1), false},
		{"snap_try_kernel", "kernel_111.snap", "kernel", snap.R(1), false},
	} {
		s.loader.BootVars[t.bootVarKey] = t.bootVarValue
		c.Assert(boot.InUse(t.snapName, t.snapRev), Equals, t.inUse, Commentf("unexpected result: %s %s %v", t.snapName, t.snapRev, t.inUse))
	}
}

func (s *bootSetSuite) TestInUseUnhapy(c *C) {
	logbuf, restore := logger.MockLogger()
	defer restore()
	s.loader.BootVars["snap_kernel"] = "kernel_41.snap"

	// sanity check
	c.Check(boot.InUse("kernel", snap.R(41)), Equals, true)

	// make GetVars fail
	s.loader.GetErr = errors.New("zap")
	c.Check(boot.InUse("kernel", snap.R(41)), Equals, false)
	c.Check(logbuf.String(), testutil.Contains, "cannot get boot vars: zap")
	s.loader.GetErr = nil

	// make bootloader.Find fail
	bootloader.ForceError(errors.New("broken bootloader"))
	c.Check(boot.InUse("kernel", snap.R(41)), Equals, false)
	c.Check(logbuf.String(), testutil.Contains, "cannot get boot settings: broken bootloader")
}

func (s *bootSetSuite) TestCurrentBootNameAndRevision(c *C) {
	s.loader.BootVars["snap_core"] = "core_2.snap"
	s.loader.BootVars["snap_kernel"] = "canonical-pc-linux_2.snap"

	current, err := boot.GetCurrentBoot(snap.TypeOS)
	c.Check(err, IsNil)
	c.Check(current.Name, Equals, "core")
	c.Check(current.Revision, Equals, snap.R(2))

	current, err = boot.GetCurrentBoot(snap.TypeKernel)
	c.Check(err, IsNil)
	c.Check(current.Name, Equals, "canonical-pc-linux")
	c.Check(current.Revision, Equals, snap.R(2))

	s.loader.BootVars["snap_mode"] = "trying"
	_, err = boot.GetCurrentBoot(snap.TypeKernel)
	c.Check(err, Equals, boot.ErrBootNameAndRevisionAgain)
}

func (s *bootSetSuite) TestCurrentBootNameAndRevisionUnhappy(c *C) {
	_, err := boot.GetCurrentBoot(snap.TypeKernel)
	c.Check(err, ErrorMatches, "cannot get name and revision of boot kernel: unset")

	_, err = boot.GetCurrentBoot(snap.TypeOS)
	c.Check(err, ErrorMatches, "cannot get name and revision of boot snap: unset")

	_, err = boot.GetCurrentBoot(snap.TypeBase)
	c.Check(err, ErrorMatches, "cannot get name and revision of boot snap: unset")

	_, err = boot.GetCurrentBoot(snap.TypeApp)
	c.Check(err, ErrorMatches, "internal error: cannot find boot revision for snap type \"app\"")

	// sanity check
	s.loader.BootVars["snap_kernel"] = "kernel_41.snap"
	current, err := boot.GetCurrentBoot(snap.TypeKernel)
	c.Check(err, IsNil)
	c.Check(current.Name, Equals, "kernel")
	c.Check(current.Revision, Equals, snap.R(41))

	// make GetVars fail
	s.loader.GetErr = errors.New("zap")
	_, err = boot.GetCurrentBoot(snap.TypeKernel)
	c.Check(err, ErrorMatches, "cannot get boot variables: zap")
	s.loader.GetErr = nil

	// make bootloader.Find fail
	bootloader.ForceError(errors.New("broken bootloader"))
	_, err = boot.GetCurrentBoot(snap.TypeKernel)
	c.Check(err, ErrorMatches, "cannot get boot settings: broken bootloader")
}

func (s *bootSetSuite) TestLookup(c *C) {
	info := &snap.Info{}
	info.RealName = "some-snap"

	_, err := boot.Lookup(info, snap.TypeApp, true)
	c.Check(err, ErrorMatches, `cannot lookup boot set with snap "some-snap" of type "app"`)

	for _, typ := range []snap.Type{
		snap.TypeKernel,
		snap.TypeOS,
		// snap.TypeGadget, XXX: why not gadget?
		snap.TypeBase,
		snap.TypeSnapd,
	} {
		bs, err := boot.Lookup(info, typ, true)
		c.Check(err, IsNil)
		c.Check(bs, DeepEquals, boot.NewClassicBootSet())

		bs, err = boot.Lookup(info, typ, false)
		c.Check(err, IsNil)
		c.Check(bs, DeepEquals, boot.NewCoreBootSet(info, typ))
	}
}

// these are tests for the concrete classic boot set, but not worth
// having their own suite:
func (s *bootSetSuite) TestClassic(c *C) {
	defer release.MockOnClassic(true)()

	bs := boot.NewClassicBootSet()

	c.Check(bs.RemoveKernelAssets(), ErrorMatches, "cannot remove kernel assets on classic systems")
	c.Check(bs.ExtractKernelAssets(nil), ErrorMatches, "cannot extract kernel assets on classic systems")
	c.Check(bs.ChangeRequiresReboot(), Equals, false)
	// SetNextBoot should do nothing on classic LP: #1580403 (yay trivial regression test)
	c.Check(bs.SetNextBoot(), ErrorMatches, "cannot set next boot on classic systems")
}
