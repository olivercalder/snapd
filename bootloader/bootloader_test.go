// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2015 Canonical Ltd
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

package bootloader

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/boot/boottest"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"
)

// Hook up check.v1 into the "go test" runner
func Test(t *testing.T) { TestingT(t) }

// partition specific testsuite
type PartitionTestSuite struct{}

var _ = Suite(&PartitionTestSuite{})

func (s *PartitionTestSuite) SetUpTest(c *C) {
	dirs.SetRootDir(c.MkDir())
	err := os.MkdirAll((&grub{}).Dir(), 0755)
	c.Assert(err, IsNil)
	err = os.MkdirAll((&uboot{}).Dir(), 0755)
	c.Assert(err, IsNil)
}

func (s *PartitionTestSuite) TestForceBootloader(c *C) {
	b := boottest.NewMockBootloader("mocky", c.MkDir())
	Force(b)
	defer Force(nil)

	got, err := Find()
	c.Assert(err, IsNil)
	c.Check(got, Equals, b)
}

func (s *PartitionTestSuite) TestMarkBootSuccessfulAllSnap(c *C) {
	b := boottest.NewMockBootloader("mocky", c.MkDir())
	b.BootVars["snap_mode"] = "trying"
	b.BootVars["snap_try_core"] = "os1"
	b.BootVars["snap_try_kernel"] = "k1"
	err := MarkBootSuccessful(b)
	c.Assert(err, IsNil)

	expected := map[string]string{
		// cleared
		"snap_mode":       "",
		"snap_try_kernel": "",
		"snap_try_core":   "",
		// updated
		"snap_kernel": "k1",
		"snap_core":   "os1",
	}
	c.Assert(b.BootVars, DeepEquals, expected)

	// do it again, verify its still valid
	err = MarkBootSuccessful(b)
	c.Assert(err, IsNil)
	c.Assert(b.BootVars, DeepEquals, expected)
}

func (s *PartitionTestSuite) TestMarkBootSuccessfulKKernelUpdate(c *C) {
	b := boottest.NewMockBootloader("mocky", c.MkDir())
	b.BootVars["snap_mode"] = "trying"
	b.BootVars["snap_core"] = "os1"
	b.BootVars["snap_kernel"] = "k1"
	b.BootVars["snap_try_core"] = ""
	b.BootVars["snap_try_kernel"] = "k2"
	err := MarkBootSuccessful(b)
	c.Assert(err, IsNil)
	c.Assert(b.BootVars, DeepEquals, map[string]string{
		// cleared
		"snap_mode":       "",
		"snap_try_kernel": "",
		"snap_try_core":   "",
		// unchanged
		"snap_core": "os1",
		// updated
		"snap_kernel": "k2",
	})
}

func (s *PartitionTestSuite) TestInstallBootloaderConfigNoConfig(c *C) {
	err := InstallBootConfig(c.MkDir())
	c.Assert(err, ErrorMatches, `cannot find boot config in.*`)
}

func (s *PartitionTestSuite) TestInstallBootloaderConfig(c *C) {
	for _, t := range []struct{ gadgetFile, systemFile string }{
		{"grub.conf", "/boot/grub/grub.cfg"},
		{"uboot.conf", "/boot/uboot/uboot.env"},
		{"androidboot.conf", "/boot/androidboot/androidboot.env"},
	} {
		mockGadgetDir := c.MkDir()
		err := ioutil.WriteFile(filepath.Join(mockGadgetDir, t.gadgetFile), nil, 0644)
		c.Assert(err, IsNil)
		err = InstallBootConfig(mockGadgetDir)
		c.Assert(err, IsNil)
		fn := filepath.Join(dirs.GlobalRootDir, t.systemFile)
		c.Assert(osutil.FileExists(fn), Equals, true)
	}
}
