// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package osutil_test

import (
	"os"
	"syscall"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/osutil"
)

type DiskSuite struct{}

var _ = Suite(&DiskSuite{})

func (s *DiskSuite) TestCheckFreeSpaceHappy(c *C) {
	var called bool
	restore := osutil.MockSyscalStatfs(func(path string, st *syscall.Statfs_t) error {
		c.Assert(path, Equals, "/path")
		st.Bsize = 4096
		st.Bavail = 2
		called = true
		return nil
	})
	defer restore()

	c.Assert(osutil.CheckFreeSpace("/path", 8191), IsNil)
	c.Assert(called, Equals, true)
}

func (s *DiskSuite) TestCheckFreeSpaceUnhappy(c *C) {
	restore := osutil.MockSyscalStatfs(func(path string, st *syscall.Statfs_t) error {
		c.Assert(path, Equals, "/path")
		st.Bsize = 4096
		st.Bavail = 2
		return nil
	})
	defer restore()

	err := osutil.CheckFreeSpace("/path", 8193)
	c.Assert(err, ErrorMatches, "not enough free space in /path, requires 1B")
	diskSpaceErr, ok := err.(*osutil.NotEnoughDiskSpaceError)
	c.Assert(ok, Equals, true)
	c.Check(diskSpaceErr.Path, Equals, "/path")
	c.Check(diskSpaceErr.Delta, Equals, int64(1))
}

func (s *DiskSuite) TestCheckFreeSpacePathError(c *C) {
	err := osutil.CheckFreeSpace("/path", 8193)
	c.Assert(os.IsNotExist(err), Equals, true)
}
