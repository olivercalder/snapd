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

package snapdir_test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/ubuntu-core/snappy/snap/snapdir"

	. "gopkg.in/check.v1"
)

// Hook up check.v1 into the "go test" runner
func Test(t *testing.T) { TestingT(t) }

type SnapdirTestSuite struct {
}

var _ = Suite(&SnapdirTestSuite{})

func (s *SnapdirTestSuite) TestReadFile(c *C) {
	d := c.MkDir()
	needle := []byte(`stuff`)
	err := ioutil.WriteFile(filepath.Join(d, "foo"), needle, 0644)
	c.Assert(err, IsNil)

	snap := snapdir.New(d)
	content, err := snap.ReadFile("foo")
	c.Assert(err, IsNil)
	c.Assert(content, DeepEquals, needle)
}

func (s *SnapdirTestSuite) TestInstall(c *C) {
	snap := &snapdir.Snap{}
	c.Assert(snap.Install("foo", "bar"), ErrorMatches, "cannot install a snapdir snap")
}

func (s *SnapdirTestSuite) TestUnpack(c *C) {
	snap := &snapdir.Snap{}
	c.Assert(snap.Unpack("src", "dst"), ErrorMatches, "cannot unpack a snapdir snap")
}
