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

package main

import (
	"strings"

	. "gopkg.in/check.v1"
)

type bootstrapSuite struct{}

var _ = Suite(&bootstrapSuite{})

func (s *bootstrapSuite) TestReadCmdLine(c *C) {
	buf := make([]byte, 1024)
	numRead := readCmdline(buf)
	c.Assert(numRead, Not(Equals), -1)
	c.Assert(numRead, Not(Equals), 1)
	// The trailing byte is a '\0'
	str := string(buf[0 : numRead-1])
	// Smoke test, the actual value looks like
	// "/tmp/go-build020699516/github.com/snapcore/snapd/cmd/snap-update-ns/_test/snap-update-ns.test"
	c.Assert(strings.HasSuffix(str, "snap-update-ns.test"), Equals, true) // dummy
}

// Check that if there is only one argument we return nil.
func (s *bootstrapSuite) TestFindSnapName1(c *C) {
	buf := []byte("arg0\x00")
	result := findSnapName(buf)
	c.Assert(result, Equals, (*string)(nil))
}

// Check that if there are multiple arguments we return the 2nd one.
func (s *bootstrapSuite) TestFindSnapName2(c *C) {
	buf := []byte("arg0\x00arg1\x00arg2\x00")
	result := findSnapName(buf)
	c.Assert(result, Not(Equals), (*string)(nil))
	c.Assert(*result, Equals, "arg1")
}

// Check that if the 1st argument in the buffer is not terminated we don't crash.
func (s *bootstrapSuite) TestFindSnapName3(c *C) {
	buf := []byte("arg0")
	result := findSnapName(buf)
	c.Assert(result, Equals, (*string)(nil))
}

// Check that if the 2nd argument in the buffer is not terminated we don't crash.
func (s *bootstrapSuite) TestFindSnapName4(c *C) {
	buf := []byte("arg0\x00arg1")
	result := findSnapName(buf)
	c.Assert(result, Not(Equals), (*string)(nil))
	c.Assert(*result, Equals, "arg1")
}

func (s *bootstrapSuite) TestSanitizeSnapName(c *C) {
	c.Assert(sanitizeSnapName("hello-world"), Equals, 0)
	c.Assert(sanitizeSnapName("hello/world"), Equals, -1)
	c.Assert(sanitizeSnapName("hello..world"), Equals, -1)
}
