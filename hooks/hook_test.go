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

package hooks_test

import (
	"encoding/json"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/hooks"
)

func TestHooks(t *testing.T) { TestingT(t) }

type hooksSuite struct{}

var _ = Suite(&hooksSuite{})

func (s *hooksSuite) TestJsonMarshalHookRef(c *C) {
	hookRef := hooks.HookRef{Snap: "snap-name", Hook: "hook-name"}
	out, err := json.Marshal(hookRef)
	c.Assert(err, IsNil)
	c.Check(string(out), Equals, "{\"snap\":\"snap-name\",\"hook\":\"hook-name\"}")
}

func (s *hooksSuite) TestJsonUnmarshalHookRef(c *C) {
	out, err := json.Marshal(hooks.HookRef{Snap: "snap-name", Hook: "hook-name"})
	c.Assert(err, IsNil)

	var hookRef hooks.HookRef
	err = json.Unmarshal(out, &hookRef)
	c.Assert(err, IsNil)
	c.Check(hookRef.Snap, Equals, "snap-name")
	c.Check(hookRef.Hook, Equals, "hook-name")
}
