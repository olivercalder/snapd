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

package client_test

import (
	"encoding/json"

	"gopkg.in/check.v1"
)

func (cs *clientSuite) TestClientRunSnaptoolCallsEndpoint(c *check.C) {
	cs.cli.RunSnaptool("1234ABCD", []string{"foo", "bar"})
	c.Check(cs.req.Method, check.Equals, "POST")
	c.Check(cs.req.URL.Path, check.Equals, "/v2/snaptool")
}

func (cs *clientSuite) TestClientRunSnaptool(c *check.C) {
	cs.rsp = `{
		"type": "sync",
        "status-code": 200,
		"result": {
			"stdout": "test stdout",
			"stderr": "test stderr"
		}
	}`

	stdout, stderr, err := cs.cli.RunSnaptool("1234ABCD", []string{"foo", "bar"})
	c.Assert(err, check.IsNil)
	c.Check(stdout, check.Equals, "test stdout")
	c.Check(stderr, check.Equals, "test stderr")

	var body map[string]interface{}
	decoder := json.NewDecoder(cs.req.Body)
	err = decoder.Decode(&body)
	c.Check(err, check.IsNil)
	c.Check(body, check.DeepEquals, map[string]interface{}{
		"context": "1234ABCD",
		"args":    []interface{}{"foo", "bar"},
	})
}
