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

package main_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"gopkg.in/check.v1"

	"github.com/snapcore/snapd/cmd/snap"
)

type validateSuite struct {
	BaseSnapSuite
}

var _ = check.Suite(&validateSuite{})

func makeFakeValidateHandler(c *check.C, body string, mode string, pinned int) func(w http.ResponseWriter, r *http.Request) {
	var called bool
	return func(w http.ResponseWriter, r *http.Request) {
		if called {
			c.Fatalf("expected a single request")
		}
		called = true
		c.Check(r.URL.Path, check.Equals, "/v2/validation-sets")
		c.Check(r.URL.Query(), check.DeepEquals, url.Values{
			"validation-set": []string{"foo/bar"},
		})

		buf, err := ioutil.ReadAll(r.Body)
		c.Assert(err, check.IsNil)
		if pinned != 0 {
			c.Check(string(buf), check.DeepEquals, fmt.Sprintf("{\"mode\":%q,\"pin-at\":%d}\n", mode, pinned))
		} else {
			c.Check(string(buf), check.DeepEquals, fmt.Sprintf("{\"mode\":%q}\n", mode))
		}

		c.Check(r.Method, check.Equals, "POST")
		w.WriteHeader(200)
		fmt.Fprintln(w, body)
	}
}

func makeFakeValidateQueryHandler(c *check.C, body string, all bool) func(w http.ResponseWriter, r *http.Request) {
	var called bool
	return func(w http.ResponseWriter, r *http.Request) {
		if called {
			c.Fatalf("expected a single request")
		}
		called = true
		c.Check(r.URL.Path, check.Equals, "/v2/validation-sets")
		if all {
			c.Check(r.URL.Query(), check.HasLen, 0)
		} else {
			c.Check(r.URL.Query(), check.DeepEquals, url.Values{
				"validation-set": []string{"foo/bar"},
			})
		}

		c.Check(r.Method, check.Equals, "GET")
		w.WriteHeader(200)
		fmt.Fprintln(w, body)
	}
}

func (s *validateSuite) TestValidateInvalidArgs(c *check.C) {
	for _, args := range []struct {
		args []string
		err  string
	}{
		{[]string{"foo"}, `cannot parse validation set "foo": expected a single account/name`},
		{[]string{"foo/bar/baz"}, `cannot parse validation set "foo/bar/baz": expected a single account/name`},
		{[]string{"--monitor", "--enforce"}, `cannot use --monitor and --enforce together`},
		{[]string{"--monitor", "--forget"}, `cannot use --monitor and --forget together`},
		{[]string{"--enforce", "--forget"}, `cannot use --enforce and --forget together`},
		{[]string{"--enforce"}, `missing validation set argument`},
		{[]string{"--monitor"}, `missing validation set argument`},
		{[]string{"--forget"}, `missing validation set argument`},
	} {
		s.stdout.Truncate(0)
		s.stderr.Truncate(0)

		_, err := main.Parser(main.Client()).ParseArgs(append([]string{"validate"}, args.args...))
		c.Assert(err, check.ErrorMatches, args.err)
	}
}

func (s *validateSuite) TestValidateMonitor(c *check.C) {
	s.RedirectClientToTestServer(makeFakeValidateHandler(c, `{"type": "sync", "status-code": 200, "result": []}`, "monitor", 0))

	rest, err := main.Parser(main.Client()).ParseArgs([]string{"validate", "--monitor", "foo/bar"})
	c.Assert(err, check.IsNil)
	c.Check(rest, check.HasLen, 0)
	c.Check(s.Stderr(), check.Equals, "")
	c.Check(s.Stdout(), check.Equals, "")
}

func (s *validateSuite) TestValidateMonitorPinned(c *check.C) {
	s.RedirectClientToTestServer(makeFakeValidateHandler(c, `{"type": "sync", "status-code": 200, "result": []}`, "monitor", 3))

	rest, err := main.Parser(main.Client()).ParseArgs([]string{"validate", "--monitor", "foo/bar=3"})
	c.Assert(err, check.IsNil)
	c.Check(rest, check.HasLen, 0)
	c.Check(s.Stderr(), check.Equals, "")
	c.Check(s.Stdout(), check.Equals, "")
}

func (s *validateSuite) TestValidateEnforce(c *check.C) {
	s.RedirectClientToTestServer(makeFakeValidateHandler(c, `{"type": "sync", "status-code": 200, "result": []}`, "enforce", 0))

	rest, err := main.Parser(main.Client()).ParseArgs([]string{"validate", "--enforce", "foo/bar"})
	c.Assert(err, check.IsNil)
	c.Check(rest, check.HasLen, 0)
	c.Check(s.Stderr(), check.Equals, "")
	c.Check(s.Stdout(), check.Equals, "")
}

func (s *validateSuite) TestValidateEnforcePinned(c *check.C) {
	s.RedirectClientToTestServer(makeFakeValidateHandler(c, `{"type": "sync", "status-code": 200, "result": []}`, "enforce", 5))

	rest, err := main.Parser(main.Client()).ParseArgs([]string{"validate", "--enforce", "foo/bar=5"})
	c.Assert(err, check.IsNil)
	c.Check(rest, check.HasLen, 0)
	c.Check(s.Stderr(), check.Equals, "")
	c.Check(s.Stdout(), check.Equals, "")
}

func (s *validateSuite) TestValidateForget(c *check.C) {
	s.RedirectClientToTestServer(makeFakeValidateHandler(c, `{"type": "sync", "status-code": 200, "result": []}`, "forget", 0))

	rest, err := main.Parser(main.Client()).ParseArgs([]string{"validate", "--forget", "foo/bar"})
	c.Assert(err, check.IsNil)
	c.Check(rest, check.HasLen, 0)
	c.Check(s.Stderr(), check.Equals, "")
	c.Check(s.Stdout(), check.Equals, "")
}

func (s *validateSuite) TestValidateForgetPinned(c *check.C) {
	s.RedirectClientToTestServer(makeFakeValidateHandler(c, `{"type": "sync", "status-code": 200, "result": []}`, "forget", 5))

	rest, err := main.Parser(main.Client()).ParseArgs([]string{"validate", "--forget", "foo/bar=5"})
	c.Assert(err, check.IsNil)
	c.Check(rest, check.HasLen, 0)
	c.Check(s.Stderr(), check.Equals, "")
	c.Check(s.Stdout(), check.Equals, "")
}

func (s *validateSuite) TestValidateQueryOne(c *check.C) {
	restore := main.MockIsStdinTTY(true)
	defer restore()

	s.RedirectClientToTestServer(makeFakeValidateQueryHandler(c, `{"type": "sync", "status-code": 200, "result": [{"validation-set":"foo/bar","mode":"monitor","seq":3,"valid":true}]}`, false))

	rest, err := main.Parser(main.Client()).ParseArgs([]string{"validate", "foo/bar"})
	c.Assert(err, check.IsNil)
	c.Check(rest, check.HasLen, 0)
	c.Check(s.Stderr(), check.Equals, "")
	c.Check(s.Stdout(), check.Equals, "valid")
}

func (s *validateSuite) TestValidateQueryOneInvalid(c *check.C) {
	restore := main.MockIsStdinTTY(true)
	defer restore()

	s.RedirectClientToTestServer(makeFakeValidateQueryHandler(c, `{"type": "sync", "status-code": 200, "result": [{"validation-set":"foo/bar","mode":"monitor","seq":3,"valid":false}]}`, false))

	rest, err := main.Parser(main.Client()).ParseArgs([]string{"validate", "foo/bar"})
	c.Assert(err, check.IsNil)
	c.Check(rest, check.HasLen, 0)
	c.Check(s.Stderr(), check.Equals, "")
	c.Check(s.Stdout(), check.Equals, "invalid")
}

func (s *validateSuite) TestValidateQueryAll(c *check.C) {
	restore := main.MockIsStdinTTY(true)
	defer restore()

	s.RedirectClientToTestServer(makeFakeValidateQueryHandler(c, `{"type": "sync", "status-code": 200, "result": [
		{"validation-set":"foo/bar","mode":"monitor","seq":3,"valid":true},
		{"validation-set":"foo/baz","mode":"enforce","seq":1,"valid":false}
	]}`, true))

	rest, err := main.Parser(main.Client()).ParseArgs([]string{"validate"})
	c.Assert(err, check.IsNil)
	c.Check(rest, check.HasLen, 0)
	c.Check(s.Stderr(), check.Equals, "")
	c.Check(s.Stdout(), check.Equals, "Validation  Mode     Seq  Current       Notes\n"+
		"foo/bar     monitor  3    valid    \n"+
		"foo/baz     enforce  1    invalid  \n"+
		"\n")
}
