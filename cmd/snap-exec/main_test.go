// -*- Mode: Go; indent-tabs-mode: t -*-
// +build !integrationcoverage

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

package main

import (
	"os"
	"syscall"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

// Hook up check.v1 into the "go test" runner
func Test(t *testing.T) { TestingT(t) }

type snapExecSuite struct {
}

var _ = Suite(&snapExecSuite{})

func (s *snapExecSuite) SetUpTest(c *C) {
	snapReadInfo = snap.ReadInfo
	syscallExec = syscall.Exec
}

var mockYaml = []byte(`name: snapname
version: 1.0
apps:
 app:
  command: run-app
  stop-command: stop-app
  post-stop-command: post-stop-app
  environment:
   LD_LIBRARY_PATH: /some/path
 nostop:
  command: nostop
`)

func (s *snapExecSuite) TestFindCommand(c *C) {
	info, err := snap.InfoFromSnapYaml(mockYaml)
	c.Assert(err, IsNil)

	for _, t := range []struct {
		cmd      string
		expected string
	}{
		{cmd: "", expected: "run-app"},
		{cmd: "stop", expected: "stop-app"},
		{cmd: "post-stop", expected: "post-stop-app"},
	} {
		cmd, err := findCommand(info.Apps["app"], t.cmd)
		c.Check(err, IsNil)
		c.Check(cmd, Equals, t.expected)
	}
}

func (s *snapExecSuite) TestFindCommandInvalidCommand(c *C) {
	info, err := snap.InfoFromSnapYaml(mockYaml)
	c.Assert(err, IsNil)

	_, err = findCommand(info.Apps["app"], "xxx")
	c.Check(err, ErrorMatches, `cannot use "xxx" command`)
}

func (s *snapExecSuite) TestFindCommandNoCommand(c *C) {
	info, err := snap.InfoFromSnapYaml(mockYaml)
	c.Assert(err, IsNil)

	_, err = findCommand(info.Apps["nostop"], "stop")
	c.Check(err, ErrorMatches, `no "stop" command found for "nostop"`)
}

func (s *snapExecSuite) TestSnapLaunchIntegration(c *C) {
	os.Setenv("SNAP_REVISION", "42")
	snapReadInfo = func(string, *snap.SideInfo) (*snap.Info, error) {
		info, err := snap.InfoFromSnapYaml(mockYaml)
		info.SideInfo.Revision = snap.R(os.Getenv("SNAP_REVISION"))
		return info, err
	}

	execArgv0 := ""
	execArgs := []string{}
	execEnv := []string{}
	syscallExec = func(argv0 string, argv []string, env []string) error {
		execArgv0 = argv0
		execArgs = argv
		execEnv = env
		return nil
	}

	err := snapLaunch("snap.app", "stop", []string{"arg1", "arg2"})
	c.Assert(err, IsNil)
	c.Check(execArgv0, Equals, "/snap/snapname/42/stop-app")
	c.Check(execArgs, DeepEquals, []string{"arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "LD_LIBRARY_PATH=/some/path\n")
}

func (s *snapExecSuite) TestSplitSnapApp(c *C) {
	for _, t := range []struct {
		in  string
		out []string
	}{
		// normal cases
		{"foo.bar", []string{"foo", "bar"}},
		{"foo.bar.baz", []string{"foo", "bar.baz"}},
		// special case, snapName == appName
		{"foo", []string{"foo", "foo"}},
	} {
		snap, app := splitSnapApp(t.in)
		c.Check([]string{snap, app}, DeepEquals, t.out)
	}
}
