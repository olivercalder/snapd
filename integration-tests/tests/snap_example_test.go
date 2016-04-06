// -*- Mode: Go; indent-tabs-mode: t -*-
// +build !excludeintegration

/*
 * Copyright (C) 2015, 2016 Canonical Ltd
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

package tests

import (
	"io/ioutil"
	"net/http"

	"github.com/ubuntu-core/snappy/integration-tests/testutils/cli"
	"github.com/ubuntu-core/snappy/integration-tests/testutils/common"
	"github.com/ubuntu-core/snappy/integration-tests/testutils/wait"
	"github.com/ubuntu-core/snappy/testutil"

	"gopkg.in/check.v1"
)

var _ = check.Suite(&helloWorldExampleSuite{})

type snapHelloWorldExampleSuite struct {
	common.SnappySuite
}

func installSnap(c *check.C, packageName string) string {
	cli.ExecCommand(c, "sudo", "snap", "install", packageName)
	// FIXME: should `snap install` shold show a list afterards?
	//        like `snappy install`?
	return cli.ExecCommand(c, "snap", "list")
}

func removeSnap(c *check.C, packageName string) string {
	return cli.ExecCommand(c, "sudo", "snap", "remove", packageName)
}

func (s *snapHelloWorldExampleSuite) TestCallHelloWorldBinary(c *check.C) {
	installSnap(c, "hello-world")
	s.AddCleanup(func() {
		removeSnap(c, "hello-world")
	})

	echoOutput := cli.ExecCommand(c, "hello-world.echo")

	c.Assert(echoOutput, check.Equals, "Hello World!\n",
		check.Commentf("Wrong output from hello-world binary"))
}

func (s *snapHelloWorldExampleSuite) TestCallHelloWorldEvilMustPrintPermissionDeniedError(c *check.C) {
	installSnap(c, "hello-world")
	s.AddCleanup(func() {
		removeSnap(c, "hello-world")
	})

	echoOutput, err := cli.ExecCommandErr("hello-world.evil")
	c.Assert(err, check.NotNil, check.Commentf("hello-world.evil did not fail"))

	expected := "" +
		"Hello Evil World!\n" +
		"This example demonstrates the app confinement\n" +
		"You should see a permission denied error next\n" +
		"/snaps/hello-world/.*/bin/evil: \\d+: " +
		"/snaps/hello-world/.*/bin/evil: " +
		"cannot create /var/tmp/myevil.txt: Permission denied\n"

	c.Assert(string(echoOutput), check.Matches, expected)
}

var _ = check.Suite(&snapPythonWebserverExampleSuite{})

type snapPythonWebserverExampleSuite struct {
	common.SnappySuite
}

func (s *snapPythonWebserverExampleSuite) TestNetworkingServiceMustBeStarted(c *check.C) {
	baseAppName := "xkcd-webserver"
	appName := baseAppName + ".canonical"
	installSnap(c, appName)
	defer removeSnap(c, appName)

	err := wait.ForServerOnPort(c, "tcp", 80)
	c.Assert(err, check.IsNil, check.Commentf("Error waiting for server: %s", err))

	resp, err := http.Get("http://localhost")
	c.Assert(err, check.IsNil, check.Commentf("Error getting the http resource: %s", err))
	c.Check(resp.Status, check.Equals, "200 OK", check.Commentf("Wrong reply status"))
	c.Assert(resp.Proto, check.Equals, "HTTP/1.0", check.Commentf("Wrong reply protocol"))
}

var _ = check.Suite(&snapGoWebserverExampleSuite{})

type snapGoWebserverExampleSuite struct {
	common.SnappySuite
}

func (s *snapGoWebserverExampleSuite) TestGetRootPathMustPrintMessage(c *check.C) {
	appName := "go-example-webserver"
	output := installSnap(c, appName)
	defer removeSnap(c, appName)
	c.Assert(output, testutil.Contains, "go-example-webserver")

	err := wait.ForServerOnPort(c, "tcp6", 8081)
	c.Assert(err, check.IsNil, check.Commentf("Error waiting for server: %s", err))

	resp, err := http.Get("http://localhost:8081/")
	defer resp.Body.Close()
	c.Assert(err, check.IsNil, check.Commentf("Error getting the http resource: %s", err))
	c.Check(resp.Status, check.Equals, "200 OK", check.Commentf("Wrong reply status"))
	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, check.IsNil, check.Commentf("Error reading the reply body: %s", err))
	c.Assert(string(body), check.Equals, "Hello World\n", check.Commentf("Wrong reply body"))
}
