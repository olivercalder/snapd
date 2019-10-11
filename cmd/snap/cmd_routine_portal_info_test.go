// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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
	"net/http"

	. "gopkg.in/check.v1"

	snap "github.com/snapcore/snapd/cmd/snap"
	snapdsnap "github.com/snapcore/snapd/snap"
)

// only used for /v2/snaps/hello
const mockInfoJSONWithApps = `
{
  "type": "sync",
  "status-code": 200,
  "status": "OK",
  "result": {
    "id": "mVyGrEwiqSi5PugCwyH7WgpoQLemtTd6",
    "title": "hello",
    "summary": "GNU Hello, the \"hello world\" snap",
    "description": "GNU hello prints a friendly greeting. This is part of the snapcraft tour at https://snapcraft.io/",
    "installed-size": 98304,
    "name": "hello",
    "publisher": {
      "id": "canonical",
      "username": "canonical",
      "display-name": "Canonical",
      "validation": "verified"
    },
    "developer": "canonical",
    "status": "active",
    "type": "app",
    "version": "2.10",
    "channel": "stable",
    "tracking-channel": "stable",
    "ignore-validation": false,
    "revision": "38",
    "confinement": "strict",
    "private": false,
    "devmode": false,
    "jailmode": false,
    "apps": [
      {
        "snap": "hello",
        "name": "hello",
        "desktop-file": "/path/to/hello_hello.desktop"
      },
      {
        "snap": "hello",
        "name": "universe",
        "desktop-file": "/path/to/hello_universe.desktop"
      }
    ],
    "contact": "mailto:snaps@canonical.com",
    "mounted-from": "/var/lib/snapd/snaps/hello_38.snap",
    "install-date": "2019-10-11T13:34:15.630955389+08:00"
  }
}
`

func (s *SnapSuite) TestPortalInfo(c *C) {
	snap.MockSnapNameFromPid(func(pid int) (snapdsnap.ProcessInfo, error) {
		c.Check(pid, Equals, 42)
		return snapdsnap.ProcessInfo{"hello", "universe", ""}, nil
	})
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		c.Check(r.Method, Equals, "GET")
		c.Check(r.URL.Path, Equals, "/v2/snaps/hello")
		fmt.Fprintln(w, mockInfoJSONWithApps)
	})
	_, err := snap.Parser(snap.Client()).ParseArgs([]string{"routine", "portal-info", "42"})
	c.Assert(err, IsNil)
	c.Check(s.Stdout(), Equals, `[Snap Info]
InstanceName=hello
AppName=universe
DesktopFile=/path/to/hello_universe.desktop
`)
	c.Check(s.Stderr(), Equals, "")
}

func (s *SnapSuite) TestPortalInfoNoAppInfo(c *C) {
	snap.MockSnapNameFromPid(func(pid int) (snapdsnap.ProcessInfo, error) {
		c.Check(pid, Equals, 42)
		// On systems without AppArmor support, we can't
		// distinguish different apps within the snap.
		return snapdsnap.ProcessInfo{"hello", "", ""}, nil
	})
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		c.Check(r.Method, Equals, "GET")
		c.Check(r.URL.Path, Equals, "/v2/snaps/hello")
		fmt.Fprintln(w, mockInfoJSONWithApps)
	})
	_, err := snap.Parser(snap.Client()).ParseArgs([]string{"routine", "portal-info", "42"})
	c.Assert(err, IsNil)
	c.Check(s.Stdout(), Equals, `[Snap Info]
InstanceName=hello
AppName=hello
DesktopFile=/path/to/hello_hello.desktop
`)
	c.Check(s.Stderr(), Equals, "")
}
