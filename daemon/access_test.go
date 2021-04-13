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

package daemon

import (
	"net/http"
	"net/http/httptest"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/polkit"
	"github.com/snapcore/snapd/testutil"
)

type accessSuite struct{}

var _ = Suite(&accessSuite{})

func (s *accessSuite) TestOpenAccess(c *C) {
	var ac accessChecker = openAccess{}

	// openAccess denies access from snapd-snap.socket
	ucred := &ucrednet{Uid: 42, Pid: 100, Socket: dirs.SnapSocket}
	c.Check(ac.CheckAccess(nil, ucred, nil), Equals, accessForbidden)

	// Access allowed from other sockets
	ucred.Socket = dirs.SnapdSocket
	c.Check(ac.CheckAccess(nil, ucred, nil), Equals, accessOK)

	// Access forbidden without peer credentials.  This will need
	// to be revisited if the API is ever exposed over TCP.
	c.Check(ac.CheckAccess(nil, nil, nil), Equals, accessForbidden)
}

func (s *accessSuite) TestAuthenticatedAccess(c *C) {
	defer func() {
		checkPolkitAction = checkPolkitActionImpl
	}()
	checkPolkitAction = func(r *http.Request, ucred *ucrednet, action string) accessResult {
		// Polkit is not consulted if no action is specified
		c.Fail()
		return accessForbidden
	}

	var ac accessChecker = authenticatedAccess{}

	req := httptest.NewRequest("GET", "/", nil)
	user := &auth.UserState{}

	// authenticatedAccess denies access from snapd-snap.socket
	ucred := &ucrednet{Uid: 0, Pid: 100, Socket: dirs.SnapSocket}
	c.Check(ac.CheckAccess(req, ucred, nil), Equals, accessForbidden)
	c.Check(ac.CheckAccess(req, ucred, user), Equals, accessForbidden)

	// With macaroon auth, a normal user is granted access
	ucred = &ucrednet{Uid: 42, Pid: 100, Socket: dirs.SnapdSocket}
	c.Check(ac.CheckAccess(req, ucred, user), Equals, accessOK)

	// Macaroon access requires peer credentials
	c.Check(ac.CheckAccess(req, nil, user), Equals, accessForbidden)

	// Without macaroon auth, normal users are unauthorized
	c.Check(ac.CheckAccess(req, ucred, nil), Equals, accessUnauthorized)

	// The root user is granted access without a macaroon
	ucred = &ucrednet{Uid: 0, Pid: 100, Socket: dirs.SnapdSocket}
	c.Check(ac.CheckAccess(req, ucred, nil), Equals, accessOK)
}

func (s *accessSuite) TestAuthenticatedAccessPolkit(c *C) {
	defer func() {
		checkPolkitAction = checkPolkitActionImpl
	}()

	var ac accessChecker = authenticatedAccess{Polkit: "action-id"}

	req := httptest.NewRequest("GET", "/", nil)
	user := &auth.UserState{}
	ucred := &ucrednet{Uid: 0, Pid: 100, Socket: dirs.SnapdSocket}

	// polkit is not checked if any of:
	//   * ucred is missing
	//   * macaroon auth is provided
	//   * user is root
	checkPolkitAction = func(r *http.Request, ucred *ucrednet, action string) accessResult {
		c.Fail()
		return accessForbidden
	}
	c.Check(ac.CheckAccess(req, nil, nil), Equals, accessForbidden)
	c.Check(ac.CheckAccess(req, nil, user), Equals, accessForbidden)
	c.Check(ac.CheckAccess(req, ucred, nil), Equals, accessOK)

	// polkit is checked for regular users without macaroon auth
	checkPolkitAction = func(r *http.Request, u *ucrednet, action string) accessResult {
		c.Check(r, Equals, req)
		c.Check(u, Equals, ucred)
		c.Check(action, Equals, "action-id")
		return accessOK
	}
	ucred = &ucrednet{Uid: 42, Pid: 100, Socket: dirs.SnapdSocket}
	c.Check(ac.CheckAccess(req, ucred, nil), Equals, accessOK)
}

func (s *accessSuite) TestCheckPolkitActionImpl(c *C) {
	defer func() {
		polkitCheckAuthorization = polkit.CheckAuthorization
	}()

	logbuf, restore := logger.MockLogger()
	defer restore()

	req := httptest.NewRequest("GET", "/", nil)
	ucred := &ucrednet{Uid: 42, Pid: 1000, Socket: dirs.SnapdSocket}

	// Access granted if polkit authorizes the request
	polkitCheckAuthorization = func(pid int32, uid uint32, actionId string, details map[string]string, flags polkit.CheckFlags) (bool, error) {
		c.Check(pid, Equals, int32(1000))
		c.Check(uid, Equals, uint32(42))
		c.Check(actionId, Equals, "action-id")
		c.Check(details, IsNil)
		c.Check(flags, Equals, polkit.CheckFlags(0))
		return true, nil
	}
	c.Check(checkPolkitActionImpl(req, ucred, "action-id"), Equals, accessOK)
	c.Check(logbuf.String(), Equals, "")

	// Unauthorized if polkit denies the request
	polkitCheckAuthorization = func(pid int32, uid uint32, actionId string, details map[string]string, flags polkit.CheckFlags) (bool, error) {
		return false, nil
	}
	c.Check(checkPolkitActionImpl(req, ucred, "action-id"), Equals, accessUnauthorized)
	c.Check(logbuf.String(), Equals, "")

	// Cancelled if the user dismisses the auth check
	polkitCheckAuthorization = func(pid int32, uid uint32, actionId string, details map[string]string, flags polkit.CheckFlags) (bool, error) {
		return false, polkit.ErrDismissed
	}
	c.Check(checkPolkitActionImpl(req, ucred, "action-id"), Equals, accessCancelled)
	c.Check(logbuf.String(), Equals, "")

	// The X-Allow-Interaction header can be set to tell polkitd
	// that interaction with the user is allowed.
	req.Header.Set(client.AllowInteractionHeader, "true")
	polkitCheckAuthorization = func(pid int32, uid uint32, actionId string, details map[string]string, flags polkit.CheckFlags) (bool, error) {
		c.Check(flags, Equals, polkit.CheckFlags(polkit.CheckAllowInteraction))
		return true, nil
	}
	c.Check(checkPolkitActionImpl(req, ucred, "action-id"), Equals, accessOK)
	c.Check(logbuf.String(), Equals, "")

	// Bad values in the request header are logged
	req.Header.Set(client.AllowInteractionHeader, "garbage")
	polkitCheckAuthorization = func(pid int32, uid uint32, actionId string, details map[string]string, flags polkit.CheckFlags) (bool, error) {
		c.Check(flags, Equals, polkit.CheckFlags(0))
		return true, nil
	}
	c.Check(checkPolkitActionImpl(req, ucred, "action-id"), Equals, accessOK)
	c.Check(logbuf.String(), testutil.Contains, "error parsing X-Allow-Interaction header:")
}

func (s *accessSuite) TestRootAccess(c *C) {
	var ac accessChecker = rootAccess{}

	user := &auth.UserState{}

	// rootAccess denies access without ucred
	c.Check(ac.CheckAccess(nil, nil, nil), Equals, accessForbidden)
	c.Check(ac.CheckAccess(nil, nil, user), Equals, accessForbidden)

	// rootAccess denies access from snapd-snap.socket
	ucred := &ucrednet{Uid: 0, Pid: 100, Socket: dirs.SnapSocket}
	c.Check(ac.CheckAccess(nil, ucred, nil), Equals, accessForbidden)
	c.Check(ac.CheckAccess(nil, ucred, user), Equals, accessForbidden)

	// Non-root users are forbidden, even with macaroon auth
	ucred = &ucrednet{Uid: 42, Pid: 100, Socket: dirs.SnapdSocket}
	c.Check(ac.CheckAccess(nil, ucred, nil), Equals, accessForbidden)
	c.Check(ac.CheckAccess(nil, ucred, user), Equals, accessForbidden)

	// Root is granted access
	ucred = &ucrednet{Uid: 0, Pid: 100, Socket: dirs.SnapdSocket}
	c.Check(ac.CheckAccess(nil, ucred, nil), Equals, accessOK)
}

func (s *accessSuite) TestSnapAccess(c *C) {
	var ac accessChecker = snapAccess{}

	// snapAccess allows access from snapd-snap.socket
	ucred := &ucrednet{Uid: 42, Pid: 100, Socket: dirs.SnapSocket}
	c.Check(ac.CheckAccess(nil, ucred, nil), Equals, accessOK)

	// access is forbidden on the main socket or without peer creds
	ucred.Socket = dirs.SnapdSocket
	c.Check(ac.CheckAccess(nil, ucred, nil), Equals, accessForbidden)
	c.Check(ac.CheckAccess(nil, nil, nil), Equals, accessForbidden)
}
