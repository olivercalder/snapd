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
	"strconv"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/polkit"
)

type accessResult int

const (
	accessUnknown accessResult = iota
	accessOK
	accessUnauthorized
	accessForbidden
	accessCancelled
)

var polkitCheckAuthorization = polkit.CheckAuthorization

// accessChecker checks whether a particular request is allowed.
//
// An access checker will either allow a request, deny it, or return
// accessUnknown, which indicates the decision should be delegated to
// the next access checker.
type accessChecker interface {
	canAccess(r *http.Request, ucred *ucrednet, user *auth.UserState) accessResult
}

// allowSnapSocket is an access checker that allows requests received
// from the snapd-snap.socket socket.
type allowSnapSocket struct{}

func (c allowSnapSocket) canAccess(r *http.Request, ucred *ucrednet, user *auth.UserState) accessResult {
	if ucred != nil && ucred.socket == dirs.SnapSocket {
		return accessOK
	}
	return accessUnknown
}

// denySnapSocket is an access checker that denies requests received
// from the snapd-snap.socket socket.
type denySnapSocket struct{}

func (c denySnapSocket) canAccess(r *http.Request, ucred *ucrednet, user *auth.UserState) accessResult {
	if ucred != nil && ucred.socket == dirs.SnapSocket {
		return accessUnauthorized
	}
	return accessUnknown
}

// allowGetByGuest is an access checker that allows GET requests from anyone.
type allowGetByGuest struct{}

func (c allowGetByGuest) canAccess(r *http.Request, ucred *ucrednet, user *auth.UserState) accessResult {
	if r.Method == "GET" {
		return accessOK
	}
	return accessUnknown
}

// allowGetByUser is an access checker that allows GET requests from any user.
type allowGetByUser struct{}

func (c allowGetByUser) canAccess(r *http.Request, ucred *ucrednet, user *auth.UserState) accessResult {
	if r.Method == "GET" && ucred != nil {
		return accessOK
	}
	return accessUnknown
}

// allowSnapUser is an access checker that allows requests from
// authorised users.
type allowSnapUser struct{}

func (c allowSnapUser) canAccess(r *http.Request, ucred *ucrednet, user *auth.UserState) accessResult {
	if user != nil {
		return accessOK
	}
	return accessUnknown
}

// allowRoot is an access checker that allows requests from root (uid 0).
type allowRoot struct{}

func (c allowRoot) canAccess(r *http.Request, ucred *ucrednet, user *auth.UserState) accessResult {
	if ucred != nil && ucred.uid == 0 {
		return accessOK
	}
	return accessUnknown
}

// polkitCheck is an access checker that delegates the decision to polkitd.
type polkitCheck struct {
	actionID string
}

func (c polkitCheck) canAccess(r *http.Request, ucred *ucrednet, user *auth.UserState) accessResult {
	// Can not perform Polkit authorization without peer credentials
	if ucred == nil {
		return accessUnknown
	}

	var flags polkit.CheckFlags
	allowHeader := r.Header.Get(client.AllowInteractionHeader)
	if allowHeader != "" {
		if allow, err := strconv.ParseBool(allowHeader); err != nil {
			logger.Noticef("error parsing %s header: %s", client.AllowInteractionHeader, err)
		} else if allow {
			flags |= polkit.CheckAllowInteraction
		}
	}
	// Pass both pid and uid from the peer ucred to avoid pid race
	if authorized, err := polkitCheckAuthorization(ucred.pid, ucred.uid, c.actionID, nil, flags); err == nil {
		if authorized {
			// polkit says user is authorised
			return accessOK
		}
	} else if err == polkit.ErrDismissed {
		return accessCancelled
	} else {
		logger.Noticef("polkit error: %s", err)
	}
	return accessUnknown
}
