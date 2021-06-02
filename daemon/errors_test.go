// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2021 Canonical Ltd
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

package daemon_test

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/daemon"
)

type errorsSuite struct{}

var _ = Suite(&errorsSuite{})

func (s *errorsSuite) TestJSON(c *C) {
	rspe := &daemon.APIError{
		Status:  400,
		Message: "req is wrong",
	}

	c.Check(rspe.JSON(), DeepEquals, &daemon.RespJSON{
		Status: 400,
		Type:   daemon.ResponseTypeError,
		Result: &daemon.ErrorResult{
			Message: "req is wrong",
		},
	})

	rspe = &daemon.APIError{
		Status:  404,
		Message: "snap not found",
		Kind:    client.ErrorKindSnapNotFound,
		Value: map[string]string{
			"snap-name": "foo",
		},
	}
	c.Check(rspe.JSON(), DeepEquals, &daemon.RespJSON{
		Status: 404,
		Type:   daemon.ResponseTypeError,
		Result: &daemon.ErrorResult{
			Message: "snap not found",
			Kind:    client.ErrorKindSnapNotFound,
			Value: map[string]string{
				"snap-name": "foo",
			},
		},
	})
}

func (s *errorsSuite) TestError(c *C) {
	rspe := &daemon.APIError{
		Status:  400,
		Message: "req is wrong",
	}

	c.Check(rspe.Error(), Equals, `req is wrong (api)`)

	rspe = &daemon.APIError{
		Status:  404,
		Message: "snap not found",
		Kind:    client.ErrorKindSnapNotFound,
		Value: map[string]string{
			"snap-name": "foo",
		},
	}

	c.Check(rspe.Error(), Equals, `snap not found (api: snap-not-found)`)

	rspe = &daemon.APIError{
		Status:  500,
		Message: "internal error",
	}
	c.Check(rspe.Error(), Equals, `internal error (api 500)`)
}

func (s *errorsSuite) TestThroughSyncResponse(c *C) {
	rspe := &daemon.APIError{
		Status:  400,
		Message: "req is wrong",
	}

	rsp := daemon.SyncResponse(rspe, nil)
	c.Check(rsp, Equals, rspe)
}
