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
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/devicestate"
	"github.com/snapcore/snapd/overlord/hookstate"
	"github.com/snapcore/snapd/seed"
	"github.com/snapcore/snapd/seed/seedtest"
	"github.com/snapcore/snapd/snap"
)

func (s *apiSuite) mockSystemSeeds(c *check.C) (restore func()) {
	// now create a minimal uc20 seed dir with snaps/assertions
	seed20 := &seedtest.TestingSeed20{
		SeedSnaps: seedtest.SeedSnaps{
			StoreSigning: s.storeSigning,
			Brands:       s.brands,
		},
		SeedDir: dirs.SnapSeedDir,
	}

	restore = seed.MockTrusted(seed20.StoreSigning.Trusted)

	assertstest.AddMany(s.storeSigning.Database, s.brands.AccountsAndKeys("my-brand")...)
	// add essential snaps
	seed20.MakeAssertedSnap(c, "name: snapd\nversion: 1\ntype: snapd", nil, snap.R(1), "my-brand", s.storeSigning.Database)
	seed20.MakeAssertedSnap(c, "name: pc\nversion: 1\ntype: gadget\nbase: core20", nil, snap.R(1), "my-brand", s.storeSigning.Database)
	seed20.MakeAssertedSnap(c, "name: pc-kernel\nversion: 1\ntype: kernel", nil, snap.R(1), "my-brand", s.storeSigning.Database)
	seed20.MakeAssertedSnap(c, "name: core20\nversion: 1\ntype: base", nil, snap.R(1), "my-brand", s.storeSigning.Database)
	seed20.MakeSeed(c, "20191119", "my-brand", "my-model", map[string]interface{}{
		"display-name": "my fancy model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []interface{}{
			map[string]interface{}{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]interface{}{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			}},
	}, nil)
	seed20.MakeSeed(c, "20200318", "my-brand", "my-model-2", map[string]interface{}{
		"display-name": "same brand different model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []interface{}{
			map[string]interface{}{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]interface{}{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			}},
	}, nil)

	return restore
}

func (s *apiSuite) TestGetSystemsSome(c *check.C) {
	d := s.daemonWithOverlordMock(c)
	hookMgr, err := hookstate.Manager(d.overlord.State(), d.overlord.TaskRunner())
	c.Assert(err, check.IsNil)
	mgr, err := devicestate.Manager(d.overlord.State(), hookMgr, d.overlord.TaskRunner(), nil)
	c.Assert(err, check.IsNil)
	d.overlord.AddManager(mgr)

	restore := s.mockSystemSeeds(c)
	defer restore()

	req, err := http.NewRequest("GET", "/v2/systems", nil)
	c.Assert(err, check.IsNil)
	rsp := getSystems(systemsCmd, req, nil).(*resp)

	c.Assert(rsp.Status, check.Equals, 200)
	sys := rsp.Result.(*systemsResponse)

	c.Assert(sys, check.DeepEquals, &systemsResponse{
		Systems: []client.System{
			{
				Current: false,
				Label:   "20191119",
				Model: client.SystemModelData{
					Model:       "my-model",
					BrandID:     "my-brand",
					DisplayName: "my fancy model",
				},
				Brand: snap.StoreAccount{
					ID:          "my-brand",
					Username:    "my-brand",
					DisplayName: "My-brand",
					Validation:  "unproven",
				},
				Actions: []client.SystemAction{
					{Title: "reinstall", Mode: "install"},
				},
			}, {
				Current: false,
				Label:   "20200318",
				Model: client.SystemModelData{
					Model:       "my-model-2",
					BrandID:     "my-brand",
					DisplayName: "same brand different model",
				},
				Brand: snap.StoreAccount{
					ID:          "my-brand",
					Username:    "my-brand",
					DisplayName: "My-brand",
					Validation:  "unproven",
				},
				Actions: []client.SystemAction{
					{Title: "reinstall", Mode: "install"},
				},
			},
		}})
}

func (s *apiSuite) TestGetSystemsNone(c *check.C) {
	// model assertion setup
	d := s.daemonWithOverlordMock(c)
	hookMgr, err := hookstate.Manager(d.overlord.State(), d.overlord.TaskRunner())
	c.Assert(err, check.IsNil)
	mgr, err := devicestate.Manager(d.overlord.State(), hookMgr, d.overlord.TaskRunner(), nil)
	c.Assert(err, check.IsNil)
	d.overlord.AddManager(mgr)

	// no system seeds
	req, err := http.NewRequest("GET", "/v2/systems", nil)
	c.Assert(err, check.IsNil)
	rsp := getSystems(systemsCmd, req, nil).(*resp)

	c.Assert(rsp.Status, check.Equals, 200)
	sys := rsp.Result.(*systemsResponse)

	c.Assert(sys, check.DeepEquals, &systemsResponse{})
}

func (s *apiSuite) TestSystemActionRequestInvalid(c *check.C) {
	type table struct{ body, error string }
	tests := []table{
		{
			body:  `"bogus"`,
			error: "cannot decode request body into system action:.*",
		}, {
			body:  `{"mode":"install"}`,
			error: "system action requires the system label to be provided",
		}, {
			body:  `{"label":"1234"}`,
			error: "system action requires the mode to be provided",
		},
	}
	for _, tc := range tests {
		c.Logf("tc: %v", tc)
		// no label
		req, err := http.NewRequest("POST", "/v2/systems", strings.NewReader(tc.body))
		c.Assert(err, check.IsNil)
		rsp := postSystems(systemsCmd, req, nil).(*resp)
		c.Assert(rsp.Type, check.Equals, ResponseTypeError)
		c.Check(rsp.Status, check.Equals, 400)
		c.Check(rsp.ErrorResult().Message, check.Matches, tc.error)
	}
}

func (s *apiSuite) TestSystemActionRequestNoSystem(c *check.C) {
	d := s.daemonWithOverlordMock(c)
	hookMgr, err := hookstate.Manager(d.overlord.State(), d.overlord.TaskRunner())
	c.Assert(err, check.IsNil)
	mgr, err := devicestate.Manager(d.overlord.State(), hookMgr, d.overlord.TaskRunner(), nil)
	c.Assert(err, check.IsNil)
	d.overlord.AddManager(mgr)

	body := `{"label":"1234","mode":"install"}`
	req, err := http.NewRequest("POST", "/v2/systems", strings.NewReader(body))
	c.Assert(err, check.IsNil)
	rsp := postSystems(systemsCmd, req, nil).(*resp)

	c.Assert(rsp.Type, check.Equals, ResponseTypeError)
	c.Check(rsp.Status, check.Equals, 404)
	c.Check(rsp.ErrorResult().Message, check.Equals, `requested seed system "1234" does not exist`)
}

func (s *apiSuite) TestSystemActionRequestHappy(c *check.C) {
	d := s.daemonWithOverlordMock(c)
	hookMgr, err := hookstate.Manager(d.overlord.State(), d.overlord.TaskRunner())
	c.Assert(err, check.IsNil)
	mgr, err := devicestate.Manager(d.overlord.State(), hookMgr, d.overlord.TaskRunner(), nil)
	c.Assert(err, check.IsNil)
	d.overlord.AddManager(mgr)

	restore := s.mockSystemSeeds(c)
	defer restore()

	body := `{"label":"20191119","mode":"install"}`
	req, err := http.NewRequest("POST", "/v2/systems", strings.NewReader(body))
	c.Assert(err, check.IsNil)
	rsp := postSystems(systemsCmd, req, nil).(*resp)
	c.Check(rsp.Status, check.Equals, 200)
}

func (s *apiSuite) TestSystemActionBrokenSeed(c *check.C) {
	d := s.daemonWithOverlordMock(c)
	hookMgr, err := hookstate.Manager(d.overlord.State(), d.overlord.TaskRunner())
	c.Assert(err, check.IsNil)
	mgr, err := devicestate.Manager(d.overlord.State(), hookMgr, d.overlord.TaskRunner(), nil)
	c.Assert(err, check.IsNil)
	d.overlord.AddManager(mgr)

	restore := s.mockSystemSeeds(c)
	defer restore()

	err = os.Remove(filepath.Join(dirs.SnapSeedDir, "systems", "20191119", "model"))
	c.Assert(err, check.IsNil)

	body := `{"label":"20191119","mode":"install"}`
	req, err := http.NewRequest("POST", "/v2/systems", strings.NewReader(body))
	c.Assert(err, check.IsNil)
	rsp := postSystems(systemsCmd, req, nil).(*resp)
	c.Check(rsp.Status, check.Equals, 500)
	c.Check(rsp.ErrorResult().Message, check.Matches, `cannot load seed system: cannot load assertions: .*`)
}
