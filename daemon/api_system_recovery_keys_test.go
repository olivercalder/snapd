// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2022 Canonical Ltd
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
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/daemon"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/snapstate/snapstatetest"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/secboot/keys"
	"github.com/snapcore/snapd/snap/snaptest"
)

var _ = Suite(&recoveryKeysSuite{})

type recoveryKeysSuite struct {
	apiBaseSuite
}

func (s *recoveryKeysSuite) SetUpTest(c *C) {
	s.apiBaseSuite.SetUpTest(c)

	s.expectRootAccess()
}

func mockSystemRecoveryKeys(c *C) {
	// same inputs/outputs as secboot:crypt_test.go in this test
	rkeystr, err := hex.DecodeString("e1f01302c5d43726a9b85b4a8d9c7f6e")
	c.Assert(err, IsNil)
	rkeyPath := filepath.Join(dirs.SnapFDEDir, "recovery.key")
	err = os.MkdirAll(filepath.Dir(rkeyPath), 0755)
	c.Assert(err, IsNil)
	err = os.WriteFile(rkeyPath, []byte(rkeystr), 0644)
	c.Assert(err, IsNil)

	skeystr := "1234567890123456"
	c.Assert(err, IsNil)
	skeyPath := filepath.Join(dirs.SnapFDEDir, "reinstall.key")
	err = os.WriteFile(skeyPath, []byte(skeystr), 0644)
	c.Assert(err, IsNil)
}

func (s *recoveryKeysSuite) TestGetSystemRecoveryKeysAsRootHappy(c *C) {
	if (keys.RecoveryKey{}).String() == "not-implemented" {
		c.Skip("needs working secboot recovery key")
	}

	s.daemon(c)
	mockSystemRecoveryKeys(c)

	req, err := http.NewRequest("GET", "/v2/system-recovery-keys", nil)
	c.Assert(err, IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)
	c.Assert(rsp.Status, Equals, 200)
	srk := rsp.Result.(*client.SystemRecoveryKeysResponse)
	c.Assert(srk, DeepEquals, &client.SystemRecoveryKeysResponse{
		RecoveryKey:  "61665-00531-54469-09783-47273-19035-40077-28287",
		ReinstallKey: "12849-13363-13877-14391-12345-12849-13363-13877",
	})
}

func (s *recoveryKeysSuite) TestGetSystemRecoveryKeysAsUserErrors(c *C) {
	s.daemon(c)
	mockSystemRecoveryKeys(c)

	req, err := http.NewRequest("GET", "/v2/system-recovery-keys", nil)
	c.Assert(err, IsNil)

	// being properly authorized as user is not enough, needs root
	s.asUserAuth(c, req)
	rec := httptest.NewRecorder()
	s.serveHTTP(c, rec, req)
	c.Assert(rec.Code, Equals, 403)
}

func (s *recoveryKeysSuite) TestPostSystemRecoveryKeysActionRemove(c *C) {
	s.daemon(c)

	called := 0
	defer daemon.MockDeviceManagerRemoveRecoveryKeys(func() error {
		called++
		return nil
	})()

	buf := bytes.NewBufferString(`{"action":"remove"}`)
	req, err := http.NewRequest("POST", "/v2/system-recovery-keys", buf)
	c.Assert(err, IsNil)
	rsp := s.syncReq(c, req, nil, actionIsExpected)
	c.Check(rsp.Status, Equals, 200)
	c.Check(called, Equals, 1)
}

func (s *recoveryKeysSuite) TestPostSystemRecoveryKeysAsUserErrors(c *C) {
	s.daemon(c)
	mockSystemRecoveryKeys(c)

	req, err := http.NewRequest("POST", "/v2/system-recovery-keys", nil)
	c.Assert(err, IsNil)

	// being properly authorized as user is not enough, needs root
	s.asUserAuth(c, req)
	rec := httptest.NewRecorder()
	s.serveHTTP(c, rec, req)
	c.Assert(rec.Code, Equals, 403)
}

func (s *recoveryKeysSuite) TestPostSystemRecoveryKeysBadAction(c *C) {
	s.daemon(c)

	called := 0
	defer daemon.MockDeviceManagerRemoveRecoveryKeys(func() error {
		called++
		return nil
	})()

	buf := bytes.NewBufferString(`{"action":"unknown"}`)
	req, err := http.NewRequest("POST", "/v2/system-recovery-keys", buf)
	c.Assert(err, IsNil)

	rspe := s.errorReq(c, req, nil, actionIsUnexpected)
	c.Check(rspe, DeepEquals, daemon.BadRequest(`unsupported recovery keys action "unknown"`))
	c.Check(called, Equals, 0)
}

func (s *recoveryKeysSuite) TestPostSystemRecoveryKeysActionRemoveError(c *C) {
	s.daemon(c)

	called := 0
	defer daemon.MockDeviceManagerRemoveRecoveryKeys(func() error {
		called++
		return errors.New("boom")
	})()

	buf := bytes.NewBufferString(`{"action":"remove"}`)
	req, err := http.NewRequest("POST", "/v2/system-recovery-keys", buf)
	c.Assert(err, IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe, DeepEquals, daemon.InternalError("boom"))
	c.Check(called, Equals, 1)
}

func (s *recoveryKeysSuite) TestGetSystemRecoveryKeysFailsOnHybrid(c *C) {
	s.daemon(c)
	mockSystemRecoveryKeys(c)

	restore := release.MockReleaseInfo(&release.OS{
		ID:        "ubuntu",
		VersionID: "25.10",
	})
	defer restore()

	// create a hybrid classic model that results in this API being disabled
	model := s.Brands.Model("can0nical", "pc-new", map[string]any{
		"classic":      "true",
		"distribution": "ubuntu",
		"architecture": "amd64",
		"base":         "core24",
		"snaps": []any{
			map[string]any{
				"name": "pc-kernel",
				"id":   snaptest.AssertedSnapID("pc-kernel"),
				"type": "kernel",
			},
			map[string]any{
				"name": "pc",
				"id":   snaptest.AssertedSnapID("pc"),
				"type": "gadget",
			},
		},
	})
	restore = snapstatetest.MockDeviceModel(model)
	defer restore()

	req, err := http.NewRequest("GET", "/v2/system-recovery-keys", nil)
	c.Assert(err, IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, Equals, 400)
	c.Check(rspe.Message, Equals, "this action is not supported on 25.10+ classic systems")
}

func (s *recoveryKeysSuite) TestPostSystemRecoveryKeysFailsOnHybrid(c *C) {
	s.daemon(c)
	mockSystemRecoveryKeys(c)

	restore := release.MockReleaseInfo(&release.OS{
		ID:        "ubuntu",
		VersionID: "25.10",
	})
	defer restore()

	// create a hybrid classic model that results in this API being disabled
	model := s.Brands.Model("can0nical", "pc-new", map[string]any{
		"classic":      "true",
		"distribution": "ubuntu",
		"architecture": "amd64",
		"base":         "core24",
		"snaps": []any{
			map[string]any{
				"name": "pc-kernel",
				"id":   snaptest.AssertedSnapID("pc-kernel"),
				"type": "kernel",
			},
			map[string]any{
				"name": "pc",
				"id":   snaptest.AssertedSnapID("pc"),
				"type": "gadget",
			},
		},
	})
	restore = snapstatetest.MockDeviceModel(model)
	defer restore()

	req, err := http.NewRequest("POST", "/v2/system-recovery-keys", strings.NewReader(`{"action": "remove"}`))
	c.Assert(err, IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, Equals, 400)
	c.Check(rspe.Message, Equals, "this action is not supported on 25.10+ classic systems")
}

func (s *recoveryKeysSuite) TestPostSystemRecoveryKeysFailsWithoutModel(c *C) {
	s.daemon(c)
	mockSystemRecoveryKeys(c)

	restore := release.MockReleaseInfo(&release.OS{
		ID:        "ubuntu",
		VersionID: "25.10",
	})
	defer restore()

	// unset our model, the route should detect this and fail
	restore = snapstatetest.MockDeviceModel(nil)
	defer restore()

	req, err := http.NewRequest("POST", "/v2/system-recovery-keys", strings.NewReader(`{"action": "remove"}`))
	c.Assert(err, IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, Equals, 400)
	c.Check(rspe.Message, Equals, "cannot use this API prior to device having a model")
}
