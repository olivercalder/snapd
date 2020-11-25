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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"gopkg.in/check.v1"

	"github.com/snapcore/snapd/overlord/assertstate"
	"github.com/snapcore/snapd/overlord/state"
)

var _ = check.Suite(&apiValidationSetsSuite{})

type apiValidationSetsSuite struct {
	apiBaseSuite
}

func (s *apiValidationSetsSuite) SetUpTest(c *check.C) {
	s.apiBaseSuite.SetUpTest(c)
	s.vars = map[string]string{"account": "foo", "name": "bar"}
}

func (s *apiValidationSetsSuite) TearDownTest(c *check.C) {
	s.apiBaseSuite.TearDownTest(c)
}

func mockValidationSetsTracking(st *state.State) {
	st.Set("validation-sets", map[string]interface{}{
		"foo/bar": map[string]interface{}{
			"account-id": "foo",
			"name":       "bar",
			"mode":       assertstate.Enforce,
			"pinned-at":  9,
			"current":    12,
		},
		"foo/baz": map[string]interface{}{
			"account-id": "foo",
			"name":       "baz",
			"mode":       assertstate.Monitor,
			"pinned-at":  0,
			"current":    2,
		},
	})
}

func (s *apiValidationSetsSuite) TestQueryValidationSetsErrors(c *check.C) {
	d := s.daemonWithOverlordMock(c)
	st := d.overlord.State()
	st.Lock()
	mockValidationSetsTracking(st)
	st.Unlock()

	for i, tc := range []struct {
		validationSet string
		// pinAt is normally an int, use string for passing invalid ones.
		pinAt   string
		message string
		status  int
	}{
		{
			validationSet: "ąśćź",
			message:       "invalid validation-set argument",
			status:        400,
		},
		{
			validationSet: "1foo/bar",
			message:       `invalid account name "1foo"`,
			status:        400,
		},
		{
			validationSet: "foo/1abc",
			message:       `invalid name "1abc"`,
			status:        400,
		},
		{
			validationSet: "foo/foo",
			message:       "validation set not found",
			status:        404,
		},
		{
			validationSet: "foo/bar",
			pinAt:         "1999",
			message:       "validation set not found",
			status:        404,
		},
		{
			validationSet: "foo/bar",
			pinAt:         "x",
			message:       "invalid pin-at argument",
			status:        400,
		},
	} {
		q := url.Values{}
		q.Set("validation-set", tc.validationSet)
		if tc.pinAt != "" {
			q.Set("pin-at", tc.pinAt)
		}
		req, err := http.NewRequest("GET", "/v2/validation-sets?"+q.Encode(), nil)
		c.Assert(err, check.IsNil)

		rsp := listValidationSets(validationSetsListCmd, req, nil).(*resp)

		c.Check(rsp.Type, check.Equals, ResponseTypeError, check.Commentf("case #%d", i))
		c.Check(rsp.Status, check.Equals, tc.status, check.Commentf("case #%d", i))
		c.Check(rsp.ErrorResult().Message, check.Matches, tc.message)
	}
}

func (s *apiValidationSetsSuite) TestQueryValidationSetsNone(c *check.C) {
	req, err := http.NewRequest("GET", "/v2/validation-sets", nil)
	c.Assert(err, check.IsNil)

	s.daemonWithOverlordMock(c)
	rsp := listValidationSets(validationSetsListCmd, req, nil).(*resp)

	c.Assert(rsp.Status, check.Equals, 200)
	res := rsp.Result.([]validationSetResult)
	c.Check(res, check.HasLen, 0)
}

func (s *apiValidationSetsSuite) TestQueryValidationSets(c *check.C) {
	req, err := http.NewRequest("GET", "/v2/validation-sets", nil)
	c.Assert(err, check.IsNil)

	d := s.daemonWithOverlordMock(c)
	st := d.overlord.State()
	st.Lock()
	mockValidationSetsTracking(st)
	st.Unlock()

	rsp := listValidationSets(validationSetsListCmd, req, nil).(*resp)

	c.Assert(rsp.Status, check.Equals, 200)
	res := rsp.Result.([]validationSetResult)
	c.Check(res, check.DeepEquals, []validationSetResult{
		{
			ValidationSet: "foo/bar=9",
			Mode:          "enforce",
			Seq:           12,
			Valid:         false,
		},
		{
			ValidationSet: "foo/baz",
			Mode:          "monitor",
			Seq:           2,
			Valid:         false,
		},
	})
}

func (s *apiValidationSetsSuite) TestQueryValidationSingleValidationSet(c *check.C) {
	req, err := http.NewRequest("GET", "/v2/validation-sets/foo/bar", nil)
	c.Assert(err, check.IsNil)

	d := s.daemonWithOverlordMock(c)
	st := d.overlord.State()
	st.Lock()
	mockValidationSetsTracking(st)
	st.Unlock()

	rsp := getValidationSet(validationSetsCmd, req, nil).(*resp)

	c.Assert(rsp.Status, check.Equals, 200)
	res := rsp.Result.(validationSetResult)
	c.Check(res, check.DeepEquals, validationSetResult{
		ValidationSet: "foo/bar=9",
		Mode:          "enforce",
		Seq:           12,
		Valid:         false,
	})
}

func (s *apiValidationSetsSuite) TestQueryValidationSingleValidationSetPinned(c *check.C) {
	q := url.Values{}
	q.Set("pin-at", "9")
	req, err := http.NewRequest("GET", "/v2/validation-sets/foo/bar"+q.Encode(), nil)
	c.Assert(err, check.IsNil)

	d := s.daemonWithOverlordMock(c)
	st := d.overlord.State()
	st.Lock()
	mockValidationSetsTracking(st)
	st.Unlock()

	rsp := getValidationSet(validationSetsCmd, req, nil).(*resp)

	c.Assert(rsp.Status, check.Equals, 200)
	res := rsp.Result.(validationSetResult)
	c.Check(res, check.DeepEquals, validationSetResult{
			ValidationSet: "foo/bar=9",
			Mode:          "enforce",
			Seq:           12,
			Valid:         false,
	})
}

func (s *apiValidationSetsSuite) TestQueryValidationSingleValidationSetNotFound(c *check.C) {
	s.vars = map[string]string{"account": "foo", "name": "other"}

	req, err := http.NewRequest("GET", "/v2/validation-sets/foo/other", nil)
	c.Assert(err, check.IsNil)

	d := s.daemonWithOverlordMock(c)
	st := d.overlord.State()
	st.Lock()
	mockValidationSetsTracking(st)
	st.Unlock()

	rsp := getValidationSet(validationSetsCmd, req, nil).(*resp)
	c.Assert(rsp.Status, check.Equals, 404)
	res := rsp.Result.(*errorResult)
	c.Assert(res, check.NotNil)
	c.Check(string(res.Kind), check.Equals, "validation-set-not-found")
	c.Check(res.Value, check.DeepEquals, "foo/other")
}

func (s *apiValidationSetsSuite) TestQueryValidationSingleValidationSetPinnedNotFound(c *check.C) {
	q := url.Values{}
	q.Set("pin-at", "333")
	req, err := http.NewRequest("GET", "/v2/validation-sets/foo/bar?"+q.Encode(), nil)
	c.Assert(err, check.IsNil)

	d := s.daemonWithOverlordMock(c)
	st := d.overlord.State()
	st.Lock()
	mockValidationSetsTracking(st)
	st.Unlock()

	rsp := getValidationSet(validationSetsCmd, req, nil).(*resp)
	c.Assert(rsp.Status, check.Equals, 404)
	res := rsp.Result.(*errorResult)
	c.Assert(res, check.NotNil)
	c.Check(string(res.Kind), check.Equals, "validation-set-not-found")
	c.Check(res.Value, check.DeepEquals, "foo/bar=333")
}

func (s *apiValidationSetsSuite) TestApplyValidationSet(c *check.C) {
	d := s.daemonWithOverlordMock(c)
	st := d.overlord.State()

	for _, tc := range []struct {
		mode  string
		pinAt int
		expectedMode  assertstate.ValidationSetMode
	}{
		{
			mode:  "enforce",
			pinAt: 12,
			expectedMode:  assertstate.Enforce,
		},
		{
			mode:  "monitor",
			pinAt: 99,
			expectedMode:  assertstate.Monitor,
		},
		{
			mode: "enforce",
			expectedMode: assertstate.Enforce,
		},
		{
			mode: "monitor",
			expectedMode: assertstate.Monitor,
		},
	} {
		var body string
		if tc.pinAt != 0 {
			body = fmt.Sprintf(`{"mode":"%s", "pin-at":%d}`, tc.mode, tc.pinAt)
		} else {
			body = fmt.Sprintf(`{"mode":"%s"}`, tc.mode)
		}
		
		req, err := http.NewRequest("POST", "/v2/validation-sets/foo/bar", strings.NewReader(body))
		c.Assert(err, check.IsNil)

		rsp := applyValidationSet(validationSetsCmd, req, nil).(*resp)
		c.Assert(rsp.Status, check.Equals, 200)

		var tr assertstate.ValidationSetTracking

		st.Lock()
		err = assertstate.GetValidationSet(st, "foo", "bar", &tr)
		st.Unlock()
		c.Assert(err, check.IsNil)
		c.Check(tr, check.DeepEquals, assertstate.ValidationSetTracking{
			AccountID: "foo",
			Name:      "bar",
			PinnedAt:  tc.pinAt,
			Mode:      tc.expectedMode,
		})
	}
}

func (s *apiValidationSetsSuite) TestForgetValidationSet(c *check.C) {
	d := s.daemonWithOverlordMock(c)
	st := d.overlord.State()

	for i, pinAt := range []int{0, 9} {
		st.Lock()
		mockValidationSetsTracking(st)
		st.Unlock()

		var body string
		if pinAt != 0 {
			body = fmt.Sprintf(`{"flag":"forget", "pin-at":%d}`, pinAt)
		} else {
			body = fmt.Sprintf(`{"flag":"forget"}`)
		}
		req, err := http.NewRequest("POST", "/v2/validation-sets/foo/bar", strings.NewReader(body))
		c.Assert(err, check.IsNil)

		var tr assertstate.ValidationSetTracking

		st.Lock()
		// sanity, it exists before removing
		err = assertstate.GetValidationSet(st, "foo", "bar", &tr)
		st.Unlock()
		c.Assert(err, check.IsNil)
		c.Check(tr.AccountID, check.Equals, "foo")
		c.Check(tr.Name, check.Equals, "bar")

		rsp := applyValidationSet(validationSetsCmd, req, nil).(*resp)
		c.Check(rsp.Status, check.Equals, 200, check.Commentf("case #%d", i))

		// after forget it's removed
		st.Lock()
		err = assertstate.GetValidationSet(st, "foo", "bar", &tr)
		st.Unlock()
		c.Check(err, check.Equals, state.ErrNoState)

		// and forget again fails
		req, err = http.NewRequest("POST", "/v2/validation-sets/foo/bar", strings.NewReader(body))
		c.Assert(err, check.IsNil)
		rsp = applyValidationSet(validationSetsCmd, req, nil).(*resp)
		c.Check(rsp.Status, check.Equals, 404, check.Commentf("case #%d", i))
	}
}

func (s *apiValidationSetsSuite) TestApplyValidationSetsErrors(c *check.C) {
	d := s.daemonWithOverlordMock(c)
	st := d.overlord.State()
	st.Lock()
	mockValidationSetsTracking(st)
	st.Unlock()

	for i, tc := range []struct {
		validationSet string
		flag          string
		// pinAt is normally an int, use string for passing invalid ones.
		pinAt   string
		message string
		status  int
	}{
		{
			validationSet: "zzz",
			flag:          "monitor",
			message:       `invalid account name ""`,
			status:        400,
		},
		{
			validationSet: "1foo/bar",
			flag:          "monitor",
			message:       `invalid account name "1foo"`,
			status:        400,
		},
		{
			validationSet: "foo/1abc",
			flag:          "monitor",
			message:       `invalid name "1abc"`,
			status:        400,
		},
		{
			validationSet: "foo/bar",
			pinAt:         "x",
			message:       "cannot decode request body into validation set action: invalid character 'x' looking for beginning of value",
			status:        400,
		},
		{
			validationSet: "foo/bar",
			flag:          "bad",
			message:       `invalid mode "bad"`,
			status:        400,
		},
	} {
		//q := url.Values{}
		//if tc.pinAt != "" {
		//	q.Set("pin-at", tc.pinAt)
		//}
		var body string
		if tc.pinAt != "" {
			body = fmt.Sprintf(`{"mode":"%s", "pin-at":%s}`, tc.flag, tc.pinAt)
		} else {
			body = fmt.Sprintf(`{"mode":"%s"}`, tc.flag)
		}
		req, err := http.NewRequest("POST", fmt.Sprintf("/v2/validation-sets/%s", tc.validationSet), strings.NewReader(body))
		c.Assert(err, check.IsNil)
		rsp := applyValidationSet(validationSetsCmd, req, nil).(*resp)

		c.Check(rsp.Type, check.Equals, ResponseTypeError, check.Commentf("case #%d", i))
		c.Check(rsp.Status, check.Equals, tc.status, check.Commentf("case #%d", i))
		c.Check(rsp.ErrorResult().Message, check.Matches, tc.message)
	}
}
