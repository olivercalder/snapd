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
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/overlord/assertstate"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/state"
)

type validationSetResult struct {
	ValidationSet string `json:"validation-set,omitempty"`
	Mode          string `json:"mode"`
	Seq           int    `json:"seq,omitempty"`
	Valid         bool   `json:"valid"`
	// TODO: attributes for Notes column
}

func modeString(mode assertstate.ValidationSetMode) (string, error) {
	switch mode {
	case assertstate.Monitor:
		return "monitor", nil
	case assertstate.Enforce:
		return "enforce", nil
	}
	return "", fmt.Errorf("internal error: unhandled mode %d", mode)
}

func validationSetKeyString(accountID, name string, sequence int) string {
	key := assertstate.ValidationSetKey(accountID, name)
	if sequence != 0 {
		key = fmt.Sprintf("%s=%d", key, sequence)
	}
	return key
}

func validationSetNotFound(accountID, name string, sequence int) Response {
	res := &errorResult{
		Message: "validation set not found",
		Kind:    client.ErrorKindValidationSetNotFound,
		Value:   validationSetKeyString(accountID, name, sequence),
	}
	return &resp{
		Type:   ResponseTypeError,
		Result: res,
		Status: 404,
	}
}

func validationSetAccountAndName(validationSet string) (accountID, name string, err error) {
	parts := strings.Split(validationSet, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid validation-set argument")
	}
	accountID = parts[0]
	name = parts[1]
	if !asserts.IsValidAccountID(accountID) {
		return "", "", fmt.Errorf("invalid account ID %q", accountID)
	}
	if !asserts.IsValidValidationSetName(name) {
		return "", "", fmt.Errorf("invalid validation set name %q", name)
	}
	return accountID, name, nil
}

func listValidationSets(c *Command, r *http.Request, _ *auth.UserState) Response {
	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()

	validationSets, err := assertstate.ValidationSets(st)
	if err != nil {
		return InternalError("accessing validation sets failed: %v", err)
	}

	names := make([]string, 0, len(validationSets))
	for k := range validationSets {
		names = append(names, k)
	}
	sort.Strings(names)

	results := make([]validationSetResult, len(names))
	for i, vs := range names {
		tr := validationSets[vs]
		// TODO: evaluate against installed snaps
		var valid bool
		modeStr, err := modeString(tr.Mode)
		if err != nil {
			return InternalError(err.Error())
		}
		results[i] = validationSetResult{
			ValidationSet: validationSetKeyString(tr.AccountID, tr.Name, tr.PinnedAt),
			Mode:          modeStr,
			Seq:           tr.Current,
			Valid:         valid,
		}
	}

	return SyncResponse(results, nil)
}

func getValidationSet(c *Command, r *http.Request, _ *auth.UserState) Response {
	vars := muxVars(r)
	accountID := vars["account"]
	name := vars["name"]

	if !asserts.IsValidAccountID(accountID) {
		return BadRequest("invalid account ID %q", accountID)
	}
	if !asserts.IsValidValidationSetName(name) {
		return BadRequest("invalid name %q", name)
	}

	query := r.URL.Query()

	// sequence is optional
	sequenceStr := query.Get("sequence")
	var sequence int
	if sequenceStr != "" {
		var err error
		sequence, err = strconv.Atoi(sequenceStr)
		if err != nil {
			return BadRequest("invalid sequence argument")
		}
		if sequence < 0 {
			return BadRequest("invalid sequence argument: %d", sequence)
		}
	}

	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()

	var tr assertstate.ValidationSetTracking
	err := assertstate.GetValidationSet(st, accountID, name, &tr)
	if err == state.ErrNoState || (err == nil && sequence != 0 && sequence != tr.PinnedAt) {
		return validationSetNotFound(accountID, name, sequence)
	}
	if err != nil {
		return InternalError("accessing validation sets failed: %v", err)
	}

	modeStr, err := modeString(tr.Mode)
	if err != nil {
		return InternalError(err.Error())
	}
	// TODO: evaluate against installed snaps
	var valid bool
	res := validationSetResult{
		ValidationSet: validationSetKeyString(tr.AccountID, tr.Name, tr.PinnedAt),
		Mode:          modeStr,
		Seq:           tr.Current,
		Valid:         valid,
	}
	return SyncResponse(res, nil)
}

type validationSetApplyRequest struct {
	Action   string `json:"action"`
	Mode     string `json:"mode"`
	Sequence int    `json:"sequence,omitempty"`
}

func applyValidationSet(c *Command, r *http.Request, _ *auth.UserState) Response {
	vars := muxVars(r)
	accountID := vars["account"]
	name := vars["name"]

	if !asserts.IsValidAccountID(accountID) {
		return BadRequest("invalid account ID %q", accountID)
	}
	if !asserts.IsValidValidationSetName(name) {
		return BadRequest("invalid name %q", name)
	}

	var req validationSetApplyRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		return BadRequest("cannot decode request body into validation set action: %v", err)
	}
	if decoder.More() {
		return BadRequest("extra content found in request body")
	}
	if req.Sequence < 0 {
		return BadRequest("invalid sequence argument: %d", req.Sequence)
	}

	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()

	if req.Action == "forget" {
		return forgetValidationSet(st, accountID, name, req.Sequence)
	}
	if req.Action != "apply" {
		return BadRequest("unsupported action %q", req.Action)
	}

	var mode assertstate.ValidationSetMode
	switch req.Mode {
	case "monitor":
		mode = assertstate.Monitor
	case "enforce":
		mode = assertstate.Enforce
	default:
		return BadRequest("invalid mode %q", req.Mode)
	}

	// TODO: check that it exists in the store?

	tr := assertstate.ValidationSetTracking{
		AccountID: accountID,
		Name:      name,
		Mode:      mode,
		// note, Sequence may be 0, meaning not pinned.
		PinnedAt: req.Sequence,
	}
	assertstate.UpdateValidationSet(st, &tr)
	return SyncResponse(nil, nil)
}

func forgetValidationSet(st *state.State, accountID, name string, sequence int) Response {
	// check if it exists first
	var tr assertstate.ValidationSetTracking
	err := assertstate.GetValidationSet(st, accountID, name, &tr)
	if err == state.ErrNoState || (err == nil && sequence != 0 && sequence != tr.PinnedAt) {
		return validationSetNotFound(accountID, name, sequence)
	}
	if err != nil {
		return InternalError("accessing validation sets failed: %v", err)
	}
	assertstate.DeleteValidationSet(st, accountID, name)
	return SyncResponse(nil, nil)
}
