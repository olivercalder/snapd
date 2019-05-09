// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017 Canonical Ltd
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

package healthstate

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/hookstate"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/strutil"
)

var checkTimeout = 30 * time.Second

func init() {
	if s, ok := os.LookupEnv("SNAPD_CHECK_HEALTH_HOOK_TIMEOUT"); ok {
		if to, err := time.ParseDuration(s); err == nil {
			checkTimeout = to
		} else {
			logger.Debugf("cannot override check-health timeout: %v", err)
		}
	}

	snapstate.HealthCheckHook = CheckHook
}

func CheckHook(st *state.State, snapName string) *state.Task {
	summary := fmt.Sprintf("Run health check of %q snap", snapName)
	hooksup := &hookstate.HookSetup{
		Snap:     snapName,
		Hook:     "check-health",
		Optional: true,
		Timeout:  checkTimeout,
	}

	return hookstate.HookTask(st, summary, hooksup, nil)
}

type HealthStatus int

const (
	UnknownStatus = HealthStatus(iota)
	OkayStatus
	WaitingStatus
	BlockedStatus
	ErrorStatus
)

var knownStatuses = []string{"unknown", "okay", "waiting", "blocked", "error"}

func StatusLookup(str string) (HealthStatus, error) {
	for i, k := range knownStatuses {
		if k == str {
			return HealthStatus(i), nil
		}
	}
	return -1, fmt.Errorf("invalid status %q, must be one of %s", str, strutil.Quoted(knownStatuses))
}

func (s HealthStatus) String() string {
	if s < 0 || s >= HealthStatus(len(knownStatuses)) {
		return fmt.Sprintf("invalid (%d)", s)
	}
	return knownStatuses[s]
}

type HealthState struct {
	Revision  snap.Revision `json:"revision"`
	Timestamp time.Time     `json:"timestamp"`
	Status    HealthStatus  `json:"status"`
	Message   string        `json:"message,omitempty"`
	Code      string        `json:"code,omitempty"`
}

func Init(hookManager *hookstate.HookManager) {
	hookManager.Register(regexp.MustCompile("^check-health$"), newHealthHandler)
}

func newHealthHandler(ctx *hookstate.Context) hookstate.Handler {
	return &healthHandler{context: ctx}
}

type healthHandler struct {
	context *hookstate.Context
}

// Before is called just before the hook runs -- nothing to do
func (*healthHandler) Before() error {
	return nil
}

func (h *healthHandler) Done() error {
	var health HealthState

	h.context.Lock()
	err := h.context.Get("health", &health)
	h.context.Unlock()

	if err != nil {
		if err != state.ErrNoState {
			return err
		}
		health = HealthState{
			Revision:  h.context.SnapRevision(),
			Timestamp: time.Now(),
			Status:    UnknownStatus,
			Message:   "hook did not call set-health",
		}
	}

	return h.appendHealth(&health)
}

func (h *healthHandler) Error(err error) error {
	return h.appendHealth(&HealthState{
		Revision:  h.context.SnapRevision(),
		Timestamp: time.Now(),
		Status:    UnknownStatus,
		Code:      "snapd-hook-failed",
		Message:   "hook failed",
	})
}

func (h *healthHandler) appendHealth(health *HealthState) error {
	st := h.context.State()
	st.Lock()
	defer st.Unlock()

	var hs map[string]*HealthState
	if err := st.Get("health", &hs); err != nil {
		if err != state.ErrNoState {
			return err
		}
		hs = map[string]*HealthState{}
	}
	hs[h.context.InstanceName()] = health
	st.Set("health", hs)

	return nil
}
