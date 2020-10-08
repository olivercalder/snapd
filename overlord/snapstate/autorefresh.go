// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017-2020 Canonical Ltd
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

package snapstate

import (
	"fmt"
	"os"
	"time"

	"github.com/snapcore/snapd/httputil"
	"github.com/snapcore/snapd/i18n"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/configstate/config"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/strutil"
	"github.com/snapcore/snapd/timeutil"
	"github.com/snapcore/snapd/timings"
)

// the default refresh pattern
const defaultRefreshSchedule = "00:00~24:00/4"

// cannot keep without refreshing for more than maxPostponement
const maxPostponement = 60 * 24 * time.Hour

// cannot inhibit refreshes for more than maxInhibition
const maxInhibition = 7 * 24 * time.Hour

// hooks setup by devicestate
var (
	CanAutoRefresh        func(st *state.State) (bool, error)
	CanManageRefreshes    func(st *state.State) bool
	IsOnMeteredConnection func() (bool, error)
)

// refreshRetryDelay specified the minimum time to retry failed refreshes
var refreshRetryDelay = 20 * time.Minute

// autoRefresh will ensure that snaps are refreshed automatically
// according to the refresh schedule.
type autoRefresh struct {
	state *state.State

	lastRefreshSchedule string
	nextRefresh         time.Time
	lastRefreshAttempt  time.Time
	managedDeniedLogged bool
}

func newAutoRefresh(st *state.State) *autoRefresh {
	return &autoRefresh{
		state: st,
	}
}

// RefreshSchedule will return a user visible string with the current schedule
// for the automatic refreshes and a flag indicating whether the schedule is a
// legacy one.
func (m *autoRefresh) RefreshSchedule() (schedule string, legacy bool, err error) {
	_, schedule, legacy, err = m.refreshScheduleWithDefaultsFallback()
	return schedule, legacy, err
}

// NextRefresh returns when the next automatic refresh will happen.
func (m *autoRefresh) NextRefresh() time.Time {
	return m.nextRefresh
}

// LastRefresh returns when the last refresh happened.
func (m *autoRefresh) LastRefresh() (time.Time, error) {
	return getTime(m.state, "last-refresh")
}

// EffectiveRefreshHold returns the time until to which refreshes are
// held if refresh.hold configuration is set and accounting for the
// max postponement since the last refresh.
func (m *autoRefresh) EffectiveRefreshHold() (time.Time, error) {
	var holdTime time.Time

	tr := config.NewTransaction(m.state)
	err := tr.Get("core", "refresh.hold", &holdTime)
	if err != nil && !config.IsNoOption(err) {
		return time.Time{}, err
	}

	// cannot hold beyond last-refresh + max-postponement
	lastRefresh, err := m.LastRefresh()
	if err != nil {
		return time.Time{}, err
	}
	if lastRefresh.IsZero() {
		seedTime, err := getTime(m.state, "seed-time")
		if err != nil {
			return time.Time{}, err
		}
		if seedTime.IsZero() {
			// no reference to know whether holding is reasonable
			return time.Time{}, nil
		}
		lastRefresh = seedTime
	}

	limitTime := lastRefresh.Add(maxPostponement)
	if holdTime.After(limitTime) {
		return limitTime, nil
	}

	return holdTime, nil
}

func (m *autoRefresh) ensureRefreshHoldAtLeast(duration time.Duration) error {
	now := time.Now()

	// get the effective refresh hold and check if it is sooner than the
	// specified duration in the future
	effective, err := m.EffectiveRefreshHold()
	if err != nil {
		return err
	}

	if effective.IsZero() || effective.Sub(now) < duration {
		// the effective refresh hold is sooner than the desired delay, so
		// move it out to the specified duration
		holdTime := now.Add(duration)
		tr := config.NewTransaction(m.state)
		err := tr.Set("core", "refresh.hold", &holdTime)
		if err != nil && !config.IsNoOption(err) {
			return err
		}
		tr.Commit()
	}

	return nil
}

// clearRefreshHold clears refresh.hold configuration.
func (m *autoRefresh) clearRefreshHold() {
	tr := config.NewTransaction(m.state)
	tr.Set("core", "refresh.hold", nil)
	tr.Commit()
}

// AtSeed configures refresh policies at end of seeding.
func (m *autoRefresh) AtSeed() error {
	// on classic hold refreshes for 2h after seeding
	if release.OnClassic {
		var t1 time.Time
		tr := config.NewTransaction(m.state)
		err := tr.Get("core", "refresh.hold", &t1)
		if !config.IsNoOption(err) {
			// already set or error
			return err
		}
		// TODO: have a policy that if the snapd exe itself
		// is older than X weeks/months we skip the holding?
		now := time.Now().UTC()
		tr.Set("core", "refresh.hold", now.Add(2*time.Hour))
		tr.Commit()
		m.nextRefresh = now
	}
	return nil
}

func canRefreshOnMeteredConnection(st *state.State) (bool, error) {
	tr := config.NewTransaction(st)
	var onMetered string
	err := tr.GetMaybe("core", "refresh.metered", &onMetered)
	if err != nil && err != state.ErrNoState {
		return false, err
	}

	return onMetered != "hold", nil
}

func (m *autoRefresh) canRefreshRespectingMetered(now, lastRefresh time.Time) (can bool, err error) {
	can, err = canRefreshOnMeteredConnection(m.state)
	if err != nil {
		return false, err
	}
	if can {
		return true, nil
	}

	// ignore any errors that occurred while checking if we are on a metered
	// connection
	metered, _ := IsOnMeteredConnection()
	if !metered {
		return true, nil
	}

	if now.Sub(lastRefresh) >= maxPostponement {
		// TODO use warnings when the infra becomes available
		logger.Noticef("Auto refresh disabled while on metered connections, but pending for too long (%d days). Trying to refresh now.", int(maxPostponement.Hours()/24))
		return true, nil
	}

	logger.Debugf("Auto refresh disabled on metered connections")

	return false, nil
}

// Ensure ensures that we refresh all installed snaps periodically
func (m *autoRefresh) Ensure() error {
	m.state.Lock()
	defer m.state.Unlock()

	// see if it even makes sense to try to refresh
	if CanAutoRefresh == nil {
		return nil
	}
	if ok, err := CanAutoRefresh(m.state); err != nil || !ok {
		return err
	}

	// get lastRefresh and schedule
	lastRefresh, err := m.LastRefresh()
	if err != nil {
		return err
	}

	refreshSchedule, refreshScheduleStr, _, err := m.refreshScheduleWithDefaultsFallback()
	if err != nil {
		return err
	}
	if len(refreshSchedule) == 0 {
		m.nextRefresh = time.Time{}
		return nil
	}
	// we already have a refresh time, check if we got a new config
	if !m.nextRefresh.IsZero() {
		if m.lastRefreshSchedule != refreshScheduleStr {
			// the refresh schedule has changed
			logger.Debugf("Refresh timer changed.")
			m.nextRefresh = time.Time{}
		}
	}
	m.lastRefreshSchedule = refreshScheduleStr

	// ensure nothing is in flight already
	if autoRefreshInFlight(m.state) {
		return nil
	}

	now := time.Now()
	// compute next refresh attempt time (if needed)
	if m.nextRefresh.IsZero() {
		// store attempts in memory so that we can backoff
		if !lastRefresh.IsZero() {
			delta := timeutil.Next(refreshSchedule, lastRefresh, maxPostponement)
			now = time.Now()
			m.nextRefresh = now.Add(delta)
		} else {
			// make sure either seed-time or last-refresh
			// are set for hold code below
			m.ensureLastRefreshAnchor()
			// immediate
			m.nextRefresh = now
		}
		logger.Debugf("Next refresh scheduled for %s.", m.nextRefresh.Format(time.RFC3339))
	}

	held, holdTime, err := m.isRefreshHeld(refreshSchedule)
	if err != nil {
		return err
	}

	// do refresh attempt (if needed)
	if !held {
		if !holdTime.IsZero() {
			// expired hold case
			m.clearRefreshHold()
			if m.nextRefresh.Before(holdTime) {
				// next refresh is obsolete, compute the next one
				delta := timeutil.Next(refreshSchedule, holdTime, maxPostponement)
				now = time.Now()
				m.nextRefresh = now.Add(delta)
			}
		}

		// refresh is also "held" if the next time is in the future
		// note that the two times here could be exactly equal, so we use
		// !After() because that is true in the case that the next refresh is
		// before now, and the next refresh is equal to now without requiring an
		// or operation
		if !m.nextRefresh.After(now) {
			var can bool
			can, err = m.canRefreshRespectingMetered(now, lastRefresh)
			if err != nil {
				return err
			}
			if !can {
				// clear nextRefresh so that another refresh time is calculated
				m.nextRefresh = time.Time{}
				return nil
			}

			// Check that we have reasonable delays between attempts.
			// If the store is under stress we need to make sure we do not
			// hammer it too often
			if !m.lastRefreshAttempt.IsZero() && m.lastRefreshAttempt.Add(refreshRetryDelay).After(time.Now()) {
				return nil
			}

			err = m.launchAutoRefresh(refreshSchedule)
			if _, ok := err.(*httputil.PersistentNetworkError); !ok {
				m.nextRefresh = time.Time{}
			} // else - refresh will be retried after refreshRetryDelay
		}
	}

	return err
}

// isRefreshHeld returns whether an auto-refresh is currently held back or not,
// as indicated by m.EffectiveRefreshHold().
func (m *autoRefresh) isRefreshHeld(refreshSchedule []*timeutil.Schedule) (bool, time.Time, error) {
	now := time.Now()
	// should we hold back refreshes?
	holdTime, err := m.EffectiveRefreshHold()
	if err != nil {
		return false, time.Time{}, err
	}
	if holdTime.After(now) {
		return true, holdTime, nil
	}

	return false, holdTime, nil
}

func (m *autoRefresh) ensureLastRefreshAnchor() {
	seedTime, _ := getTime(m.state, "seed-time")
	if !seedTime.IsZero() {
		return
	}

	// last core refresh
	coreRefreshDate := snap.InstallDate("core")
	if !coreRefreshDate.IsZero() {
		m.state.Set("last-refresh", coreRefreshDate)
		return
	}

	// fallback to executable time
	st, err := os.Stat("/proc/self/exe")
	if err == nil {
		m.state.Set("last-refresh", st.ModTime())
		return
	}
}

// refreshScheduleWithDefaultsFallback returns the current refresh schedule
// and refresh string. When an invalid refresh schedule is set by the user
// the refresh schedule is automatically reset to the default.
//
// TODO: we can remove the refreshSchedule reset because we have validation
//       of the schedule now.
func (m *autoRefresh) refreshScheduleWithDefaultsFallback() (ts []*timeutil.Schedule, scheduleAsStr string, legacy bool, err error) {
	managed, requested, legacy := refreshScheduleManaged(m.state)
	if managed {
		if m.lastRefreshSchedule != "managed" {
			logger.Noticef("refresh is managed via the snapd-control interface")
			m.lastRefreshSchedule = "managed"
		}
		m.managedDeniedLogged = false
		return nil, "managed", legacy, nil
	} else if requested {
		// managed refresh schedule was denied
		if !m.managedDeniedLogged {
			logger.Noticef("managed refresh schedule denied, no properly configured snapd-control")
			m.managedDeniedLogged = true
		}
		// fallback to default schedule
		return refreshScheduleDefault()
	} else {
		m.managedDeniedLogged = false
	}

	tr := config.NewTransaction(m.state)
	// try the new refresh.timer config option first
	err = tr.Get("core", "refresh.timer", &scheduleAsStr)
	if err != nil && !config.IsNoOption(err) {
		return nil, "", false, err
	}
	if scheduleAsStr != "" {
		ts, err = timeutil.ParseSchedule(scheduleAsStr)
		if err != nil {
			logger.Noticef("cannot use refresh.timer configuration: %s", err)
			return refreshScheduleDefault()
		}
		return ts, scheduleAsStr, false, nil
	}

	// fallback to legacy refresh.schedule setting when the new
	// config option is not set
	err = tr.Get("core", "refresh.schedule", &scheduleAsStr)
	if err != nil && !config.IsNoOption(err) {
		return nil, "", false, err
	}
	if scheduleAsStr != "" {
		ts, err = timeutil.ParseLegacySchedule(scheduleAsStr)
		if err != nil {
			logger.Noticef("cannot use refresh.schedule configuration: %s", err)
			return refreshScheduleDefault()
		}
		return ts, scheduleAsStr, true, nil
	}

	return refreshScheduleDefault()
}

// launchAutoRefresh creates the auto-refresh taskset and a change for it.
func (m *autoRefresh) launchAutoRefresh(refreshSchedule []*timeutil.Schedule) error {
	perfTimings := timings.New(map[string]string{"ensure": "auto-refresh"})
	tm := perfTimings.StartSpan("auto-refresh", "query store and setup auto-refresh change")
	defer func() {
		tm.Stop()
		perfTimings.Save(m.state)
	}()

	m.lastRefreshAttempt = time.Now()

	// NOTE: this will unlock and re-lock state for network ops
	updated, tasksets, err := AutoRefresh(auth.EnsureContextTODO(), m.state)

	// TODO: we should have some way to lock just creating and starting changes,
	//       as that would alleviate this race condition we are guarding against
	//       with this check and probably would eliminate other similar race
	//       conditions elsewhere

	// re-check if the refresh is held because it could have been re-held and
	// pushed back, in which case we need to abort the auto-refresh and wait
	held, _, holdErr := m.isRefreshHeld(refreshSchedule)
	if holdErr != nil {
		return holdErr
	}

	if held {
		// then a request came in that pushed the refresh out, so we will need
		// to try again later
		logger.Noticef("Auto-refresh was delayed mid-way through launching, aborting to try again later")
		return nil
	}

	if _, ok := err.(*httputil.PersistentNetworkError); ok {
		logger.Noticef("Cannot prepare auto-refresh change due to a permanent network error: %s", err)
		return err
	}
	m.state.Set("last-refresh", time.Now())
	if err != nil {
		logger.Noticef("Cannot prepare auto-refresh change: %s", err)
		return err
	}

	var msg string
	switch len(updated) {
	case 0:
		logger.Noticef(i18n.G("auto-refresh: all snaps are up-to-date"))
		return nil
	case 1:
		msg = fmt.Sprintf(i18n.G("Auto-refresh snap %q"), updated[0])
	case 2, 3:
		quoted := strutil.Quoted(updated)
		// TRANSLATORS: the %s is a comma-separated list of quoted snap names
		msg = fmt.Sprintf(i18n.G("Auto-refresh snaps %s"), quoted)
	default:
		msg = fmt.Sprintf(i18n.G("Auto-refresh %d snaps"), len(updated))
	}

	chg := m.state.NewChange("auto-refresh", msg)
	for _, ts := range tasksets {
		chg.AddAll(ts)
	}
	chg.Set("snap-names", updated)
	chg.Set("api-data", map[string]interface{}{"snap-names": updated})
	state.TagTimingsWithChange(perfTimings, chg)

	return nil
}

func refreshScheduleDefault() (ts []*timeutil.Schedule, scheduleStr string, legacy bool, err error) {
	refreshSchedule, err := timeutil.ParseSchedule(defaultRefreshSchedule)
	if err != nil {
		panic(fmt.Sprintf("defaultRefreshSchedule cannot be parsed: %s", err))
	}

	return refreshSchedule, defaultRefreshSchedule, false, nil
}

func autoRefreshInFlight(st *state.State) bool {
	for _, chg := range st.Changes() {
		if chg.Kind() == "auto-refresh" && !chg.Status().Ready() {
			return true
		}
	}
	return false
}

// refreshScheduleManaged returns true if the refresh schedule of the
// device is managed by an external snap
func refreshScheduleManaged(st *state.State) (managed, requested, legacy bool) {
	var confStr string

	// this will only be "nil" if running in tests
	if CanManageRefreshes == nil {
		return false, false, legacy
	}

	// check new style timer first
	tr := config.NewTransaction(st)
	err := tr.Get("core", "refresh.timer", &confStr)
	if err != nil && !config.IsNoOption(err) {
		return false, false, legacy
	}
	// if not set, fallback to refresh.schedule
	if confStr == "" {
		if err := tr.Get("core", "refresh.schedule", &confStr); err != nil {
			return false, false, legacy
		}
		legacy = true
	}

	if confStr != "managed" {
		return false, false, legacy
	}

	return CanManageRefreshes(st), true, legacy
}

// getTime retrieves a time from a state value.
func getTime(st *state.State, timeKey string) (time.Time, error) {
	var t1 time.Time
	err := st.Get(timeKey, &t1)
	if err != nil && err != state.ErrNoState {
		return time.Time{}, err
	}
	return t1, nil
}

// inhibitRefresh returns an error if refresh is inhibited by running apps.
//
// Internally the snap state is updated to remember when the inhibition first
// took place. Apps can inhibit refreshes for up to "maxInhibition", beyond
// that period the refresh will go ahead despite application activity.
func inhibitRefresh(st *state.State, snapst *SnapState, info *snap.Info, checker func(*snap.Info) error) error {
	if err := checker(info); err != nil {
		days := int(maxInhibition.Truncate(time.Hour).Hours() / 24)
		now := time.Now()
		if snapst.RefreshInhibitedTime == nil {
			// Store the instant when the snap was first inhibited.
			// This is reset to nil on successful refresh.
			snapst.RefreshInhibitedTime = &now
			Set(st, info.InstanceName(), snapst)
			if _, ok := err.(*BusySnapError); ok {
				st.Warnf(i18n.NG(
					"snap %q is currently in use. Its refresh will be postponed for up to %d day to wait for the snap to no longer be in use.",
					"snap %q is currently in use. Its refresh will be postponed for up to %d days to wait for the snap to no longer be in use.", days),
					info.SnapName(), days)
			}
			return err
		}

		if now.Sub(*snapst.RefreshInhibitedTime) < maxInhibition {
			// If we are still in the allowed window then just return
			// the error but don't change the snap state again.
			return err
		}
		if _, ok := err.(*BusySnapError); ok {
			st.Warnf(i18n.NG(
				"snap %q has been running for the maximum allowable %d day since its refresh was postponed. It will now be refreshed.",
				"snap %q has been running for the maximum allowable %d days since its refresh was postponed. It will now be refreshed.", days),
				info.SnapName(), days)
		}
	}
	return nil
}
