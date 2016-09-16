// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016 Canonical Ltd
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

// Package assertstate implements the manager and state aspects responsible
// for the enforcement of assertions in the system and manages the system-wide
// assertion database.
package assertstate

import (
	"fmt"
	"strings"

	"gopkg.in/tomb.v2"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/snapasserts"
	"github.com/snapcore/snapd/asserts/sysdb"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/store"
)

// AssertManager is responsible for the enforcement of assertions in
// system states. It manipulates the observed system state to ensure
// nothing in it violates existing assertions, or misses required
// ones.
type AssertManager struct {
	runner *state.TaskRunner
}

// Manager returns a new assertion manager.
func Manager(s *state.State) (*AssertManager, error) {
	runner := state.NewTaskRunner(s)

	runner.AddHandler("validate-snap", doValidateSnap, nil)

	db, err := sysdb.Open()
	if err != nil {
		return nil, err
	}

	s.Lock()
	ReplaceDB(s, db)
	s.Unlock()

	return &AssertManager{runner: runner}, nil
}

// Ensure implements StateManager.Ensure.
func (m *AssertManager) Ensure() error {
	m.runner.Ensure()
	return nil
}

// Wait implements StateManager.Wait.
func (m *AssertManager) Wait() {
	m.runner.Wait()
}

// Stop implements StateManager.Stop.
func (m *AssertManager) Stop() {
	m.runner.Stop()
}

type cachedDBKey struct{}

// ReplaceDB replaces the assertion database used by the manager.
func ReplaceDB(state *state.State, db *asserts.Database) {
	state.Cache(cachedDBKey{}, db)
}

func cachedDB(s *state.State) *asserts.Database {
	db := s.Cached(cachedDBKey{})
	if db == nil {
		panic("internal error: needing an assertion database before the assertion manager is initialized")
	}
	return db.(*asserts.Database)
}

// DB returns a read-only view of system assertion database.
func DB(s *state.State) asserts.RODatabase {
	return cachedDB(s)
}

// Add the given assertion to the system assertiond database. Readding the current revision is a no-op.
func Add(s *state.State, a asserts.Assertion) error {
	// TODO: deal together with asserts itself with (cascading) side effects of possible assertion updates
	return cachedDB(s).Add(a)
}

// TODO: snapstate also has this, move to auth, or change a bit the approach now that we have AuthContext in the store?
func userFromUserID(st *state.State, userID int) (*auth.UserState, error) {
	if userID == 0 {
		return nil, nil
	}
	return auth.User(st, userID)
}

type fetcher struct {
	db *asserts.Database
	asserts.Fetcher
	fetched []asserts.Assertion
}

// newFetches creates a fetcher used to retrieve assertions from the store and later commit them to the system database in one go.
func newFetcher(s *state.State, user *auth.UserState) *fetcher {
	db := cachedDB(s)
	sto := snapstate.Store(s)

	f := &fetcher{db: db}

	retrieve := func(ref *asserts.Ref) (asserts.Assertion, error) {
		// TODO: ignore errors if already in db?
		return sto.Assertion(ref.Type, ref.PrimaryKey, user)
	}

	save := func(a asserts.Assertion) error {
		f.fetched = append(f.fetched, a)
		return nil
	}

	f.Fetcher = asserts.NewFetcher(db, retrieve, save)

	return f
}

type commitError struct {
	errs []error
}

func (e *commitError) Error() string {
	l := []string{""}
	for _, e := range e.errs {
		l = append(l, e.Error())
	}
	return fmt.Sprintf("cannot add some assertions to the system database:%s", strings.Join(l, "\n - "))
}

// commit does a best effort of adding all the fetched assertions to the system database.
func (f *fetcher) commit() error {
	var errs []error
	for _, a := range f.fetched {
		err := f.db.Add(a)
		if revErr, ok := err.(*asserts.RevisionError); ok {
			if revErr.Current >= a.Revision() {
				// be idempotent
				// system db has already the same or newer
				continue
			}
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return &commitError{errs: errs}
	}
	return nil
}

func doFetch(s *state.State, userID int, fetching func(asserts.Fetcher) error) error {
	// TODO: once we have a bulk assertion retrieval endpoint this approach will change

	user, err := userFromUserID(s, userID)
	if err != nil {
		return err
	}

	f := newFetcher(s, user)

	s.Unlock()
	err = fetching(f)
	s.Lock()
	if err != nil {
		return err
	}

	// TODO: trigger w. caller a global sanity check if a is revoked
	// (but try to save as much possible still),
	// or err is a check error
	return f.commit()
}

// doValidateSnap fetches the relevant assertions for the snap being installed and cross checks them with the snap.
func doValidateSnap(t *state.Task, _ *tomb.Tomb) error {
	t.State().Lock()
	defer t.State().Unlock()

	ss, err := snapstate.TaskSnapSetup(t)
	if err != nil {
		return nil
	}

	sha3_384, snapSize, err := asserts.SnapFileSHA3_384(ss.SnapPath)
	if err != nil {
		return err
	}

	err = doFetch(t.State(), ss.UserID, func(f asserts.Fetcher) error {
		return snapasserts.FetchSnapAssertions(f, sha3_384)
	})
	if notFound, ok := err.(*store.AssertionNotFoundError); ok {
		if notFound.Ref.Type == asserts.SnapRevisionType {
			return fmt.Errorf("cannot verify snap %q, no matching signatures found", ss.Name())
		} else {
			return fmt.Errorf("cannot find signatures to verify snap %q and its hash (%v)", ss.Name(), notFound)
		}
	}
	if err != nil {
		return err
	}

	db := DB(t.State())
	err = snapasserts.CrossCheck(ss.Name(), sha3_384, snapSize, ss.SideInfo, db)
	if err != nil {
		// TODO: trigger a global sanity check
		// that will generate the changes to deal with this
		// for things like snap-decl revocation and renames?
		return err
	}

	// TODO: set DeveloperID from assertions
	return nil
}

// RefreshSnapDeclarations refetches all the current snap declarations and their prerequisites.
func RefreshSnapDeclarations(s *state.State, userID int) error {
	snapStates, err := snapstate.All(s)
	if err != nil {
		return nil
	}
	fetching := func(f asserts.Fetcher) error {
		for _, snapState := range snapStates {
			info, err := snapState.CurrentInfo()
			if err != nil {
				return err
			}
			if info.SnapID == "" {
				continue
			}
			if err := snapasserts.FetchSnapDeclaration(f, info.SnapID); err != nil {
				return fmt.Errorf("cannot refresh snap-declaration for %q: %v", info.Name(), err)
			}
		}
		return nil
	}
	return doFetch(s, userID, fetching)
}

type refreshControlError struct {
	errs []error
}

func (e *refreshControlError) Error() string {
	l := []string{""}
	for _, e := range e.errs {
		l = append(l, e.Error())
	}
	return fmt.Sprintf("refresh control errors:%s", strings.Join(l, "\n - "))
}

// ValidateRefreshes validates the refresh candidate revisions represented by the snapInfos, looking for the needed refresh-control validation assertions, it returns a validated subset in validated and a summary error if not all candidates validated.
func ValidateRefreshes(s *state.State, snapInfos []*snap.Info, userID int) (validated []*snap.Info, err error) {
	// maps gated snap-ids to gating snap-ids
	controlled := make(map[string][]string)
	// maps gating snap-ids to their snap names
	gatingNames := make(map[string]string)

	db := DB(s)
	snapStates, err := snapstate.All(s)
	if err != nil {
		return nil, err
	}
	for snapName, snapState := range snapStates {
		info, err := snapState.CurrentInfo()
		if err != nil {
			return nil, err
		}
		if info.SnapID == "" {
			continue
		}
		gatingID := info.SnapID
		a, err := db.Find(asserts.SnapDeclarationType, map[string]string{
			"series":  release.Series,
			"snap-id": gatingID,
		})
		if err != nil {
			return nil, fmt.Errorf("internal error: cannot find snap declaration for installed snap %q (id: %s): err", snapName, gatingID)
		}
		decl := a.(*asserts.SnapDeclaration)
		control := decl.RefreshControl()
		if len(control) == 0 {
			continue
		}
		gatingNames[gatingID] = decl.SnapName()
		for _, gatedID := range control {
			controlled[gatedID] = append(controlled[gatedID], gatingID)
		}
	}

	var errs []error
	for _, candInfo := range snapInfos {
		gatedID := candInfo.SnapID
		gating := controlled[gatedID]
		if len(gating) == 0 { // easy case, no refresh control
			validated = append(validated, candInfo)
			continue
		}

		fetching := func(f asserts.Fetcher) error {
			for _, gatingID := range gating {
				err := f.Fetch(&asserts.Ref{
					Type:       asserts.ValidationType,
					PrimaryKey: []string{release.Series, gatingID, gatedID, candInfo.Revision.String()},
				})
				if err != nil {
					return fmt.Errorf("cannot find validation by %q: %v", gatingNames[gatingID], err)
				}
			}
			return nil
		}
		err := doFetch(s, userID, fetching)
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot validate refresh for %q (%s): %v", candInfo.Name(), candInfo.Revision, err))
			continue
		}
		// XXX: check the validations are not revoked

		validated = append(validated, candInfo)
	}

	if errs != nil {
		return validated, &refreshControlError{errs}
	}

	return validated, nil
}
