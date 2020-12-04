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

package snapasserts

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/naming"
)

// InstalledSnap holds the minimal details about an installed snap required to
// check the validation set.
type InstalledSnap struct {
	naming.SnapRef
	Revision snap.Revision
}

// NewInstalledSnap creates InstalledSnap.
func NewInstalledSnap(name, snapID string, revision snap.Revision) *InstalledSnap {
	return &InstalledSnap{
		SnapRef:  naming.NewSnapRef(name, snapID),
		Revision: revision,
	}
}

func (e *ValidationSetsConflictError) Error() string {
	buf := bytes.NewBufferString("validation sets are in conflict:")
	for _, err := range e.Snaps {
		fmt.Fprintf(buf, "\n- %v", err)
	}
	return buf.String()
}

// ValidationSetsValidationError describes an error arising
// from validation of snaps against ValidationSets.
type ValidationSetsValidationError struct {
	// snapName -> validationSetKey
	MissingSnaps       map[string][]string
	InvalidSnaps       map[string][]string
	WrongRevisionSnaps map[string][]string
	Sets               map[string]*asserts.ValidationSet
}

// ValidationSetsConflictError describes an error where multiple
// validation sets are in conflict about snaps.
type ValidationSetsConflictError struct {
	Sets  map[string]*asserts.ValidationSet
	Snaps map[string]error
}

func (e *ValidationSetsValidationError) Error() string {
	buf := bytes.NewBufferString("validation sets assertions are not met:")
	printDetails := func(header string, details map[string][]string) {
		if len(details) == 0 {
			return
		}
		fmt.Fprintf(buf, "\n%s:", header)
		for snapName, validationSetKeys := range details {
			fmt.Fprintf(buf, "\n- %s", snapName)
			for _, key := range validationSetKeys {
				fmt.Fprintf(buf, "\n  - validation set: %s", key)
			}
		}
	}

	printDetails("missing required snaps", e.MissingSnaps)
	printDetails("invalid snaps", e.InvalidSnaps)
	printDetails("snaps at wrong revisions", e.WrongRevisionSnaps)
	return buf.String()
}

// ValidationSets can hold a combination of validation-set assertions
// and can check for conflicts or help applying them.
type ValidationSets struct {
	// sets maps sequence keys to validation-set in the combination
	sets map[string]*asserts.ValidationSet
	// snaps maps snap-ids to snap constraints
	snaps map[string]*snapContraints
}

const presConflict asserts.Presence = "conflict"

var unspecifiedRevision = snap.R(0)
var invalidPresRevision = snap.R(-1)

type snapContraints struct {
	name     string
	presence asserts.Presence
	// revisions maps revisions to pairing of ValidationSetSnap
	// and the originating validation-set key
	// * unspecifiedRevision is used for constraints without a
	//   revision
	// * invalidPresRevision is used for constraints that mark
	//   presence as invalid
	revisions map[snap.Revision][]*revConstraint
}

type revConstraint struct {
	validationSetKey string
	asserts.ValidationSetSnap
}

func (c *snapContraints) conflict() *snapConflictsError {
	if c.presence != presConflict {
		return nil
	}

	const dontCare asserts.Presence = ""
	whichSets := func(rcs []*revConstraint, presence asserts.Presence) []string {
		which := make([]string, 0, len(rcs))
		for _, rc := range rcs {
			if presence != dontCare && rc.Presence != presence {
				continue
			}
			which = append(which, rc.validationSetKey)
		}
		if len(which) == 0 {
			return nil
		}
		sort.Strings(which)
		return which
	}

	byRev := make(map[snap.Revision][]string, len(c.revisions))
	for r := range c.revisions {
		pres := dontCare
		switch r {
		case invalidPresRevision:
			pres = asserts.PresenceInvalid
		case unspecifiedRevision:
			pres = asserts.PresenceRequired
		}
		which := whichSets(c.revisions[r], pres)
		if len(which) != 0 {
			byRev[r] = which
		}
	}

	return &snapConflictsError{
		name:      c.name,
		revisions: byRev,
	}
}

type snapConflictsError struct {
	name string
	// revisions maps revisions to validation-set keys of the sets
	// that are in conflict over the revision.
	// * unspecifiedRevision is used for validation-sets conflicting
	//   on the snap by requiring it but without a revision
	// * invalidPresRevision is used for validation-sets that mark
	//   presence as invalid
	// see snapContraints.revisions as well
	revisions map[snap.Revision][]string
}

func (e *snapConflictsError) Error() string {
	whichSets := func(which []string) string {
		return fmt.Sprintf("(%s)", strings.Join(which, ","))
	}

	msg := fmt.Sprintf("cannot constrain snap %q", e.name)
	invalid := false
	if invalidOnes, ok := e.revisions[invalidPresRevision]; ok {
		msg += fmt.Sprintf(" as both invalid %s and required", whichSets(invalidOnes))
		invalid = true
	}

	var revnos []int
	for r := range e.revisions {
		if r.N >= 1 {
			revnos = append(revnos, r.N)
		}
	}
	if len(revnos) == 1 {
		msg += fmt.Sprintf(" at revision %d %s", revnos[0], whichSets(e.revisions[snap.R(revnos[0])]))
	} else if len(revnos) > 1 {
		sort.Ints(revnos)
		l := make([]string, 0, len(revnos))
		for _, rev := range revnos {
			l = append(l, fmt.Sprintf("%d %s", rev, whichSets(e.revisions[snap.R(rev)])))
		}
		msg += fmt.Sprintf(" at different revisions %s", strings.Join(l, ", "))
	}

	if unspecifiedOnes, ok := e.revisions[unspecifiedRevision]; ok {
		which := whichSets(unspecifiedOnes)
		if which != "" {
			if len(revnos) != 0 {
				msg += " or"
			}
			if invalid {
				msg += fmt.Sprintf(" at any revision %s", which)
			} else {
				msg += fmt.Sprintf(" required at any revision %s", which)
			}
		}
	}
	return msg
}

// NewValidationSets returns a new ValidationSets.
func NewValidationSets() *ValidationSets {
	return &ValidationSets{
		sets:  map[string]*asserts.ValidationSet{},
		snaps: map[string]*snapContraints{},
	}
}

func valSetKey(valset *asserts.ValidationSet) string {
	return fmt.Sprintf("%s/%s", valset.AccountID(), valset.Name())
}

// Add adds the given asserts.ValidationSet to the combination.
// It errors if a validation-set with the same sequence key has been
// added already.
func (v *ValidationSets) Add(valset *asserts.ValidationSet) error {
	k := valSetKey(valset)
	if _, ok := v.sets[k]; ok {
		return fmt.Errorf("cannot add a second validation-set under %q", k)
	}
	v.sets[k] = valset
	for _, sn := range valset.Snaps() {
		v.addSnap(sn, k)
	}
	return nil
}

func (v *ValidationSets) addSnap(sn *asserts.ValidationSetSnap, validationSetKey string) {
	rev := snap.R(sn.Revision)
	if sn.Presence == asserts.PresenceInvalid {
		rev = invalidPresRevision
	}

	rc := &revConstraint{
		validationSetKey:  validationSetKey,
		ValidationSetSnap: *sn,
	}

	cs := v.snaps[sn.SnapID]
	if cs == nil {
		v.snaps[sn.SnapID] = &snapContraints{
			name:     sn.Name,
			presence: sn.Presence,
			revisions: map[snap.Revision][]*revConstraint{
				rev: {rc},
			},
		}
		return
	}

	cs.revisions[rev] = append(cs.revisions[rev], rc)
	if cs.presence == presConflict {
		// nothing to check anymore
		return
	}
	// this counts really different revisions or invalid
	ndiff := len(cs.revisions)
	if _, ok := cs.revisions[unspecifiedRevision]; ok {
		ndiff -= 1
	}
	switch {
	case cs.presence == asserts.PresenceOptional:
		cs.presence = sn.Presence
		fallthrough
	case cs.presence == sn.Presence || sn.Presence == asserts.PresenceOptional:
		if ndiff > 1 {
			if cs.presence == asserts.PresenceRequired {
				// different revisions required/invalid
				cs.presence = presConflict
				return
			}
			// multiple optional at different revisions => invalid
			cs.presence = asserts.PresenceInvalid
		}
		return
	}
	// we are left with a combo of required and invalid => conflict
	cs.presence = presConflict
	return
}

// Conflict returns a non-nil error if the combination is in conflict,
// nil otherwise.
func (v *ValidationSets) Conflict() error {
	sets := make(map[string]*asserts.ValidationSet)
	snaps := make(map[string]error)

	for snapID, snConstrs := range v.snaps {
		snConflictsErr := snConstrs.conflict()
		if snConflictsErr != nil {
			snaps[snapID] = snConflictsErr
			for _, valsetKeys := range snConflictsErr.revisions {
				for _, valsetKey := range valsetKeys {
					sets[valsetKey] = v.sets[valsetKey]
				}
			}
		}
	}

	if len(snaps) != 0 {
		return &ValidationSetsConflictError{
			Sets:  sets,
			Snaps: snaps,
		}
	}
	return nil
}

type snapRef struct {
	naming.SnapRef
	revision snap.Revision
}

// CheckInstalledSnaps checks installed snaps against the validation sets.
func (v *ValidationSets) CheckInstalledSnaps(snaps []*InstalledSnap) error {
	installed := naming.NewSnapSet(nil)
	for _, sn := range snaps {
		installed.Add(sn)
	}

	// snapName -> validationSet key -> validation set
	invalid := make(map[string]map[string]bool)
	missing := make(map[string]map[string]bool)
	wrongrev := make(map[string]map[string]bool)
	sets := make(map[string]*asserts.ValidationSet)

	for _, cstrs := range v.snaps {
		for rev, revCstr := range cstrs.revisions {
			for _, rc := range revCstr {
				ref := naming.NewSnapRef(rc.Name, rc.SnapID)
				snap := installed.Lookup(ref)
				isInstalled := snap != nil
				if !isInstalled && cstrs.presence != asserts.PresenceRequired {
					continue
				}
				switch {
				case isInstalled && cstrs.presence == asserts.PresenceInvalid:
					if invalid[rc.Name] == nil {
						invalid[rc.Name] = make(map[string]bool)
					}
					invalid[rc.Name][rc.validationSetKey] = true
					sets[rc.validationSetKey] = v.sets[rc.validationSetKey]
				case isInstalled: // presence is either optional or required
					if rev != unspecifiedRevision && rev != snap.(*InstalledSnap).Revision {
						if wrongrev[rc.Name] == nil {
							wrongrev[rc.Name] = make(map[string]bool)
						}
						wrongrev[rc.Name][rc.validationSetKey] = true
						sets[rc.validationSetKey] = v.sets[rc.validationSetKey]
					}
				default:
					// not installed but required
					if missing[rc.Name] == nil {
						missing[rc.Name] = make(map[string]bool)
					}
					missing[rc.Name][rc.validationSetKey] = true
					sets[rc.validationSetKey] = v.sets[rc.validationSetKey]
				}
			}
		}
	}

	flatten := func(in map[string]map[string]bool) map[string][]string {
		if len(in) == 0 {
			return nil
		}
		out := make(map[string][]string)
		for snap, sets := range in {
			out[snap] = make([]string, 0, len(sets))
			for validationSetKey := range sets {
				out[snap] = append(out[snap], validationSetKey)
			}
			sort.Strings(out[snap])
		}
		return out
	}

	if len(invalid) > 0 || len(missing) > 0 || len(wrongrev) > 0 {
		return &ValidationSetsValidationError{
			InvalidSnaps:       flatten(invalid),
			MissingSnaps:       flatten(missing),
			WrongRevisionSnaps: flatten(wrongrev),
			Sets:               sets,
		}
	}

	return nil
}
