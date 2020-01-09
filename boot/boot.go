// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package boot

import (
	"errors"
	"fmt"
	"strings"

	"github.com/snapcore/snapd/snap"
)

// A BootParticipant handles the boot process details for a snap involved in it.
type BootParticipant interface {
	// SetNextBoot will schedule the snap to be used in the next boot. For
	// base snaps it is up to the caller to select the right bootable base
	// (from the model assertion). It is a noop for not relevant snaps.
	// Otherwise it returns whether a reboot is required.
	SetNextBoot() (rebootRequired bool, err error)

	// Is this a trivial implementation of the interface?
	IsTrivial() bool
}

// A BootKernel handles the bootloader setup of a kernel.
type BootKernel interface {
	// RemoveKernelAssets removes the unpacked kernel/initrd for the given
	// kernel snap.
	RemoveKernelAssets() error
	// ExtractKernelAssets extracts kernel/initrd/dtb data from the given
	// kernel snap, if required, to a versioned bootloader directory so
	// that the bootloader can use it.
	ExtractKernelAssets(snap.Container) error
	// Is this a trivial implementation of the interface?
	IsTrivial() bool
}

type trivial struct{}

func (trivial) SetNextBoot() (bool, error)               { return false, nil }
func (trivial) IsTrivial() bool                          { return true }
func (trivial) RemoveKernelAssets() error                { return nil }
func (trivial) ExtractKernelAssets(snap.Container) error { return nil }

// ensure trivial is a BootParticipant
var _ BootParticipant = trivial{}

// ensure trivial is a Kernel
var _ BootKernel = trivial{}

// Device carries information about the devie model and mode that is
// relevant to boot. Note snapstate.DeviceContext implements this, and that's
// the expected use case.
type Device interface {
	RunMode() bool
	Classic() bool

	Kernel() string
	Base() string
}

// Participant figures out what the BootParticipant is for the given
// arguments, and returns it. If the snap does _not_ participate in
// the boot process, the returned object will be a NOP, so it's safe
// to call anything on it always.
//
// Currently, on classic, nothing is a boot participant (returned will
// always be NOP).
func Participant(s snap.PlaceInfo, t snap.Type, dev Device) BootParticipant {
	if applicable(s, t, dev) {
		bs, err := bootStateFor(t, dev)
		if err != nil {
			// all internal errors at this point
			panic(err)
		}
		return &coreBootParticipant{s: s, bs: bs}
	}
	return trivial{}
}

// Kernel checks that the given arguments refer to a kernel snap
// that participates in the boot process, and returns the associated
// BootKernel, or a trivial implementation otherwise.
func Kernel(s snap.PlaceInfo, t snap.Type, dev Device) BootKernel {
	if t == snap.TypeKernel && applicable(s, t, dev) {
		return &coreKernel{s: s}
	}
	return trivial{}
}

func applicable(s snap.PlaceInfo, t snap.Type, dev Device) bool {
	if dev.Classic() {
		return false
	}
	// In ephemeral modes we never need to care about updating the boot
	// config. This will be done via boot.MakeBootable().
	if !dev.RunMode() {
		return false
	}

	if t != snap.TypeOS && t != snap.TypeKernel && t != snap.TypeBase {
		// note we don't currently have anything useful to do with gadgets
		return false
	}

	switch t {
	case snap.TypeKernel:
		if s.InstanceName() != dev.Kernel() {
			// a remodel might leave you in this state
			return false
		}
	case snap.TypeBase, snap.TypeOS:
		base := dev.Base()
		if base == "" {
			base = "core"
		}
		if s.InstanceName() != base {
			return false
		}
	}

	return true
}

// bootState exposes the boot state for a type of boot snap.
type bootState interface {
	// revisions retrieves the revisions of the current snap and
	// the try snap (only the latter might not be set), and
	// whether the snap is in "trying" state.
	revisions() (snap, trySnap *NameAndRevision, trying bool, err error)

	// setNext lazily implements setting the next boot target for
	// the type's boot snap. actually committing the update
	// is done via the returned bootStateUpdate's commit.
	setNext(s snap.PlaceInfo) (rebootRequired bool, u bootStateUpdate, err error)
	// markSuccessful lazily implements marking the boot
	// successful for the type's boot snap. The actual committing
	// of the update is done via bootStateUpdate's commit, that
	// way different markSuccessful can be folded together.
	markSuccessful(bootStateUpdate) (bootStateUpdate, error)
}

// bootStateFor finds the right bootState implementation of the given
// snap type and Device, if applicable.
func bootStateFor(typ snap.Type, dev Device) (s bootState, err error) {
	if !dev.RunMode() {
		return nil, fmt.Errorf("internal error: no boot state handling for ephemeral modes")
	}
	switch typ {
	case snap.TypeOS, snap.TypeBase:
		return newBootState16(snap.TypeBase), nil
	case snap.TypeKernel:
		return newBootState16(snap.TypeKernel), nil
	default:
		return nil, fmt.Errorf("internal error: no boot state handling for snap type %q", typ)
	}
}

type InUseFunc func(name string, rev snap.Revision) bool

func fixedInUse(inUse bool) InUseFunc {
	return func(string, snap.Revision) bool {
		return inUse
	}
}

// InUse returns a checker for whether a given name/revision is used in the
// boot environment for snaps of the relevant snap type.
func InUse(typ snap.Type, dev Device) (InUseFunc, error) {
	if dev.Classic() {
		// no boot state on classic
		return fixedInUse(false), nil
	}
	if !dev.RunMode() {
		// ephemeral mode, block manipulations for now
		return fixedInUse(true), nil
	}
	switch typ {
	case snap.TypeKernel, snap.TypeBase, snap.TypeOS:
		break
	default:
		return fixedInUse(false), nil
	}
	cands := make([]*NameAndRevision, 0, 2)
	s, err := bootStateFor(typ, dev)
	if err != nil {
		return nil, err
	}
	cand, tryCand, _, err := s.revisions()
	if err != nil {
		return nil, err
	}
	cands = append(cands, cand)
	if tryCand != nil {
		cands = append(cands, tryCand)
	}

	return func(name string, rev snap.Revision) bool {
		for _, cand := range cands {
			if cand.Name == name && cand.Revision == rev {
				return true
			}
		}
		return false
	}, nil
}

var (
	ErrBootNameAndRevisionNotReady = errors.New("boot revision not yet established")
)

type NameAndRevision struct {
	Name     string
	Revision snap.Revision
}

// GetCurrentBoot returns the currently set name and revision for boot for the given
// type of snap, which can be snap.TypeBase (or snap.TypeOS), or snap.TypeKernel.
// Returns ErrBootNameAndRevisionNotReady if the values are temporarily not established.
func GetCurrentBoot(t snap.Type, dev Device) (*NameAndRevision, error) {
	s, err := bootStateFor(t, dev)
	if err != nil {
		return nil, err
	}

	snap, _, trying, err := s.revisions()
	if err != nil {
		return nil, err
	}

	if trying {
		return nil, ErrBootNameAndRevisionNotReady
	}

	return snap, nil
}

// nameAndRevnoFromSnap grabs the snap name and revision from the
// value of a boot variable. E.g., foo_2.snap -> name "foo", revno 2
func nameAndRevnoFromSnap(sn string) (*NameAndRevision, error) {
	if sn == "" {
		return nil, fmt.Errorf("boot variable unset")
	}
	idx := strings.IndexByte(sn, '_')
	if idx < 1 {
		return nil, fmt.Errorf("input %q has invalid format (not enough '_')", sn)
	}
	name := sn[:idx]
	revnoNSuffix := sn[idx+1:]
	rev, err := snap.ParseRevision(strings.TrimSuffix(revnoNSuffix, ".snap"))
	if err != nil {
		return nil, err
	}
	return &NameAndRevision{Name: name, Revision: rev}, nil
}

// bootStateUpdate carries the state for an on-going boot state update.
// At the end it can be used to commit it.
type bootStateUpdate interface {
	commit() error
}

// MarkBootSuccessful marks the current boot as successful. This means
// that snappy will consider this combination of kernel/os a valid
// target for rollback.
//
// The states that a boot goes through for UC16/18 are the following:
// - By default snap_mode is "" in which case the bootloader loads
//   two squashfs'es denoted by variables snap_core and snap_kernel.
// - On a refresh of core/kernel snapd will set snap_mode=try and
//   will also set snap_try_{core,kernel} to the core/kernel that
//   will be tried next.
// - On reboot the bootloader will inspect the snap_mode and if the
//   mode is set to "try" it will set "snap_mode=trying" and then
//   try to boot the snap_try_{core,kernel}".
// - On a successful boot snapd resets snap_mode to "" and copies
//   snap_try_{core,kernel} to snap_{core,kernel}. The snap_try_*
//   values are cleared afterwards.
// - On a failing boot the bootloader will see snap_mode=trying which
//   means snapd did not start successfully. In this case the bootloader
//   will set snap_mode="" and the system will boot with the known good
//   values from snap_{core,kernel}
func MarkBootSuccessful(dev Device) error {
	const errPrefix = "cannot mark boot successful: %s"

	var u bootStateUpdate
	for _, t := range []snap.Type{snap.TypeBase, snap.TypeKernel} {
		s, err := bootStateFor(t, dev)
		if err != nil {
			return err
		}
		u, err = s.markSuccessful(u)
		if err != nil {
			return fmt.Errorf(errPrefix, err)
		}
	}

	if u != nil {
		if err := u.commit(); err != nil {
			return fmt.Errorf(errPrefix, err)
		}
	}
	return nil
}
