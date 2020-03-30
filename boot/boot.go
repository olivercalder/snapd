// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2020 Canonical Ltd
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

	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/snap"
)

const (
	// DefaultStatus is the value of a status boot variable when nothing is
	// being tried
	DefaultStatus = ""
	// TryStatus is the value of a status boot variable when something is about
	// to be tried
	TryStatus = "try"
	// TryingStatus is the value of a status boot variable after we have
	// attempted a boot with a try snap - this status is only set in the early
	// boot sequence (bootloader, initramfs, etc.)
	TryingStatus = "trying"
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

// Device carries information about the device model and mode that is
// relevant to boot. Note snapstate.DeviceContext implements this, and that's
// the expected use case.
type Device interface {
	RunMode() bool
	Classic() bool

	Kernel() string
	Base() string

	HasModeenv() bool
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

// bootloaderOptionsForDeviceKernel returns a set of bootloader options that
// enable correct kernel extraction and removal for given device
func bootloaderOptionsForDeviceKernel(dev Device) *bootloader.Options {
	return &bootloader.Options{
		// unified extractable kernel if in uc20 mode
		ExtractedRunKernelImage: dev.HasModeenv(),
	}
}

// Kernel checks that the given arguments refer to a kernel snap
// that participates in the boot process, and returns the associated
// BootKernel, or a trivial implementation otherwise.
func Kernel(s snap.PlaceInfo, t snap.Type, dev Device) BootKernel {
	if t == snap.TypeKernel && applicable(s, t, dev) {
		return &coreKernel{s: s, bopts: bootloaderOptionsForDeviceKernel(dev)}
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
	// the status of the trying snap.
	revisions() (curSnap, trySnap snap.PlaceInfo, tryingStatus string, err error)

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
	newBootState := newBootState16
	if dev.HasModeenv() {
		newBootState = newBootState20
	}
	switch typ {
	case snap.TypeOS, snap.TypeBase:
		return newBootState(snap.TypeBase), nil
	case snap.TypeKernel:
		return newBootState(snap.TypeKernel), nil
	default:
		return nil, fmt.Errorf("internal error: no boot state handling for snap type %q", typ)
	}
}

// InUseFunc is a function to check if the snap is in use or not.
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
	cands := make([]snap.PlaceInfo, 0, 2)
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
			if cand.SnapName() == name && cand.SnapRevision() == rev {
				return true
			}
		}
		return false
	}, nil
}

var (
	// ErrBootNameAndRevisionNotReady is returned when the boot revision is not
	// established yet.
	ErrBootNameAndRevisionNotReady = errors.New("boot revision not yet established")
)

// GetCurrentBoot returns the currently set name and revision for boot for the given
// type of snap, which can be snap.TypeBase (or snap.TypeOS), or snap.TypeKernel.
// Returns ErrBootNameAndRevisionNotReady if the values are temporarily not established.
func GetCurrentBoot(t snap.Type, dev Device) (snap.PlaceInfo, error) {
	s, err := bootStateFor(t, dev)
	if err != nil {
		return nil, err
	}

	snap, _, status, err := s.revisions()
	if err != nil {
		return nil, err
	}

	if status == TryingStatus {
		return nil, ErrBootNameAndRevisionNotReady
	}

	return snap, nil
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

var ErrUnsupportedSystemBootMode = errors.New("system boot mode is unsupported")

// SetRecoveryBootSystemAndMode configures the bootloader to boot into the given
// recovery system in a particular mode. Returns ErrUnsupportedSystemBootMode
// when booting into a recovery system is not supported by the device.
func SetRecoveryBootSystemAndMode(dev Device, systemLabel, mode string) error {
	if !dev.HasModeenv() {
		// only UC20 devices are supported
		return ErrUnsupportedSystemBootMode
	}
	if systemLabel == "" || mode == "" {
		return fmt.Errorf("internal error: system or mode is unset")
	}

	opts := &bootloader.Options{
		// setup the recovery bootloader
		Recovery: true,
	}
	bl, err := bootloader.Find(InitramfsUbuntuSeedDir, opts)
	if err != nil {
		return err
	}

	m := map[string]string{
		"snapd_recovery_system": systemLabel,
		"snapd_recovery_mode":   mode,
	}
	return bl.SetBootVars(m)
}
