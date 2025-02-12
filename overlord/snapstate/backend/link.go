// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2016 Canonical Ltd
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

package backend

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/cmd/snaplock/runinhibit"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/progress"
	"github.com/snapcore/snapd/sandbox/cgroup"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/timings"
	"github.com/snapcore/snapd/wrappers"
)

var wrappersAddSnapdSnapServices = wrappers.AddSnapdSnapServices
var cgroupKillSnapProcesses = cgroup.KillSnapProcesses

// LinkContext carries additional information about the current or the previous
// state of the snap
type LinkContext struct {
	// FirstInstall indicates whether this is the first time given snap is
	// installed
	FirstInstall bool

	// ServiceOptions is used to configure services.
	ServiceOptions *wrappers.SnapServiceOptions

	// RunInhibitHint is used only in Unlink snap, and can be used to
	// establish run inhibition lock for refresh operations.
	RunInhibitHint runinhibit.Hint

	// StateUnlocker is passed to inhibition lock operations.
	StateUnlocker runinhibit.Unlocker

	// RequireMountedSnapdSnap indicates that the apps and services
	// generated when linking need to use tooling from the snapd snap mount.
	RequireMountedSnapdSnap bool

	// SkipBinaries indicates that we should skip removing snap binaries,
	// icons and desktop files in UnlinkSnap
	SkipBinaries bool

	// HasOtherInstances indicates that other instances of the snap are
	// already installed in the system.
	HasOtherInstances bool
}

func createSharedSnapDirForParallelInstance(s snap.PlaceInfo) error {
	_, key := snap.SplitInstanceName(s.InstanceName())

	if key != "" {
		err := os.MkdirAll(snap.BaseDir(s.SnapName()), 0755)
		if err != nil && !os.IsExist(err) {
			return err
		}
	}
	return nil
}

func removeSharedSnapDirForParallelInstance(s snap.PlaceInfo) {
	_, instanceKey := snap.SplitInstanceName(s.InstanceName())

	if instanceKey != "" {
		// failure to remove is ok, there may be revisions of the
		// instance-less snap installed in the system
		os.Remove(snap.BaseDir(s.SnapName()))
	}
}

func updateCurrentSymlinks(info *snap.Info) (revert func(), e error) {
	mountDir := info.MountDir()
	dataDir := info.DataDir()

	var previousActiveSymlinkTarget string
	var previousDataSymlinkTarget string
	currentActiveSymlink := filepath.Join(filepath.Dir(mountDir), "current")
	currentDataSymlink := filepath.Join(filepath.Dir(dataDir), "current")
	revertFunc := func() {
		if previousActiveSymlinkTarget != "" {
			if err := osutil.AtomicSymlink(previousActiveSymlinkTarget, currentActiveSymlink); err != nil {
				logger.Noticef("Cannot restore symlink %q: %v", currentActiveSymlink, err)
			}
		}
		if previousDataSymlinkTarget != "" {
			if err := osutil.AtomicSymlink(previousDataSymlinkTarget, currentDataSymlink); err != nil {
				logger.Noticef("Cannot restore symlink %q: %v", currentDataSymlink, err)
			}
		}
	}
	defer func() {
		if e != nil {
			revertFunc()
		}
	}()

	if info.Type() == snap.TypeSnapd {
		var err error
		previousActiveSymlinkTarget, err = os.Readlink(currentActiveSymlink)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Noticef("Cannot read %q: %v", currentActiveSymlink, err)
		}
		previousDataSymlinkTarget, err = os.Readlink(currentDataSymlink)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Noticef("Cannot read %q: %v", currentDataSymlink, err)
		}
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	defer func() {
		if e != nil {
			if err := os.Remove(dataDir); err != nil {
				logger.Noticef("Cannot clean up %q: %v", dataDir, err)
			}
		}
	}()

	if err := osutil.AtomicSymlink(filepath.Base(dataDir), currentDataSymlink); err != nil {
		return nil, err
	}
	if err := osutil.AtomicSymlink(filepath.Base(mountDir), currentActiveSymlink); err != nil {
		return nil, err
	}

	return revertFunc, nil
}

// MaybeSetNextBoot configures the system for a reboot if necesssary because
// of a snap refresh. isUndo must be set when we are installing the previous
// snap while performing a revert of the latest one that was installed
func (b Backend) MaybeSetNextBoot(info *snap.Info, dev snap.Device, isUndo bool) (boot.RebootInfo, error) {
	if b.preseed {
		return boot.RebootInfo{}, nil
	}

	bootCtx := boot.NextBootContext{BootWithoutTry: isUndo}
	return boot.Participant(info, info.Type(), dev).SetNextBoot(bootCtx)
}

// LinkSnap makes the snap available by generating wrappers and setting the current symlinks.
func (b Backend) LinkSnap(info *snap.Info, dev snap.Device, linkCtx LinkContext, tm timings.Measurer) (e error) {
	// explicitly prevent passing nil state unlocker to avoid internal errors of
	// forgeting to pass the unlocker leading to deadlocks.
	if linkCtx.StateUnlocker == nil {
		return errors.New("internal error: LinkContext.StateUnlocker cannot be nil")
	}

	if info.Revision.Unset() {
		return fmt.Errorf("cannot link snap %q with unset revision", info.InstanceName())
	}

	osutil.MaybeInjectFault("link-snap")

	var err error
	var restart wrappers.SnapdRestart
	timings.Run(tm, "generate-wrappers", fmt.Sprintf("generate wrappers for snap %s", info.InstanceName()), func(timings.Measurer) {
		restart, err = b.generateWrappers(info, linkCtx)
	})
	if err != nil {
		return err
	}
	defer func() {
		if e == nil {
			return
		}
		timings.Run(tm, "remove-wrappers", fmt.Sprintf("remove wrappers of snap %s", info.InstanceName()), func(timings.Measurer) {
			removeGeneratedWrappers(info, linkCtx, progress.Null)
		})
	}()

	// only after link snap it will be possible to execute snap
	// applications, so ensure that the shared snap directory exists for
	// parallel installed snaps
	if err := createSharedSnapDirForParallelInstance(info); err != nil {
		return err
	}
	cleanupSharedParallelInstanceDir := func() {
		if !linkCtx.HasOtherInstances {
			removeSharedSnapDirForParallelInstance(info)
		}
	}

	revertSymlinks, err := updateCurrentSymlinks(info)
	if err != nil {
		cleanupSharedParallelInstanceDir()
		return err
	}
	// if anything below here could return error, you need to
	// somehow clean up whatever updateCurrentSymlinks did

	if restart != nil {
		if err := restart.Restart(); err != nil {
			logger.Noticef("WARNING: cannot restart services: %v", err)
			revertSymlinks()
			cleanupSharedParallelInstanceDir()

			return err
		}

	}

	// Stop inhibiting application startup by removing the inhibitor file.
	if err := runinhibit.Unlock(info.InstanceName(), linkCtx.StateUnlocker); err != nil {
		return err
	}

	return nil
}

func (b Backend) LinkComponent(cpi snap.ContainerPlaceInfo, snapRev snap.Revision) error {
	mountDir := cpi.MountDir()
	linkPath := snap.ComponentLinkPath(cpi, snapRev)

	// Create components directory
	compsDir := filepath.Dir(linkPath)
	if err := os.MkdirAll(compsDir, 0755); err != nil {
		return fmt.Errorf("while linking component: %v", err)
	}

	// Work out relative path to go from the dir where the symlink lives to
	// the mount dir
	linkTarget, err := filepath.Rel(compsDir, mountDir)
	if err != nil {
		return err
	}

	return osutil.AtomicSymlink(linkTarget, linkPath)
}

func (b Backend) StartServices(apps []*snap.AppInfo, disabledSvcs *wrappers.DisabledServices, meter progress.Meter, tm timings.Measurer) error {
	opts := &wrappers.StartServicesOptions{Enable: true}
	return wrappers.StartServices(apps, disabledSvcs, opts, meter, tm)
}

func (b Backend) StopServices(apps []*snap.AppInfo, reason snap.ServiceStopReason, meter progress.Meter, tm timings.Measurer) error {
	return wrappers.StopServices(apps, nil, reason, meter, tm)
}

func (b Backend) generateWrappers(s *snap.Info, linkCtx LinkContext) (wrappers.SnapdRestart, error) {
	var err error
	var cleanupFuncs []func(*snap.Info) error
	defer func() {
		if err != nil {
			for _, cleanup := range cleanupFuncs {
				cleanup(s)
			}
		}
	}()

	if s.Type() == snap.TypeSnapd {
		// snapd services are handled separately
		return GenerateSnapdWrappers(s, &GenerateSnapdWrappersOptions{b.preseed})
	}

	// add the CLI apps from the snap.yaml
	if err = wrappers.EnsureSnapBinaries(s); err != nil {
		return nil, err
	}
	cleanupFuncs = append(cleanupFuncs, wrappers.RemoveSnapBinaries)

	// add the daemons from the snap.yaml
	ensureOpts := &wrappers.EnsureSnapServicesOptions{
		Preseeding:              b.preseed,
		RequireMountedSnapdSnap: linkCtx.RequireMountedSnapdSnap,
	}
	if err = wrappers.EnsureSnapServices(map[*snap.Info]*wrappers.SnapServiceOptions{
		s: linkCtx.ServiceOptions,
	}, ensureOpts, nil, progress.Null); err != nil {
		return nil, err
	}
	cleanupFuncs = append(cleanupFuncs, func(s *snap.Info) error {
		return wrappers.RemoveSnapServices(s, progress.Null)
	})

	// add D-Bus service activation files
	if err = wrappers.AddSnapDBusActivationFiles(s); err != nil {
		return nil, err
	}
	cleanupFuncs = append(cleanupFuncs, wrappers.RemoveSnapDBusActivationFiles)

	// add the desktop files
	if err = wrappers.EnsureSnapDesktopFiles([]*snap.Info{s}); err != nil {
		return nil, err
	}
	cleanupFuncs = append(cleanupFuncs, wrappers.RemoveSnapDesktopFiles)

	// add the desktop icons
	if err = wrappers.EnsureSnapIcons(s); err != nil {
		return nil, err
	}
	cleanupFuncs = append(cleanupFuncs, wrappers.RemoveSnapIcons)

	return nil, nil
}

func removeGeneratedWrappers(s *snap.Info, linkCtx LinkContext, meter progress.Meter) error {
	if s.Type() == snap.TypeSnapd {
		return removeGeneratedSnapdWrappers(s, linkCtx.FirstInstall, progress.Null)
	}

	var err1, err2, err3 error
	if !linkCtx.SkipBinaries {
		err1 = wrappers.RemoveSnapBinaries(s)
		if err1 != nil {
			logger.Noticef("Cannot remove binaries for %q: %v", s.InstanceName(), err1)
		}

		err2 = wrappers.RemoveSnapDesktopFiles(s)
		if err2 != nil {
			logger.Noticef("Cannot remove desktop files for %q: %v", s.InstanceName(), err2)
		}

		err3 = wrappers.RemoveSnapIcons(s)
		if err3 != nil {
			logger.Noticef("Cannot remove desktop icons for %q: %v", s.InstanceName(), err3)
		}
	}

	err4 := wrappers.RemoveSnapDBusActivationFiles(s)
	if err4 != nil {
		logger.Noticef("Cannot remove D-Bus activation for %q: %v", s.InstanceName(), err4)
	}

	err5 := wrappers.RemoveSnapServices(s, meter)
	if err5 != nil {
		logger.Noticef("Cannot remove services for %q: %v", s.InstanceName(), err5)
	}

	return firstErr(err1, err2, err3, err4, err5)
}

// GenerateSnapdWrappersOptions carries options for GenerateSnapdWrappers.
type GenerateSnapdWrappersOptions struct {
	Preseeding bool
}

func GenerateSnapdWrappers(s *snap.Info, opts *GenerateSnapdWrappersOptions) (wrappers.SnapdRestart, error) {
	wrappersOpts := &wrappers.AddSnapdSnapServicesOptions{}
	if opts != nil {
		wrappersOpts.Preseeding = opts.Preseeding
	}
	// snapd services are handled separately via an explicit helper
	return wrappersAddSnapdSnapServices(s, wrappersOpts, progress.Null)
}

func removeGeneratedSnapdWrappers(s *snap.Info, firstInstall bool, meter progress.Meter) error {
	if !firstInstall {
		// snapd service units are only removed during first
		// installation of the snapd snap, in other scenarios they are
		// overwritten
		return nil
	}
	return wrappers.RemoveSnapdSnapServicesOnCore(s, meter)
}

// UnlinkSnap makes the snap unavailable to the system removing wrappers and
// symlinks. The firstInstallUndo is true when undoing the first installation of
// the snap.
func (b Backend) UnlinkSnap(info *snap.Info, linkCtx LinkContext, meter progress.Meter) error {
	var err0 error
	if hint := linkCtx.RunInhibitHint; hint != runinhibit.HintNotInhibited {
		// explicitly prevent passing nil state unlocker to avoid internal errors of
		// forgeting to pass the unlocker leading to deadlocks.
		if linkCtx.StateUnlocker == nil {
			return errors.New("internal error: LinkContext.StateUnlocker cannot be nil if LinkContext.RunInhibitHint is set")
		}
		// inhibit startup of new programs
		inhibitInfo := runinhibit.InhibitInfo{Previous: info.SnapRevision()}
		err0 = runinhibit.LockWithHint(info.InstanceName(), hint, inhibitInfo, linkCtx.StateUnlocker)
	}

	// remove generated services, binaries etc
	err1 := removeGeneratedWrappers(info, linkCtx, meter)

	// and finally remove current symlinks
	err2 := removeCurrentSymlinks(info)

	// XXX intentional lack of symmetry with LinkSnap wrt. parallel installs
	// handling, the directory cleanup is left to be executed during the
	// last phase of snap removal

	// FIXME: aggregate errors instead
	return firstErr(err0, err1, err2)
}

func (b Backend) QueryDisabledServices(info *snap.Info, pb progress.Meter) (*wrappers.DisabledServices, error) {
	return wrappers.QueryDisabledServices(info, pb)
}

func removeCurrentSymlinks(info snap.PlaceInfo) error {
	var err1, err2 error

	// the snap "current" symlink
	currentActiveSymlink := filepath.Join(info.MountDir(), "..", "current")
	err1 = os.Remove(currentActiveSymlink)
	if err1 != nil && !os.IsNotExist(err1) {
		logger.Noticef("Cannot remove %q: %v", currentActiveSymlink, err1)
	} else {
		err1 = nil
	}

	// the data "current" symlink
	currentDataSymlink := filepath.Join(info.DataDir(), "..", "current")
	err2 = os.Remove(currentDataSymlink)
	if err2 != nil && !os.IsNotExist(err2) {
		logger.Noticef("Cannot remove %q: %v", currentDataSymlink, err2)
	} else {
		err2 = nil
	}

	if err1 != nil && err2 != nil {
		return fmt.Errorf("cannot remove snap current symlink: %v and %v", err1, err2)
	} else if err1 != nil {
		return fmt.Errorf("cannot remove snap current symlink: %v", err1)
	} else if err2 != nil {
		return fmt.Errorf("cannot remove snap current symlink: %v", err2)
	}

	return nil
}

func (b Backend) UnlinkComponent(cpi snap.ContainerPlaceInfo, snapRev snap.Revision) error {
	linkPath := snap.ComponentLinkPath(cpi, snapRev)

	err := os.Remove(linkPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Noticef("cannot remove symlink %q: %v", linkPath, err)
		} else {
			return err
		}
	}

	// Try also to remove the <snap_rev>/ subdirectory, as this might be
	// the only installed component. But simply ignore if not empty.
	os.Remove(filepath.Dir(linkPath))

	return nil
}

func (b Backend) KillSnapApps(snapName string, reason snap.AppKillReason, tm timings.Measurer) error {
	if reason != snap.KillReasonOther {
		logger.Debugf("KillSnapApps called for %q, reason: %v", snapName, reason)
	} else {
		logger.Debugf("KillSnapApps called for %q", snapName)
	}

	var err error
	timings.Run(tm, "kill-snap-apps", fmt.Sprintf("kill running apps for snap %s", snapName), func(timings.Measurer) {
		// TODO: Ideally the context should come from the caller
		err = cgroupKillSnapProcesses(context.TODO(), snapName)
	})

	return err
}
