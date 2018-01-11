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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/snapcore/snapd/interfaces/mount"
	"github.com/snapcore/snapd/logger"
)

// Action represents a mount action (mount, remount, unmount, etc).
type Action string

const (
	// Keep indicates that a given mount entry should be kept as-is.
	Keep Action = "keep"
	// Mount represents an action that results in mounting something somewhere.
	Mount Action = "mount"
	// Unmount represents an action that results in unmounting something from somewhere.
	Unmount Action = "unmount"
	// Remount when needed
)

// Change describes a change to the mount table (action and the entry to act on).
type Change struct {
	Entry  mount.Entry
	Action Action
}

// String formats mount change to a human-readable line.
func (c Change) String() string {
	return fmt.Sprintf("%s (%s)", c.Action, c.Entry)
}

// changePerform is Change.Perform that can be mocked for testing.
var changePerform func(*Change) ([]*Change, error)

// changePerformImpl is the real implementation of Change.Perform
func changePerformImpl(c *Change) ([]*Change, error) {
	var changes []*Change
	if c.Action == Mount {
		// We may be asked to bind mount a file, bind mount a directory, mount
		// a filesystem over a directory or create a symlink (which is abusing
		// the "mount" concept slightly). That actual operation is performed in
		// c.lowLevelPerform. Here we just set the stage to make that possible.
		kind, _ := c.Entry.OptStr("x-snapd.kind")
		path := c.Entry.Dir

		// We use lstat to ensure that we don't follow a symlink in case one
		// was set up by the snap. Note that at the time this is run, all the
		// snap's processes are frozen.
		fi, err := osLstat(path)

		// In case we need to create something, some constants.
		const (
			mode = 0755
			uid  = 0
			gid  = 0
		)

		if err != nil && os.IsNotExist(err) {
			// If the element doesn't exist we can attempt to create it.
			// We will create the parent directory and then the final element
			// relative to it. The traversed space may be writable so we try a
			// to create the parent directory first.
			switch kind {
			case "":
				err = secureMkdirAll(path, mode, uid, gid)
			case "file":
				err = secureMkfileAll(path, mode, uid, gid)
			case "symlink":
				path = filepath.Dir(c.Entry.Dir)
				err = secureMkdirAll(path, mode, uid, gid)
				if err == nil {
					// Normally symlinks would be created
					// later but calling c.lowLevelPerform
					// now lets us check if the medium is
					// writable and take advantage of the
					// code below.
					err = c.lowLevelPerform()
				}
			}

			if err2, _ := err.(*ReadOnlyFsError); err2 != nil {
				// If the writing failed because the underlying filesystem
				// is read-only we can construct a writable mimic to fix that.
				changes, err = createWritableMimic(err2.Path)
				if err != nil {
					return nil, fmt.Errorf("cannot create writable mimic over %q: %s", err2.Path, err)
				}
				// We can now try again.
				switch kind {
				case "":
					err = secureMkdirAll(path, mode, uid, gid)
				case "file":
					err = secureMkfileAll(path, mode, uid, gid)
				case "symlink":
					err = secureMkdirAll(path, mode, uid, gid)
					if err == nil {
						err = c.lowLevelPerform()
					}
				}
			}
			// Check if we eventually succeeded.
			if err != nil {
				return changes, err
			}
		} else if err != nil {
			// If we cannot inspect the element let's just bail out.
			return nil, fmt.Errorf("cannot inspect %q: %v", path, err)
		} else {
			// If the element already existed we just need to ensure it is of
			// the correct type. The desired type depends on the kind of entry
			// we are working with.
			switch kind {
			case "":
				if !fi.Mode().IsDir() {
					return nil, fmt.Errorf("cannot use %q for mounting, not a directory", path)
				}
			case "file":
				if !fi.Mode().IsRegular() {
					return nil, fmt.Errorf("cannot use %q for mounting, not a regular file", path)
				}
			case "symlink":
				// When we want to create a symlink we just need the empty
				// space so anything that is in the way is a problem.
				return nil, fmt.Errorf("cannot create symlink in %q, existing file in the way", path)
			}
		}

		// At this time we can be sure that the element (for files and
		// directories) exists and is of the right type or that it (for
		// symlinks) doesn't exist but the parent directory does.

		flags, _ := mount.OptsToCommonFlags(c.Entry.Options)
		if flags&syscall.MS_BIND != 0 {
			// This is a simplified variant of the code above. Simplified in
			// that we don't attempt to poke writable holes as those would only
			// be visible from the originating mount namespace so really
			// useless in connecting two snaps together.
			path = c.Entry.Name
			fi, err := osLstat(path)
			if err != nil && os.IsNotExist(err) {
				switch kind {
				case "":
					err = secureMkdirAll(path, mode, uid, gid)
				case "file":
					err = secureMkfileAll(path, mode, uid, gid)
				}
				if err != nil {
					return changes, fmt.Errorf("cannot create file/directory %q: %s", path, err)
				}
			} else if err != nil {
				return changes, fmt.Errorf("cannot inspect %q: %v", path, err)
			} else {
				switch kind {
				case "":
					if !fi.Mode().IsDir() {
						return nil, fmt.Errorf("cannot use %q for mounting, not a directory", path)
					}
				case "file":
					if !fi.Mode().IsRegular() {
						return nil, fmt.Errorf("cannot use %q for mounting, not a regular file", path)
					}
				}
			}
		}

		if kind == "symlink" {
			return changes, nil
		}

	}
	return changes, c.lowLevelPerform()
}

func init() {
	changePerform = changePerformImpl
}

// Perform executes the desired mount or unmount change using system calls.
// Filesystems that depend on helper programs or multiple independent calls to
// the kernel (--make-shared, for example) are unsupported.
//
// Perform may synthesize *additional* changes that were necessary to perform
// this change (such as mounted tmpfs or overlayfs).
func (c *Change) Perform() ([]*Change, error) {
	return changePerform(c)
}

// lowLevelPerform is simple bridge from Change to mount / unmount syscall.
func (c *Change) lowLevelPerform() error {
	var err error
	switch c.Action {
	case Mount:
		kind, _ := c.Entry.OptStr("x-snapd.kind")
		switch kind {
		case "symlink":
			target, _ := c.Entry.OptStr("x-snapd.symlink")
			err = osSymlink(target, c.Entry.Dir)
			logger.Debugf("symlink %q -> %q (error: %v)", c.Entry.Dir, target, err)
			if err == syscall.EROFS {
				return &ReadOnlyFsError{Path: filepath.Dir(c.Entry.Dir)}
			}
		case "", "file":
			flags, unparsed := mount.OptsToCommonFlags(c.Entry.Options)
			err = sysMount(c.Entry.Name, c.Entry.Dir, c.Entry.Type, uintptr(flags), strings.Join(unparsed, ","))
			logger.Debugf("mount %q %q %q %d %q (error: %v)", c.Entry.Name, c.Entry.Dir, c.Entry.Type, uintptr(flags), strings.Join(unparsed, ","), err)
		}
		return err
	case Unmount:
		kind, _ := c.Entry.OptStr("x-snapd.kind")
		switch kind {
		case "symlink":
			err = osRemove(c.Entry.Dir)
			logger.Debugf("remove %q (error: %v)", c.Entry.Dir, err)
		case "", "file":
			err = sysUnmount(c.Entry.Dir, umountNoFollow)
			logger.Debugf("umount %q (error: %v)", c.Entry.Dir, err)
		}
		return err
	case Keep:
		return nil
	}
	return fmt.Errorf("cannot process mount change, unknown action: %q", c.Action)
}

// NeededChanges computes the changes required to change current to desired mount entries.
//
// The current and desired profiles is a fstab like list of mount entries. The
// lists are processed and a "diff" of mount changes is produced. The mount
// changes, when applied in order, transform the current profile into the
// desired profile.
func NeededChanges(currentProfile, desiredProfile *mount.Profile) []*Change {
	// Copy both profiles as we will want to mutate them.
	current := make([]mount.Entry, len(currentProfile.Entries))
	copy(current, currentProfile.Entries)
	desired := make([]mount.Entry, len(desiredProfile.Entries))
	copy(desired, desiredProfile.Entries)

	// Clean the directory part of both profiles. This is done so that we can
	// easily test if a given directory is a subdirectory with
	// strings.HasPrefix coupled with an extra slash character.
	for i := range current {
		current[i].Dir = filepath.Clean(current[i].Dir)
	}
	for i := range desired {
		desired[i].Dir = filepath.Clean(desired[i].Dir)
	}

	// Sort both lists by directory name with implicit trailing slash.
	sort.Sort(byMagicDir(current))
	sort.Sort(byMagicDir(desired))

	// Construct a desired directory map.
	desiredMap := make(map[string]*mount.Entry)
	for i := range desired {
		desiredMap[desired[i].Dir] = &desired[i]
	}

	// Indexed by mount point path.
	reuse := make(map[string]bool)
	// Indexed by entry ID
	desiredIDs := make(map[string]bool)
	var skipDir string

	// Collect the IDs of desired changes.
	// We need that below to keep implicit changes from the current profile.
	for i := range desired {
		desiredIDs[XSnapdEntryID(&desired[i])] = true
	}

	// Compute reusable entries: those which are equal in current and desired and which
	// are not prefixed by another entry that changed.
	for i := range current {
		dir := current[i].Dir
		if skipDir != "" && strings.HasPrefix(dir, skipDir) {
			logger.Debugf("skipping entry %q", current[i])
			continue
		}
		skipDir = "" // reset skip prefix as it no longer applies

		// Reuse synthetic entries if their needed-by entry is desired.
		// Synthetic entries cannot exist on their own and always couple to a
		// non-synthetic entry.

		// NOTE: Synthetic changes have a special purpose.
		//
		// They are a "shadow" of mount events that occurred to allow one of
		// the desired mount entries to be possible. The changes have only one
		// goal: tell snap-update-ns how those mount events can be undone in
		// case they are no longer needed. The actual changes may have been
		// different and may have involved steps not represented as synthetic
		// mount entires as long as those synthetic entries can be undone to
		// reverse the effect. In reality each non-tmpfs synthetic entry was
		// constructed using a temporary bind mount that contained the original
		// mount entries of a directory that was hidden with a tmpfs, but this
		// fact was lost.
		if XSnapdSynthetic(&current[i]) && desiredIDs[XSnapdNeededBy(&current[i])] {
			logger.Debugf("reusing synthetic entry %q", current[i])
			reuse[dir] = true
			continue
		}

		// Reuse entries that are desired and identical in the current profile.
		if entry, ok := desiredMap[dir]; ok && current[i].Equal(entry) {
			logger.Debugf("reusing unchanged entry %q", current[i])
			reuse[dir] = true
			continue
		}

		skipDir = strings.TrimSuffix(dir, "/") + "/"
	}

	logger.Debugf("desiredIDs: %v", desiredIDs)
	logger.Debugf("reuse: %v", reuse)

	// We are now ready to compute the necessary mount changes.
	var changes []*Change

	// Unmount entries not reused in reverse to handle children before their parent.
	for i := len(current) - 1; i >= 0; i-- {
		if reuse[current[i].Dir] {
			changes = append(changes, &Change{Action: Keep, Entry: current[i]})
		} else {
			changes = append(changes, &Change{Action: Unmount, Entry: current[i]})
		}
	}

	// Mount desired entries not reused.
	for i := range desired {
		if !reuse[desired[i].Dir] {
			changes = append(changes, &Change{Action: Mount, Entry: desired[i]})
		}
	}

	return changes
}
