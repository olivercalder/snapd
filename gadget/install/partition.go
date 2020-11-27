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

package install

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/snapcore/snapd/gadget"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
)

var (
	ensureNodesExist = ensureNodesExistImpl
)

// createMissingPartitions creates the partitions listed in the laid out volume
// pv that are missing from the existing device layout, returning a list of
// structures that have been created.
func createMissingPartitions(dl *gadget.OnDiskVolume, pv *gadget.LaidOutVolume) ([]gadget.OnDiskStructure, error) {
	buf, created := gadget.BuildPartitionList(dl, pv)
	if len(created) == 0 {
		return created, nil
	}

	logger.Debugf("create partitions on %s: %s", dl.Device, buf.String())

	// Write the partition table. By default sfdisk will try to re-read the
	// partition table with the BLKRRPART ioctl but will fail because the
	// kernel side rescan removes and adds partitions and we have partitions
	// mounted (so it fails on removal). Use --no-reread to skip this attempt.
	cmd := exec.Command("sfdisk", "--append", "--no-reread", dl.Device)
	cmd.Stdin = buf
	if output, err := cmd.CombinedOutput(); err != nil {
		return created, osutil.OutputErr(output, err)
	}

	// Re-read the partition table
	if err := reloadPartitionTable(dl.Device); err != nil {
		return nil, err
	}

	// Make sure the devices for the partitions we created are available
	if err := ensureNodesExist(created, 5*time.Second); err != nil {
		return nil, fmt.Errorf("partition not available: %v", err)
	}

	return created, nil
}

// removeCreatedPartitions removes partitions added during a previous install.
func removeCreatedPartitions(lv *gadget.LaidOutVolume, dl *gadget.OnDiskVolume) error {
	indexes := make([]string, 0, len(dl.Structure))
	for i, s := range dl.Structure {
		if wasCreatedDuringInstall(lv, s) {
			logger.Noticef("partition %s was created during previous install", s.Node)
			indexes = append(indexes, strconv.Itoa(i+1))
		}
	}
	if len(indexes) == 0 {
		return nil
	}

	// Delete disk partitions
	logger.Debugf("delete disk partitions %v", indexes)
	cmd := exec.Command("sfdisk", append([]string{"--no-reread", "--delete", dl.Device}, indexes...)...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}

	// Reload the partition table
	if err := reloadPartitionTable(dl.Device); err != nil {
		return err
	}

	// Re-read the partition table from the device to update our partition list
	if err := gadget.UpdatePartitionList(dl); err != nil {
		return err
	}

	// Ensure all created partitions were removed
	if remaining := createdDuringInstall(lv, dl); len(remaining) > 0 {
		return fmt.Errorf("cannot remove partitions: %s", strings.Join(remaining, ", "))
	}

	return nil
}

// ensureNodeExists makes sure the device nodes for all device structures are
// available and notified to udev, within a specified amount of time.
func ensureNodesExistImpl(dss []gadget.OnDiskStructure, timeout time.Duration) error {
	t0 := time.Now()
	for _, ds := range dss {
		found := false
		for time.Since(t0) < timeout {
			if osutil.FileExists(ds.Node) {
				found = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if found {
			if err := udevTrigger(ds.Node); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("device %s not available", ds.Node)
		}
	}
	return nil
}

// reloadPartitionTable instructs the kernel to re-read the partition
// table of a given block device.
func reloadPartitionTable(device string) error {
	// Re-read the partition table using the BLKPG ioctl, which doesn't
	// remove existing partitions, only appends new partitions with the right
	// size and offset. As long as we provide consistent partitioning from
	// userspace we're safe.
	output, err := exec.Command("partx", "-u", device).CombinedOutput()
	if err != nil {
		return osutil.OutputErr(output, err)
	}
	return nil
}

// udevTrigger triggers udev for the specified device and waits until
// all events in the udev queue are handled.
func udevTrigger(device string) error {
	if output, err := exec.Command("udevadm", "trigger", "--settle", device).CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}
	return nil
}

// wasCreatedDuringInstall returns if the OnDiskStructure was created during
// install by referencing the gadget volume. A structure is only considered to
// be created during install if it is a role that is created during install and
// the start offsets match. We specifically don't look at anything on the
// structure such as filesystem information since this may be incomplete due to
// a failed installation, or due to the partial layout that is created by some
// ARM tools (i.e. ptool and fastboot) when flashing images to internal MMC.
func wasCreatedDuringInstall(lv *gadget.LaidOutVolume, s gadget.OnDiskStructure) bool {
	// for a structure to have been created during install, it must be one of
	// the system-boot, system-data, or system-save roles from the gadget, and
	// as such the on disk structure must exist in the exact same location as
	// the role from the gadget, so only return true if the provided structure
	// has the exact same StartOffset as one of those roles
	for _, gs := range lv.LaidOutStructure {
		// TODO: how to handle ubuntu-save here? maybe a higher level function
		//       should decide whether to delete it or not?
		switch gs.Role {
		case gadget.SystemSave, gadget.SystemData, gadget.SystemBoot:
			// then it was created during install or is to be created during
			// install, see if the offset matches the provided on disk structure
			// has
			if s.StartOffset == gs.StartOffset {
				return true
			}
		}
	}

	return false
}

// createdDuringInstall returns a list of partitions created during the
// install process.
func createdDuringInstall(lv *gadget.LaidOutVolume, layout *gadget.OnDiskVolume) (created []string) {
	created = make([]string, 0, len(layout.Structure))
	for _, s := range layout.Structure {
		if wasCreatedDuringInstall(lv, s) {
			created = append(created, s.Node)
		}
	}
	return created
}
