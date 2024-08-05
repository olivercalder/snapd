// -*- Mode: Go; indent-tabs-mode: t -*-
//go:build !nosecboot

/*
 * Copyright (C) 2024 Canonical Ltd
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

package secboot_test

import (
	"fmt"

	sb "github.com/snapcore/secboot"
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/secboot"
)

type bootstrapContainerSuite struct {
}

var _ = Suite(&bootstrapContainerSuite{})

func (*bootstrapContainerSuite) TestBootstrappedContainerHappy(c *C) {
	container := secboot.CreateBootstrappedContainer([]byte{1, 2, 3, 4}, "/dev/foo")

	defer secboot.MockAddLUKS2ContainerUnlockKey(func(devicePath string, keyslotName string, existingKey sb.DiskUnlockKey, newKey sb.DiskUnlockKey) error {
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "slot-name")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(newKey, DeepEquals, sb.DiskUnlockKey([]byte{5, 6, 7, 8}))
		return nil
	})()

	_, err := container.AddKey("slot-name", []byte{5, 6, 7, 8}, false)
	c.Assert(err, IsNil)

	defer secboot.MockAddLUKS2ContainerUnlockKey(func(devicePath string, keyslotName string, existingKey sb.DiskUnlockKey, newKey sb.DiskUnlockKey) error {
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "default")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(newKey, DeepEquals, sb.DiskUnlockKey([]byte{9, 10, 11, 12}))
		return nil
	})()

	_, err = container.AddKey("", []byte{9, 10, 11, 12}, false)
	c.Assert(err, IsNil)

	defer secboot.MockDeleteLUKS2ContainerKey(func(devicePath, slotName string) error {
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(slotName, Equals, "bootstrap-key")
		return nil
	})()

	err = container.RemoveBootstrapKey()
	c.Assert(err, IsNil)

	defer secboot.MockDeleteLUKS2ContainerKey(func(devicePath, slotName string) error {
		c.Errorf("unexpected call")
		return nil
	})()

	err = container.RemoveBootstrapKey()
	c.Assert(err, IsNil)
}

func (*bootstrapContainerSuite) TestBootstrappedContainerErrorAddKey(c *C) {
	container := secboot.CreateBootstrappedContainer([]byte{1, 2, 3, 4}, "/dev/foo")

	defer secboot.MockAddLUKS2ContainerUnlockKey(func(devicePath string, keyslotName string, existingKey sb.DiskUnlockKey, newKey sb.DiskUnlockKey) error {
		return fmt.Errorf("boom")
	})()

	_, err := container.AddKey("slot-name", []byte{5, 6, 7, 8}, false)
	c.Assert(err, ErrorMatches, `boom`)
}

func (*bootstrapContainerSuite) TestBootstrappedContainerErrorRemoveKey(c *C) {
	container := secboot.CreateBootstrappedContainer([]byte{1, 2, 3, 4}, "/dev/foo")

	defer secboot.MockDeleteLUKS2ContainerKey(func(devicePath, slotName string) error {
		return fmt.Errorf("boom")
	})()

	err := container.RemoveBootstrapKey()
	c.Assert(err, ErrorMatches, `cannot remove bootstrap key: boom`)
}
