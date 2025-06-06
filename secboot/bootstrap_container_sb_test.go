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
	"bytes"
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
	var addUnlockKeyCalled, addRecoveryKeyCalled, deleteKeyCalled int

	defer secboot.MockAddLUKS2ContainerUnlockKey(func(devicePath string, keyslotName string, existingKey sb.DiskUnlockKey, newKey sb.DiskUnlockKey) error {
		addUnlockKeyCalled++
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "slot-name")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(newKey, DeepEquals, sb.DiskUnlockKey([]byte{5, 6, 7, 8}))
		return nil
	})()

	err := container.AddKey("slot-name", []byte{5, 6, 7, 8})
	c.Assert(err, IsNil)
	c.Assert(addUnlockKeyCalled, Equals, 1)
	c.Assert(addRecoveryKeyCalled, Equals, 0)
	c.Assert(deleteKeyCalled, Equals, 0)

	defer secboot.MockAddLUKS2ContainerUnlockKey(func(devicePath string, keyslotName string, existingKey sb.DiskUnlockKey, newKey sb.DiskUnlockKey) error {
		addUnlockKeyCalled++
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "default")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(newKey, DeepEquals, sb.DiskUnlockKey([]byte{9, 10, 11, 12}))
		return nil
	})()

	err = container.AddKey("", []byte{9, 10, 11, 12})
	c.Assert(err, IsNil)
	c.Assert(addUnlockKeyCalled, Equals, 2)
	c.Assert(addRecoveryKeyCalled, Equals, 0)
	c.Assert(deleteKeyCalled, Equals, 0)

	defer secboot.MockAddLUKS2ContainerRecoveryKey(func(devicePath, keyslotName string, existingKey sb.DiskUnlockKey, recoveryKey sb.RecoveryKey) error {
		addRecoveryKeyCalled++
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "recovery-slot-name")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(recoveryKey, Equals, sb.RecoveryKey([16]byte{12, 11, 10, 9}))
		return nil
	})()

	err = container.AddRecoveryKey("recovery-slot-name", [16]byte{12, 11, 10, 9})
	c.Assert(err, IsNil)
	c.Assert(addUnlockKeyCalled, Equals, 2)
	c.Assert(addRecoveryKeyCalled, Equals, 1)
	c.Assert(deleteKeyCalled, Equals, 0)

	defer secboot.MockAddLUKS2ContainerRecoveryKey(func(devicePath, keyslotName string, existingKey sb.DiskUnlockKey, recoveryKey sb.RecoveryKey) error {
		addRecoveryKeyCalled++
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "default-recovery")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(recoveryKey, Equals, sb.RecoveryKey([16]byte{12, 11, 10, 9}))
		return nil
	})()

	err = container.AddRecoveryKey("", [16]byte{12, 11, 10, 9})
	c.Assert(err, IsNil)
	c.Assert(addUnlockKeyCalled, Equals, 2)
	c.Assert(addRecoveryKeyCalled, Equals, 2)
	c.Assert(deleteKeyCalled, Equals, 0)

	defer secboot.MockDeleteLUKS2ContainerKey(func(devicePath, slotName string) error {
		deleteKeyCalled++
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(slotName, Equals, "bootstrap-key")
		return nil
	})()

	err = container.RemoveBootstrapKey()
	c.Assert(err, IsNil)
	c.Assert(addUnlockKeyCalled, Equals, 2)
	c.Assert(addRecoveryKeyCalled, Equals, 2)
	c.Assert(deleteKeyCalled, Equals, 1)

	defer secboot.MockDeleteLUKS2ContainerKey(func(devicePath, slotName string) error {
		deleteKeyCalled++
		c.Errorf("unexpected call")
		return nil
	})()

	err = container.RemoveBootstrapKey()
	c.Assert(err, IsNil)
	c.Assert(addUnlockKeyCalled, Equals, 2)
	c.Assert(addRecoveryKeyCalled, Equals, 2)
	c.Assert(deleteKeyCalled, Equals, 1)
}

type myKeyDataWriter struct {
	bytes.Buffer
}

func (m *myKeyDataWriter) Commit() error {
	return nil
}

func (*bootstrapContainerSuite) TestBootstrappedContainerHappyTokenWriter(c *C) {
	container := secboot.CreateBootstrappedContainer([]byte{1, 2, 3, 4}, "/dev/foo")

	defer secboot.MockAddLUKS2ContainerUnlockKey(func(devicePath string, keyslotName string, existingKey sb.DiskUnlockKey, newKey sb.DiskUnlockKey) error {
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "slot-name")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(newKey, DeepEquals, sb.DiskUnlockKey([]byte{5, 6, 7, 8}))
		return nil
	})()

	err := container.AddKey("slot-name", []byte{5, 6, 7, 8})
	c.Assert(err, IsNil)

	defer secboot.MockAddLUKS2ContainerUnlockKey(func(devicePath string, keyslotName string, existingKey sb.DiskUnlockKey, newKey sb.DiskUnlockKey) error {
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "default")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(newKey, DeepEquals, sb.DiskUnlockKey([]byte{9, 10, 11, 12}))
		return nil
	})()

	keyDataWriter := &myKeyDataWriter{}

	defer secboot.MockNewLUKS2KeyDataWriter(func(devicePath string, keyslotName string) (secboot.KeyDataWriter, error) {
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "default")
		return keyDataWriter, nil
	})()

	err = container.AddKey("", []byte{9, 10, 11, 12})
	c.Assert(err, IsNil)
	tokenWriter, err := container.GetTokenWriter("")
	c.Assert(err, IsNil)
	c.Check(tokenWriter, Equals, keyDataWriter)

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

	err := container.AddKey("slot-name", []byte{5, 6, 7, 8})
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

func (*bootstrapContainerSuite) TestBootstrappedContainerTokenWriterFailure(c *C) {
	container := secboot.CreateBootstrappedContainer([]byte{1, 2, 3, 4}, "/dev/foo")

	defer secboot.MockAddLUKS2ContainerUnlockKey(func(devicePath string, keyslotName string, existingKey sb.DiskUnlockKey, newKey sb.DiskUnlockKey) error {
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "slot-name")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(newKey, DeepEquals, sb.DiskUnlockKey([]byte{5, 6, 7, 8}))
		return nil
	})()

	err := container.AddKey("slot-name", []byte{5, 6, 7, 8})
	c.Assert(err, IsNil)

	defer secboot.MockAddLUKS2ContainerUnlockKey(func(devicePath string, keyslotName string, existingKey sb.DiskUnlockKey, newKey sb.DiskUnlockKey) error {
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "default")
		c.Check(existingKey, DeepEquals, sb.DiskUnlockKey([]byte{1, 2, 3, 4}))
		c.Check(newKey, DeepEquals, sb.DiskUnlockKey([]byte{9, 10, 11, 12}))
		return nil
	})()

	defer secboot.MockNewLUKS2KeyDataWriter(func(devicePath string, keyslotName string) (secboot.KeyDataWriter, error) {
		c.Check(devicePath, Equals, "/dev/foo")
		c.Check(keyslotName, Equals, "default")
		return nil, fmt.Errorf("some error")
	})()

	err = container.AddKey("", []byte{9, 10, 11, 12})
	c.Assert(err, IsNil)
	_, err = container.GetTokenWriter("")
	c.Assert(err, ErrorMatches, `some error`)
}

func (*bootstrapContainerSuite) TestBootstrappedContainerKeyringHappy(c *C) {
	container := secboot.CreateBootstrappedContainer([]byte{50, 51, 52, 53}, "/dev/foo")

	primaryKeyRegistered := 0
	unlockKeyRegistered := 0
	defer secboot.MockUnixAddKey(func(keyType string, description string, payload []byte, ringid int) (int, error) {
		switch description {
		case "ubuntu-fde:/dev/disk/by-uuid/1234:aux":
			primaryKeyRegistered++
			c.Check(payload, DeepEquals, []byte{1, 2, 3, 4})
		case "ubuntu-fde:/dev/disk/by-uuid/1234:unlock":
			unlockKeyRegistered++
			c.Check(payload, DeepEquals, []byte{5, 6, 7, 8})
		default:
			c.Errorf("unexpected description")
			return 0, fmt.Errorf("unexpected description")
		}

		c.Check(keyType, Equals, "user")
		c.Check(ringid, Equals, -4)

		return 42, nil
	})()

	defer secboot.MockDisksDevlinks(func(node string) ([]string, error) {
		c.Check(node, Equals, "/dev/foo")
		return []string{
			"/dev/foo",
			"/dev/disk/by-uuid/1234",
		}, nil
	})()

	container.RegisterKeyAsUsed([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})

	c.Check(primaryKeyRegistered, Equals, 1)
	c.Check(unlockKeyRegistered, Equals, 1)
}
