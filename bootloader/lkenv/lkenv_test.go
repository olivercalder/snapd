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

package lkenv_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/bootloader/lkenv"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/testutil"
)

// Hook up check.v1 into the "go test" runner
func Test(t *testing.T) { TestingT(t) }

type lkenvTestSuite struct {
	envPath    string
	envPathbak string
}

var _ = Suite(&lkenvTestSuite{})

func (l *lkenvTestSuite) SetUpTest(c *C) {
	l.envPath = filepath.Join(c.MkDir(), "snapbootsel.bin")
	l.envPathbak = l.envPath + "bak"
}

// unpack test data packed with gzip
func unpackTestData(data []byte) (resData []byte, err error) {
	b := bytes.NewBuffer(data)
	var r io.Reader
	r, err = gzip.NewReader(b)
	if err != nil {
		return
	}
	var env bytes.Buffer
	_, err = env.ReadFrom(r)
	if err != nil {
		return
	}
	return env.Bytes(), nil
}

func (l *lkenvTestSuite) TestCtoGoString(c *C) {
	for _, t := range []struct {
		input    []byte
		expected string
	}{
		{[]byte{0, 0, 0, 0, 0}, ""},
		{[]byte{'a', 0, 0, 0, 0}, "a"},
		{[]byte{'a', 'b', 0, 0, 0}, "ab"},
		{[]byte{'a', 'b', 'c', 0, 0}, "abc"},
		{[]byte{'a', 'b', 'c', 'd', 0}, "abcd"},
		// no trailing \0 - assume corrupted "" ?
		{[]byte{'a', 'b', 'c', 'd', 'e'}, ""},
		// first \0 is the cutof
		{[]byte{'a', 'b', 0, 'z', 0}, "ab"},
	} {
		c.Check(lkenv.CToGoString(t.input), Equals, t.expected)
	}
}

func (l *lkenvTestSuite) TestCopyStringHappy(c *C) {
	for _, t := range []struct {
		input    string
		expected []byte
	}{
		// input up to the size of the buffer works
		{"", []byte{0, 0, 0, 0, 0}},
		{"a", []byte{'a', 0, 0, 0, 0}},
		{"ab", []byte{'a', 'b', 0, 0, 0}},
		{"abc", []byte{'a', 'b', 'c', 0, 0}},
		{"abcd", []byte{'a', 'b', 'c', 'd', 0}},
		// only what fit is copied
		{"abcde", []byte{'a', 'b', 'c', 'd', 0}},
		{"abcdef", []byte{'a', 'b', 'c', 'd', 0}},
		// strange embedded stuff works
		{"ab\000z", []byte{'a', 'b', 0, 'z', 0}},
	} {
		b := make([]byte, 5)
		lkenv.CopyString(b, t.input)
		c.Check(b, DeepEquals, t.expected)
	}
}

func (l *lkenvTestSuite) TestCopyStringNoPanic(c *C) {
	// too long, string should get concatenate
	b := make([]byte, 5)
	defer lkenv.CopyString(b, "12345")
	c.Assert(recover(), IsNil)
	defer lkenv.CopyString(b, "123456")
	c.Assert(recover(), IsNil)
}

func (l *lkenvTestSuite) TestSet(c *C) {
	tt := []struct {
		version lkenv.Version
		key     string
		val     string
	}{
		{
			lkenv.V1,
			"snap_mode",
			boot.TryStatus,
		},
		{
			lkenv.V2Run,
			"kernel_status",
			boot.TryingStatus,
		},
		{
			lkenv.V2Recovery,
			"snapd_recovery_mode",
			"recover",
		},
	}
	for _, t := range tt {
		env := lkenv.NewEnv(l.envPath, t.version)
		c.Check(env, NotNil)
		env.Set(t.key, t.val)
		c.Check(env.Get(t.key), Equals, t.val)
	}
}

func (l *lkenvTestSuite) TestSave(c *C) {
	tt := []struct {
		version       lkenv.Version
		keyValuePairs map[string]string
		comment       string
	}{
		{
			lkenv.V1,
			map[string]string{
				"snap_mode":         boot.TryingStatus,
				"snap_kernel":       "kernel-1",
				"snap_try_kernel":   "kernel-2",
				"snap_core":         "core-1",
				"snap_try_core":     "core-2",
				"snap_gadget":       "gadget-1",
				"snap_try_gadget":   "gadget-2",
				"bootimg_file_name": "boot.img",
			},
			"lkenv v1",
		},
		{
			lkenv.V2Run,
			map[string]string{
				"kernel_status":     boot.TryStatus,
				"snap_kernel":       "kernel-1",
				"snap_try_kernel":   "kernel-2",
				"snap_gadget":       "gadget-1",
				"snap_try_gadget":   "gadget-2",
				"bootimg_file_name": "boot.img",
			},
			"lkenv v2 run",
		},
		{
			lkenv.V2Recovery,
			map[string]string{
				"snapd_recovery_mode":   "recover",
				"snapd_recovery_system": "11192020",
				"bootimg_file_name":     "boot.img",
			},
			"lkenv v2 recovery",
		},
	}
	for _, t := range tt {
		for _, makeBackup := range []bool{true, false} {
			var comment CommentInterface
			if makeBackup {
				comment = Commentf("testcase %s with backup", t.comment)
			} else {
				comment = Commentf("testcase %s without backup", t.comment)
			}

			// make unique files per test case
			testFile := filepath.Join(c.MkDir(), "lk.bin")
			testFileBackup := testFile + "bak"
			if makeBackup {
				// create the backup file too
				buf := make([]byte, 4096)
				err := ioutil.WriteFile(testFileBackup, buf, 0644)
				c.Assert(err, IsNil, comment)
			}

			buf := make([]byte, 4096)
			err := ioutil.WriteFile(testFile, buf, 0644)
			c.Assert(err, IsNil, comment)

			env := lkenv.NewEnv(testFile, t.version)
			c.Check(env, NotNil, comment)

			for k, v := range t.keyValuePairs {
				env.Set(k, v)
			}

			err = env.Save()
			c.Assert(err, IsNil, comment)

			env2 := lkenv.NewEnv(testFile, t.version)
			err = env2.Load()
			c.Assert(err, IsNil, comment)

			for k, v := range t.keyValuePairs {
				c.Check(env2.Get(k), Equals, v, comment)
			}

			// check the backup too
			if makeBackup {
				env3 := lkenv.NewEnv(testFileBackup, t.version)
				err := env3.Load()
				c.Assert(err, IsNil, comment)

				for k, v := range t.keyValuePairs {
					c.Check(env3.Get(k), Equals, v, comment)
				}
			}
		}
	}
}

func (l *lkenvTestSuite) TestLoad(c *C) {

	for _, version := range []lkenv.Version{lkenv.V1, lkenv.V2Run, lkenv.V2Recovery} {
		for _, makeBackup := range []bool{true, false} {
			loggerBuf, restore := logger.MockLogger()
			defer restore()
			// make unique files per test case
			testFile := filepath.Join(c.MkDir(), "lk.bin")
			testFileBackup := testFile + "bak"
			if makeBackup {
				buf := make([]byte, 100000)
				err := ioutil.WriteFile(testFileBackup, buf, 0644)
				c.Assert(err, IsNil)
			}

			buf := make([]byte, 100000)
			err := ioutil.WriteFile(testFile, buf, 0644)
			c.Assert(err, IsNil)

			// create an env for this file and try to load it
			env := lkenv.NewEnv(testFile, version)
			c.Check(env, NotNil)

			err = env.Load()
			// possible error messages could be "cannot open LK env file: ..."
			// or "cannot read LK env from file: ..."
			// c.Assert(err, ErrorMatches, "cannot .* LK env .*")
			if makeBackup {
				// here we will read the backup file which exists but like the
				// primary file is corrupted
				c.Assert(err, ErrorMatches, fmt.Sprintf("cannot validate %s: expected version 0x%X, got 0x0", testFileBackup, version.Number()))
			} else {
				// here we fail to read the normal file, and automatically try
				// to read the backup, but fail because it doesn't exist
				c.Assert(err, ErrorMatches, fmt.Sprintf("cannot open LK env file: open %s: no such file or directory", testFileBackup))
			}

			c.Assert(loggerBuf.String(), testutil.Contains, fmt.Sprintf("cannot load primary bootloader environment: cannot validate %s:", testFile))
			c.Assert(loggerBuf.String(), testutil.Contains, "attempting to load backup bootloader environment")
		}
	}
}

func (l *lkenvTestSuite) TestFailedCRCFallBack(c *C) {
	buf := make([]byte, 4096)
	err := ioutil.WriteFile(l.envPath, buf, 0644)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(l.envPathbak, buf, 0644)
	c.Assert(err, IsNil)

	env := lkenv.NewEnv(l.envPath, lkenv.V1)
	c.Check(env, NotNil)

	env.Set("snap_mode", boot.TryingStatus)
	env.Set("snap_kernel", "kernel-1")
	env.Set("snap_try_kernel", "kernel-2")
	err = env.Save()
	c.Assert(err, IsNil)

	// break main env file
	err = ioutil.WriteFile(l.envPath, buf, 0644)
	c.Assert(err, IsNil)

	env2 := lkenv.NewEnv(l.envPath, lkenv.V1)
	err = env2.Load()
	c.Assert(err, IsNil)
	c.Check(env2.Get("snap_mode"), Equals, boot.TryingStatus)
	c.Check(env2.Get("snap_kernel"), Equals, "kernel-1")
	c.Check(env2.Get("snap_try_kernel"), Equals, "kernel-2")
}

func (l *lkenvTestSuite) TestGetBootPartition(c *C) {
	buf := make([]byte, 4096)
	err := ioutil.WriteFile(l.envPath, buf, 0644)
	c.Assert(err, IsNil)

	env := lkenv.NewEnv(l.envPath, lkenv.V1)
	c.Assert(err, IsNil)
	env.InitializeBootPartitions("boot_a", "boot_b")
	// test no boot partition used
	p, err := env.FindFreeKernelBootPartition("kernel-1")
	c.Check(p, Equals, "boot_a")
	c.Assert(err, IsNil)
	//  set kernel-2 to boot_a partition
	err = env.SetBootPartitionKernel("boot_a", "kernel-1")
	c.Assert(err, IsNil)
	//  set kernel-2 to boot_a partition
	err = env.SetBootPartitionKernel("boot_b", "kernel-2")
	c.Assert(err, IsNil)

	// 'boot_a' has 'kernel-1' revision
	p, err = env.GetKernelBootPartition("kernel-1")
	c.Check(p, Equals, "boot_a")
	c.Assert(err, IsNil)
	// 'boot_b' has 'kernel-2' revision
	p, err = env.GetKernelBootPartition("kernel-2")
	c.Check(p, Equals, "boot_b")
	c.Assert(err, IsNil)
}

func (l *lkenvTestSuite) TestFindFree_Set_Free_BootPartition(c *C) {
	buf := make([]byte, 4096)
	err := ioutil.WriteFile(l.envPath, buf, 0644)
	c.Assert(err, IsNil)

	env := lkenv.NewEnv(l.envPath, lkenv.V1)
	c.Assert(err, IsNil)
	env.InitializeBootPartitions("boot_a", "boot_b")
	// test no boot partition used
	p, err := env.FindFreeKernelBootPartition("kernel-1")
	c.Check(p, Equals, "boot_a")
	c.Assert(err, IsNil)
	//  set kernel-2 to boot_a partition
	err = env.SetBootPartitionKernel("boot_a", "kernel-2")
	c.Assert(err, IsNil)

	env.Set("snap_kernel", "kernel-2")
	// kernel-2 should now return first part, as it's already there
	// TODO: do we really care about this check? What does it represent? I can't
	// think of a situation in which we have snap_kernel of kernel-2 installed
	// and we go to then call FindFreeKernelBootPartition("kernel-2")? why would
	// snapd try to call ExtractKernelAssets on an already installed kernel?
	p, err = env.FindFreeKernelBootPartition("kernel-2")
	c.Check(p, Equals, "boot_a")
	c.Assert(err, IsNil)
	// test kernel-1 snapd, it should now offer second partition
	p, err = env.FindFreeKernelBootPartition("kernel-1")
	c.Check(p, Equals, "boot_b")
	c.Assert(err, IsNil)
	err = env.SetBootPartitionKernel("boot_b", "kernel-1")
	c.Assert(err, IsNil)
	// set boot kernel-1
	env.Set("snap_kernel", "kernel-1")
	// now kernel-2 should not be protected and boot_a shoild be offered
	p, err = env.FindFreeKernelBootPartition("kernel-3")
	c.Check(p, Equals, "boot_a")
	c.Assert(err, IsNil)
	err = env.SetBootPartitionKernel("boot_a", "kernel-3")
	c.Assert(err, IsNil)
	// remove kernel
	err = env.RemoveKernelFromBootPartition("kernel-3")
	c.Assert(err, IsNil)
	// repeated use should return false and error
	err = env.RemoveKernelFromBootPartition("kernel-3")
	c.Assert(err, NotNil)
}

func (l *lkenvTestSuite) TestZippedDataSample(c *C) {
	// test data is generated with gadget build helper tool:
	// $ parts/snap-boot-sel-env/build/lk-boot-env -w test.bin \
	//   --snap-mode="trying" --snap-kernel="kernel-1" --snap-try-kernel="kernel-2" \
	//   --snap-core="core-1" --snap-try-core="core-2" --reboot-reason="" \
	//   --boot-0-part="boot_a" --boot-1-part="boot_b" --boot-0-snap="kernel-1" \
	//   --boot-1-snap="kernel-3" --bootimg-file="boot.img"
	// $ cat test.bin | gzip | xxd -i
	gzipedData := []byte{
		0x1f, 0x8b, 0x08, 0x00, 0x95, 0x88, 0x77, 0x5d, 0x00, 0x03, 0xed, 0xd7,
		0xc1, 0x09, 0xc2, 0x40, 0x10, 0x05, 0xd0, 0xa4, 0x20, 0x05, 0x63, 0x07,
		0x96, 0xa0, 0x05, 0x88, 0x91, 0x25, 0x04, 0x35, 0x0b, 0x6b, 0x2e, 0x1e,
		0xac, 0xcb, 0xf6, 0xc4, 0x90, 0x1e, 0x06, 0xd9, 0xf7, 0x2a, 0xf8, 0xc3,
		0x1f, 0x18, 0xe6, 0x74, 0x78, 0xa6, 0xb6, 0x69, 0x9b, 0xb9, 0xbc, 0xc6,
		0x69, 0x68, 0xaa, 0x75, 0xcd, 0x25, 0x6d, 0x76, 0xd1, 0x29, 0xe2, 0x2c,
		0xf3, 0x77, 0xd1, 0x29, 0xe2, 0xdc, 0x52, 0x99, 0xd2, 0xbd, 0xde, 0x0d,
		0x58, 0xe7, 0xaf, 0x78, 0x03, 0x80, 0x5a, 0xf5, 0x39, 0xcf, 0xe7, 0x4b,
		0x74, 0x8a, 0x38, 0xb5, 0xdf, 0xbf, 0xa5, 0xff, 0x3e, 0x3a, 0x45, 0x9c,
		0xb5, 0xff, 0x7d, 0x74, 0x8e, 0x28, 0xbf, 0xfe, 0xb7, 0xe3, 0xa3, 0xe2,
		0x0f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xf8, 0x17, 0xc7, 0xf7, 0xa7, 0xfb, 0x02, 0x1c, 0xdf, 0x44, 0x21, 0x0c,
		0x3a, 0x00, 0x00}

	// uncompress test data to sample env file
	rawData, err := unpackTestData(gzipedData)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(l.envPath, rawData, 0644)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(l.envPathbak, rawData, 0644)
	c.Assert(err, IsNil)

	env := lkenv.NewEnv(l.envPath, lkenv.V1)
	c.Check(env, NotNil)
	err = env.Load()
	c.Assert(err, IsNil)
	c.Check(env.Get("snap_mode"), Equals, boot.TryingStatus)
	c.Check(env.Get("snap_kernel"), Equals, "kernel-1")
	c.Check(env.Get("snap_try_kernel"), Equals, "kernel-2")
	c.Check(env.Get("snap_core"), Equals, "core-1")
	c.Check(env.Get("snap_try_core"), Equals, "core-2")
	c.Check(env.Get("bootimg_file_name"), Equals, "boot.img")
	c.Check(env.Get("reboot_reason"), Equals, "")
	// first partition should be with label 'boot_a' and 'kernel-1' revision
	p, err := env.GetKernelBootPartition("kernel-1")
	c.Check(p, Equals, "boot_a")
	c.Assert(err, IsNil)
	// test second boot partition is free with label "boot_b"
	p, err = env.FindFreeKernelBootPartition("kernel-2")
	c.Check(p, Equals, "boot_b")
	c.Assert(err, IsNil)
}
