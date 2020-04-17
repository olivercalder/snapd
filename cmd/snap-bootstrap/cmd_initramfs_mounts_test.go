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

package main_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot"
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/boot/boottest"
	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/bootloader/bootloadertest"
	main "github.com/snapcore/snapd/cmd/snap-bootstrap"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/seed"
	"github.com/snapcore/snapd/seed/seedtest"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

var brandPrivKey, _ = assertstest.GenerateKey(752)

type initramfsMountsSuite struct {
	testutil.BaseTest

	// makes available a bunch of helper (like MakeAssertedSnap)
	*seedtest.TestingSeed20

	Stdout *bytes.Buffer

	seedDir  string
	sysLabel string
}

var _ = Suite(&initramfsMountsSuite{})

func (s *initramfsMountsSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.Stdout = bytes.NewBuffer(nil)
	restore := main.MockStdout(s.Stdout)
	s.AddCleanup(restore)

	_, restore = logger.MockLogger()
	s.AddCleanup(restore)

	// mock /run/mnt
	dirs.SetRootDir(c.MkDir())
	restore = func() { dirs.SetRootDir("") }
	s.AddCleanup(restore)

	// pretend /run/mnt/ubuntu-seed has a valid seed
	s.seedDir = boot.InitramfsUbuntuSeedDir

	// now create a minimal uc20 seed dir with snaps/assertions
	seed20 := &seedtest.TestingSeed20{SeedDir: s.seedDir}
	seed20.SetupAssertSigning("canonical")
	restore = seed.MockTrusted(seed20.StoreSigning.Trusted)
	s.AddCleanup(restore)

	// XXX: we don't really use this but seedtest always expects my-brand
	seed20.Brands.Register("my-brand", brandPrivKey, map[string]interface{}{
		"verification": "verified",
	})

	// add a bunch of snaps
	seed20.MakeAssertedSnap(c, "name: snapd\nversion: 1\ntype: snapd", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)
	seed20.MakeAssertedSnap(c, "name: pc\nversion: 1\ntype: gadget\nbase: core20", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)
	seed20.MakeAssertedSnap(c, "name: pc-kernel\nversion: 1\ntype: kernel", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)
	seed20.MakeAssertedSnap(c, "name: core20\nversion: 1\ntype: base", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)

	s.sysLabel = "20191118"
	seed20.MakeSeed(c, s.sysLabel, "my-brand", "my-model", map[string]interface{}{
		"display-name": "my model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []interface{}{
			map[string]interface{}{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]interface{}{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			}},
	}, nil)
}

func (s *initramfsMountsSuite) mockProcCmdlineContent(c *C, newContent string) {
	mockProcCmdline := filepath.Join(c.MkDir(), "proc-cmdline")
	err := ioutil.WriteFile(mockProcCmdline, []byte(newContent), 0644)
	c.Assert(err, IsNil)
	restore := boot.MockProcCmdline(mockProcCmdline)
	s.AddCleanup(restore)
}

func (s *initramfsMountsSuite) TestInitramfsMountsNoModeError(c *C) {
	s.mockProcCmdlineContent(c, "nothing-to-see")

	_, err := main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, ErrorMatches, "cannot detect mode nor recovery system to use")
}

func (s *initramfsMountsSuite) TestInitramfsMountsUnknownMode(c *C) {
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=install-foo")

	_, err := main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, ErrorMatches, `cannot use unknown mode "install-foo"`)
}

func (s *initramfsMountsSuite) TestInitramfsMountsInstallModeStep1(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode= snapd_recovery_system="+s.sysLabel)

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return false, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	_, err := main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 1)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf("/dev/disk/by-label/ubuntu-seed %s/ubuntu-seed\n", boot.InitramfsRunMntDir))
}

func (s *initramfsMountsSuite) TestInitramfsMountsInstallModeStep2(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=install snapd_recovery_system="+s.sysLabel)

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return false, nil
		case 3:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return false, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "snapd"))
			return false, nil
		case 5:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return false, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	_, err := main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 5)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`%[1]s/snaps/snapd_1.snap %[2]s/snapd
%[1]s/snaps/pc-kernel_1.snap %[2]s/kernel
%[1]s/snaps/core20_1.snap %[2]s/base
--type=tmpfs tmpfs /run/mnt/ubuntu-data
`, s.seedDir, boot.InitramfsRunMntDir))
}

func (s *initramfsMountsSuite) TestInitramfsMountsInstallModeStep4(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=install snapd_recovery_system="+s.sysLabel)

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return true, nil
		case 3:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "snapd"))
			return true, nil
		case 5:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return true, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	_, err := main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 5)
	c.Check(s.Stdout.String(), Equals, "")
	modeEnv := dirs.SnapModeenvFileUnder(boot.InitramfsWritableDir)
	c.Check(modeEnv, testutil.FileEquals, `mode=install
recovery_system=20191118
`)
	cloudInitDisable := filepath.Join(boot.InitramfsWritableDir, "etc/cloud/cloud-init.disabled")
	c.Check(cloudInitDisable, testutil.FilePresent)
}

func (s *initramfsMountsSuite) TestInitramfsMountsRunModeStep1(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return false, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return false, nil
		case 3:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return false, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	_, err := main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 3)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`/dev/disk/by-label/ubuntu-seed %[1]s/ubuntu-seed
/dev/disk/by-label/ubuntu-boot %[1]s/ubuntu-boot
/dev/disk/by-label/ubuntu-data %[1]s/ubuntu-data
`, boot.InitramfsRunMntDir))
}

func (s *initramfsMountsSuite) TestInitramfsMountsRunModeStep2(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return false, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return false, nil
		case 6:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "snapd"))
			return false, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write modeenv
	modeEnv := boot.Modeenv{
		RecoverySystem: "20191118",
		Base:           "core20_123.snap",
		CurrentKernels: []string{"pc-kernel_1.snap"},
	}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	// mock a bootloader
	bloader := boottest.MockUC20RunBootenv(bootloadertest.Mock("mock", c.MkDir()))
	bootloader.Force(bloader)
	defer bootloader.Force(nil)

	// set the current kernel
	kernel, err := snap.ParsePlaceInfoFromSnapFileName("pc-kernel_1.snap")
	c.Assert(err, IsNil)
	r := bloader.SetRunKernelImageEnabledKernel(kernel)
	defer r()

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 6)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`%[1]s/ubuntu-data/system-data/var/lib/snapd/snaps/core20_123.snap %[1]s/base
%[1]s/ubuntu-data/system-data/var/lib/snapd/snaps/pc-kernel_1.snap %[1]s/kernel
%[1]s/ubuntu-seed/snaps/snapd_1.snap %[1]s/snapd
`, boot.InitramfsRunMntDir))
}

func (s *initramfsMountsSuite) TestInitramfsMountsRunModeBaseSnapUpgradeFailsHappy(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return false, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return true, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write modeenv as if we failed to boot and were rebooted because the
	// base snap was broken
	modeEnv := &boot.Modeenv{
		Base:       "core20_123.snap",
		TryBase:    "core20_124.snap",
		BaseStatus: boot.TryingStatus,
	}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	tryBaseSnap := filepath.Join(boot.InitramfsWritableDir, dirs.SnapBlobDir, "core20_124.snap")
	err = os.MkdirAll(filepath.Dir(tryBaseSnap), 0755)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(tryBaseSnap, []byte{0}, 0644)
	c.Assert(err, IsNil)
	defer os.Remove(tryBaseSnap)

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 5)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`%[1]s/ubuntu-data/system-data/var/lib/snapd/snaps/core20_123.snap %[1]s/base
`, boot.InitramfsRunMntDir))

	// check that the modeenv was re-written
	newModeenv, err := boot.ReadModeenv(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)
	// BaseStatus was re-set to default
	c.Assert(newModeenv.BaseStatus, DeepEquals, boot.DefaultStatus)
	c.Assert(newModeenv.TryBase, DeepEquals, modeEnv.TryBase)
	c.Assert(newModeenv.Base, DeepEquals, modeEnv.Base)
}

func (s *initramfsMountsSuite) TestInitramfsMountsRunModeModeenvTryBaseEmptyHappy(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return false, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return true, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write a modeenv with no try_base so we fall back to using base
	modeEnv := &boot.Modeenv{
		Base:       "core20_123.snap",
		BaseStatus: boot.TryStatus,
	}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 5)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`%[1]s/ubuntu-data/system-data/var/lib/snapd/snaps/core20_123.snap %[1]s/base
`, boot.InitramfsRunMntDir))

	// check that the modeenv is the same
	newModeenv, err := boot.ReadModeenv(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)
	c.Assert(newModeenv.BaseStatus, DeepEquals, modeEnv.BaseStatus)
	c.Assert(newModeenv.TryBase, DeepEquals, modeEnv.TryBase)
	c.Assert(newModeenv.Base, DeepEquals, modeEnv.Base)
}

func (s *initramfsMountsSuite) TestInitramfsMountsRunModeBaseSnapUpgradeHappy(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return false, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return true, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write modeenv
	modeEnv := &boot.Modeenv{
		Base:       "core20_123.snap",
		TryBase:    "core20_124.snap",
		BaseStatus: boot.TryStatus,
	}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	tryBaseSnap := filepath.Join(dirs.SnapBlobDirUnder(boot.InitramfsWritableDir), "core20_124.snap")
	err = os.MkdirAll(filepath.Dir(tryBaseSnap), 0755)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(tryBaseSnap, []byte{0}, 0644)
	c.Assert(err, IsNil)
	defer os.Remove(tryBaseSnap)

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 5)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`%[1]s/ubuntu-data/system-data/var/lib/snapd/snaps/core20_124.snap %[1]s/base
`, boot.InitramfsRunMntDir))

	// check that the modeenv was re-written
	newModeenv, err := boot.ReadModeenv(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)
	c.Assert(newModeenv.BaseStatus, DeepEquals, boot.TryingStatus)
	c.Assert(newModeenv.TryBase, DeepEquals, modeEnv.TryBase)
	c.Assert(newModeenv.Base, DeepEquals, modeEnv.Base)
}

func (s *initramfsMountsSuite) TestInitramfsMountsRunModeModeenvBaseEmptyUnhappy(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return false, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return true, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write an empty modeenv
	modeEnv := &boot.Modeenv{}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, ErrorMatches, "modeenv corrupt: missing base setting")
	c.Assert(n, Equals, 4)
	c.Check(s.Stdout.String(), Equals, "")
}

func (s *initramfsMountsSuite) TestInitramfsMountsRunModeModeenvTryBaseNotExistsHappy(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return false, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return true, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write a modeenv with try_base not existing on disk so we fall back to
	// using the normal base
	modeEnv := &boot.Modeenv{
		Base:       "core20_123.snap",
		TryBase:    "core20_124.snap",
		BaseStatus: boot.TryStatus,
	}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 5)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`%[1]s/ubuntu-data/system-data/var/lib/snapd/snaps/core20_123.snap %[1]s/base
`, boot.InitramfsRunMntDir))

	// check that the modeenv is the same
	newModeenv, err := boot.ReadModeenv(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)
	c.Assert(newModeenv.BaseStatus, DeepEquals, modeEnv.BaseStatus)
	c.Assert(newModeenv.TryBase, DeepEquals, modeEnv.TryBase)
	c.Assert(newModeenv.Base, DeepEquals, modeEnv.Base)
}

func (s *initramfsMountsSuite) TestInitramfsMountsRunModeKernelSnapUpgradeHappy(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, filepath.Join(boot.InitramfsUbuntuDataDir))
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return true, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return false, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write modeenv
	modeEnv := &boot.Modeenv{
		Base:           "core20_123.snap",
		CurrentKernels: []string{"pc-kernel_1.snap", "pc-kernel_2.snap"},
	}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	tryBaseSnap := filepath.Join(dirs.SnapBlobDirUnder(boot.InitramfsWritableDir), "core20_124.snap")
	err = os.MkdirAll(filepath.Dir(tryBaseSnap), 0755)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(tryBaseSnap, []byte{0}, 0644)
	c.Assert(err, IsNil)
	defer os.Remove(tryBaseSnap)

	// mock a bootloader
	bloader := boottest.MockUC20RunBootenv(bootloadertest.Mock("mock", c.MkDir()))
	bootloader.Force(bloader)
	defer bootloader.Force(nil)

	bloader.BootVars["kernel_status"] = boot.TryingStatus

	// set the current kernel
	kernel, err := snap.ParsePlaceInfoFromSnapFileName("pc-kernel_1.snap")
	c.Assert(err, IsNil)
	r := bloader.SetRunKernelImageEnabledKernel(kernel)
	defer r()

	// set the try kernel
	tryKernel, err := snap.ParsePlaceInfoFromSnapFileName("pc-kernel_2.snap")
	c.Assert(err, IsNil)
	r = bloader.SetRunKernelImageEnabledTryKernel(tryKernel)
	defer r()

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 5)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`%[1]s/ubuntu-data/system-data/var/lib/snapd/snaps/pc-kernel_2.snap %[1]s/kernel
`, boot.InitramfsRunMntDir))
}

// TODO:UC20: in this case snap-bootstrap should request a reboot, since we
//            already booted the try snap, so mounting the fallback kernel will
//            not match in some cases
func (s *initramfsMountsSuite) TestInitramfsMountsRunModeUntrustedKernelSnap(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, filepath.Join(boot.InitramfsUbuntuDataDir))
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return true, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return false, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write modeenv
	modeEnv := boot.Modeenv{
		Base:           "core20_123.snap",
		CurrentKernels: []string{"pc-kernel_1.snap"},
	}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	// mock a bootloader
	bloader := boottest.MockUC20RunBootenv(bootloadertest.Mock("mock", c.MkDir()))
	bootloader.Force(bloader)
	defer bootloader.Force(nil)

	// set the current kernel as a kernel not in CurrentKernels
	kernel, err := snap.ParsePlaceInfoFromSnapFileName("pc-kernel_2.snap")
	c.Assert(err, IsNil)
	r := bloader.SetRunKernelImageEnabledKernel(kernel)
	defer r()

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})
	c.Assert(err, ErrorMatches, fmt.Sprintf("fallback kernel snap %q is not trusted in the modeenv", "pc-kernel_2.snap"))
	c.Assert(n, Equals, 5)
}

// TODO:UC20: in this case snap-bootstrap should request a reboot, since we
//            already booted the try snap, so mounting the fallback kernel will
//            not match in some cases
func (s *initramfsMountsSuite) TestInitramfsMountsRunModeUntrustedTryKernelSnapFallsBack(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, filepath.Join(boot.InitramfsUbuntuDataDir))
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return true, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return false, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write modeenv
	modeEnv := boot.Modeenv{
		Base:           "core20_123.snap",
		CurrentKernels: []string{"pc-kernel_1.snap"},
	}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	// mock a bootloader
	bloader := boottest.MockUC20RunBootenv(bootloadertest.Mock("mock", c.MkDir()))
	bootloader.Force(bloader)
	defer bootloader.Force(nil)

	// set the try kernel as a kernel not in CurrentKernels
	kernel2, err := snap.ParsePlaceInfoFromSnapFileName("pc-kernel_2.snap")
	c.Assert(err, IsNil)
	r := bloader.SetRunKernelImageEnabledTryKernel(kernel2)
	defer r()

	// set the normal kernel as a valid kernel
	kernel1, err := snap.ParsePlaceInfoFromSnapFileName("pc-kernel_1.snap")
	c.Assert(err, IsNil)
	r = bloader.SetRunKernelImageEnabledKernel(kernel1)
	defer r()

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})

	// TODO:UC20: if we have somewhere to log errors from snap-bootstrap during
	// the initramfs, check that log here
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 5)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`%[1]s/ubuntu-data/system-data/var/lib/snapd/snaps/pc-kernel_1.snap %[1]s/kernel
`, boot.InitramfsRunMntDir))
}

func (s *initramfsMountsSuite) TestInitramfsMountsRunModeKernelStatusTryingNoTryKernel(c *C) {
	n := 0
	s.mockProcCmdlineContent(c, "snapd_recovery_mode=run")

	restore := main.MockOsutilIsMounted(func(path string) (bool, error) {
		n++
		switch n {
		case 1:
			c.Check(path, Equals, boot.InitramfsUbuntuSeedDir)
			return true, nil
		case 2:
			c.Check(path, Equals, boot.InitramfsUbuntuBootDir)
			return true, nil
		case 3:
			c.Check(path, Equals, boot.InitramfsUbuntuDataDir)
			return true, nil
		case 4:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "base"))
			return true, nil
		case 5:
			c.Check(path, Equals, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			return false, nil
		}
		return false, fmt.Errorf("unexpected number of calls: %v", n)
	})
	defer restore()

	// write modeenv
	modeEnv := boot.Modeenv{
		Base:           "core20_123.snap",
		CurrentKernels: []string{"pc-kernel_1.snap"},
	}
	err := modeEnv.WriteTo(boot.InitramfsWritableDir)
	c.Assert(err, IsNil)

	// mock a bootloader
	bloader := boottest.MockUC20RunBootenv(bootloadertest.Mock("mock", c.MkDir()))
	bootloader.Force(bloader)
	defer bootloader.Force(nil)

	// we are in trying mode, but don't set a try-kernel so we fallback to the
	// fallback kernel
	err = bloader.SetBootVars(map[string]string{"kernel_status": boot.TryingStatus})
	c.Assert(err, IsNil)

	// set the normal kernel as a valid kernel
	kernel, err := snap.ParsePlaceInfoFromSnapFileName("pc-kernel_1.snap")
	c.Assert(err, IsNil)
	r := bloader.SetRunKernelImageEnabledKernel(kernel)
	defer r()

	_, err = main.Parser().ParseArgs([]string{"initramfs-mounts"})

	// TODO:UC20: if we have somewhere to log errors from snap-bootstrap during
	// the initramfs, check that log here
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 5)
	c.Check(s.Stdout.String(), Equals, fmt.Sprintf(`%[1]s/ubuntu-data/system-data/var/lib/snapd/snaps/pc-kernel_1.snap %[1]s/kernel
`, boot.InitramfsRunMntDir))
}

func (s *initramfsMountsSuite) TestUnlockIfEncrypted(c *C) {
	for _, tc := range []struct {
		hasTPM    bool
		tpmErr    error
		hasEncdev bool
		last      bool
		lockOk    bool
		device    string
		err       string
	}{
		{true, nil, true, true, true, "/dev/disk/by-label/name", ""},
		{true, nil, true, true, false, "", "cannot lock access to sealed keys: lock failed"},
		{true, nil, true, false, true, "/dev/disk/by-label/name", ""},
		{true, nil, true, false, false, "/dev/disk/by-label/name", ""},
		{true, nil, false, true, true, "/dev/disk/by-label/name", ""},
		{true, nil, false, true, false, "", "cannot lock access to sealed keys: lock failed"},
		{true, nil, false, false, true, "/dev/disk/by-label/name", ""},
		{true, nil, false, false, false, "/dev/disk/by-label/name", ""},
		{true, errors.New("tpm error"), true, true, false, "", `cannot unlock encrypted device "name": tpm error`},
		{true, errors.New("tpm error"), true, false, false, "", `cannot unlock encrypted device "name": tpm error`},
		{true, errors.New("tpm error"), false, true, false, "/dev/disk/by-label/name", ""},
		{true, errors.New("tpm error"), false, false, false, "/dev/disk/by-label/name", ""},
		{false, errors.New("no tpm"), true, true, false, "", `cannot unlock encrypted device "name": no tpm`},
		{false, errors.New("no tpm"), true, false, false, "", `cannot unlock encrypted device "name": no tpm`},
		{false, errors.New("no tpm"), false, true, false, "/dev/disk/by-label/name", ""},
		{false, errors.New("no tpm"), false, false, false, "/dev/disk/by-label/name", ""},
	} {
		c.Logf("hasTPM:%v tpmErr:%v hasEncdev:%v last:%v lockOk:%v", tc.hasTPM, tc.tpmErr, tc.hasEncdev, tc.last, tc.lockOk)
		var mockTPM *secboot.TPMConnection
		if tc.hasTPM {
			tcti, err := os.Open("/dev/null")
			c.Assert(err, IsNil)
			tpm, err := tpm2.NewTPMContext(tcti)
			c.Assert(err, IsNil)
			mockTPM = &secboot.TPMConnection{TPMContext: tpm}
		} else {
			mockTPM = nil
		}
		restoreConnect := main.MockSecbootConnectToDefaultTPM(func() (*secboot.TPMConnection, error) {
			return mockTPM, tc.tpmErr
		})
		defer restoreConnect()

		n := 0
		restoreLock := main.MockSecbootLockAccessToSealedKeys(func(tpm *secboot.TPMConnection) error {
			n++
			c.Assert(tpm, Equals, mockTPM)
			if tc.lockOk {
				return nil
			}
			return errors.New("lock failed")
		})
		defer restoreLock()

		restoreFileExists := main.MockOsutilFileExists(func(name string) bool {
			return tc.hasEncdev
		})
		defer restoreFileExists()

		restoreUnlock := main.MockUnlockEncryptedPartition(func(tpm *secboot.TPMConnection, name, device, keyfile, pinfile string, lock bool) error {
			c.Assert(tpm, Equals, mockTPM)
			c.Assert(name, Equals, "name")
			c.Assert(device, Equals, "/dev/disk/by-label/name-enc")
			c.Assert(keyfile, Equals, filepath.Join(boot.InitramfsUbuntuSeedDir, "name.sealed-key"))
			c.Assert(lock, Equals, tc.last)
			if !tc.hasTPM || tc.tpmErr != nil {
				return errors.New("cannot unlock: tpm error")
			}
			return nil
		})
		defer restoreUnlock()

		device, err := main.UnlockIfEncrypted("name", tc.last)
		c.Assert(device, Equals, tc.device)
		if tc.err == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, ErrorMatches, tc.err)
		}
		// LockAccessToSealedKeys should be called whenever there is a TPM device
		// detected, regardless of whether secure boot is enabled or there is an
		// encrypted volume to unlock. If we have multiple encrypted volumes, we
		// should call it after the last one is unlocked.
		if tc.hasTPM && tc.tpmErr == nil && tc.last {
			c.Assert(n, Equals, 1)
		}
	}
}

func (s *initramfsMountsSuite) TestUnlockEncryptedPartition(c *C) {
	tcti, err := os.Open("/dev/null")
	c.Assert(err, IsNil)
	tpm, err := tpm2.NewTPMContext(tcti)
	c.Assert(err, IsNil)
	mockTPM := &secboot.TPMConnection{TPMContext: tpm}

	for _, tc := range []struct {
		tpm                  *secboot.TPMConnection
		lockSealedKeyAccess  bool
		activationSuccessful bool
		activationError      error
		errStr               string
	}{
		{mockTPM, true, true, nil, ""},
		{mockTPM, true, true, errors.New("some error"), ""},
		{mockTPM, true, false, errors.New("some error"), `cannot activate encrypted device "device": some error`},
		{mockTPM, false, true, nil, ""},
		{mockTPM, false, true, errors.New("some error"), ""},
		{mockTPM, false, false, errors.New("some error"), `cannot activate encrypted device "device": some error`},
		{nil, true, true, nil, ""},
		{nil, true, true, errors.New("some error"), ""},
		{nil, true, false, errors.New("some error"), `cannot activate encrypted device "device": some error`},
		{nil, false, true, nil, ""},
		{nil, false, true, errors.New("some error"), ""},
		{nil, false, false, errors.New("some error"), `cannot activate encrypted device "device": some error`},
		// ActivateVolumeWithTPMSealedKey always return an error when activation is false
	} {
		n := 0
		restore := main.MockSecbootActivateVolumeWithTPMSealedKey(func(tpm *secboot.TPMConnection, volumeName, sourceDevicePath,
			keyPath string, pinReader io.Reader, options *secboot.ActivateWithTPMSealedKeyOptions) (bool, error) {
			n++
			c.Assert(tpm, Equals, tc.tpm)
			c.Assert(volumeName, Equals, "name")
			c.Assert(sourceDevicePath, Equals, "device")
			c.Assert(keyPath, Equals, "keyfile")
			c.Assert(*options, DeepEquals, secboot.ActivateWithTPMSealedKeyOptions{
				PINTries:            1,
				RecoveryKeyTries:    3,
				LockSealedKeyAccess: tc.lockSealedKeyAccess,
			})
			return tc.activationSuccessful, tc.activationError
		})
		defer restore()

		err = main.UnlockEncryptedPartition(tc.tpm, "name", "device", "keyfile", "pinfile", tc.lockSealedKeyAccess)
		c.Assert(n, Equals, n)
		if tc.errStr == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, ErrorMatches, tc.errStr)
		}
	}
}
