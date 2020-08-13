// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2019 Canonical Ltd
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

package boot_test

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/gadget"
	"github.com/snapcore/snapd/testutil"
)

type assetsSuite struct {
	baseBootenvSuite
}

var _ = Suite(&assetsSuite{})

func checkContentGlob(c *C, glob string, expected []string) {
	l, err := filepath.Glob(glob)
	c.Assert(err, IsNil)
	c.Check(l, DeepEquals, expected)
}

func (s *assetsSuite) TestAssetsCacheAddDrop(c *C) {
	cacheDir := c.MkDir()
	d := c.MkDir()

	cache := boot.NewTrustedAssetsCache(cacheDir)

	data := []byte("foobar")
	// SHA3-384
	hash := "0fa8abfbdaf924ad307b74dd2ed183b9a4a398891a2f6bac8fd2db7041b77f068580f9c6c66f699b496c2da1cbcc7ed8"
	err := ioutil.WriteFile(filepath.Join(d, "foobar"), data, 0644)
	c.Assert(err, IsNil)

	// add a new file
	ta, err := cache.Add(filepath.Join(d, "foobar"), "grub", "grubx64.efi")
	c.Assert(err, IsNil)
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("grubx64.efi-%s", hash)), testutil.FileEquals, string(data))
	c.Check(ta, NotNil)

	// try the same file again
	taAgain, err := cache.Add(filepath.Join(d, "foobar"), "grub", "grubx64.efi")
	c.Assert(err, IsNil)
	// file already cached
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("grubx64.efi-%s", hash)), testutil.FileEquals, string(data))
	// and there's just one entry in the cache
	checkContentGlob(c, filepath.Join(cacheDir, "grub", "*"), []string{
		filepath.Join(cacheDir, "grub", fmt.Sprintf("grubx64.efi-%s", hash)),
	})
	// let go-check do the deep equals check
	c.Check(taAgain, DeepEquals, ta)

	// same data but different asset name
	taDifferentAsset, err := cache.Add(filepath.Join(d, "foobar"), "grub", "bootx64.efi")
	c.Assert(err, IsNil)
	// new entry in cache
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("bootx64.efi-%s", hash)), testutil.FileEquals, string(data))
	// 2 files now
	checkContentGlob(c, filepath.Join(cacheDir, "grub", "*"), []string{
		filepath.Join(cacheDir, "grub", fmt.Sprintf("bootx64.efi-%s", hash)),
		filepath.Join(cacheDir, "grub", fmt.Sprintf("grubx64.efi-%s", hash)),
	})
	c.Check(taDifferentAsset, NotNil)

	// same source, data (new hash), existing asset name
	newData := []byte("new foobar")
	newH := crypto.SHA256.New()
	newH.Write(newData)
	newHash := "5aa87615f6613a37d63c9a29746ef57457286c37148a4ae78493b0face5976c1fea940a19486e6bef65d43aec6b8f5a2"
	err = ioutil.WriteFile(filepath.Join(d, "foobar"), newData, 0644)
	c.Assert(err, IsNil)

	taExistingAssetName, err := cache.Add(filepath.Join(d, "foobar"), "grub", "bootx64.efi")
	c.Assert(err, IsNil)
	// new entry in cache
	c.Check(taExistingAssetName, NotNil)
	// we have both new and old asset
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("bootx64.efi-%s", newHash)), testutil.FileEquals, string(newData))
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("bootx64.efi-%s", hash)), testutil.FileEquals, string(data))
	// 3 files in total
	checkContentGlob(c, filepath.Join(cacheDir, "grub", "*"), []string{
		filepath.Join(cacheDir, "grub", fmt.Sprintf("bootx64.efi-%s", hash)),
		filepath.Join(cacheDir, "grub", fmt.Sprintf("bootx64.efi-%s", newHash)),
		filepath.Join(cacheDir, "grub", fmt.Sprintf("grubx64.efi-%s", hash)),
	})

	// drop
	err = cache.Remove("grub", "bootx64.efi", newHash)
	c.Assert(err, IsNil)
	// asset bootx64.efi with given hash was dropped
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("bootx64.efi-%s", newHash)), testutil.FileAbsent)
	// the other file still exists
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("bootx64.efi-%s", hash)), testutil.FileEquals, string(data))
	// remove it too
	err = cache.Remove("grub", "bootx64.efi", hash)
	c.Assert(err, IsNil)
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("bootx64.efi-%s", hash)), testutil.FileAbsent)

	// what is left is the grub assets only
	checkContentGlob(c, filepath.Join(cacheDir, "grub", "*"), []string{
		filepath.Join(cacheDir, "grub", fmt.Sprintf("grubx64.efi-%s", hash)),
	})
}

func (s *assetsSuite) TestAssetsCacheAddErr(c *C) {
	cacheDir := c.MkDir()
	d := c.MkDir()
	cache := boot.NewTrustedAssetsCache(cacheDir)

	defer os.Chmod(cacheDir, 0755)
	err := os.Chmod(cacheDir, 0000)
	c.Assert(err, IsNil)

	err = ioutil.WriteFile(filepath.Join(d, "foobar"), []byte("foo"), 0644)
	c.Assert(err, IsNil)
	// cannot create bootloader subdirectory
	ta, err := cache.Add(filepath.Join(d, "foobar"), "grub", "grubx64.efi")
	c.Assert(err, ErrorMatches, "cannot create cache directory: mkdir .*/grub: permission denied")
	c.Check(ta, IsNil)

	// fix it now
	err = os.Chmod(cacheDir, 0755)
	c.Assert(err, IsNil)

	_, err = cache.Add(filepath.Join(d, "no-file"), "grub", "grubx64.efi")
	c.Assert(err, ErrorMatches, "cannot open asset file: open .*/no-file: no such file or directory")

	blDir := filepath.Join(cacheDir, "grub")
	defer os.Chmod(blDir, 0755)
	err = os.Chmod(blDir, 0000)
	c.Assert(err, IsNil)

	_, err = cache.Add(filepath.Join(d, "foobar"), "grub", "grubx64.efi")
	c.Assert(err, ErrorMatches, `cannot create temporary cache file: open .*/grub/grubx64\.efi\.temp\.[a-zA-Z0-9]+~: permission denied`)
}

func (s *assetsSuite) TestAssetsCacheRemoveErr(c *C) {
	cacheDir := c.MkDir()
	d := c.MkDir()
	cache := boot.NewTrustedAssetsCache(cacheDir)

	data := []byte("foobar")
	dataHash := "0fa8abfbdaf924ad307b74dd2ed183b9a4a398891a2f6bac8fd2db7041b77f068580f9c6c66f699b496c2da1cbcc7ed8"
	err := ioutil.WriteFile(filepath.Join(d, "foobar"), data, 0644)
	c.Assert(err, IsNil)
	// cannot create bootloader subdirectory
	_, err = cache.Add(filepath.Join(d, "foobar"), "grub", "grubx64.efi")
	c.Assert(err, IsNil)
	// sanity
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("grubx64.efi-%s", dataHash)), testutil.FileEquals, string(data))

	err = cache.Remove("grub", "no file", "some-hash")
	c.Assert(err, IsNil)

	// different asset name but known hash
	err = cache.Remove("grub", "different-name", dataHash)
	c.Assert(err, IsNil)
	c.Check(filepath.Join(cacheDir, "grub", fmt.Sprintf("grubx64.efi-%s", dataHash)), testutil.FileEquals, string(data))
}

func (s *assetsSuite) TestInstallObserverNew(c *C) {
	d := c.MkDir()

	// we get an observer for UC20
	uc20Model := makeMockUC20Model()
	obs, err := boot.TrustedAssetsInstallObserverForModel(uc20Model, d)
	c.Assert(obs, NotNil)
	c.Assert(err, IsNil)

	// but nil for non UC20
	nonUC20Model := makeMockModel()
	nonUC20obs, err := boot.TrustedAssetsInstallObserverForModel(nonUC20Model, d)
	c.Assert(nonUC20obs, IsNil)
	c.Assert(err, IsNil)
}

func (s *assetsSuite) TestInstallObserverObserveSystemBoot(c *C) {
	d := c.MkDir()

	err := ioutil.WriteFile(filepath.Join(d, "grub.conf"), nil, 0644)
	c.Assert(err, IsNil)

	// we get an observer for UC20
	uc20Model := makeMockUC20Model()
	obs, err := boot.TrustedAssetsInstallObserverForModel(uc20Model, d)
	c.Assert(obs, NotNil)
	c.Assert(err, IsNil)

	data := []byte("foobar")
	// SHA3-384
	dataHash := "0fa8abfbdaf924ad307b74dd2ed183b9a4a398891a2f6bac8fd2db7041b77f068580f9c6c66f699b496c2da1cbcc7ed8"
	err = ioutil.WriteFile(filepath.Join(d, "foobar"), data, 0644)
	c.Assert(err, IsNil)

	otherData := []byte("other foobar")
	err = ioutil.WriteFile(filepath.Join(d, "other-foobar"), otherData, 0644)
	c.Assert(err, IsNil)

	runBootStruct := &gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Role: gadget.SystemBoot,
		},
	}
	// only grubx64.efi gets installed to system-boot
	_, err = obs.Observe(gadget.ContentWrite, runBootStruct, boot.InitramfsUbuntuBootDir,
		filepath.Join(d, "foobar"), "EFI/boot/grubx64.efi")
	c.Assert(err, IsNil)
	// Observe is called when populating content, but one can freely specify
	// overlapping content entries, so a same file may be observed more than
	// once
	_, err = obs.Observe(gadget.ContentWrite, runBootStruct, boot.InitramfsUbuntuBootDir,
		filepath.Join(d, "foobar"), "EFI/boot/grubx64.efi")
	c.Assert(err, IsNil)
	// try with one more file, which is not a trusted asset of a run mode, so it is ignored
	_, err = obs.Observe(gadget.ContentWrite, runBootStruct, boot.InitramfsUbuntuBootDir,
		filepath.Join(d, "foobar"), "EFI/boot/bootx64.efi")
	c.Assert(err, IsNil)
	// a single file in cache
	checkContentGlob(c, filepath.Join(dirs.SnapBootAssetsDir, "grub", "*"), []string{
		filepath.Join(dirs.SnapBootAssetsDir, "grub", fmt.Sprintf("grubx64.efi-%s", dataHash)),
	})

	// and one more, a non system-boot structure, so the file is ignored
	systemSeedStruct := &gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Role: gadget.SystemSeed,
		},
	}
	_, err = obs.Observe(gadget.ContentWrite, systemSeedStruct, boot.InitramfsUbuntuBootDir,
		filepath.Join(d, "other-foobar"), "EFI/boot/grubx64.efi")
	c.Assert(err, IsNil)
	// still, only one entry in the cache
	checkContentGlob(c, filepath.Join(dirs.SnapBootAssetsDir, "grub", "*"), []string{
		filepath.Join(dirs.SnapBootAssetsDir, "grub", fmt.Sprintf("grubx64.efi-%s", dataHash)),
	})

	// let's see what the observer has tracked
	tracked := obs.CurrentTrustedBootAssetsMap()
	c.Check(tracked, DeepEquals, boot.BootAssetsMap{
		"grubx64.efi": []string{dataHash},
	})
}

func (s *assetsSuite) TestInstallObserverObserveErr(c *C) {
	d := c.MkDir()

	// we get an observer for UC20
	uc20Model := makeMockUC20Model()
	obs, err := boot.TrustedAssetsInstallObserverForModel(uc20Model, d)
	c.Assert(obs, NotNil)
	c.Assert(err, IsNil)

	err = ioutil.WriteFile(filepath.Join(d, "foobar"), []byte("data"), 0644)
	c.Assert(err, IsNil)

	runBootStruct := &gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Role: gadget.SystemBoot,
		},
	}
	// there is no known bootloader in gadget
	_, err = obs.Observe(gadget.ContentWrite, runBootStruct, boot.InitramfsUbuntuBootDir,
		filepath.Join(d, "foobar"), "EFI/boot/grubx64.efi")
	c.Assert(err, ErrorMatches, "cannot find bootloader: cannot determine bootloader")

	// mock the bootloader
	err = ioutil.WriteFile(filepath.Join(d, "grub.conf"), nil, 0644)
	c.Assert(err, IsNil)
	// but break the cache
	err = os.MkdirAll(dirs.SnapBootAssetsDir, 0755)
	c.Assert(err, IsNil)
	err = os.Chmod(dirs.SnapBootAssetsDir, 0000)
	c.Assert(err, IsNil)
	defer os.Chmod(dirs.SnapBootAssetsDir, 0755)

	_, err = obs.Observe(gadget.ContentWrite, runBootStruct, boot.InitramfsUbuntuBootDir,
		filepath.Join(d, "foobar"), "EFI/boot/grubx64.efi")
	c.Assert(err, ErrorMatches, "cannot create cache directory: mkdir .*/var/lib/snapd/boot-assets/grub: permission denied")
}
