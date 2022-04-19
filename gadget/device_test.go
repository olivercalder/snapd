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

package gadget_test

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/gadget"
)

type deviceSuite struct {
	dir string
}

var _ = Suite(&deviceSuite{})

func (d *deviceSuite) SetUpTest(c *C) {
	d.dir = c.MkDir()
	dirs.SetRootDir(d.dir)

	err := os.MkdirAll(filepath.Join(d.dir, "/dev/disk/by-label"), 0755)
	c.Assert(err, IsNil)
	err = os.MkdirAll(filepath.Join(d.dir, "/dev/disk/by-partlabel"), 0755)
	c.Assert(err, IsNil)
	err = os.MkdirAll(filepath.Join(d.dir, "/dev/mapper"), 0755)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(d.dir, "/dev/fakedevice"), []byte(""), 0644)
	c.Assert(err, IsNil)
}

func (d *deviceSuite) TearDownTest(c *C) {
	dirs.SetRootDir("/")
}

func (d *deviceSuite) setupMockSysfs(c *C) {
	// setup everything for 'writable'
	err := ioutil.WriteFile(filepath.Join(d.dir, "/dev/fakedevice0p1"), []byte(""), 0644)
	c.Assert(err, IsNil)
	err = os.Symlink("../../fakedevice0p1", filepath.Join(d.dir, "/dev/disk/by-label/writable"))
	c.Assert(err, IsNil)
	// make parent device
	err = ioutil.WriteFile(filepath.Join(d.dir, "/dev/fakedevice0"), []byte(""), 0644)
	c.Assert(err, IsNil)
	// and fake /sys/block structure
	err = os.MkdirAll(filepath.Join(d.dir, "/sys/block/fakedevice0/fakedevice0p1"), 0755)
	c.Assert(err, IsNil)
}

func (d *deviceSuite) setupMockSysfsForDevMapper(c *C) {
	// setup a mock /dev/mapper environment (incomplete we have no "happy"
	// test; use a complex setup that mimics LVM in LUKS:
	// /dev/mapper/data_crypt (symlink)
	//   ⤷ /dev/dm-1 (LVM)
	//      ⤷ /dev/dm-0 (LUKS)
	//         ⤷ /dev/fakedevice0 (actual device)
	err := ioutil.WriteFile(filepath.Join(d.dir, "/dev/dm-0"), nil, 0644)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(d.dir, "/dev/dm-1"), nil, 0644)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(d.dir, "/dev/fakedevice0"), []byte(""), 0644)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(d.dir, "/dev/fakedevice"), []byte(""), 0644)
	c.Assert(err, IsNil)
	// symlinks added by dm/udev are relative
	err = os.Symlink("../dm-1", filepath.Join(d.dir, "/dev/mapper/data_crypt"))
	c.Assert(err, IsNil)
	err = os.MkdirAll(filepath.Join(d.dir, "/sys/block/dm-1/slaves/"), 0755)
	c.Assert(err, IsNil)
	// sys symlinks are relative too
	err = os.Symlink("../../dm-0", filepath.Join(d.dir, "/sys/block/dm-1/slaves/dm-0"))
	c.Assert(err, IsNil)
	err = os.MkdirAll(filepath.Join(d.dir, "/sys/block/dm-0/slaves/"), 0755)
	c.Assert(err, IsNil)
	// real symlink would point to ../../../../<bus, eg. pci>/<addr>/block/fakedevice/fakedevice0
	err = os.Symlink("../../../../fakedevice/fakedevice0", filepath.Join(d.dir, "/sys/block/dm-0/slaves/fakedevice0"))
	c.Assert(err, IsNil)
	err = os.MkdirAll(filepath.Join(d.dir, "/sys/block/fakedevice/fakedevice0"), 0755)
	c.Assert(err, IsNil)
}

func (d *deviceSuite) TestDeviceFindByStructureName(c *C) {
	names := []struct {
		escaped   string
		structure string
	}{
		{"foo", "foo"},
		{"123", "123"},
		{"foo\\x20bar", "foo bar"},
		{"foo#bar", "foo#bar"},
		{"Новый_том", "Новый_том"},
		{`pinkié\x20pie`, `pinkié pie`},
	}
	for _, name := range names {
		err := os.Symlink(filepath.Join(d.dir, "/dev/fakedevice"), filepath.Join(d.dir, "/dev/disk/by-partlabel", name.escaped))
		c.Assert(err, IsNil)
	}

	for _, tc := range names {
		c.Logf("trying: %q", tc)
		found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
			VolumeStructure: &gadget.VolumeStructure{Name: tc.structure},
		})
		c.Check(err, IsNil)
		c.Check(found, Equals, filepath.Join(d.dir, "/dev/fakedevice"))
	}
}

func (d *deviceSuite) TestDeviceFindRelativeSymlink(c *C) {
	err := os.Symlink("../../fakedevice", filepath.Join(d.dir, "/dev/disk/by-partlabel/relative"))
	c.Assert(err, IsNil)

	found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{Name: "relative"},
	})
	c.Check(err, IsNil)
	c.Check(found, Equals, filepath.Join(d.dir, "/dev/fakedevice"))
}

func (d *deviceSuite) TestDeviceFindByFilesystemLabel(c *C) {
	names := []struct {
		escaped   string
		structure string
	}{
		{"foo", "foo"},
		{"123", "123"},
		{`foo\x20bar`, "foo bar"},
		{"foo#bar", "foo#bar"},
		{"Новый_том", "Новый_том"},
		{`pinkié\x20pie`, `pinkié pie`},
	}
	for _, name := range names {
		err := os.Symlink(filepath.Join(d.dir, "/dev/fakedevice"), filepath.Join(d.dir, "/dev/disk/by-label", name.escaped))
		c.Assert(err, IsNil)
	}

	for _, tc := range names {
		c.Logf("trying: %q", tc)
		found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
			VolumeStructure: &gadget.VolumeStructure{
				Filesystem: "ext4",
				Label:      tc.structure,
			},
		})
		c.Check(err, IsNil)
		c.Check(found, Equals, filepath.Join(d.dir, "/dev/fakedevice"))
	}
}

func (d *deviceSuite) TestDeviceFindChecksPartlabelAndFilesystemLabelHappy(c *C) {
	fakedevice := filepath.Join(d.dir, "/dev/fakedevice")
	err := os.Symlink(fakedevice, filepath.Join(d.dir, "/dev/disk/by-label/foo"))
	c.Assert(err, IsNil)

	err = os.Symlink(fakedevice, filepath.Join(d.dir, "/dev/disk/by-partlabel/bar"))
	c.Assert(err, IsNil)

	found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Name:  "bar",
			Label: "foo",
		},
	})
	c.Check(err, IsNil)
	c.Check(found, Equals, filepath.Join(d.dir, "/dev/fakedevice"))
}

func (d *deviceSuite) TestDeviceFindFilesystemLabelToNameFallback(c *C) {
	fakedevice := filepath.Join(d.dir, "/dev/fakedevice")
	// only the by-filesystem-label symlink
	err := os.Symlink(fakedevice, filepath.Join(d.dir, "/dev/disk/by-label/foo"))
	c.Assert(err, IsNil)

	found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Name:       "foo",
			Filesystem: "ext4",
		},
	})
	c.Check(err, IsNil)
	c.Check(found, Equals, filepath.Join(d.dir, "/dev/fakedevice"))
}

func (d *deviceSuite) TestDeviceFindChecksPartlabelAndFilesystemLabelMismatch(c *C) {
	fakedevice := filepath.Join(d.dir, "/dev/fakedevice")
	err := os.Symlink(fakedevice, filepath.Join(d.dir, "/dev/disk/by-label/foo"))
	c.Assert(err, IsNil)

	// partlabel of the structure points to a different device
	fakedeviceOther := filepath.Join(d.dir, "/dev/fakedevice-other")
	err = ioutil.WriteFile(fakedeviceOther, []byte(""), 0644)
	c.Assert(err, IsNil)
	err = os.Symlink(fakedeviceOther, filepath.Join(d.dir, "/dev/disk/by-partlabel/bar"))
	c.Assert(err, IsNil)

	found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Name:       "bar",
			Label:      "foo",
			Filesystem: "ext4",
		},
	})
	c.Check(err, ErrorMatches, `conflicting device match, ".*/by-label/foo" points to ".*/fakedevice", previous match ".*/by-partlabel/bar" points to ".*/fakedevice-other"`)
	c.Check(found, Equals, "")
}

func (d *deviceSuite) TestDeviceFindNotFound(c *C) {
	found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Name:  "bar",
			Label: "foo",
		},
	})
	c.Check(err, ErrorMatches, `device not found`)
	c.Check(found, Equals, "")
}

func (d *deviceSuite) TestDeviceFindNotFoundEmpty(c *C) {
	// neither name nor filesystem label set
	found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Name: "",
			// structure has no filesystem, fs label check is
			// ineffective
			Label: "",
		},
	})
	c.Check(err, ErrorMatches, `device not found`)
	c.Check(found, Equals, "")

	// try with proper filesystem now
	found, err = gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Name:       "",
			Label:      "",
			Filesystem: "ext4",
		},
	})
	c.Check(err, ErrorMatches, `device not found`)
	c.Check(found, Equals, "")
}

func (d *deviceSuite) TestDeviceFindNotFoundSymlinkPointsNowhere(c *C) {
	fakedevice := filepath.Join(d.dir, "/dev/fakedevice-not-found")
	err := os.Symlink(fakedevice, filepath.Join(d.dir, "/dev/disk/by-label/foo"))
	c.Assert(err, IsNil)

	found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Label: "foo",
		},
	})
	c.Check(err, ErrorMatches, `device not found`)
	c.Check(found, Equals, "")
}

func (d *deviceSuite) TestDeviceFindNotFoundNotASymlink(c *C) {
	err := ioutil.WriteFile(filepath.Join(d.dir, "/dev/disk/by-label/foo"), nil, 0644)
	c.Assert(err, IsNil)

	found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Filesystem: "ext4",
			Label:      "foo",
		},
	})
	c.Check(err, ErrorMatches, `candidate .*/dev/disk/by-label/foo is not a symlink`)
	c.Check(found, Equals, "")
}

func (d *deviceSuite) TestDeviceFindBadEvalSymlinks(c *C) {
	fakedevice := filepath.Join(d.dir, "/dev/fakedevice")
	fooSymlink := filepath.Join(d.dir, "/dev/disk/by-label/foo")
	err := os.Symlink(fakedevice, fooSymlink)
	c.Assert(err, IsNil)

	restore := gadget.MockEvalSymlinks(func(p string) (string, error) {
		c.Assert(p, Equals, fooSymlink)
		return "", errors.New("failed")
	})
	defer restore()

	found, err := gadget.FindDeviceForStructure(&gadget.LaidOutStructure{
		VolumeStructure: &gadget.VolumeStructure{
			Filesystem: "vfat",
			Label:      "foo",
		},
	})
	c.Check(err, ErrorMatches, `cannot read device link: failed`)
	c.Check(found, Equals, "")
}

var writableMountInfoFmt = `26 27 8:3 / /writable rw,relatime shared:7 - ext4 %s/dev/fakedevice0p1 rw,data=ordered`
