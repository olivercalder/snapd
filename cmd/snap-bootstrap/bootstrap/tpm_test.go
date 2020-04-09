// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package bootstrap_test

import (
	"os"
	"path/filepath"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/snapcore/secboot"
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/cmd/snap-bootstrap/bootstrap"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/testutil"
)

type bootstrapTPMSuite struct {
	testutil.BaseTest

	dir string
}

var _ = Suite(&bootstrapTPMSuite{})

func (s *bootstrapTPMSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.dir = c.MkDir()
	dirs.SetRootDir(s.dir)
	s.AddCleanup(func() { dirs.SetRootDir("/") })
}

func (s *bootstrapTPMSuite) TestProvision(c *C) {
	n := 0
	restore := bootstrap.MockSecbootProvisionTPM(func(tpm *secboot.TPMConnection, mode secboot.ProvisionMode, newLockoutAuth []byte) error {
		c.Assert(mode, Equals, secboot.ProvisionModeFull)
		n++
		return nil
	})
	defer restore()

	t := bootstrap.TPMSupport{}
	err := t.Provision()
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 1)
}

func (s *bootstrapTPMSuite) TestSeal(c *C) {
	n := 0
	myKey := []byte("528491")
	myKeyPath := "keyFilename"
	myPolicyUpdatePath := "policyUpdateFilename"

	// dummy OS component files
	shimFile := filepath.Join(s.dir, "shim")
	f, err := os.Create(shimFile)
	c.Assert(err, IsNil)
	f.Close()
	grubFile := filepath.Join(s.dir, "grub")
	f, err = os.Create(grubFile)
	c.Assert(err, IsNil)
	f.Close()
	kernelFile := filepath.Join(s.dir, "kernel")
	f, err = os.Create(kernelFile)
	c.Assert(err, IsNil)
	f.Close()

	t := bootstrap.TPMSupport{}
	t.SetShimFiles(shimFile)
	t.SetBootloaderFiles(grubFile)
	t.SetKernelFiles(kernelFile)

	sbRestore := bootstrap.MockSecbootAddEFISecureBootPolicyProfile(func(profile *secboot.PCRProtectionProfile,
		params *secboot.EFISecureBootPolicyProfileParams) error {
		c.Assert(*params, DeepEquals, secboot.EFISecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*secboot.EFIImageLoadEvent{
				{
					Source: secboot.Firmware,
					Image:  secboot.FileEFIImage(shimFile),
					Next: []*secboot.EFIImageLoadEvent{
						{
							Source: secboot.Shim,
							Image:  secboot.FileEFIImage(grubFile),
							Next: []*secboot.EFIImageLoadEvent{
								{
									Source: secboot.Shim,
									Image:  secboot.FileEFIImage(kernelFile),
								},
							},
						},
					},
				},
			},
		})
		return nil
	})
	defer sbRestore()

	stubRestore := bootstrap.MockSecbootAddSystemdEFIStubProfile(func(profile *secboot.PCRProtectionProfile,
		params *secboot.SystemdEFIStubProfileParams) error {
		c.Assert(*params, DeepEquals, secboot.SystemdEFIStubProfileParams{
			PCRAlgorithm:   tpm2.HashAlgorithmSHA256,
			PCRIndex:       12,
			KernelCmdlines: bootstrap.KernelCmdlines,
		})
		return nil
	})
	defer stubRestore()

	sealRestore := bootstrap.MockSecbootSealKeyToTPM(func(tpm *secboot.TPMConnection, key []byte,
		keyPath, policyUpdatePath string, params *secboot.KeyCreationParams) error {
		c.Assert(key, DeepEquals, myKey)
		c.Assert(keyPath, Equals, myKeyPath)
		c.Assert(policyUpdatePath, Equals, policyUpdatePath)
		c.Assert(params.PINHandle, Equals, tpm2.Handle(0x01800000))
		n++
		return nil
	})
	defer sealRestore()

	err = t.Seal(myKey, myKeyPath, myPolicyUpdatePath)
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 1)
}

func (s *bootstrapTPMSuite) TestSetFiles(c *C) {
	t := &bootstrap.TPMSupport{}

	p1 := filepath.Join(s.dir, "f1")
	f, err := os.Create(p1)
	c.Assert(err, IsNil)
	f.Close()

	// set shim files
	err = t.SetShimFiles("foo")
	c.Assert(err, ErrorMatches, "file foo does not exist")
	err = t.SetShimFiles(p1, "bar")
	c.Assert(err, ErrorMatches, "file bar does not exist")
	err = t.SetShimFiles(p1)
	c.Assert(err, IsNil)

	// set bootloader
	err = t.SetBootloaderFiles("foo")
	c.Assert(err, ErrorMatches, "file foo does not exist")
	err = t.SetBootloaderFiles(p1, "bar")
	c.Assert(err, ErrorMatches, "file bar does not exist")
	err = t.SetBootloaderFiles(p1)
	c.Assert(err, IsNil)

	// set kernel files
	err = t.SetKernelFiles("foo")
	c.Assert(err, ErrorMatches, "file foo does not exist")
	err = t.SetKernelFiles(p1, "bar")
	c.Assert(err, ErrorMatches, "file bar does not exist")
	err = t.SetKernelFiles(p1)
	c.Assert(err, IsNil)
}
