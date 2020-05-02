// -*- Mode: Go; indent-tabs-mode: t -*-
// +build !nosecboot

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

package secboot_test

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/go-tpm2"
	sb "github.com/snapcore/secboot"
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/bootloader/efi"
	// TODO: UC20: move/merge partition with gadget
	"github.com/snapcore/snapd/cmd/snap-bootstrap/partition"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/secboot"
	"github.com/snapcore/snapd/testutil"
)

func TestSecboot(t *testing.T) { TestingT(t) }

type secbootSuite struct {
	testutil.BaseTest
}

var _ = Suite(&secbootSuite{})

func (s *secbootSuite) SetUpTest(c *C) {
	dirs.SetRootDir(c.MkDir())
	s.AddCleanup(func() { dirs.SetRootDir("/") })
}

func (s *secbootSuite) TestCheckKeySealingSupported(c *C) {
	sbEmpty := []uint8{}
	sbEnabled := []uint8{1}
	sbDisabled := []uint8{0}
	efiNotSupported := []uint8(nil)

	type testCase struct {
		hasTPM bool
		sbData []uint8
		errStr string
	}
	for _, t := range []testCase{
		{true, sbEnabled, ""},
		{true, sbEmpty, "secure boot variable does not exist"},
		{false, sbEmpty, "secure boot variable does not exist"},
		{true, sbDisabled, "secure boot is disabled"},
		{false, sbEnabled, "cannot connect to TPM device: TPM not available"},
		{false, sbDisabled, "secure boot is disabled"},
		{true, efiNotSupported, "not a supported EFI system"},
	} {
		c.Logf("t: %v %v %q", t.hasTPM, t.sbData, t.errStr)

		restore := secboot.MockSbConnectToDefaultTPM(func() (*sb.TPMConnection, error) {
			if !t.hasTPM {
				return nil, errors.New("TPM not available")
			}
			tcti, err := os.Open("/dev/null")
			c.Assert(err, IsNil)
			tpm, err := tpm2.NewTPMContext(tcti)
			c.Assert(err, IsNil)
			mockTPM := &sb.TPMConnection{TPMContext: tpm}
			return mockTPM, nil
		})
		defer restore()

		var vars map[string][]byte
		if t.sbData != nil {
			vars = map[string][]byte{"SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c": t.sbData}
		}
		restoreEfiVars := efi.MockVars(vars, nil)
		defer restoreEfiVars()

		err := secboot.CheckKeySealingSupported()
		if t.errStr == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, ErrorMatches, t.errStr)
		}
	}
}

func (s *secbootSuite) TestMeasureEpoch(c *C) {
	pcr := 0
	calls := 0
	restore := secboot.MockSbMeasureSnapSystemEpochToTPM(func(tpm *sb.TPMConnection, pcrIndex int) error {
		calls++
		pcr = pcrIndex
		return nil
	})
	defer restore()

	h := &secboot.SecbootHandle{}
	err := secboot.MeasureEpoch(h)
	c.Assert(err, IsNil)
	c.Assert(calls, Equals, 1)
	c.Assert(pcr, Equals, 12)
}

func (s *secbootSuite) TestMeasureModel(c *C) {
	pcr := 0
	calls := 0
	var model *asserts.Model
	restore := secboot.MockSbMeasureSnapModelToTPM(func(tpm *sb.TPMConnection, pcrIndex int, m *asserts.Model) error {
		calls++
		pcr = pcrIndex
		model = m
		return nil
	})
	defer restore()

	h := &secboot.SecbootHandle{}
	myModel := &asserts.Model{}
	err := secboot.MeasureModel(h, myModel)
	c.Assert(err, IsNil)
	c.Assert(calls, Equals, 1)
	c.Assert(pcr, Equals, 12)
	c.Assert(model, Equals, myModel)
}

func (s *secbootSuite) TestMeasureWhenPossible(c *C) {
	for _, tc := range []struct {
		tpmErr error
		cbErr  error
		calls  int
		err    string
	}{
		{tpmErr: nil, cbErr: nil, calls: 1, err: ""},
		{tpmErr: nil, cbErr: errors.New("some error"), calls: 1, err: "some error"},
		{tpmErr: errors.New("tpm error"), cbErr: nil, calls: 0, err: "cannot open TPM connection: tpm error"},
		{tpmErr: &os.PathError{Op: "open", Path: "path", Err: errors.New("enoent")}, cbErr: nil, calls: 0, err: ""},
	} {
		// set up tpm mock
		_, restore := mockSbTPMConnection(c, tc.tpmErr)
		defer restore()

		calls := 0
		testCallback := func(h *secboot.SecbootHandle) error {
			calls++
			return tc.cbErr
		}
		err := secboot.MeasureWhenPossible(testCallback)
		if tc.err == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, ErrorMatches, tc.err)
		}
		c.Assert(calls, Equals, tc.calls)
	}
}

func (s *secbootSuite) TestUnlockIfEncrypted(c *C) {
	for idx, tc := range []struct {
		hasTPM    bool
		tpmErr    error
		hasEncdev bool
		last      bool
		lockOk    bool
		activated bool
		device    string
		err       string
	}{
		// TODO: verify which cases are possible
		{
			hasTPM: true, hasEncdev: true, last: true, lockOk: true,
			activated: true, device: "name",
		}, {
			hasTPM: true, hasEncdev: true, last: true, lockOk: true,
			err: "cannot activate encrypted device .*: activation error",
		}, {
			hasTPM: true, hasEncdev: true, last: true, activated: true,
			err: "cannot lock access to sealed keys: lock failed",
		}, {
			hasTPM: true, hasEncdev: true, lockOk: true, activated: true,
			device: "name",
		}, {
			hasTPM: true, hasEncdev: true, lockOk: true,
			err: "cannot activate encrypted device .*: activation error",
		}, {
			hasTPM: true, hasEncdev: true, activated: true, device: "name",
		}, {
			hasTPM: true, hasEncdev: true,
			err: "cannot activate encrypted device .*: activation error",
		}, {
			hasTPM: true, last: true, lockOk: true, activated: true,
			device: "name",
		}, {
			hasTPM: true, last: true, activated: true,
			err: "cannot lock access to sealed keys: lock failed",
		}, {
			hasTPM: true, lockOk: true, activated: true, device: "name",
		}, {
			hasTPM: true, activated: true, device: "name",
		}, {
			hasTPM: true, hasEncdev: true, last: true,
			tpmErr: errors.New("tpm error"),
			err:    `cannot unlock encrypted device "name": tpm error`,
		}, {
			hasTPM: true, hasEncdev: true,
			tpmErr: errors.New("tpm error"),
			err:    `cannot unlock encrypted device "name": tpm error`,
		}, {
			hasTPM: true, last: true, device: "name",
			tpmErr: errors.New("tpm error"),
		}, {
			hasTPM: true, device: "name",
			tpmErr: errors.New("tpm error"),
		}, {
			hasEncdev: true, last: true,
			tpmErr: errors.New("no tpm"),
			err:    `cannot unlock encrypted device "name": no tpm`,
		}, {
			hasEncdev: true,
			tpmErr:    errors.New("no tpm"),
			err:       `cannot unlock encrypted device "name": no tpm`,
		}, {
			last: true, device: "name", tpmErr: errors.New("no tpm"),
		}, {
			tpmErr: errors.New("no tpm"), device: "name",
		},
	} {
		c.Logf("tc %v: %#v", idx, tc)
		mockSbTPM, restoreConnect := mockSbTPMConnection(c, tc.tpmErr)
		defer restoreConnect()

		n := 0
		restoreLock := secboot.MockSbLockAccessToSealedKeys(func(tpm *sb.TPMConnection) error {
			n++
			c.Assert(tpm, Equals, mockSbTPM)
			if tc.lockOk {
				return nil
			}
			return errors.New("lock failed")
		})
		defer restoreLock()

		devDiskByLabel, restoreDev := mockDevDiskByLabel(c)
		defer restoreDev()
		if tc.hasEncdev {
			err := ioutil.WriteFile(filepath.Join(devDiskByLabel, "name-enc"), nil, 0644)
			c.Assert(err, IsNil)
		}

		restoreActivate := secboot.MockSbActivateVolumeWithTPMSealedKey(func(tpm *sb.TPMConnection, volumeName, sourceDevicePath,
			keyPath string, pinReader io.Reader, options *sb.ActivateWithTPMSealedKeyOptions) (bool, error) {
			c.Assert(volumeName, Equals, "name")
			c.Assert(sourceDevicePath, Equals, filepath.Join(devDiskByLabel, "name-enc"))
			c.Assert(keyPath, Equals, filepath.Join(boot.InitramfsEncryptionKeyDir, "name.sealed-key"))
			c.Assert(*options, DeepEquals, sb.ActivateWithTPMSealedKeyOptions{
				PINTries:            1,
				RecoveryKeyTries:    3,
				LockSealedKeyAccess: tc.last,
			})
			if !tc.activated {
				return false, errors.New("activation error")
			}
			return true, nil
		})
		defer restoreActivate()

		device, err := secboot.UnlockIfEncrypted("name", tc.last)
		if tc.err == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, ErrorMatches, tc.err)
		}
		if tc.device == "" {
			c.Assert(device, Equals, tc.device)
		} else {
			c.Assert(device, Equals, filepath.Join(devDiskByLabel, tc.device))
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

func (s *secbootSuite) TestSealKey(c *C) {
	tmpDir := c.MkDir()

	var mockEFI []string
	for _, name := range []string{"a", "b", "c", "d", "e", "f"} {
		mockFileName := filepath.Join(tmpDir, name)
		err := ioutil.WriteFile(mockFileName, nil, 0644)
		c.Assert(err, IsNil)
		mockEFI = append(mockEFI, mockFileName)
	}

	myParams := secboot.SealKeyParams{
		EFILoadChains:        [][]string{{mockEFI[0], mockEFI[1], mockEFI[2]}, {mockEFI[3], mockEFI[4]}},
		KernelCmdlines:       []string{"cmdline1", "cmdline2"},
		Models:               []*asserts.Model{{}, {}},
		KeyFile:              "keyfile",
		PolicyUpdateDataFile: "policy-update-data-file",
		TPMLockoutAuthFile:   filepath.Join(tmpDir, "lockout-auth-file"),
	}

	myKey := partition.EncryptionKey{}
	for i := range myKey {
		myKey[i] = byte(i)
	}

	sequences := []*sb.EFIImageLoadEvent{
		{
			Source: sb.Firmware,
			Image:  sb.FileEFIImage(mockEFI[0]),
			Next: []*sb.EFIImageLoadEvent{
				{
					Source: sb.Shim,
					Image:  sb.FileEFIImage(mockEFI[1]),
					Next: []*sb.EFIImageLoadEvent{
						{
							Source: sb.Shim,
							Image:  sb.FileEFIImage(mockEFI[2]),
						},
					},
				},
			},
		},
		{
			Source: sb.Firmware,
			Image:  sb.FileEFIImage(mockEFI[3]),
			Next: []*sb.EFIImageLoadEvent{
				{
					Source: sb.Shim,
					Image:  sb.FileEFIImage(mockEFI[4]),
				},
			},
		},
	}

	for _, tc := range []struct {
		tpmErr  error
		callNum int
		err     string
	}{
		{tpmErr: errors.New("tpm error"), callNum: 0, err: "cannot connect to TPM: tpm error"},
		{tpmErr: nil, callNum: 1, err: ""},
	} {
		tpm, restore := mockSbTPMConnection(c, tc.tpmErr)
		defer restore()

		// mock adding EFI secure boot policy profile
		var pcrProfile *sb.PCRProtectionProfile
		addEFISbPolicyCalls := 0
		restore = secboot.MockSbAddEFISecureBootPolicyProfile(func(profile *sb.PCRProtectionProfile, params *sb.EFISecureBootPolicyProfileParams) error {
			addEFISbPolicyCalls++
			pcrProfile = profile
			c.Assert(params.PCRAlgorithm, Equals, tpm2.HashAlgorithmSHA256)
			c.Assert(params.LoadSequences, DeepEquals, sequences)
			return nil
		})
		defer restore()

		// mock adding systemd EFI stub profile
		addSystemdEfiStubCalls := 0
		restore = secboot.MockSbAddSystemdEFIStubProfile(func(profile *sb.PCRProtectionProfile, params *sb.SystemdEFIStubProfileParams) error {
			addSystemdEfiStubCalls++
			c.Assert(profile, Equals, pcrProfile)
			c.Assert(params.PCRAlgorithm, Equals, tpm2.HashAlgorithmSHA256)
			c.Assert(params.PCRIndex, Equals, 12)
			c.Assert(params.KernelCmdlines, DeepEquals, myParams.KernelCmdlines)
			return nil
		})
		defer restore()

		// mock adding snap model profile
		addSnapModelCalls := 0
		restore = secboot.MockSbAddSnapModelProfile(func(profile *sb.PCRProtectionProfile, params *sb.SnapModelProfileParams) error {
			addSnapModelCalls++
			c.Assert(profile, Equals, pcrProfile)
			c.Assert(params.PCRAlgorithm, Equals, tpm2.HashAlgorithmSHA256)
			c.Assert(params.PCRIndex, Equals, 12)
			c.Assert(params.Models, DeepEquals, myParams.Models)
			return nil
		})
		defer restore()

		// mock provisioning
		provisioningCalls := 0
		restore = secboot.MockSbProvisionTPM(func(t *sb.TPMConnection, mode sb.ProvisionMode, newLockoutAuth []byte) error {
			provisioningCalls++
			c.Assert(t, Equals, tpm)
			c.Assert(mode, Equals, sb.ProvisionModeFull)
			c.Assert(myParams.TPMLockoutAuthFile, testutil.FilePresent)
			return nil
		})
		defer restore()

		// test sealing
		sealCalls := 0
		restore = secboot.MockSbSealKeyToTPM(func(t *sb.TPMConnection, key []byte, keyPath, policyUpdatePath string, params *sb.KeyCreationParams) error {
			sealCalls++
			c.Assert(t, Equals, tpm)
			c.Assert(key, DeepEquals, myKey[:])
			c.Assert(keyPath, Equals, myParams.KeyFile)
			c.Assert(policyUpdatePath, Equals, myParams.PolicyUpdateDataFile)
			c.Assert(params.PCRProfile, Equals, pcrProfile)
			c.Assert(params.PINHandle, Equals, tpm2.Handle(0x01880000))

			return nil
		})
		defer restore()

		err := secboot.SealKey(myKey, &myParams)
		if tc.err == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, ErrorMatches, tc.err)
		}
		c.Assert(addEFISbPolicyCalls, Equals, tc.callNum)
		c.Assert(addSystemdEfiStubCalls, Equals, tc.callNum)
		c.Assert(addSnapModelCalls, Equals, tc.callNum)
		c.Assert(provisioningCalls, Equals, tc.callNum)
		c.Assert(sealCalls, Equals, tc.callNum)

	}
}

func mockSbTPMConnection(c *C, tpmErr error) (*sb.TPMConnection, func()) {
	tcti, err := os.Open("/dev/null")
	c.Assert(err, IsNil)
	tpmctx, err := tpm2.NewTPMContext(tcti)
	c.Assert(err, IsNil)
	tpm := &sb.TPMConnection{TPMContext: tpmctx}
	restore := secboot.MockSbConnectToDefaultTPM(func() (*sb.TPMConnection, error) {
		if tpmErr != nil {
			return nil, tpmErr
		}
		return tpm, nil
	})
	return tpm, restore
}

func mockDevDiskByLabel(c *C) (string, func()) {
	devDir := filepath.Join(c.MkDir(), "dev/disk/by-label")
	err := os.MkdirAll(devDir, 0755)
	c.Assert(err, IsNil)
	restore := secboot.MockDevDiskByLabelDir(devDir)
	return devDir, restore
}
