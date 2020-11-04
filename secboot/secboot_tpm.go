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

package secboot

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/canonical/go-tpm2"
	sb "github.com/snapcore/secboot"
	"golang.org/x/xerrors"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/bootloader/efi"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/disks"
	"github.com/snapcore/snapd/randutil"
	"github.com/snapcore/snapd/snap/snapfile"
)

const (
	keyringPrefix = "snapd"
)

var (
	sbConnectToDefaultTPM                  = sb.ConnectToDefaultTPM
	sbMeasureSnapSystemEpochToTPM          = sb.MeasureSnapSystemEpochToTPM
	sbMeasureSnapModelToTPM                = sb.MeasureSnapModelToTPM
	sbBlockPCRProtectionPolicies           = sb.BlockPCRProtectionPolicies
	sbActivateVolumeWithTPMSealedKey       = sb.ActivateVolumeWithTPMSealedKey
	sbActivateVolumeWithRecoveryKey        = sb.ActivateVolumeWithRecoveryKey
	sbActivateVolumeWithKey                = sb.ActivateVolumeWithKey
	sbAddEFISecureBootPolicyProfile        = sb.AddEFISecureBootPolicyProfile
	sbAddEFIBootManagerProfile             = sb.AddEFIBootManagerProfile
	sbAddSystemdEFIStubProfile             = sb.AddSystemdEFIStubProfile
	sbAddSnapModelProfile                  = sb.AddSnapModelProfile
	sbSealKeyToTPMMultiple                 = sb.SealKeyToTPMMultiple
	sbUpdateKeyPCRProtectionPolicyMultiple = sb.UpdateKeyPCRProtectionPolicyMultiple

	randutilRandomKernelUUID = randutil.RandomKernelUUID

	isTPMEnabled = isTPMEnabledImpl
	provisionTPM = provisionTPMImpl
)

func isTPMEnabledImpl(tpm *sb.TPMConnection) bool {
	return tpm.IsEnabled()
}

func CheckKeySealingSupported() error {
	logger.Noticef("checking if secure boot is enabled...")
	if err := checkSecureBootEnabled(); err != nil {
		logger.Noticef("secure boot not enabled: %v", err)
		return err
	}
	logger.Noticef("secure boot is enabled")

	logger.Noticef("checking if TPM device is available...")
	tpm, err := sbConnectToDefaultTPM()
	if err != nil {
		err = fmt.Errorf("cannot connect to TPM device: %v", err)
		logger.Noticef("%v", err)
		return err
	}
	defer tpm.Close()

	if !isTPMEnabled(tpm) {
		logger.Noticef("TPM device detected but not enabled")
		return fmt.Errorf("TPM device is not enabled")
	}

	logger.Noticef("TPM device detected and enabled")

	return nil
}

func checkSecureBootEnabled() error {
	// 8be4df61-93ca-11d2-aa0d-00e098032b8c is the EFI Global Variable vendor GUID
	b, _, err := efi.ReadVarBytes("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil {
		if err == efi.ErrNoEFISystem {
			return err
		}
		return fmt.Errorf("cannot read secure boot variable: %v", err)
	}
	if len(b) < 1 {
		return errors.New("secure boot variable does not exist")
	}
	if b[0] != 1 {
		return errors.New("secure boot is disabled")
	}

	return nil
}

// initramfsPCR is the TPM PCR that we reserve for the EFI image and use
// for measurement from the initramfs.
const initramfsPCR = 12

func secureConnectToTPM(ekcfile string) (*sb.TPMConnection, error) {
	ekCertReader, err := os.Open(ekcfile)
	if err != nil {
		return nil, fmt.Errorf("cannot open endorsement key certificate file: %v", err)
	}
	defer ekCertReader.Close()

	return sb.SecureConnectToDefaultTPM(ekCertReader, nil)
}

func insecureConnectToTPM() (*sb.TPMConnection, error) {
	return sbConnectToDefaultTPM()
}

func measureWhenPossible(whatHow func(tpm *sb.TPMConnection) error) error {
	// the model is ready, we're good to try measuring it now
	tpm, err := insecureConnectToTPM()
	if err != nil {
		if xerrors.Is(err, sb.ErrNoTPM2Device) {
			return nil
		}
		return fmt.Errorf("cannot open TPM connection: %v", err)
	}
	defer tpm.Close()

	if !isTPMEnabled(tpm) {
		return nil
	}

	return whatHow(tpm)
}

// MeasureSnapSystemEpochWhenPossible measures the snap system epoch only if the
// TPM device is available. If there's no TPM device success is returned.
func MeasureSnapSystemEpochWhenPossible() error {
	measure := func(tpm *sb.TPMConnection) error {
		return sbMeasureSnapSystemEpochToTPM(tpm, initramfsPCR)
	}

	if err := measureWhenPossible(measure); err != nil {
		return fmt.Errorf("cannot measure snap system epoch: %v", err)
	}

	return nil
}

// MeasureSnapModelWhenPossible measures the snap model only if the TPM device is
// available. If there's no TPM device success is returned.
func MeasureSnapModelWhenPossible(findModel func() (*asserts.Model, error)) error {
	measure := func(tpm *sb.TPMConnection) error {
		model, err := findModel()
		if err != nil {
			return err
		}
		return sbMeasureSnapModelToTPM(tpm, initramfsPCR, model)
	}

	if err := measureWhenPossible(measure); err != nil {
		return fmt.Errorf("cannot measure snap model: %v", err)
	}

	return nil
}

// UnlockVolumeUsingSealedKeyIfEncrypted verifies whether an encrypted volume
// with the specified name exists and unlocks it using a sealed key in a file
// with a corresponding name. With lockKeysOnFinish set, access to the sealed
// keys will be locked when this function completes. The path to the device node
// is returned as well as whether the device node is an decrypted device node (
// in the encrypted case). If no encrypted volume was found, then the returned
// device node is an unencrypted normal volume.
func UnlockVolumeUsingSealedKeyIfEncrypted(disk disks.Disk, name string, encryptionKeyDir string, lockKeysOnFinish bool) (string, bool, error) {
	// TODO:UC20: use sb.SecureConnectToDefaultTPM() if we decide there's benefit in doing that or
	//            we have a hard requirement for a valid EK cert chain for every boot (ie, panic
	//            if there isn't one). But we can't do that as long as we need to download
	//            intermediate certs from the manufacturer.
	tpm, tpmErr := sbConnectToDefaultTPM()
	if tpmErr != nil {
		if !xerrors.Is(tpmErr, sb.ErrNoTPM2Device) {
			return "", false, fmt.Errorf("cannot unlock encrypted device %q: %v", name, tpmErr)
		}
		logger.Noticef("cannot open TPM connection: %v", tpmErr)
	} else {
		defer tpm.Close()
	}

	// Also check if the TPM device is enabled. The platform firmware may disable the storage
	// and endorsement hierarchies, but the device will remain visible to the operating system.
	tpmDeviceAvailable := tpmErr == nil && isTPMEnabled(tpm)

	var lockErr error
	var mapperName string
	err, foundEncDev := func() (error, bool) {
		defer func() {
			if lockKeysOnFinish && tpmDeviceAvailable {
				// Lock access to the sealed keys. This should be called whenever there
				// is a TPM device detected, regardless of whether secure boot is enabled
				// or there is an encrypted volume to unlock. Note that snap-bootstrap can
				// be called several times during initialization, and if there are multiple
				// volumes to unlock we should lock access to the sealed keys only after
				// the last encrypted volume is unlocked, in which case lockKeysOnFinish
				// should be set to true.
				//
				// We should only touch the PCR that we've currently reserved for the kernel
				// EFI image. Touching others will break the ability to perform any kind of
				// attestation using the TPM because it will make the log inconsistent.
				lockErr = sbBlockPCRProtectionPolicies(tpm, []int{initramfsPCR})
			}
		}()

		// find the encrypted device using the disk we were provided - note that
		// we do not specify IsDecryptedDevice in opts because here we are
		// looking for the encrypted device to unlock, later on in the boot
		// process we will look for the decrypted device to ensure it matches
		// what we expected
		partUUID, err := disk.FindMatchingPartitionUUID(name + "-enc")
		var errNotFound disks.FilesystemLabelNotFoundError
		if xerrors.As(err, &errNotFound) {
			// didn't find the encrypted label, so return nil to try the
			// decrypted label again
			return nil, false
		}
		if err != nil {
			return err, false
		}
		encdev := filepath.Join("/dev/disk/by-partuuid", partUUID)

		mapperName = name + "-" + randutilRandomKernelUUID()
		if !tpmDeviceAvailable {
			return unlockEncryptedPartitionWithRecoveryKey(mapperName, encdev), true
		}

		sealedKeyPath := filepath.Join(encryptionKeyDir, name+".sealed-key")
		return unlockEncryptedPartitionWithSealedKey(tpm, mapperName, encdev, sealedKeyPath, ""), true
	}()
	if err != nil {
		return "", false, err
	}
	if lockErr != nil {
		return "", false, fmt.Errorf("cannot lock access to sealed keys: %v", lockErr)
	}

	if foundEncDev {
		// return the encrypted device if the device we are maybe unlocking is
		// an encrypted device
		return filepath.Join("/dev/mapper", mapperName), true, nil
	}

	// otherwise find the device from the disk
	partUUID, err := disk.FindMatchingPartitionUUID(name)
	if err != nil {
		return "", false, err
	}
	return filepath.Join("/dev/disk/by-partuuid", partUUID), false, nil
}

// UnlockEncryptedVolumeUsingKey unlocks an existing volume using the provided key. The
// path to the device node is returned.
func UnlockEncryptedVolumeUsingKey(disk disks.Disk, name string, key []byte) (string, error) {
	// find the encrypted device using the disk we were provided - note that
	// we do not specify IsDecryptedDevice in opts because here we are
	// looking for the encrypted device to unlock, later on in the boot
	// process we will look for the decrypted device to ensure it matches
	// what we expected
	partUUID, err := disk.FindMatchingPartitionUUID(name + "-enc")
	if err != nil {
		return "", err
	}
	// we have a device
	encdev := filepath.Join("/dev/disk/by-partuuid", partUUID)
	// make up a new name for the mapped device
	mapperName := name + "-" + randutilRandomKernelUUID()
	if err := unlockEncryptedPartitionWithKey(mapperName, encdev, key); err != nil {
		return "", err
	}
	return filepath.Join("/dev/mapper", mapperName), nil
}

// unlockEncryptedPartitionWithRecoveryKey prompts for the recovery key and use
// it to open an encrypted device.
func unlockEncryptedPartitionWithRecoveryKey(name, device string) error {
	options := sb.ActivateVolumeOptions{
		RecoveryKeyTries: 3,
		KeyringPrefix:    keyringPrefix,
	}

	if err := sbActivateVolumeWithRecoveryKey(name, device, nil, &options); err != nil {
		return fmt.Errorf("cannot unlock encrypted device %q: %v", device, err)
	}

	return nil
}

// unlockEncryptedPartitionWithSealedKey unseals the keyfile and opens an encrypted
// device. If activation with the sealed key fails, this function will attempt to
// activate it with the fallback recovery key instead.
func unlockEncryptedPartitionWithSealedKey(tpm *sb.TPMConnection, name, device, keyfile, pinfile string) error {
	options := sb.ActivateVolumeOptions{
		PassphraseTries:  1,
		RecoveryKeyTries: 3,
		KeyringPrefix:    keyringPrefix,
	}

	// XXX: pinfile is currently not used
	activated, err := sbActivateVolumeWithTPMSealedKey(tpm, name, device, keyfile, nil, &options)
	if !activated {
		// ActivateVolumeWithTPMSealedKey should always return an error if activated == false
		return fmt.Errorf("cannot activate encrypted device %q: %v", device, err)
	}
	if err != nil {
		logger.Noticef("successfully activated encrypted device %q using a fallback activation method", device)
	} else {
		logger.Noticef("successfully activated encrypted device %q with TPM", device)
	}

	return nil
}

// unlockEncryptedPartitionWithKey unlocks encrypted partition with the provided
// key.
func unlockEncryptedPartitionWithKey(name, device string, key []byte) error {
	// no special options set
	options := sb.ActivateVolumeOptions{}
	err := sbActivateVolumeWithKey(name, device, key, &options)
	if err == nil {
		logger.Noticef("successfully activated encrypted device %v using a key", device)
	}
	return err
}

// SealKeys provisions the TPM and seals the encryption keys according to the
// specified parameters. If the TPM is already provisioned, or a sealed key already
// exists, SealKeys will fail and return an error.
func SealKeys(keys []SealKeyRequest, params *SealKeysParams) error {
	numModels := len(params.ModelParams)
	if numModels < 1 {
		return fmt.Errorf("at least one set of model-specific parameters is required")
	}

	tpm, err := sbConnectToDefaultTPM()
	if err != nil {
		return fmt.Errorf("cannot connect to TPM: %v", err)
	}
	defer tpm.Close()
	if !isTPMEnabled(tpm) {
		return fmt.Errorf("TPM device is not enabled")
	}

	pcrProfile, err := buildPCRProtectionProfile(params.ModelParams)
	if err != nil {
		return err
	}

	if params.TPMProvision {
		// Provision the TPM as late as possible
		if err := tpmProvision(tpm, params.TPMLockoutAuthFile); err != nil {
			return err
		}
	}

	// Seal the provided keys to the TPM
	creationParams := sb.KeyCreationParams{
		PCRProfile:             pcrProfile,
		PCRPolicyCounterHandle: tpm2.Handle(params.PCRPolicyCounterHandle),
		AuthKey:                params.TPMPolicyAuthKey,
	}

	sbKeys := make([]*sb.SealKeyRequest, 0, len(keys))
	for i := range keys {
		sbKeys = append(sbKeys, &sb.SealKeyRequest{
			Key:  keys[i].Key[:],
			Path: keys[i].KeyFile,
		})
	}

	authKey, err := sbSealKeyToTPMMultiple(tpm, sbKeys, &creationParams)
	if err != nil {
		return err
	}
	if params.TPMPolicyAuthKeyFile != "" {
		if err := osutil.AtomicWriteFile(params.TPMPolicyAuthKeyFile, authKey, 0600, 0); err != nil {
			return fmt.Errorf("cannot write the policy auth key file: %v", err)
		}
	}

	return nil
}

// ResealKeys updates the PCR protection policy for the sealed encryption keys
// according to the specified parameters.
func ResealKeys(params *ResealKeysParams) error {
	numModels := len(params.ModelParams)
	if numModels < 1 {
		return fmt.Errorf("at least one set of model-specific parameters is required")
	}

	tpm, err := sbConnectToDefaultTPM()
	if err != nil {
		return fmt.Errorf("cannot connect to TPM: %v", err)
	}
	defer tpm.Close()
	if !isTPMEnabled(tpm) {
		return fmt.Errorf("TPM device is not enabled")
	}

	pcrProfile, err := buildPCRProtectionProfile(params.ModelParams)
	if err != nil {
		return err
	}

	authKey, err := ioutil.ReadFile(params.TPMPolicyAuthKeyFile)
	if err != nil {
		return fmt.Errorf("cannot read the policy auth key file: %v", err)
	}

	return sbUpdateKeyPCRProtectionPolicyMultiple(tpm, params.KeyFiles, authKey, pcrProfile)
}

func buildPCRProtectionProfile(modelParams []*SealKeyModelParams) (*sb.PCRProtectionProfile, error) {
	numModels := len(modelParams)
	modelPCRProfiles := make([]*sb.PCRProtectionProfile, 0, numModels)

	for _, mp := range modelParams {
		modelProfile := sb.NewPCRProtectionProfile()

		loadSequences, err := buildLoadSequences(mp.EFILoadChains)
		if err != nil {
			return nil, fmt.Errorf("cannot build EFI image load sequences: %v", err)
		}

		// Add EFI secure boot policy profile
		policyParams := sb.EFISecureBootPolicyProfileParams{
			PCRAlgorithm:  tpm2.HashAlgorithmSHA256,
			LoadSequences: loadSequences,
			// TODO:UC20: set SignatureDbUpdateKeystore to support applying forbidden
			//            signature updates to blacklist signing keys (after rotating them).
			//            This also requires integration of sbkeysync, and some work to
			//            ensure that the PCR profile is updated before/after sbkeysync executes.
		}

		if err := sbAddEFISecureBootPolicyProfile(modelProfile, &policyParams); err != nil {
			return nil, fmt.Errorf("cannot add EFI secure boot policy profile: %v", err)
		}

		// Add EFI boot manager profile
		bootManagerParams := sb.EFIBootManagerProfileParams{
			PCRAlgorithm:  tpm2.HashAlgorithmSHA256,
			LoadSequences: loadSequences,
		}
		if err := sbAddEFIBootManagerProfile(modelProfile, &bootManagerParams); err != nil {
			return nil, fmt.Errorf("cannot add EFI boot manager profile: %v", err)
		}

		// Add systemd EFI stub profile
		if len(mp.KernelCmdlines) != 0 {
			systemdStubParams := sb.SystemdEFIStubProfileParams{
				PCRAlgorithm:   tpm2.HashAlgorithmSHA256,
				PCRIndex:       initramfsPCR,
				KernelCmdlines: mp.KernelCmdlines,
			}
			if err := sbAddSystemdEFIStubProfile(modelProfile, &systemdStubParams); err != nil {
				return nil, fmt.Errorf("cannot add systemd EFI stub profile: %v", err)
			}
		}

		// Add snap model profile
		if mp.Model != nil {
			snapModelParams := sb.SnapModelProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				PCRIndex:     initramfsPCR,
				Models:       []sb.SnapModel{mp.Model},
			}
			if err := sbAddSnapModelProfile(modelProfile, &snapModelParams); err != nil {
				return nil, fmt.Errorf("cannot add snap model profile: %v", err)
			}
		}

		modelPCRProfiles = append(modelPCRProfiles, modelProfile)
	}

	var pcrProfile *sb.PCRProtectionProfile
	if numModels > 1 {
		pcrProfile = sb.NewPCRProtectionProfile().AddProfileOR(modelPCRProfiles...)
	} else {
		pcrProfile = modelPCRProfiles[0]
	}

	logger.Debugf("PCR protection profile:\n%s", pcrProfile.String())

	return pcrProfile, nil
}

func tpmProvision(tpm *sb.TPMConnection, lockoutAuthFile string) error {
	// Create and save the lockout authorization file
	lockoutAuth := make([]byte, 16)
	// crypto rand is protected against short reads
	_, err := rand.Read(lockoutAuth)
	if err != nil {
		return fmt.Errorf("cannot create lockout authorization: %v", err)
	}
	if err := osutil.AtomicWriteFile(lockoutAuthFile, lockoutAuth, 0600, 0); err != nil {
		return fmt.Errorf("cannot write the lockout authorization file: %v", err)
	}

	// TODO:UC20: ideally we should ask the firmware to clear the TPM and then reboot
	//            if the device has previously been provisioned, see
	//            https://godoc.org/github.com/snapcore/secboot#RequestTPMClearUsingPPI
	if err := provisionTPM(tpm, sb.ProvisionModeFull, lockoutAuth); err != nil {
		logger.Noticef("TPM provisioning error: %v", err)
		return fmt.Errorf("cannot provision TPM: %v", err)
	}
	return nil
}

func provisionTPMImpl(tpm *sb.TPMConnection, mode sb.ProvisionMode, lockoutAuth []byte) error {
	return tpm.EnsureProvisioned(mode, lockoutAuth)
}

// buildLoadSequences builds EFI load image event trees from this package LoadChains
func buildLoadSequences(chains []*LoadChain) (loadseqs []*sb.EFIImageLoadEvent, err error) {
	// this will build load event trees for the current
	// device configuration, e.g. something like:
	//
	// shim -> recovery grub -> recovery kernel 1
	//                      |-> recovery kernel 2
	//                      |-> recovery kernel ...
	//                      |-> normal grub -> run kernel good
	//                                     |-> run kernel try

	for _, chain := range chains {
		// root of load events has source Firmware
		loadseq, err := chain.loadEvent(sb.Firmware)
		if err != nil {
			return nil, err
		}
		loadseqs = append(loadseqs, loadseq)
	}
	return loadseqs, nil
}

// loadEvent builds the corresponding load event and its tree
func (lc *LoadChain) loadEvent(source sb.EFIImageLoadEventSource) (*sb.EFIImageLoadEvent, error) {
	var next []*sb.EFIImageLoadEvent
	for _, nextChain := range lc.Next {
		// everything that is not the root has source shim
		ev, err := nextChain.loadEvent(sb.Shim)
		if err != nil {
			return nil, err
		}
		next = append(next, ev)
	}
	image, err := efiImageFromBootFile(lc.BootFile)
	if err != nil {
		return nil, err
	}
	return &sb.EFIImageLoadEvent{
		Source: source,
		Image:  image,
		Next:   next,
	}, nil
}

func efiImageFromBootFile(b *bootloader.BootFile) (sb.EFIImage, error) {
	if b.Snap == "" {
		if !osutil.FileExists(b.Path) {
			return nil, fmt.Errorf("file %s does not exist", b.Path)
		}
		return sb.FileEFIImage(b.Path), nil
	}

	snapf, err := snapfile.Open(b.Snap)
	if err != nil {
		return nil, err
	}
	return sb.SnapFileEFIImage{
		Container: snapf,
		Path:      b.Snap,
		FileName:  b.Path,
	}, nil
}
