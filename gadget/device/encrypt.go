// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2022 Canonical Ltd
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

package device

import (
	"io/ioutil"
	"path/filepath"

	"github.com/snapcore/snapd/osutil"
)

// encryptionMarkerUnder returns the path of the encrypted system marker under a
// given directory.
func encryptionMarkerUnder(deviceFDEDir string) string {
	return filepath.Join(deviceFDEDir, "marker")
}

// HasEncryptedMarkerUnder returns true when there is an encryption marker in a
// given directory.
func HasEncryptedMarkerUnder(deviceFDEDir string) bool {
	return osutil.FileExists(encryptionMarkerUnder(deviceFDEDir))
}

// ReadEncryptionMarkers reads the encryption marker files at the appropriate
// locations.
func ReadEncryptionMarkers(dataFDEDir, saveFDEDir string) ([]byte, []byte, error) {
	marker1, err := ioutil.ReadFile(encryptionMarkerUnder(dataFDEDir))
	if err != nil {
		return nil, nil, err
	}
	marker2, err := ioutil.ReadFile(encryptionMarkerUnder(saveFDEDir))
	if err != nil {
		return nil, nil, err
	}
	return marker1, marker2, nil
}

// WriteEncryptionMarkers writes the encryption marker files at the appropriate
// locations.
func WriteEncryptionMarkers(dataFDEDir, saveFDEDir string, markerSecret []byte) error {
	err := osutil.AtomicWriteFile(encryptionMarkerUnder(dataFDEDir), markerSecret, 0600, 0)
	if err != nil {
		return err
	}
	return osutil.AtomicWriteFile(encryptionMarkerUnder(saveFDEDir), markerSecret, 0600, 0)
}

// DataSealedKeyUnder returns the path of the sealed key for ubuntu-data.
func DataSealedKeyUnder(deviceFDEDir string) string {
	return filepath.Join(deviceFDEDir, "ubuntu-data.sealed-key")
}

// SaveKeyUnder returns the path of a plain encryption key for ubuntu-save.
func SaveKeyUnder(deviceFDEDir string) string {
	return filepath.Join(deviceFDEDir, "ubuntu-save.key")
}

// RecoveryKeyUnder returns the path of the recovery key.
func RecoveryKeyUnder(deviceFDEDir string) string {
	return filepath.Join(deviceFDEDir, "recovery.key")
}

// FallbackDataSealedKeyUnder returns the path of a fallback ubuntu data key.
func FallbackDataSealedKeyUnder(seedDeviceFDEDir string) string {
	return filepath.Join(seedDeviceFDEDir, "ubuntu-data.recovery.sealed-key")
}

// FallbackSaveSealedKeyUnder returns the path of a fallback ubuntu save key.
func FallbackSaveSealedKeyUnder(seedDeviceFDEDir string) string {
	return filepath.Join(seedDeviceFDEDir, "ubuntu-save.recovery.sealed-key")
}

// FactoryResetFallbackSaveSealedKeyUnder returns the path of a fallback ubuntu
// save key object generated during factory reset.
func FactoryResetFallbackSaveSealedKeyUnder(seedDeviceFDEDir string) string {
	return filepath.Join(seedDeviceFDEDir, "ubuntu-save.recovery.sealed-key.factory-reset")
}

// TpmLockoutAuthUnder return the path of the tpm lockout authority key.
func TpmLockoutAuthUnder(saveDeviceFDEDir string) string {
	return filepath.Join(saveDeviceFDEDir, "tpm-lockout-auth")
}
