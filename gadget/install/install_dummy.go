// -*- Mode: Go; indent-tabs-mode: t -*-
//go:build nosecboot
// +build nosecboot

/*
 * Copyright (C) 2019-2020 Canonical Ltd
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

package install

import (
	"fmt"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/gadget"
	"github.com/snapcore/snapd/secboot"
	"github.com/snapcore/snapd/secboot/keys"
	"github.com/snapcore/snapd/timings"
)

func Run(model gadget.Model, gadgetRoot, kernelRoot, device string, options Options, _ gadget.ContentObserver, _ timings.Measurer) (*InstalledSystemSideData, error) {
	return nil, fmt.Errorf("build without secboot support")
}

func FactoryReset(model gadget.Model, gadgetRoot, kernelRoot, device string, options Options, _ gadget.ContentObserver, _ timings.Measurer) (*InstalledSystemSideData, error) {
	return nil, fmt.Errorf("build without secboot support")
}

func MountVolumes(onVolumes map[string]*gadget.Volume, encSetupData *EncryptionSetupData) (espMntDir string, unmount func() error, err error) {
	return "", nil, fmt.Errorf("build without secboot support")
}

func WriteContent(onVolumes map[string]*gadget.Volume, observer gadget.ContentObserver,
	gadgetRoot, kernelRoot string, model *asserts.Model, encSetupData *EncryptionSetupData, perfTimings timings.Measurer) ([]*gadget.OnDiskVolume, error) {
	return nil, fmt.Errorf("build without secboot support")
}

func EncryptPartitions(onVolumes map[string]*gadget.Volume, gadgetRoot, kernelRoot string,
	model *asserts.Model, encryptionType secboot.EncryptionType, perfTimings timings.Measurer) (*EncryptionSetupData, error) {
	return nil, fmt.Errorf("build without secboot support")
}

func FinishEncryption(model gadget.Model, setupData *EncryptionSetupData) error {
	return fmt.Errorf("build without secboot support")
}

func KeysForRole(setupData *EncryptionSetupData) map[string]keys.EncryptionKey {
	return nil
}
