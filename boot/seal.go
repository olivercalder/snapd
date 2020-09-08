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

package boot

import (
	"fmt"
	"path/filepath"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/secboot"
	"github.com/snapcore/snapd/seed"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/timings"
)

var (
	secbootSealKey = secboot.SealKey
)

// sealKeyToModeenv seals the supplied key to the parameters specified
// in modeenv.
func sealKeyToModeenv(key secboot.EncryptionKey, model *asserts.Model, modeenv *Modeenv) error {
	// build the recovery mode boot chain
	rbl, err := bootloader.Find(InitramfsUbuntuSeedDir, &bootloader.Options{
		Role: bootloader.RoleRecovery,
	})
	if err != nil {
		return fmt.Errorf("cannot find the recovery bootloader: %v", err)
	}

	recoveryBootChain, err := buildRecoveryBootChain(rbl, model, modeenv)
	if err != nil {
		return fmt.Errorf("cannot build recovery boot chain: %v", err)
	}

	// build the run mode boot chains
	bl, err := bootloader.Find(InitramfsUbuntuBootDir, &bootloader.Options{
		Role:        bootloader.RoleRunMode,
		NoSlashBoot: true,
	})
	if err != nil {
		return fmt.Errorf("cannot find the bootloader: %v", err)
	}

	runModeBootChains, err := buildRunModeBootChains(rbl, bl, model, modeenv)
	if err != nil {
		return fmt.Errorf("cannot build run mode boot chain: %v", err)
	}

	pbc := toPredictableBootChains(append(runModeBootChains, recoveryBootChain))

	// XXX: store the predictable bootchains

	// get parameters from bootchains and seal the key
	params, err := sealKeyParams(pbc)
	if err != nil {
		return fmt.Errorf("cannot build key sealing parameters: %v", err)
	}

	if err := secbootSealKey(key, params); err != nil {
		return fmt.Errorf("cannot seal the encryption key: %v", err)
	}

	return nil
}

func buildRecoveryBootChain(rbl bootloader.Bootloader, model *asserts.Model, modeenv *Modeenv) (bc bootChain, err error) {
	// get the command line
	cmdline, err := ComposeRecoveryCommandLine(model, modeenv.RecoverySystem)
	if err != nil {
		return bc, fmt.Errorf("cannot obtain recovery kernel command line: %v", err)
	}

	// get kernel information from seed
	perf := timings.New(nil)
	_, snaps, err := seed.ReadSystemEssential(dirs.SnapSeedDir, modeenv.RecoverySystem, []snap.Type{snap.TypeKernel}, perf)
	if err != nil {
		return bc, err
	}
	if len(snaps) != 1 {
		return bc, fmt.Errorf("cannot obtain recovery kernel snap")
	}
	seedKernel := snaps[0]

	var kernelRev string
	if seedKernel.SideInfo.Revision.Store() {
		kernelRev = seedKernel.SideInfo.Revision.String()
	}

	// get asset chains
	assetChain, kbf, err := buildRecoveryAssetChain(rbl, modeenv)
	if err != nil {
		return bc, err
	}

	return bootChain{
		BrandID:        model.BrandID(),
		Model:          model.Model(),
		Grade:          string(model.Grade()),
		ModelSignKeyID: model.SignKeyID(),
		AssetChain:     assetChain,
		Kernel:         seedKernel.Path,
		KernelRevision: kernelRev,
		KernelCmdline:  cmdline,
		model:          model,
		blName:         rbl.Name(),
		kernelBootFile: bootloader.NewBootFile(seedKernel.Path, kbf.Path, kbf.Role),
	}, nil
}

func buildRunModeBootChains(rbl, bl bootloader.Bootloader, model *asserts.Model, modeenv *Modeenv) ([]bootChain, error) {
	// get the command line
	cmdline, err := ComposeCandidateCommandLine(model)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain kernel command line: %v", err)
	}

	// get asset chains
	assetChain, kbf, err := buildRunModeAssetChain(rbl, bl, modeenv)
	if err != nil {
		return nil, err
	}

	// get run mode kernels
	runModeKernels, err := runModeKernelsFromModeenv(modeenv)
	if err != nil {
		return nil, err
	}

	chains := make([]bootChain, 0, 2)
	for _, k := range runModeKernels {
		chains = append(chains, bootChain{
			BrandID:        model.BrandID(),
			Model:          model.Model(),
			Grade:          string(model.Grade()),
			ModelSignKeyID: model.SignKeyID(),
			AssetChain:     assetChain,
			Kernel:         k,
			// XXX: obtain revision
			KernelRevision: "",
			KernelCmdline:  cmdline,
			model:          model,
			blName:         rbl.Name(),
			kernelBootFile: bootloader.NewBootFile(k, kbf.Path, kbf.Role),
		})
	}

	return chains, nil
}

func buildRecoveryAssetChain(rbl bootloader.Bootloader, modeenv *Modeenv) (assets []bootAsset, kernel bootloader.BootFile, err error) {
	tbl, ok := rbl.(bootloader.TrustedAssetsBootloader)
	if !ok {
		return nil, kernel, fmt.Errorf("bootloader doesn't support trusted assets")
	}

	recoveryBootChain, err := tbl.RecoveryBootChain("")
	if err != nil {
		return nil, kernel, err
	}

	// the last entry is the kernel
	numAssets := len(recoveryBootChain) - 1
	assets = make([]bootAsset, numAssets)

	for i := 0; i < numAssets; i++ {
		name := filepath.Base(recoveryBootChain[i].Path)
		hashes, ok := modeenv.CurrentTrustedRecoveryBootAssets[name]
		if !ok {
			return nil, kernel, fmt.Errorf("cannot find asset %s in modeenv", name)
		}
		assets[i] = bootAsset{
			Role:   string(recoveryBootChain[i].Role),
			Name:   name,
			Hashes: hashes,
		}
	}

	return assets, recoveryBootChain[len(recoveryBootChain)-1], nil
}

func buildRunModeAssetChain(rbl, bl bootloader.Bootloader, modeenv *Modeenv) (assets []bootAsset, kernel bootloader.BootFile, err error) {
	tbl, ok := rbl.(bootloader.TrustedAssetsBootloader)
	if !ok {
		return nil, kernel, fmt.Errorf("recovery bootloader doesn't support trusted assets")
	}

	recoveryBootChain, err := tbl.RecoveryBootChain("")
	if err != nil {
		return nil, kernel, err
	}
	// the last entry is the kernel
	numRecoveryAssets := len(recoveryBootChain) - 1

	runModeBootChain, err := tbl.BootChain(bl, "")
	if err != nil {
		return nil, kernel, err
	}
	// we want the number of additional assets after the recovery asset list
	numRunModeAssets := len(runModeBootChain) - numRecoveryAssets - 1

	assets = make([]bootAsset, numRecoveryAssets+numRunModeAssets)

	for i := 0; i < numRecoveryAssets; i++ {
		name := filepath.Base(recoveryBootChain[i].Path)
		hashes, ok := modeenv.CurrentTrustedRecoveryBootAssets[name]
		if !ok {
			return nil, kernel, fmt.Errorf("cannot find asset %s in modeenv", name)
		}
		assets[i] = bootAsset{
			Role:   string(recoveryBootChain[i].Role),
			Name:   name,
			Hashes: hashes,
		}
	}
	for i := 0; i < numRunModeAssets; i++ {
		name := filepath.Base(runModeBootChain[numRecoveryAssets+i].Path)
		hashes, ok := modeenv.CurrentTrustedBootAssets[name]
		if !ok {
			return nil, kernel, fmt.Errorf("cannot find asset %s in modeenv", name)
		}
		assets[numRecoveryAssets+i] = bootAsset{
			Role:   string(runModeBootChain[i].Role),
			Name:   name,
			Hashes: hashes,
		}
	}

	return assets, runModeBootChain[len(runModeBootChain)-1], nil
}

// runModeKernelsFromModeenv obtains the current and next kernels
// listed in modeenv.
func runModeKernelsFromModeenv(modeenv *Modeenv) ([]string, error) {
	switch len(modeenv.CurrentKernels) {
	case 1:
		current := filepath.Join(dirs.SnapBlobDir, modeenv.CurrentKernels[0])
		return []string{current}, nil
	case 2:
		current := filepath.Join(dirs.SnapBlobDir, modeenv.CurrentKernels[0])
		next := filepath.Join(dirs.SnapBlobDir, modeenv.CurrentKernels[1])
		return []string{current, next}, nil
	}
	return nil, fmt.Errorf("invalid number of kernels in modeenv")
}

func sealKeyParams(pbc predictableBootChains) (*secboot.SealKeyParams, error) {
	modelParams := make([]*secboot.SealKeyModelParams, 0, len(pbc))
	for _, bc := range pbc {
		loadChains, err := efiLoadChains(bc)
		if err != nil {
			return nil, fmt.Errorf("error building EFI load chains: %s", err)
		}

		modelParams = append(modelParams, &secboot.SealKeyModelParams{
			Model:          bc.model,
			KernelCmdlines: []string{bc.KernelCmdline},
			EFILoadChains:  loadChains,
		})
	}

	sealKeyParams := &secboot.SealKeyParams{
		ModelParams:             modelParams,
		KeyFile:                 filepath.Join(InitramfsEncryptionKeyDir, "ubuntu-data.sealed-key"),
		TPMPolicyUpdateDataFile: filepath.Join(InstallHostFDEDataDir, "policy-update-data"),
		TPMLockoutAuthFile:      filepath.Join(InstallHostFDEDataDir, "tpm-lockout-auth"),
	}

	return sealKeyParams, nil
}

func efiLoadChains(bc bootChain) ([][]bootloader.BootFile, error) {
	seq0 := make([]bootloader.BootFile, 0, len(bc.AssetChain)+1)
	seq1 := make([]bootloader.BootFile, 0, len(bc.AssetChain)+1)

	for _, ba := range bc.AssetChain {
		p0, p1, err := cachedAssetPathnames(bc.blName, ba.Name, ba.Hashes)
		if err != nil {
			return nil, err
		}
		seq0 = append(seq0, bootloader.NewBootFile("", p0, bootloader.Role(ba.Role)))
		seq1 = append(seq1, bootloader.NewBootFile("", p1, bootloader.Role(ba.Role)))
	}

	// add kernel
	seq0 = append(seq0, bc.kernelBootFile)
	seq1 = append(seq1, bc.kernelBootFile)

	// XXX: we can explode to all possible combinations now, or using load event trees later

	if sequenceEqual(seq0, seq1) {
		return [][]bootloader.BootFile{seq0}, nil
	}

	return [][]bootloader.BootFile{seq0, seq1}, nil
}

// cachedAssetPathnames returns the pathnames of the files corresponding
// to the current and next instances of a given boot asset.
func cachedAssetPathnames(blName, name string, hashes []string) (current, next string, err error) {
	cacheEntry := func(hash string) (string, error) {
		p := filepath.Join(dirs.SnapBootAssetsDir, blName, fmt.Sprintf("%s-%s", name, hash))
		if !osutil.FileExists(p) {
			return "", fmt.Errorf("file %s not found in assets cache", p)
		}
		return p, nil
	}

	switch len(hashes) {
	case 1:
		current, err = cacheEntry(hashes[0])
		if err != nil {
			return "", "", err
		}
		next = current
	case 2:
		current, err = cacheEntry(hashes[0])
		if err != nil {
			return "", "", err
		}
		next, err = cacheEntry(hashes[1])
		if err != nil {
			return "", "", err
		}
	default:
		return "", "", fmt.Errorf("invalid number of hashes for asset %s in modeenv", name)
	}
	return current, next, nil
}

func sequenceEqual(a, b []bootloader.BootFile) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
