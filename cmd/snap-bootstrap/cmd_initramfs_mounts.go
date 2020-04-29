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

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jessevdk/go-flags"

	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/secboot"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/sysconfig"
)

func init() {
	const (
		short = "Generate initramfs mount tuples"
		long  = "Generate mount tuples for the initramfs until nothing more can be done"
	)

	addCommandBuilder(func(parser *flags.Parser) {
		if _, err := parser.AddCommand("initramfs-mounts", short, long, &cmdInitramfsMounts{}); err != nil {
			panic(err)
		}
	})

	snap.SanitizePlugsSlots = func(*snap.Info) {}
}

type cmdInitramfsMounts struct{}

func (c *cmdInitramfsMounts) Execute(args []string) error {
	return generateInitramfsMounts()
}

// XXX: move all var () to the top, it's very spread out right now
var (
	// Stdout - can be overridden in tests
	stdout io.Writer = os.Stdout
)

var (
	osutilIsMounted = osutil.IsMounted
)

// generateMountsMode* is called multiple times from initramfs until it
// no longer generates more mount points and just returns an empty output.
func generateMountsModeInstall(mst initramfsMountsState, recoverySystem string) error {
	allMounted, err := generateMountsCommonInstallRecover(mst, recoverySystem)
	if err != nil {
		return err
	}
	if !allMounted {
		return nil
	}

	// n+1: final step: write $(ubuntu_data)/var/lib/snapd/modeenv - this
	//      is the tmpfs we just created above
	modeEnv := &boot.Modeenv{
		Mode:           "install",
		RecoverySystem: recoverySystem,
	}
	if err := modeEnv.WriteTo(boot.InitramfsWritableDir); err != nil {
		return err
	}
	// and disable cloud-init in install mode
	if err := sysconfig.DisableCloudInit(boot.InitramfsWritableDir); err != nil {
		return err
	}

	// n+3: done, no output, no error indicates to initramfs we are done
	//      with mounting stuff
	return nil
}

// copyUbuntuDataAuth copies the authenication files like
//  - extrausers passwd,shadow etc
//  - sshd host configuration
//  - user .ssh dir
// to the target directory. This is used to copy the authentication
// data from a real uc20 ubuntu-data partition into a ephemeral one.
func copyUbuntuDataAuth(src, dst string) error {
	for _, globEx := range []string{
		"system-data/var/lib/extrausers/*",
		"system-data/etc/ssh/*",
		"user-data/*/.ssh/*",
		// this ensures we also get non-ssh enabled accounts copied
		"user-data/*/.profile",
	} {
		matches, err := filepath.Glob(filepath.Join(src, globEx))
		if err != nil {
			return err
		}
		for _, p := range matches {
			comps := strings.Split(strings.TrimPrefix(p, src), "/")
			for i := range comps {
				part := filepath.Join(comps[0 : i+1]...)
				fi, err := os.Stat(filepath.Join(src, part))
				if err != nil {
					return err
				}
				if fi.IsDir() {
					if err := os.Mkdir(filepath.Join(dst, part), fi.Mode()); err != nil && !os.IsExist(err) {
						return err
					}
					st, ok := fi.Sys().(*syscall.Stat_t)
					if !ok {
						return fmt.Errorf("cannot get stat data: %v", err)
					}
					if err := os.Chown(filepath.Join(dst, part), int(st.Uid), int(st.Gid)); err != nil {
						return err
					}
				} else {
					if err := osutil.CopyFile(p, filepath.Join(dst, part), osutil.CopyFlagPreserveAll); err != nil {
						return err
					}
				}
			}
		}
	}

	// ensure the user state is transferred as well
	srcState := filepath.Join(src, "system-data/var/lib/snapd/state.json")
	dstState := filepath.Join(dst, "system-data/var/lib/snapd/state.json")
	err := state.CopyState(srcState, dstState, []string{"auth.users"})
	if err != nil && err != state.ErrNoState {
		return fmt.Errorf("cannot copy user state: %v", err)
	}

	return nil
}

func generateMountsModeRecover(mst initramfsMountsState, recoverySystem string) error {
	allMounted, err := generateMountsCommonInstallRecover(mst, recoverySystem)
	if err != nil {
		return err
	}
	if !allMounted {
		return nil
	}

	// n+1: mount ubuntu-data for recovery
	isRecoverDataMounted, err := osutilIsMounted(boot.InitramfsHostUbuntuDataDir)
	if err != nil {
		return err
	}
	if !isRecoverDataMounted {
		// TODO:UC20: data may need to be unlocked
		fmt.Fprintf(stdout, "/dev/disk/by-label/ubuntu-data %s\n", boot.InitramfsHostUbuntuDataDir)
		return nil
	}

	// now copy the auth data from the real ubuntu-data dir to the ephemeral
	// ubuntu-data dir
	if err := copyUbuntuDataAuth(boot.InitramfsHostUbuntuDataDir, boot.InitramfsUbuntuDataDir); err != nil {
		return err
	}

	// n+2: final step: write $(ubuntu_data)/var/lib/snapd/modeenv - this
	//      is the tmpfs we just created above
	modeEnv := &boot.Modeenv{
		Mode:           "recover",
		RecoverySystem: recoverySystem,
	}
	if err := modeEnv.WriteTo(boot.InitramfsWritableDir); err != nil {
		return err
	}
	// and disable cloud-init in recover mode
	if err := sysconfig.DisableCloudInit(boot.InitramfsWritableDir); err != nil {
		return err
	}

	// n+3: done, no output, no error indicates to initramfs we are done
	//      with mounting stuff
	return nil
}

var (
	secbootMeasureEpoch        = secboot.MeasureEpoch
	secbootMeasureModel        = secboot.MeasureModel
	secbootMeasureWhenPossible = secboot.MeasureWhenPossible
	secbootUnlockIfEncrypted   = secboot.UnlockIfEncrypted
)

func generateMountsCommonInstallRecover(mst initramfsMountsState, recoverySystem string) (allMounted bool, err error) {
	// 1. always ensure seed partition is mounted
	isMounted, err := osutilIsMounted(boot.InitramfsUbuntuSeedDir)
	if err != nil {
		return false, err
	}
	if !isMounted {
		fmt.Fprintf(stdout, "/dev/disk/by-label/ubuntu-seed %s\n", boot.InitramfsUbuntuSeedDir)
		return false, nil
	}

	// 1a. measure model
	err = stampedAction(fmt.Sprintf("%s-model-measured", recoverySystem), func() error {
		return secbootMeasureWhenPossible(func(tpm *secboot.TPM) error {
			model, err := mst.Model()
			if err != nil {
				return err
			}
			return secbootMeasureModel(tpm, model)
		})
	})
	if err != nil {
		return false, err
	}

	// 2. (auto) select recovery system for now
	isBaseMounted, err := osutilIsMounted(filepath.Join(boot.InitramfsRunMntDir, "base"))
	if err != nil {
		return false, err
	}
	isKernelMounted, err := osutilIsMounted(filepath.Join(boot.InitramfsRunMntDir, "kernel"))
	if err != nil {
		return false, err
	}
	isSnapdMounted, err := osutilIsMounted(filepath.Join(boot.InitramfsRunMntDir, "snapd"))
	if err != nil {
		return false, err
	}
	if !isBaseMounted || !isKernelMounted || !isSnapdMounted {
		// load the recovery system and generate mounts for kernel/base
		// and snapd
		var whichTypes []snap.Type
		if !isBaseMounted {
			whichTypes = append(whichTypes, snap.TypeBase)
		}
		if !isKernelMounted {
			whichTypes = append(whichTypes, snap.TypeKernel)
		}
		if !isSnapdMounted {
			whichTypes = append(whichTypes, snap.TypeSnapd)
		}
		essSnaps, err := mst.RecoverySystemEssentialSnaps("", whichTypes)
		if err != nil {
			return false, fmt.Errorf("cannot load metadata and verify essential bootstrap snaps %v: %v", whichTypes, err)
		}

		// TODO:UC20: do we need more cross checks here?
		for _, essentialSnap := range essSnaps {
			switch essentialSnap.EssentialType {
			case snap.TypeBase:
				fmt.Fprintf(stdout, "%s %s\n", essentialSnap.Path, filepath.Join(boot.InitramfsRunMntDir, "base"))
			case snap.TypeKernel:
				// TODO:UC20: we need to cross-check the kernel path with snapd_recovery_kernel used by grub
				fmt.Fprintf(stdout, "%s %s\n", essentialSnap.Path, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
			case snap.TypeSnapd:
				fmt.Fprintf(stdout, "%s %s\n", essentialSnap.Path, filepath.Join(boot.InitramfsRunMntDir, "snapd"))
			}
		}
	}

	// 3. mount "ubuntu-data" on a tmpfs
	isMounted, err = osutilIsMounted(boot.InitramfsUbuntuDataDir)
	if err != nil {
		return false, err
	}
	if !isMounted {
		fmt.Fprintf(stdout, "--type=tmpfs tmpfs /run/mnt/ubuntu-data\n")
		return false, nil
	}

	//    with mounting stuff
	return true, nil
}

func generateMountsModeRun(mst initramfsMountsState) error {
	// 1.1 always ensure basic partitions are mounted
	for _, d := range []string{boot.InitramfsUbuntuBootDir, boot.InitramfsUbuntuSeedDir} {
		isMounted, err := osutilIsMounted(d)
		if err != nil {
			return err
		}
		if !isMounted {
			// we need ubuntu-seed to be mounted before we can continue to
			// check ubuntu-data, so return if we need something mounted
			fmt.Fprintf(stdout, "/dev/disk/by-label/%s %s\n", filepath.Base(d), d)
			return nil
		}
	}

	// 1.1a measure model
	err := stampedAction("run-model-measured", func() error {
		return secbootMeasureWhenPossible(func(tpm *secboot.TPM) error {
			model, err := mst.UnverifiedBootModel()
			if err != nil {
				return err
			}
			return secbootMeasureModel(tpm, model)
		})
	})
	if err != nil {
		return err
	}
	// TODO:UC20: cross check the model we read from ubuntu-boot/model with
	// one recorded in ubuntu-data modeenv during install

	// 1.2 mount Data, and exit, as it needs to be mounted for us to do step 2
	isDataMounted, err := osutilIsMounted(boot.InitramfsUbuntuDataDir)
	if err != nil {
		return err
	}
	if !isDataMounted {
		const lockKeysForLast = true
		device, err := secbootUnlockIfEncrypted("ubuntu-data", lockKeysForLast)
		if err != nil {
			return err
		}

		fmt.Fprintf(stdout, "%s %s\n", device, boot.InitramfsUbuntuDataDir)
		return nil
	}

	// 2.1 read modeenv
	modeEnv, err := boot.ReadModeenv(boot.InitramfsWritableDir)
	if err != nil {
		return err
	}

	// 2.2.1 check if base is mounted
	isBaseMounted, err := osutilIsMounted(filepath.Join(boot.InitramfsRunMntDir, "base"))
	if err != nil {
		return err
	}
	if !isBaseMounted {
		// 2.2.2 use modeenv base_status and try_base to see  if we are trying
		// an update to the base snap
		base := modeEnv.Base
		if base == "" {
			// we have no fallback base!
			return fmt.Errorf("modeenv corrupt: missing base setting")
		}
		if modeEnv.BaseStatus == boot.TryStatus {
			// then we are trying a base snap update and there should be a
			// try_base set in the modeenv too
			if modeEnv.TryBase != "" {
				// check that the TryBase exists in ubuntu-data
				tryBaseSnapPath := filepath.Join(dirs.SnapBlobDirUnder(boot.InitramfsWritableDir), modeEnv.TryBase)
				if osutil.FileExists(tryBaseSnapPath) {
					// set the TryBase and have the initramfs mount this base
					// snap
					modeEnv.BaseStatus = boot.TryingStatus
					base = modeEnv.TryBase
				} else {
					logger.Noticef("try-base snap %q does not exist", modeEnv.TryBase)
				}
			} else {
				logger.Noticef("try-base snap is empty, but \"base_status\" is \"trying\"")
			}
			// TODO:UC20: log a message if try_base is unset here?
		} else if modeEnv.BaseStatus == boot.TryingStatus {
			// snapd failed to start with the base snap update, so we need to
			// fallback to the old base snap and clear base_status
			modeEnv.BaseStatus = boot.DefaultStatus
		} else if modeEnv.BaseStatus != boot.DefaultStatus {
			logger.Noticef("\"base_status\" has an invalid setting: %q", modeEnv.BaseStatus)
		}

		baseSnapPath := filepath.Join(dirs.SnapBlobDirUnder(boot.InitramfsWritableDir), base)
		fmt.Fprintf(stdout, "%s %s\n", baseSnapPath, filepath.Join(boot.InitramfsRunMntDir, "base"))
	}

	// 2.3.1 check if the kernel is mounted
	isKernelMounted, err := osutilIsMounted(filepath.Join(boot.InitramfsRunMntDir, "kernel"))
	if err != nil {
		return err
	}
	if !isKernelMounted {
		// make a map to easily check if a kernel snap is valid or not
		validKernels := make(map[string]bool, len(modeEnv.CurrentKernels))
		for _, validKernel := range modeEnv.CurrentKernels {
			validKernels[validKernel] = true
		}

		// find ubuntu-boot bootloader to get the kernel_status and kernel.efi
		// status so we can determine the right kernel snap to have mounted

		// TODO:UC20: should all this logic move to boot package? feels awfully
		// similar to the logic in revisions() for bootState20

		// At this point the run mode bootloader is under the native
		// layout, no /boot mount.
		opts := &bootloader.Options{NoSlashBoot: true}
		bl, err := bootloader.Find(boot.InitramfsUbuntuBootDir, opts)
		if err != nil {
			return fmt.Errorf("internal error: cannot find run system bootloader: %v", err)
		}

		var kern, tryKern snap.PlaceInfo
		var kernStatus string

		ebl, ok := bl.(bootloader.ExtractedRunKernelImageBootloader)
		if ok {
			// use ebl methods
			kern, err = ebl.Kernel()
			if err != nil {
				return fmt.Errorf("no fallback kernel snap: %v", err)
			}

			tryKern, err = ebl.TryKernel()
			if err != nil && err != bootloader.ErrNoTryKernelRef {
				return err
			}

			m, err := ebl.GetBootVars("kernel_status")
			if err != nil {
				return fmt.Errorf("cannot get kernel_status from bootloader %s", ebl.Name())
			}

			kernStatus = m["kernel_status"]
		} else {
			// use the bootenv
			m, err := bl.GetBootVars("snap_kernel", "snap_try_kernel", "kernel_status")
			if err != nil {
				return err
			}
			kern, err = snap.ParsePlaceInfoFromSnapFileName(m["snap_kernel"])
			if err != nil {
				return fmt.Errorf("no fallback kernel snap: %v", err)
			}

			// only try to parse snap_try_kernel if it is set
			if m["snap_try_kernel"] != "" {
				tryKern, err = snap.ParsePlaceInfoFromSnapFileName(m["snap_try_kernel"])
				if err != nil {
					logger.Noticef("try-kernel setting is invalid: %v", err)
				}
			}

			kernStatus = m["kernel_status"]
		}

		kernelFile := kern.Filename()
		if !validKernels[kernelFile] {
			// we don't trust the fallback kernel!
			return fmt.Errorf("fallback kernel snap %q is not trusted in the modeenv", kernelFile)
		}

		if kernStatus == boot.TryingStatus {
			// check for the try kernel
			if tryKern != nil {
				tryKernelFile := tryKern.Filename()
				if validKernels[tryKernelFile] {
					kernelFile = tryKernelFile
				} else {
					logger.Noticef("try-kernel %q is not trusted in the modeenv", tryKernelFile)
				}
			} else {
				logger.Noticef("missing try-kernel, even though \"kernel_status\" is \"trying\"")
			}

			// TODO:UC20: actually we really shouldn't be falling back here at
			//            all - if the kernel we booted isn't mountable in the
			//            initramfs, we should trigger a reboot so that we boot
			//            the fallback kernel and then mount that one
		}

		kernelPath := filepath.Join(dirs.SnapBlobDirUnder(boot.InitramfsWritableDir), kernelFile)
		fmt.Fprintf(stdout, "%s %s\n", kernelPath, filepath.Join(boot.InitramfsRunMntDir, "kernel"))
	}

	// 3.1 Maybe mount the snapd snap on first boot of run-mode
	// TODO:UC20: Make RecoverySystem empty after successful first boot
	// somewhere in devicestate
	if modeEnv.RecoverySystem != "" {
		isSnapdMounted, err := osutilIsMounted(filepath.Join(boot.InitramfsRunMntDir, "snapd"))
		if err != nil {
			return err
		}

		if !isSnapdMounted {
			// load the recovery system and generate mount for snapd
			essSnaps, err := mst.RecoverySystemEssentialSnaps(modeEnv.RecoverySystem, []snap.Type{snap.TypeSnapd})
			if err != nil {
				return fmt.Errorf("cannot load metadata and verify snapd snap: %v", err)
			}
			fmt.Fprintf(stdout, "%s %s\n", essSnaps[0].Path, filepath.Join(boot.InitramfsRunMntDir, "snapd"))
		}
	}

	// 4.1 Write the modeenv out again
	return modeEnv.Write()
}

func stampedAction(stamp string, action func() error) error {
	stampFile := filepath.Join(dirs.SnapBootstrapRunDir, stamp)
	if osutil.FileExists(stampFile) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(stampFile), 0755); err != nil {
		return err
	}
	if err := action(); err != nil {
		return err
	}
	return ioutil.WriteFile(stampFile, nil, 0644)
}

func generateInitramfsMounts() error {
	// Ensure there is a very early initial measurement
	err := stampedAction("secboot-epoch-measured", func() error {
		return secbootMeasureWhenPossible(secbootMeasureEpoch)
	})
	if err != nil {
		return err
	}

	mode, recoverySystem, err := boot.ModeAndRecoverySystemFromKernelCommandLine()
	if err != nil {
		return err
	}

	mst := newInitramfsMountsState(mode, recoverySystem)

	switch mode {
	case "recover":
		// XXX: don't pass both args
		return generateMountsModeRecover(mst, recoverySystem)
	case "install":
		// XXX: don't pass both args
		return generateMountsModeInstall(mst, recoverySystem)
	case "run":
		return generateMountsModeRun(mst)
	}
	// this should never be reached
	return fmt.Errorf("internal error: mode in generateInitramfsMounts not handled")
}
