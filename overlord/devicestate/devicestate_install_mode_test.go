// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package devicestate_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"
	"gopkg.in/tomb.v2"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/bootloader/bootloadertest"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/gadget"
	"github.com/snapcore/snapd/gadget/install"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/devicestate"
	"github.com/snapcore/snapd/overlord/devicestate/devicestatetest"
	"github.com/snapcore/snapd/overlord/hookstate"
	"github.com/snapcore/snapd/overlord/hookstate/ctlcmd"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/snapstate/snapstatetest"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/secboot"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/sysconfig"
	"github.com/snapcore/snapd/testutil"
)

type deviceMgrInstallModeSuite struct {
	deviceMgrBaseSuite

	ConfigureTargetSystemOptsPassed []*sysconfig.Options
	ConfigureTargetSystemErr        error
}

var _ = Suite(&deviceMgrInstallModeSuite{})

func (s *deviceMgrInstallModeSuite) findInstallSystem() *state.Change {
	for _, chg := range s.state.Changes() {
		if chg.Kind() == "install-system" {
			return chg
		}
	}
	return nil
}

func (s *deviceMgrInstallModeSuite) SetUpTest(c *C) {
	s.deviceMgrBaseSuite.SetUpTest(c)

	s.ConfigureTargetSystemOptsPassed = nil
	s.ConfigureTargetSystemErr = nil
	restore := devicestate.MockSysconfigConfigureTargetSystem(func(mod *asserts.Model, opts *sysconfig.Options) error {
		c.Check(mod, NotNil)
		s.ConfigureTargetSystemOptsPassed = append(s.ConfigureTargetSystemOptsPassed, opts)
		return s.ConfigureTargetSystemErr
	})
	s.AddCleanup(restore)

	restore = devicestate.MockSecbootCheckTPMKeySealingSupported(func() error {
		return fmt.Errorf("TPM not available")
	})
	s.AddCleanup(restore)

	s.state.Lock()
	defer s.state.Unlock()
	s.state.Set("seeded", true)

	fakeJournalctl := testutil.MockCommand(c, "journalctl", "")
	s.AddCleanup(fakeJournalctl.Restore)
}

const (
	pcSnapID       = "pcididididididididididididididid"
	pcKernelSnapID = "pckernelidididididididididididid"
	core20SnapID   = "core20ididididididididididididid"
)

func (s *deviceMgrInstallModeSuite) makeMockInstalledPcGadget(c *C, grade, installDeviceHook string, gadgetDefaultsYaml string) *asserts.Model {
	si := &snap.SideInfo{
		RealName: "pc-kernel",
		Revision: snap.R(1),
		SnapID:   pcKernelSnapID,
	}
	snapstate.Set(s.state, "pc-kernel", &snapstate.SnapState{
		SnapType: "kernel",
		Sequence: []*snap.SideInfo{si},
		Current:  si.Revision,
		Active:   true,
	})
	kernelInfo := snaptest.MockSnapWithFiles(c, "name: pc-kernel\ntype: kernel", si, nil)
	kernelFn := snaptest.MakeTestSnapWithFiles(c, "name: pc-kernel\ntype: kernel\nversion: 1.0", nil)
	err := os.Rename(kernelFn, kernelInfo.MountFile())
	c.Assert(err, IsNil)

	si = &snap.SideInfo{
		RealName: "pc",
		Revision: snap.R(1),
		SnapID:   pcSnapID,
	}
	snapstate.Set(s.state, "pc", &snapstate.SnapState{
		SnapType: "gadget",
		Sequence: []*snap.SideInfo{si},
		Current:  si.Revision,
		Active:   true,
	})

	files := [][]string{
		{"meta/gadget.yaml", uc20gadgetYamlWithSave + gadgetDefaultsYaml},
	}
	if installDeviceHook != "" {
		files = append(files, []string{"meta/hooks/install-device", installDeviceHook})
	}
	snaptest.MockSnapWithFiles(c, "name: pc\ntype: gadget", si, files)

	si = &snap.SideInfo{
		RealName: "core20",
		Revision: snap.R(2),
		SnapID:   core20SnapID,
	}
	snapstate.Set(s.state, "core20", &snapstate.SnapState{
		SnapType: "base",
		Sequence: []*snap.SideInfo{si},
		Current:  si.Revision,
		Active:   true,
	})
	snaptest.MockSnapWithFiles(c, "name: core20\ntype: base", si, nil)

	mockModel := s.makeModelAssertionInState(c, "my-brand", "my-model", map[string]interface{}{
		"display-name": "my model",
		"architecture": "amd64",
		"base":         "core20",
		"grade":        grade,
		"snaps": []interface{}{
			map[string]interface{}{
				"name":            "pc-kernel",
				"id":              pcKernelSnapID,
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]interface{}{
				"name":            "pc",
				"id":              pcSnapID,
				"type":            "gadget",
				"default-channel": "20",
			}},
	})
	devicestatetest.SetDevice(s.state, &auth.DeviceState{
		Brand: "my-brand",
		Model: "my-model",
		// no serial in install mode
	})

	return mockModel
}

type encTestCase struct {
	tpm               bool
	bypass            bool
	encrypt           bool
	trustedBootloader bool
}

var (
	dataEncryptionKey = secboot.EncryptionKey{'d', 'a', 't', 'a', 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	dataRecoveryKey   = secboot.RecoveryKey{'r', 'e', 'c', 'o', 'v', 'e', 'r', 'y', 10, 11, 12, 13, 14, 15, 16, 17}

	saveKey      = secboot.EncryptionKey{'s', 'a', 'v', 'e', 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	reinstallKey = secboot.RecoveryKey{'r', 'e', 'i', 'n', 's', 't', 'a', 'l', 'l', 11, 12, 13, 14, 15, 16, 17}
)

func (s *deviceMgrInstallModeSuite) doRunChangeTestWithEncryption(c *C, grade string, tc encTestCase) error {
	restore := release.MockOnClassic(false)
	defer restore()
	bootloaderRootdir := c.MkDir()

	var brGadgetRoot, brDevice string
	var brOpts install.Options
	var installRunCalled int
	var installSealingObserver gadget.ContentObserver
	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, obs gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		// ensure we can grab the lock here, i.e. that it's not taken
		s.state.Lock()
		s.state.Unlock()

		c.Check(mod.Grade(), Equals, asserts.ModelGrade(grade))

		brGadgetRoot = gadgetRoot
		brDevice = device
		brOpts = options
		installSealingObserver = obs
		installRunCalled++
		var keysForRoles map[string]*install.EncryptionKeySet
		if tc.encrypt {
			keysForRoles = map[string]*install.EncryptionKeySet{
				gadget.SystemData: {
					Key:         dataEncryptionKey,
					RecoveryKey: dataRecoveryKey,
				},
				gadget.SystemSave: {
					Key:         saveKey,
					RecoveryKey: reinstallKey,
				},
			}
		}
		return &install.InstalledSystemSideData{
			KeysForRoles: keysForRoles,
		}, nil
	})
	defer restore()

	restore = devicestate.MockSecbootCheckTPMKeySealingSupported(func() error {
		if tc.tpm {
			return nil
		} else {
			return fmt.Errorf("TPM not available")
		}
	})
	defer restore()

	if tc.trustedBootloader {
		tab := bootloadertest.Mock("trusted", bootloaderRootdir).WithTrustedAssets()
		tab.TrustedAssetsList = []string{"trusted-asset"}
		bootloader.Force(tab)
		s.AddCleanup(func() { bootloader.Force(nil) })

		err := os.MkdirAll(boot.InitramfsUbuntuSeedDir, 0755)
		c.Assert(err, IsNil)
		err = ioutil.WriteFile(filepath.Join(boot.InitramfsUbuntuSeedDir, "trusted-asset"), nil, 0644)
		c.Assert(err, IsNil)
	}

	s.state.Lock()
	mockModel := s.makeMockInstalledPcGadget(c, grade, "", "")
	s.state.Unlock()

	bypassEncryptionPath := filepath.Join(boot.InitramfsUbuntuSeedDir, ".force-unencrypted")
	if tc.bypass {
		err := os.MkdirAll(filepath.Dir(bypassEncryptionPath), 0755)
		c.Assert(err, IsNil)
		f, err := os.Create(bypassEncryptionPath)
		c.Assert(err, IsNil)
		f.Close()
	} else {
		os.RemoveAll(bypassEncryptionPath)
	}

	bootMakeBootableCalled := 0
	restore = devicestate.MockBootMakeSystemRunnable(func(model *asserts.Model, bootWith *boot.BootableSet, seal *boot.TrustedAssetsInstallObserver) error {
		c.Check(model, DeepEquals, mockModel)
		c.Check(bootWith.KernelPath, Matches, ".*/var/lib/snapd/snaps/pc-kernel_1.snap")
		c.Check(bootWith.BasePath, Matches, ".*/var/lib/snapd/snaps/core20_2.snap")
		c.Check(bootWith.RecoverySystemDir, Matches, "/systems/20191218")
		c.Check(bootWith.UnpackedGadgetDir, Equals, filepath.Join(dirs.SnapMountDir, "pc/1"))
		if tc.encrypt {
			c.Check(seal, NotNil)
		} else {
			c.Check(seal, IsNil)
		}
		bootMakeBootableCalled++
		return nil
	})
	defer restore()

	modeenv := boot.Modeenv{
		Mode:           "install",
		RecoverySystem: "20191218",
	}
	c.Assert(modeenv.WriteTo(""), IsNil)
	devicestate.SetSystemMode(s.mgr, "install")

	// normally done by snap-bootstrap
	err := os.MkdirAll(boot.InitramfsUbuntuBootDir, 0755)
	c.Assert(err, IsNil)

	s.settle(c)

	// the install-system change is created
	s.state.Lock()
	defer s.state.Unlock()
	installSystem := s.findInstallSystem()
	c.Assert(installSystem, NotNil)

	// and was run successfully
	if err := installSystem.Err(); err != nil {
		// we failed, no further checks needed
		return err
	}

	c.Assert(installSystem.Status(), Equals, state.DoneStatus)

	// in the right way
	c.Assert(brGadgetRoot, Equals, filepath.Join(dirs.SnapMountDir, "/pc/1"))
	c.Assert(brDevice, Equals, "")
	if tc.encrypt {
		c.Assert(brOpts, DeepEquals, install.Options{
			Mount:   true,
			Encrypt: true,
		})
	} else {
		c.Assert(brOpts, DeepEquals, install.Options{
			Mount: true,
		})
	}
	if tc.encrypt {
		// inteface is not nil
		c.Assert(installSealingObserver, NotNil)
		// we expect a very specific type
		trustedInstallObserver, ok := installSealingObserver.(*boot.TrustedAssetsInstallObserver)
		c.Assert(ok, Equals, true, Commentf("unexpected type: %T", installSealingObserver))
		c.Assert(trustedInstallObserver, NotNil)
	} else {
		c.Assert(installSealingObserver, IsNil)
	}

	c.Assert(installRunCalled, Equals, 1)
	c.Assert(bootMakeBootableCalled, Equals, 1)
	c.Assert(s.restartRequests, DeepEquals, []state.RestartType{state.RestartSystemNow})

	return nil
}

func (s *deviceMgrInstallModeSuite) TestInstallTaskErrors(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		return nil, fmt.Errorf("The horror, The horror")
	})
	defer restore()

	err := ioutil.WriteFile(filepath.Join(dirs.GlobalRootDir, "/var/lib/snapd/modeenv"),
		[]byte("mode=install\n"), 0644)
	c.Assert(err, IsNil)

	s.state.Lock()
	s.makeMockInstalledPcGadget(c, "dangerous", "", "")
	devicestate.SetSystemMode(s.mgr, "install")
	s.state.Unlock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), ErrorMatches, `(?ms)cannot perform the following tasks:
- Setup system for run mode \(cannot install system: The horror, The horror\)`)
	// no restart request on failure
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrInstallModeSuite) TestInstallExpTasks(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		return nil, nil
	})
	defer restore()

	err := ioutil.WriteFile(filepath.Join(dirs.GlobalRootDir, "/var/lib/snapd/modeenv"),
		[]byte("mode=install\n"), 0644)
	c.Assert(err, IsNil)

	s.state.Lock()
	s.makeMockInstalledPcGadget(c, "dangerous", "", "")
	devicestate.SetSystemMode(s.mgr, "install")
	s.state.Unlock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), IsNil)

	tasks := installSystem.Tasks()
	c.Assert(tasks, HasLen, 2)
	setupRunSystemTask := tasks[0]
	restartSystemToRunModeTask := tasks[1]

	c.Assert(setupRunSystemTask.Kind(), Equals, "setup-run-system")
	c.Assert(restartSystemToRunModeTask.Kind(), Equals, "restart-system-to-run-mode")

	// setup-run-system has no pre-reqs
	c.Assert(setupRunSystemTask.WaitTasks(), HasLen, 0)

	// restart-system-to-run-mode has a pre-req of setup-run-system
	waitTasks := restartSystemToRunModeTask.WaitTasks()
	c.Assert(waitTasks, HasLen, 1)
	c.Assert(waitTasks[0].ID(), Equals, setupRunSystemTask.ID())

	// we did request a restart through restartSystemToRunModeTask
	c.Check(s.restartRequests, DeepEquals, []state.RestartType{state.RestartSystemNow})
}

func (s *deviceMgrInstallModeSuite) TestInstallWithInstallDeviceHookExpTasks(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		return nil, nil
	})
	defer restore()

	hooksCalled := []*hookstate.Context{}
	restore = hookstate.MockRunHook(func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
		ctx.Lock()
		defer ctx.Unlock()

		hooksCalled = append(hooksCalled, ctx)
		return nil, nil
	})
	defer restore()

	err := ioutil.WriteFile(filepath.Join(dirs.GlobalRootDir, "/var/lib/snapd/modeenv"),
		[]byte("mode=install\n"), 0644)
	c.Assert(err, IsNil)

	s.state.Lock()
	s.makeMockInstalledPcGadget(c, "dangerous", "install-device-hook-content", "")
	devicestate.SetSystemMode(s.mgr, "install")
	s.state.Unlock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), IsNil)

	tasks := installSystem.Tasks()
	c.Assert(tasks, HasLen, 3)
	setupRunSystemTask := tasks[0]
	installDevice := tasks[1]
	restartSystemToRunModeTask := tasks[2]

	c.Assert(setupRunSystemTask.Kind(), Equals, "setup-run-system")
	c.Assert(restartSystemToRunModeTask.Kind(), Equals, "restart-system-to-run-mode")
	c.Assert(installDevice.Kind(), Equals, "run-hook")

	// setup-run-system has no pre-reqs
	c.Assert(setupRunSystemTask.WaitTasks(), HasLen, 0)

	// install-device has a pre-req of setup-run-system
	waitTasks := installDevice.WaitTasks()
	c.Assert(waitTasks, HasLen, 1)
	c.Assert(waitTasks[0].ID(), Equals, setupRunSystemTask.ID())

	// install-device restart-task references to restart-system-to-run-mode
	var restartTask string
	err = installDevice.Get("restart-task", &restartTask)
	c.Assert(err, IsNil)
	c.Check(restartTask, Equals, restartSystemToRunModeTask.ID())

	// restart-system-to-run-mode has a pre-req of install-device
	waitTasks = restartSystemToRunModeTask.WaitTasks()
	c.Assert(waitTasks, HasLen, 1)
	c.Assert(waitTasks[0].ID(), Equals, installDevice.ID())

	// we did request a restart through restartSystemToRunModeTask
	c.Check(s.restartRequests, DeepEquals, []state.RestartType{state.RestartSystemNow})

	c.Assert(hooksCalled, HasLen, 1)
	c.Assert(hooksCalled[0].HookName(), Equals, "install-device")
}

func (s *deviceMgrInstallModeSuite) testInstallWithInstallDeviceHookSnapctlReboot(c *C, arg string, rst state.RestartType) {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		return nil, nil
	})
	defer restore()

	restore = hookstate.MockRunHook(func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
		c.Assert(ctx.HookName(), Equals, "install-device")

		// snapctl reboot --halt
		_, _, err := ctlcmd.Run(ctx, []string{"reboot", arg}, 0)
		return nil, err
	})
	defer restore()

	err := ioutil.WriteFile(filepath.Join(dirs.GlobalRootDir, "/var/lib/snapd/modeenv"),
		[]byte("mode=install\n"), 0644)
	c.Assert(err, IsNil)

	s.state.Lock()
	s.makeMockInstalledPcGadget(c, "dangerous", "install-device-hook-content", "")
	devicestate.SetSystemMode(s.mgr, "install")
	s.state.Unlock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), IsNil)

	// we did end up requesting the right shutdown
	c.Check(s.restartRequests, DeepEquals, []state.RestartType{rst})
}

func (s *deviceMgrInstallModeSuite) TestInstallWithInstallDeviceHookSnapctlRebootHalt(c *C) {
	s.testInstallWithInstallDeviceHookSnapctlReboot(c, "--halt", state.RestartSystemHaltNow)
}

func (s *deviceMgrInstallModeSuite) TestInstallWithInstallDeviceHookSnapctlRebootPoweroff(c *C) {
	s.testInstallWithInstallDeviceHookSnapctlReboot(c, "--poweroff", state.RestartSystemPoweroffNow)
}

func (s *deviceMgrInstallModeSuite) TestInstallWithBrokenInstallDeviceHookUnhappy(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		return nil, nil
	})
	defer restore()

	hooksCalled := []*hookstate.Context{}
	restore = hookstate.MockRunHook(func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
		ctx.Lock()
		defer ctx.Unlock()

		hooksCalled = append(hooksCalled, ctx)
		return []byte("hook exited broken"), fmt.Errorf("hook broken")
	})
	defer restore()

	err := ioutil.WriteFile(filepath.Join(dirs.GlobalRootDir, "/var/lib/snapd/modeenv"),
		[]byte("mode=install\n"), 0644)
	c.Assert(err, IsNil)

	s.state.Lock()
	s.makeMockInstalledPcGadget(c, "dangerous", "install-device-hook-content", "")
	devicestate.SetSystemMode(s.mgr, "install")
	s.state.Unlock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), ErrorMatches, `cannot perform the following tasks:
- Run install-device hook \(run hook \"install-device\": hook exited broken\)`)

	tasks := installSystem.Tasks()
	c.Assert(tasks, HasLen, 3)
	setupRunSystemTask := tasks[0]
	installDevice := tasks[1]
	restartSystemToRunModeTask := tasks[2]

	c.Assert(setupRunSystemTask.Kind(), Equals, "setup-run-system")
	c.Assert(installDevice.Kind(), Equals, "run-hook")
	c.Assert(restartSystemToRunModeTask.Kind(), Equals, "restart-system-to-run-mode")

	// install-device is in Error state
	c.Assert(installDevice.Status(), Equals, state.ErrorStatus)

	// setup-run-system is in Done (it has no undo handler)
	c.Assert(setupRunSystemTask.Status(), Equals, state.DoneStatus)

	// restart-system-to-run-mode is in Hold
	c.Assert(restartSystemToRunModeTask.Status(), Equals, state.HoldStatus)

	// we didn't request a restart since restartsystemToRunMode didn't run
	c.Check(s.restartRequests, HasLen, 0)

	c.Assert(hooksCalled, HasLen, 1)
	c.Assert(hooksCalled[0].HookName(), Equals, "install-device")
}

func (s *deviceMgrInstallModeSuite) TestInstallSetupRunSystemTaskNoRestarts(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		return nil, nil
	})
	defer restore()

	err := ioutil.WriteFile(filepath.Join(dirs.GlobalRootDir, "/var/lib/snapd/modeenv"),
		[]byte("mode=install\n"), 0644)
	c.Assert(err, IsNil)

	s.state.Lock()
	defer s.state.Unlock()

	s.makeMockInstalledPcGadget(c, "dangerous", "", "")
	devicestate.SetSystemMode(s.mgr, "install")

	// also set the system as installed so that the install-system change
	// doesn't get automatically added and we can craft our own change with just
	// the setup-run-system task and not with the restart-system-to-run-mode
	// task
	devicestate.SetInstalledRan(s.mgr, true)

	s.state.Unlock()
	defer s.state.Lock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	// make sure there is no install-system change that snuck in underneath us
	installSystem := s.findInstallSystem()
	c.Check(installSystem, IsNil)

	t := s.state.NewTask("setup-run-system", "setup run system")
	chg := s.state.NewChange("install-system", "install the system")
	chg.AddTask(t)

	// now let the change run
	s.state.Unlock()
	defer s.state.Lock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	// now we should have the install-system change
	installSystem = s.findInstallSystem()
	c.Check(installSystem, Not(IsNil))
	c.Check(installSystem.Err(), IsNil)

	tasks := installSystem.Tasks()
	c.Assert(tasks, HasLen, 1)
	setupRunSystemTask := tasks[0]

	c.Assert(setupRunSystemTask.Kind(), Equals, "setup-run-system")

	// we did not request a restart (since that is done in restart-system-to-run-mode)
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrInstallModeSuite) TestInstallModeNotInstallmodeNoChg(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	s.state.Lock()
	devicestate.SetSystemMode(s.mgr, "")
	s.state.Unlock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	// the install-system change is *not* created (not in install mode)
	installSystem := s.findInstallSystem()
	c.Assert(installSystem, IsNil)
}

func (s *deviceMgrInstallModeSuite) TestInstallModeNotClassic(c *C) {
	restore := release.MockOnClassic(true)
	defer restore()

	s.state.Lock()
	devicestate.SetSystemMode(s.mgr, "install")
	s.state.Unlock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	// the install-system change is *not* created (we're on classic)
	installSystem := s.findInstallSystem()
	c.Assert(installSystem, IsNil)
}

func (s *deviceMgrInstallModeSuite) TestInstallDangerous(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "dangerous", encTestCase{tpm: false, bypass: false, encrypt: false})
	c.Assert(err, IsNil)
}

func (s *deviceMgrInstallModeSuite) TestInstallDangerousWithTPM(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "dangerous", encTestCase{
		tpm: true, bypass: false, encrypt: true, trustedBootloader: true,
	})
	c.Assert(err, IsNil)
	c.Check(filepath.Join(boot.InstallHostFDEDataDir, "recovery.key"), testutil.FileEquals, dataRecoveryKey[:])
}

func (s *deviceMgrInstallModeSuite) TestInstallDangerousBypassEncryption(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "dangerous", encTestCase{tpm: false, bypass: true, encrypt: false})
	c.Assert(err, IsNil)
}

func (s *deviceMgrInstallModeSuite) TestInstallDangerousWithTPMBypassEncryption(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "dangerous", encTestCase{tpm: true, bypass: true, encrypt: false})
	c.Assert(err, IsNil)
}

func (s *deviceMgrInstallModeSuite) TestInstallSigned(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "signed", encTestCase{tpm: false, bypass: false, encrypt: false})
	c.Assert(err, IsNil)
}

func (s *deviceMgrInstallModeSuite) TestInstallSignedWithTPM(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "signed", encTestCase{
		tpm: true, bypass: false, encrypt: true, trustedBootloader: true,
	})
	c.Assert(err, IsNil)
	c.Check(filepath.Join(boot.InstallHostFDEDataDir, "recovery.key"), testutil.FileEquals, dataRecoveryKey[:])
}

func (s *deviceMgrInstallModeSuite) TestInstallSignedBypassEncryption(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "signed", encTestCase{tpm: false, bypass: true, encrypt: false})
	c.Assert(err, IsNil)
}

func (s *deviceMgrInstallModeSuite) TestInstallSecured(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "secured", encTestCase{tpm: false, bypass: false, encrypt: false})
	c.Assert(err, ErrorMatches, "(?s).*cannot encrypt device storage as mandated by model grade secured:.*TPM not available.*")
}

func (s *deviceMgrInstallModeSuite) TestInstallSecuredWithTPM(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "secured", encTestCase{
		tpm: true, bypass: false, encrypt: true, trustedBootloader: true,
	})
	c.Assert(err, IsNil)
	c.Check(filepath.Join(boot.InstallHostFDEDataDir, "recovery.key"), testutil.FileEquals, dataRecoveryKey[:])
}

func (s *deviceMgrInstallModeSuite) TestInstallDangerousEncryptionWithTPMNoTrustedAssets(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "dangerous", encTestCase{
		tpm: true, bypass: false, encrypt: true, trustedBootloader: false,
	})
	c.Assert(err, IsNil)
	c.Check(filepath.Join(boot.InstallHostFDEDataDir, "recovery.key"), testutil.FileEquals, dataRecoveryKey[:])
}

func (s *deviceMgrInstallModeSuite) TestInstallDangerousNoEncryptionWithTrustedAssets(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "dangerous", encTestCase{
		tpm: false, bypass: false, encrypt: false, trustedBootloader: true,
	})
	c.Assert(err, IsNil)
}

func (s *deviceMgrInstallModeSuite) TestInstallSecuredWithTPMAndSave(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "secured", encTestCase{
		tpm: true, bypass: false, encrypt: true, trustedBootloader: true,
	})
	c.Assert(err, IsNil)
	c.Check(filepath.Join(boot.InstallHostFDEDataDir, "recovery.key"), testutil.FileEquals, dataRecoveryKey[:])
	c.Check(filepath.Join(boot.InstallHostFDEDataDir, "ubuntu-save.key"), testutil.FileEquals, []byte(saveKey))
	c.Check(filepath.Join(boot.InstallHostFDEDataDir, "reinstall.key"), testutil.FileEquals, reinstallKey[:])
	marker, err := ioutil.ReadFile(filepath.Join(boot.InstallHostFDEDataDir, "marker"))
	c.Assert(err, IsNil)
	c.Check(marker, HasLen, 32)
	c.Check(filepath.Join(boot.InstallHostFDESaveDir, "marker"), testutil.FileEquals, marker)
}

func (s *deviceMgrInstallModeSuite) TestInstallSecuredBypassEncryption(c *C) {
	err := s.doRunChangeTestWithEncryption(c, "secured", encTestCase{tpm: false, bypass: true, encrypt: false})
	c.Assert(err, ErrorMatches, "(?s).*cannot encrypt device storage as mandated by model grade secured:.*TPM not available.*")
}

func (s *deviceMgrInstallModeSuite) TestInstallBootloaderVarSetFails(c *C) {
	restore := devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		c.Check(options.Encrypt, Equals, false)
		// no keys set
		return &install.InstalledSystemSideData{}, nil
	})
	defer restore()

	restore = devicestate.MockBootEnsureNextBootToRunMode(func(systemLabel string) error {
		c.Check(systemLabel, Equals, "1234")
		// no keys set
		return fmt.Errorf("bootloader goes boom")
	})
	defer restore()

	restore = devicestate.MockSecbootCheckTPMKeySealingSupported(func() error { return fmt.Errorf("no encrypted soup for you") })
	defer restore()

	err := ioutil.WriteFile(filepath.Join(dirs.GlobalRootDir, "/var/lib/snapd/modeenv"),
		[]byte("mode=install\nrecovery_system=1234"), 0644)
	c.Assert(err, IsNil)

	s.state.Lock()
	s.makeMockInstalledPcGadget(c, "dangerous", "", "")
	devicestate.SetSystemMode(s.mgr, "install")
	s.state.Unlock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), ErrorMatches, `cannot perform the following tasks:
- Ensure next boot to run mode \(bootloader goes boom\)`)
	// no restart request on failure
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrInstallModeSuite) testInstallEncryptionSanityChecks(c *C, errMatch string) {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockSecbootCheckTPMKeySealingSupported(func() error { return nil })
	defer restore()

	err := ioutil.WriteFile(filepath.Join(dirs.GlobalRootDir, "/var/lib/snapd/modeenv"),
		[]byte("mode=install\n"), 0644)
	c.Assert(err, IsNil)

	s.state.Lock()
	s.makeMockInstalledPcGadget(c, "dangerous", "", "")
	devicestate.SetSystemMode(s.mgr, "install")
	s.state.Unlock()

	s.settle(c)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), ErrorMatches, errMatch)
	// no restart request on failure
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrInstallModeSuite) TestInstallEncryptionSanityChecksNoKeys(c *C) {
	restore := devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		c.Check(options.Encrypt, Equals, true)
		// no keys set
		return &install.InstalledSystemSideData{}, nil
	})
	defer restore()
	s.testInstallEncryptionSanityChecks(c, `(?ms)cannot perform the following tasks:
- Setup system for run mode \(internal error: system encryption keys are unset\)`)
}

func (s *deviceMgrInstallModeSuite) TestInstallEncryptionSanityChecksNoSystemDataKey(c *C) {
	restore := devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		c.Check(options.Encrypt, Equals, true)
		// no keys set
		return &install.InstalledSystemSideData{
			// empty map
			KeysForRoles: map[string]*install.EncryptionKeySet{},
		}, nil
	})
	defer restore()
	s.testInstallEncryptionSanityChecks(c, `(?ms)cannot perform the following tasks:
- Setup system for run mode \(internal error: system encryption keys are unset\)`)
}

func (s *deviceMgrInstallModeSuite) mockInstallModeChange(c *C, modelGrade, gadgetDefaultsYaml string) *asserts.Model {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		return nil, nil
	})
	defer restore()

	s.state.Lock()
	mockModel := s.makeMockInstalledPcGadget(c, modelGrade, "", gadgetDefaultsYaml)
	s.state.Unlock()
	c.Check(mockModel.Grade(), Equals, asserts.ModelGrade(modelGrade))

	restore = devicestate.MockBootMakeSystemRunnable(func(model *asserts.Model, bootWith *boot.BootableSet, seal *boot.TrustedAssetsInstallObserver) error {
		return nil
	})
	defer restore()

	modeenv := boot.Modeenv{
		Mode:           "install",
		RecoverySystem: "20191218",
	}
	c.Assert(modeenv.WriteTo(""), IsNil)
	devicestate.SetSystemMode(s.mgr, "install")

	// normally done by snap-bootstrap
	err := os.MkdirAll(boot.InitramfsUbuntuBootDir, 0755)
	c.Assert(err, IsNil)

	s.settle(c)

	return mockModel
}

func (s *deviceMgrInstallModeSuite) TestInstallModeRunSysconfig(c *C) {
	s.mockInstallModeChange(c, "dangerous", "")

	s.state.Lock()
	defer s.state.Unlock()

	// the install-system change is created
	installSystem := s.findInstallSystem()
	c.Assert(installSystem, NotNil)

	// and was run successfully
	c.Check(installSystem.Err(), IsNil)
	c.Check(installSystem.Status(), Equals, state.DoneStatus)

	// and sysconfig.ConfigureTargetSystem was run exactly once
	c.Assert(s.ConfigureTargetSystemOptsPassed, DeepEquals, []*sysconfig.Options{
		{
			AllowCloudInit: true,
			TargetRootDir:  boot.InstallHostWritableDir,
			GadgetDir:      filepath.Join(dirs.SnapMountDir, "pc/1/"),
		},
	})

	// and the special dirs in _writable_defaults were created
	for _, dir := range []string{"/etc/udev/rules.d/", "/etc/modules-load.d/", "/etc/modprobe.d/"} {
		fullDir := filepath.Join(sysconfig.WritableDefaultsDir(boot.InstallHostWritableDir), dir)
		c.Assert(fullDir, testutil.FilePresent)
	}
}

func (s *deviceMgrInstallModeSuite) TestInstallModeRunSysconfigErr(c *C) {
	s.ConfigureTargetSystemErr = fmt.Errorf("error from sysconfig.ConfigureTargetSystem")
	s.mockInstallModeChange(c, "dangerous", "")

	s.state.Lock()
	defer s.state.Unlock()

	// the install-system was run but errorred as specified in the above mock
	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), ErrorMatches, `(?ms)cannot perform the following tasks:
- Setup system for run mode \(error from sysconfig.ConfigureTargetSystem\)`)
	// and sysconfig.ConfigureTargetSystem was run exactly once
	c.Assert(s.ConfigureTargetSystemOptsPassed, DeepEquals, []*sysconfig.Options{
		{
			AllowCloudInit: true,
			TargetRootDir:  boot.InstallHostWritableDir,
			GadgetDir:      filepath.Join(dirs.SnapMountDir, "pc/1/"),
		},
	})
}

func (s *deviceMgrInstallModeSuite) TestInstallModeSupportsCloudInitInDangerous(c *C) {
	// pretend we have a cloud-init config on the seed partition
	cloudCfg := filepath.Join(boot.InitramfsUbuntuSeedDir, "data/etc/cloud/cloud.cfg.d")
	err := os.MkdirAll(cloudCfg, 0755)
	c.Assert(err, IsNil)
	for _, mockCfg := range []string{"foo.cfg", "bar.cfg"} {
		err = ioutil.WriteFile(filepath.Join(cloudCfg, mockCfg), []byte(fmt.Sprintf("%s config", mockCfg)), 0644)
		c.Assert(err, IsNil)
	}

	s.mockInstallModeChange(c, "dangerous", "")

	// and did tell sysconfig about the cloud-init files
	c.Assert(s.ConfigureTargetSystemOptsPassed, DeepEquals, []*sysconfig.Options{
		{
			AllowCloudInit:  true,
			CloudInitSrcDir: filepath.Join(boot.InitramfsUbuntuSeedDir, "data/etc/cloud/cloud.cfg.d"),
			TargetRootDir:   boot.InstallHostWritableDir,
			GadgetDir:       filepath.Join(dirs.SnapMountDir, "pc/1/"),
		},
	})
}

func (s *deviceMgrInstallModeSuite) TestInstallModeSignedNoUbuntuSeedCloudInit(c *C) {
	// pretend we have a cloud-init config on the seed partition
	cloudCfg := filepath.Join(boot.InitramfsUbuntuSeedDir, "data/etc/cloud/cloud.cfg.d")
	err := os.MkdirAll(cloudCfg, 0755)
	c.Assert(err, IsNil)
	for _, mockCfg := range []string{"foo.cfg", "bar.cfg"} {
		err = ioutil.WriteFile(filepath.Join(cloudCfg, mockCfg), []byte(fmt.Sprintf("%s config", mockCfg)), 0644)
		c.Assert(err, IsNil)
	}

	s.mockInstallModeChange(c, "signed", "")

	// and did NOT tell sysconfig about the cloud-init file, but also did not
	// explicitly disable cloud init
	c.Assert(s.ConfigureTargetSystemOptsPassed, DeepEquals, []*sysconfig.Options{
		{
			AllowCloudInit: true,
			TargetRootDir:  boot.InstallHostWritableDir,
			GadgetDir:      filepath.Join(dirs.SnapMountDir, "pc/1/"),
		},
	})
}

func (s *deviceMgrInstallModeSuite) TestInstallModeSecuredGadgetCloudConfCloudInit(c *C) {
	// pretend we have a cloud.conf from the gadget
	gadgetDir := filepath.Join(dirs.SnapMountDir, "pc/1/")
	err := os.MkdirAll(gadgetDir, 0755)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(gadgetDir, "cloud.conf"), nil, 0644)
	c.Assert(err, IsNil)

	err = s.doRunChangeTestWithEncryption(c, "secured", encTestCase{
		tpm: true, bypass: false, encrypt: true, trustedBootloader: true,
	})
	c.Assert(err, IsNil)

	c.Assert(s.ConfigureTargetSystemOptsPassed, DeepEquals, []*sysconfig.Options{
		{
			AllowCloudInit: true,
			TargetRootDir:  boot.InstallHostWritableDir,
			GadgetDir:      filepath.Join(dirs.SnapMountDir, "pc/1/"),
		},
	})
}

func (s *deviceMgrInstallModeSuite) TestInstallModeSecuredNoUbuntuSeedCloudInit(c *C) {
	// pretend we have a cloud-init config on the seed partition
	cloudCfg := filepath.Join(boot.InitramfsUbuntuSeedDir, "data/etc/cloud/cloud.cfg.d")
	err := os.MkdirAll(cloudCfg, 0755)
	c.Assert(err, IsNil)
	for _, mockCfg := range []string{"foo.cfg", "bar.cfg"} {
		err = ioutil.WriteFile(filepath.Join(cloudCfg, mockCfg), []byte(fmt.Sprintf("%s config", mockCfg)), 0644)
		c.Assert(err, IsNil)
	}

	err = s.doRunChangeTestWithEncryption(c, "secured", encTestCase{
		tpm: true, bypass: false, encrypt: true, trustedBootloader: true,
	})
	c.Assert(err, IsNil)

	// and did NOT tell sysconfig about the cloud-init files, instead it was
	// disabled because only gadget cloud-init is allowed
	c.Assert(s.ConfigureTargetSystemOptsPassed, DeepEquals, []*sysconfig.Options{
		{
			AllowCloudInit: false,
			TargetRootDir:  boot.InstallHostWritableDir,
			GadgetDir:      filepath.Join(dirs.SnapMountDir, "pc/1/"),
		},
	})
}

func (s *deviceMgrInstallModeSuite) TestInstallModeWritesModel(c *C) {
	// pretend we have a cloud-init config on the seed partition
	model := s.mockInstallModeChange(c, "dangerous", "")

	var buf bytes.Buffer
	err := asserts.NewEncoder(&buf).Encode(model)
	c.Assert(err, IsNil)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Assert(installSystem, NotNil)

	// and was run successfully
	c.Check(installSystem.Err(), IsNil)
	c.Check(installSystem.Status(), Equals, state.DoneStatus)

	c.Check(filepath.Join(boot.InitramfsUbuntuBootDir, "device/model"), testutil.FileEquals, buf.String())
}

func (s *deviceMgrInstallModeSuite) testInstallGadgetNoSave(c *C) {
	err := ioutil.WriteFile(filepath.Join(dirs.GlobalRootDir, "/var/lib/snapd/modeenv"),
		[]byte("mode=install\n"), 0644)
	c.Assert(err, IsNil)

	s.state.Lock()
	s.makeMockInstalledPcGadget(c, "dangerous", "", "")
	info, err := snapstate.CurrentInfo(s.state, "pc")
	c.Assert(err, IsNil)
	// replace gadget yaml with one that has no ubuntu-save
	c.Assert(uc20gadgetYaml, Not(testutil.Contains), "ubuntu-save")
	err = ioutil.WriteFile(filepath.Join(info.MountDir(), "meta/gadget.yaml"), []byte(uc20gadgetYaml), 0644)
	c.Assert(err, IsNil)
	devicestate.SetSystemMode(s.mgr, "install")
	s.state.Unlock()

	s.settle(c)
}

func (s *deviceMgrInstallModeSuite) TestInstallWithEncryptionValidatesGadgetErr(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		return nil, fmt.Errorf("unexpected call")
	})
	defer restore()

	// pretend we have a TPM
	restore = devicestate.MockSecbootCheckTPMKeySealingSupported(func() error { return nil })
	defer restore()

	s.testInstallGadgetNoSave(c)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), ErrorMatches, `(?ms)cannot perform the following tasks:
- Setup system for run mode \(cannot use gadget: gadget does not support encrypted data: required partition with system-save role is missing\)`)
	// no restart request on failure
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrInstallModeSuite) TestInstallWithoutEncryptionValidatesGadgetWithoutSaveHappy(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	restore = devicestate.MockInstallRun(func(mod gadget.Model, gadgetRoot, kernelRoot, device string, options install.Options, _ gadget.ContentObserver) (*install.InstalledSystemSideData, error) {
		return nil, nil
	})
	defer restore()

	// pretend we have a TPM
	restore = devicestate.MockSecbootCheckTPMKeySealingSupported(func() error { return fmt.Errorf("TPM2 not available") })
	defer restore()

	s.testInstallGadgetNoSave(c)

	s.state.Lock()
	defer s.state.Unlock()

	installSystem := s.findInstallSystem()
	c.Check(installSystem.Err(), IsNil)
	c.Check(s.restartRequests, HasLen, 1)
}

func (s *deviceMgrInstallModeSuite) TestInstallCheckEncrypted(c *C) {
	st := s.state
	st.Lock()
	defer st.Unlock()

	mockModel := s.makeModelAssertionInState(c, "canonical", "pc", map[string]interface{}{
		"architecture": "amd64",
		"kernel":       "pc-kernel",
		"gadget":       "pc",
	})
	devicestatetest.SetDevice(s.state, &auth.DeviceState{
		Brand: "canonical",
		Model: "pc",
	})
	deviceCtx := &snapstatetest.TrivialDeviceContext{DeviceModel: mockModel}

	for _, tc := range []struct {
		hasFDESetupHook bool
		hasTPM          bool
		encrypt         bool
	}{
		// unhappy: no tpm, no hook
		{false, false, false},
		// happy: either tpm or hook or both
		{false, true, true},
		{true, false, true},
		{true, true, true},
	} {
		hookInvoke := func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
			ctx.Lock()
			defer ctx.Unlock()
			ctx.Set("fde-setup-result", []byte(`{"features":[]}`))
			return nil, nil
		}
		rhk := hookstate.MockRunHook(hookInvoke)
		defer rhk()

		if tc.hasFDESetupHook {
			makeInstalledMockKernelSnap(c, st, kernelYamlWithFdeSetup)
		} else {
			makeInstalledMockKernelSnap(c, st, kernelYamlNoFdeSetup)
		}
		restore := devicestate.MockSecbootCheckTPMKeySealingSupported(func() error {
			if tc.hasTPM {
				return nil
			}
			return fmt.Errorf("tpm says no")
		})
		defer restore()

		encrypt, err := devicestate.DeviceManagerCheckEncryption(s.mgr, st, deviceCtx)
		c.Assert(err, IsNil)
		c.Check(encrypt, Equals, tc.encrypt, Commentf("%v", tc))
	}
}

func (s *deviceMgrInstallModeSuite) TestInstallCheckEncryptedStorageSafety(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	restore := devicestate.MockSecbootCheckTPMKeySealingSupported(func() error { return nil })
	defer restore()

	var testCases = []struct {
		grade, storageSafety string

		expectedEncryption bool
	}{
		// we don't test unset here because the assertion assembly
		// will ensure it has a default
		{"dangerous", "prefer-unencrypted", false},
		{"dangerous", "prefer-encrypted", true},
		{"dangerous", "encrypted", true},
		{"signed", "prefer-unencrypted", false},
		{"signed", "prefer-encrypted", true},
		{"signed", "encrypted", true},
		// secured+prefer-{,un}encrypted is an error at the
		// assertion level already so cannot be tested here
		{"secured", "encrypted", true},
	}
	for _, tc := range testCases {
		mockModel := s.makeModelAssertionInState(c, "my-brand", "my-model", map[string]interface{}{
			"display-name":   "my model",
			"architecture":   "amd64",
			"base":           "core20",
			"grade":          tc.grade,
			"storage-safety": tc.storageSafety,
			"snaps": []interface{}{
				map[string]interface{}{
					"name":            "pc-kernel",
					"id":              pcKernelSnapID,
					"type":            "kernel",
					"default-channel": "20",
				},
				map[string]interface{}{
					"name":            "pc",
					"id":              pcSnapID,
					"type":            "gadget",
					"default-channel": "20",
				}},
		})
		deviceCtx := &snapstatetest.TrivialDeviceContext{DeviceModel: mockModel}

		encrypt, err := devicestate.DeviceManagerCheckEncryption(s.mgr, s.state, deviceCtx)
		c.Assert(err, IsNil)
		c.Check(encrypt, Equals, tc.expectedEncryption)
	}
}

func (s *deviceMgrInstallModeSuite) TestInstallCheckEncryptedErrors(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	restore := devicestate.MockSecbootCheckTPMKeySealingSupported(func() error { return fmt.Errorf("tpm says no") })
	defer restore()

	var testCases = []struct {
		grade, storageSafety string

		expectedErr string
	}{
		// we don't test unset here because the assertion assembly
		// will ensure it has a default
		{
			"dangerous", "encrypted",
			"cannot encrypt device storage as mandated by encrypted storage-safety model option: tpm says no",
		}, {
			"signed", "encrypted",
			"cannot encrypt device storage as mandated by encrypted storage-safety model option: tpm says no",
		}, {
			"secured", "",
			"cannot encrypt device storage as mandated by model grade secured: tpm says no",
		}, {
			"secured", "encrypted",
			"cannot encrypt device storage as mandated by model grade secured: tpm says no",
		},
	}
	for _, tc := range testCases {
		mockModel := s.makeModelAssertionInState(c, "my-brand", "my-model", map[string]interface{}{
			"display-name":   "my model",
			"architecture":   "amd64",
			"base":           "core20",
			"grade":          tc.grade,
			"storage-safety": tc.storageSafety,
			"snaps": []interface{}{
				map[string]interface{}{
					"name":            "pc-kernel",
					"id":              pcKernelSnapID,
					"type":            "kernel",
					"default-channel": "20",
				},
				map[string]interface{}{
					"name":            "pc",
					"id":              pcSnapID,
					"type":            "gadget",
					"default-channel": "20",
				}},
		})
		deviceCtx := &snapstatetest.TrivialDeviceContext{DeviceModel: mockModel}
		_, err := devicestate.DeviceManagerCheckEncryption(s.mgr, s.state, deviceCtx)
		c.Check(err, ErrorMatches, tc.expectedErr, Commentf("%s %s", tc.grade, tc.storageSafety))
	}
}

func (s *deviceMgrInstallModeSuite) TestInstallCheckEncryptedFDEHook(c *C) {
	st := s.state
	st.Lock()
	defer st.Unlock()

	s.makeModelAssertionInState(c, "canonical", "pc", map[string]interface{}{
		"architecture": "amd64",
		"kernel":       "pc-kernel",
		"gadget":       "pc",
	})
	devicestatetest.SetDevice(s.state, &auth.DeviceState{
		Brand: "canonical",
		Model: "pc",
	})
	makeInstalledMockKernelSnap(c, st, kernelYamlWithFdeSetup)

	for _, tc := range []struct {
		hookOutput  string
		expectedErr string
	}{
		// invalid json
		{"xxx", `cannot parse hook output "xxx": invalid character 'x' looking for beginning of value`},
		// no output is invalid
		{"", `cannot parse hook output "": unexpected end of JSON input`},
		// specific error
		{`{"error":"failed"}`, `cannot use hook: it returned error: failed`},
		{`{}`, `cannot use hook: neither "features" nor "error" returned`},
		// valid
		{`{"features":[]}`, ""},
		{`{"features":["a"]}`, ""},
		{`{"features":["a","b"]}`, ""},
		// features must be list of strings
		{`{"features":[1]}`, `cannot parse hook output ".*": json: cannot unmarshal number into Go struct.*`},
		{`{"features":1}`, `cannot parse hook output ".*": json: cannot unmarshal number into Go struct.*`},
		{`{"features":"1"}`, `cannot parse hook output ".*": json: cannot unmarshal string into Go struct.*`},
	} {
		hookInvoke := func(ctx *hookstate.Context, tomb *tomb.Tomb) ([]byte, error) {
			ctx.Lock()
			defer ctx.Unlock()
			ctx.Set("fde-setup-result", []byte(tc.hookOutput))
			return nil, nil
		}
		rhk := hookstate.MockRunHook(hookInvoke)
		defer rhk()

		err := devicestate.DeviceManagerCheckFDEFeatures(s.mgr, st)
		if tc.expectedErr != "" {
			c.Check(err, ErrorMatches, tc.expectedErr, Commentf("%v", tc))
		} else {
			c.Check(err, IsNil, Commentf("%v", tc))
		}
	}
}

var checkEncryptionModelHeaders = map[string]interface{}{
	"display-name": "my model",
	"architecture": "amd64",
	"base":         "core20",
	"grade":        "dangerous",
	"snaps": []interface{}{
		map[string]interface{}{
			"name":            "pc-kernel",
			"id":              pcKernelSnapID,
			"type":            "kernel",
			"default-channel": "20",
		},
		map[string]interface{}{
			"name":            "pc",
			"id":              pcSnapID,
			"type":            "gadget",
			"default-channel": "20",
		}},
}

func (s *deviceMgrInstallModeSuite) TestInstallCheckEncryptedErrorsLogsTPM(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	restore := devicestate.MockSecbootCheckTPMKeySealingSupported(func() error {
		return fmt.Errorf("tpm says no")
	})
	defer restore()

	logbuf, restore := logger.MockLogger()
	defer restore()

	mockModel := s.makeModelAssertionInState(c, "my-brand", "my-model", checkEncryptionModelHeaders)
	deviceCtx := &snapstatetest.TrivialDeviceContext{DeviceModel: mockModel}
	_, err := devicestate.DeviceManagerCheckEncryption(s.mgr, s.state, deviceCtx)
	c.Check(err, IsNil)
	c.Check(logbuf.String(), Matches, "(?s).*: not encrypting device storage as checking TPM gave: tpm says no\n")
}

func (s *deviceMgrInstallModeSuite) TestInstallCheckEncryptedErrorsLogsHook(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	logbuf, restore := logger.MockLogger()
	defer restore()

	mockModel := s.makeModelAssertionInState(c, "my-brand", "my-model", checkEncryptionModelHeaders)
	// mock kernel installed but no hook or handle so checkEncryption
	// will fail
	makeInstalledMockKernelSnap(c, s.state, kernelYamlWithFdeSetup)

	deviceCtx := &snapstatetest.TrivialDeviceContext{DeviceModel: mockModel}
	_, err := devicestate.DeviceManagerCheckEncryption(s.mgr, s.state, deviceCtx)
	c.Check(err, IsNil)
	c.Check(logbuf.String(), Matches, "(?s).*: not encrypting device storage as querying kernel fde-setup hook did not succeed:.*\n")
}
