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

package devicestate_test

import (
	"errors"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/devicestate"
	"github.com/snapcore/snapd/overlord/devicestate/devicestatetest"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/seed"
	"github.com/snapcore/snapd/seed/seedtest"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/strutil"
	"github.com/snapcore/snapd/timings"
)

type mockedSystemSeed struct {
	label string
	model *asserts.Model
	brand *asserts.Account
}

type deviceMgrSystemsSuite struct {
	deviceMgrBaseSuite

	mockedSystemSeeds []mockedSystemSeed
}

var _ = Suite(&deviceMgrSystemsSuite{})

func (s *deviceMgrSystemsSuite) SetUpTest(c *C) {
	s.deviceMgrBaseSuite.SetUpTest(c)

	s.brands.Register("other-brand", brandPrivKey3, map[string]interface{}{
		"display-name": "other publisher",
	})
	s.state.Lock()
	defer s.state.Unlock()
	s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]interface{}{
		"architecture": "amd64",
		// UC20
		"grade": "dangerous",
		"base":  "core20",
		"snaps": []interface{}{
			map[string]interface{}{
				"name":            "pc-kernel",
				"id":              snaptest.AssertedSnapID("oc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]interface{}{
				"name":            "pc",
				"id":              snaptest.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
		},
	})
	devicestatetest.SetDevice(s.state, &auth.DeviceState{
		Brand:  "canonical",
		Model:  "pc-20",
		Serial: "serialserialserial",
	})
	assertstest.AddMany(s.storeSigning.Database, s.brands.AccountsAndKeys("my-brand")...)
	assertstest.AddMany(s.storeSigning.Database, s.brands.AccountsAndKeys("other-brand")...)

	// now create a minimal uc20 seed dir with snaps/assertions
	seed20 := &seedtest.TestingSeed20{
		SeedSnaps: seedtest.SeedSnaps{
			StoreSigning: s.storeSigning,
			Brands:       s.brands,
		},

		SeedDir: dirs.SnapSeedDir,
	}

	restore := seed.MockTrusted(s.storeSigning.Trusted)
	s.AddCleanup(restore)

	myBrandAcc := s.brands.Account("my-brand")
	otherBrandAcc := s.brands.Account("other-brand")

	// add essential snaps
	seed20.MakeAssertedSnap(c, "name: snapd\nversion: 1\ntype: snapd", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)
	seed20.MakeAssertedSnap(c, "name: pc\nversion: 1\ntype: gadget\nbase: core20", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)
	seed20.MakeAssertedSnap(c, "name: pc-kernel\nversion: 1\ntype: kernel", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)
	seed20.MakeAssertedSnap(c, "name: core20\nversion: 1\ntype: base", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)

	model1 := seed20.MakeSeed(c, "20191119", "my-brand", "my-model", map[string]interface{}{
		"display-name": "my fancy model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []interface{}{
			map[string]interface{}{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]interface{}{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			}},
	}, nil)
	model2 := seed20.MakeSeed(c, "20200318", "my-brand", "my-model-2", map[string]interface{}{
		"display-name": "same brand different model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []interface{}{
			map[string]interface{}{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]interface{}{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			}},
	}, nil)
	model3 := seed20.MakeSeed(c, "other-20200318", "other-brand", "other-model", map[string]interface{}{
		"display-name": "different brand different model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []interface{}{
			map[string]interface{}{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]interface{}{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			}},
	}, nil)

	s.mockedSystemSeeds = []mockedSystemSeed{{
		label: "20191119",
		model: model1,
		brand: myBrandAcc,
	}, {
		label: "20200318",
		model: model2,
		brand: myBrandAcc,
	}, {
		label: "other-20200318",
		model: model3,
		brand: otherBrandAcc,
	}}

	// all tests should be in run mode by default, if they need to be in
	// different modes they should set that individually
	devicestate.SetSystemMode(s.mgr, "run")
}

func (s *deviceMgrSystemsSuite) TestListNoSystems(c *C) {
	dirs.SetRootDir(c.MkDir())

	systems, err := s.mgr.Systems()
	c.Assert(err, Equals, devicestate.ErrNoSystems)
	c.Assert(systems, HasLen, 0)

	err = os.MkdirAll(filepath.Join(dirs.SnapSeedDir, "systems"), 0755)
	c.Assert(err, IsNil)

	systems, err = s.mgr.Systems()
	c.Assert(err, Equals, devicestate.ErrNoSystems)
	c.Assert(systems, HasLen, 0)
}

func (s *deviceMgrSystemsSuite) TestListSystemsNotPossible(c *C) {
	if os.Geteuid() == 0 {
		c.Skip("this test cannot run as root")
	}
	err := os.Chmod(filepath.Join(dirs.SnapSeedDir, "systems"), 0000)
	c.Assert(err, IsNil)
	defer os.Chmod(filepath.Join(dirs.SnapSeedDir, "systems"), 0755)

	// stdlib swallows up the errors when opening the target directory
	systems, err := s.mgr.Systems()
	c.Assert(err, Equals, devicestate.ErrNoSystems)
	c.Assert(systems, HasLen, 0)
}

// TODO:UC20 update once we can list actions
var defaultSystemActions []devicestate.SystemAction = []devicestate.SystemAction{
	{Title: "Install", Mode: "install"},
}
var currentSystemActions []devicestate.SystemAction = []devicestate.SystemAction{
	{Title: "Reinstall", Mode: "install"},
	{Title: "Recover", Mode: "recover"},
	{Title: "Run normally", Mode: "run"},
}

func (s *deviceMgrSystemsSuite) TestListSeedSystemsNoCurrent(c *C) {
	systems, err := s.mgr.Systems()
	c.Assert(err, IsNil)
	c.Assert(systems, HasLen, 3)
	c.Check(systems, DeepEquals, []*devicestate.System{{
		Current: false,
		Label:   s.mockedSystemSeeds[0].label,
		Model:   s.mockedSystemSeeds[0].model,
		Brand:   s.mockedSystemSeeds[0].brand,
		Actions: defaultSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[1].label,
		Model:   s.mockedSystemSeeds[1].model,
		Brand:   s.mockedSystemSeeds[1].brand,
		Actions: defaultSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[2].label,
		Model:   s.mockedSystemSeeds[2].model,
		Brand:   s.mockedSystemSeeds[2].brand,
		Actions: defaultSystemActions,
	}})
}

func (s *deviceMgrSystemsSuite) TestListSeedSystemsCurrent(c *C) {
	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[1].label,
			Model:   s.mockedSystemSeeds[1].model.Model(),
			BrandID: s.mockedSystemSeeds[1].brand.AccountID(),
		},
	})
	s.state.Unlock()

	systems, err := s.mgr.Systems()
	c.Assert(err, IsNil)
	c.Assert(systems, HasLen, 3)
	c.Check(systems, DeepEquals, []*devicestate.System{{
		Current: false,
		Label:   s.mockedSystemSeeds[0].label,
		Model:   s.mockedSystemSeeds[0].model,
		Brand:   s.mockedSystemSeeds[0].brand,
		Actions: defaultSystemActions,
	}, {
		// this seed was used for installing the running system
		Current: true,
		Label:   s.mockedSystemSeeds[1].label,
		Model:   s.mockedSystemSeeds[1].model,
		Brand:   s.mockedSystemSeeds[1].brand,
		Actions: currentSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[2].label,
		Model:   s.mockedSystemSeeds[2].model,
		Brand:   s.mockedSystemSeeds[2].brand,
		Actions: defaultSystemActions,
	}})
}

func (s *deviceMgrSystemsSuite) TestBrokenSeedSystems(c *C) {
	// break the first seed
	err := os.Remove(filepath.Join(dirs.SnapSeedDir, "systems", s.mockedSystemSeeds[0].label, "model"))
	c.Assert(err, IsNil)

	systems, err := s.mgr.Systems()
	c.Assert(err, IsNil)
	c.Assert(systems, HasLen, 2)
	c.Check(systems, DeepEquals, []*devicestate.System{{
		Current: false,
		Label:   s.mockedSystemSeeds[1].label,
		Model:   s.mockedSystemSeeds[1].model,
		Brand:   s.mockedSystemSeeds[1].brand,
		Actions: defaultSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[2].label,
		Model:   s.mockedSystemSeeds[2].model,
		Brand:   s.mockedSystemSeeds[2].brand,
		Actions: defaultSystemActions,
	}})
}

func (s *deviceMgrSystemsSuite) TestRequestModeInstallHappyForAny(c *C) {
	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Unlock()

	// no current system
	err := s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, IsNil)

	m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"snapd_recovery_system": "20191119",
		"snapd_recovery_mode":   "install",
	})
	c.Check(s.restartRequests, DeepEquals, []state.RestartType{state.RestartSystemNow})
}

func (s *deviceMgrSystemsSuite) TestRequestSameModeSameSystem(c *C) {
	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	label := s.mockedSystemSeeds[0].label

	happyModes := []string{"run", "recover"}
	sadModes := []string{"install"}

	for _, mode := range append(happyModes, sadModes...) {
		c.Logf("checking mode: %q", mode)
		// non run modes use modeenv
		modeenv := boot.Modeenv{
			Mode: mode,
		}
		if mode != "run" {
			modeenv.RecoverySystem = s.mockedSystemSeeds[0].label
		}
		err := modeenv.WriteTo("")
		c.Assert(err, IsNil)

		devicestate.SetSystemMode(s.mgr, mode)
		err = s.bootloader.SetBootVars(map[string]string{
			"snapd_recovery_mode":   mode,
			"snapd_recovery_system": label,
		})
		c.Assert(err, IsNil)
		err = s.mgr.RequestSystemAction(label, devicestate.SystemAction{Mode: mode})
		if strutil.ListContains(sadModes, mode) {
			c.Assert(err, Equals, devicestate.ErrUnsupportedAction)
		} else {
			c.Assert(err, IsNil)
		}
		// bootloader vars shouldn't change
		m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
		c.Assert(err, IsNil)
		c.Check(m, DeepEquals, map[string]string{
			"snapd_recovery_mode":   mode,
			"snapd_recovery_system": label,
		})
		// should never restart
		c.Check(s.restartRequests, HasLen, 0)
	}
}

func (s *deviceMgrSystemsSuite) TestRequestSeedingNotStarted(c *C) {
	// seeded and seeded-systems is unset
	label := s.mockedSystemSeeds[0].label

	for _, mode := range []string{"run", "install", "recover"} {
		c.Logf("checking mode: %q", mode)
		devicestate.SetSystemMode(s.mgr, mode)
		err := s.bootloader.SetBootVars(map[string]string{
			"snapd_recovery_mode":   mode,
			"snapd_recovery_system": label,
		})
		c.Assert(err, IsNil)
		err = s.mgr.RequestSystemAction(label, devicestate.SystemAction{Mode: mode})
		c.Assert(err, ErrorMatches, "cannot request system action, seeding not started yet")
	}
}

func (s *deviceMgrSystemsSuite) TestRequestSeedingSameConflict(c *C) {
	label := s.mockedSystemSeeds[0].label

	s.state.Lock()
	opts := devicestate.PopulateStateFromSeedOptions{
		Label: label,
		Mode:  "run",
	}
	perftimings := timings.New(nil)
	tsAll, err := devicestate.PopulateStateFromSeedImpl(s.state, &opts, perftimings)
	c.Assert(err, IsNil)
	chg := s.state.NewChange("seed", "mocked seeding")
	for _, ts := range tsAll {
		chg.AddAll(ts)
	}
	s.state.Unlock()

	devicestate.SetSystemMode(s.mgr, "run")
	for _, mode := range []string{"run", "install", "recover"} {
		c.Logf("checking mode: %q", mode)
		err := s.bootloader.SetBootVars(map[string]string{
			"snapd_recovery_mode":   "",
			"snapd_recovery_system": label,
		})
		c.Assert(err, IsNil)
		err = s.mgr.RequestSystemAction(label, devicestate.SystemAction{Mode: mode})
		c.Assert(err, ErrorMatches, "cannot request system action, system is seeding")
	}
}

func (s *deviceMgrSystemsSuite) TestRequestSeedingSameFailedNoConflict(c *C) {
	label := s.mockedSystemSeeds[0].label

	s.state.Lock()
	opts := devicestate.PopulateStateFromSeedOptions{
		Label: label,
		Mode:  "run",
	}
	perftimings := timings.New(nil)
	tsAll, err := devicestate.PopulateStateFromSeedImpl(s.state, &opts, perftimings)
	c.Assert(err, IsNil)
	chg := s.state.NewChange("seed", "mocked seeding")
	for _, ts := range tsAll {
		chg.AddAll(ts)
	}
	// pretend seeding failed
	chg.SetStatus(state.ErrorStatus)
	s.state.Unlock()

	devicestate.SetSystemMode(s.mgr, "run")

	// when seeding failed, one can only go to reinstall
	sadModes := []string{"run", "recover"}
	happyModes := []string{"install"}

	for _, mode := range append(happyModes, sadModes...) {
		c.Logf("checking mode: %q", mode)
		err := s.bootloader.SetBootVars(map[string]string{
			"snapd_recovery_mode":   "",
			"snapd_recovery_system": label,
		})
		c.Assert(err, IsNil)

		err = s.mgr.RequestSystemAction(label, devicestate.SystemAction{Mode: mode})
		m, merr := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
		c.Assert(merr, IsNil)
		if strutil.ListContains(sadModes, mode) {
			c.Assert(err, ErrorMatches, "unsupported action")
			c.Check(m, DeepEquals, map[string]string{
				"snapd_recovery_mode":   "",
				"snapd_recovery_system": label,
			})
			c.Check(s.restartRequests, HasLen, 0)
		} else {
			c.Assert(err, IsNil)
			c.Check(m, DeepEquals, map[string]string{
				"snapd_recovery_mode":   mode,
				"snapd_recovery_system": label,
			})
			c.Check(s.restartRequests, DeepEquals, []state.RestartType{state.RestartSystemNow})
		}
		s.restartRequests = nil
		s.bootloader.BootVars = map[string]string{}
	}
}

func (s *deviceMgrSystemsSuite) TestRequestSeedingDifferentNoConflict(c *C) {
	label := s.mockedSystemSeeds[0].label
	otherLabel := s.mockedSystemSeeds[1].label

	s.state.Lock()
	opts := devicestate.PopulateStateFromSeedOptions{
		Label: label,
		Mode:  "run",
	}
	perftimings := timings.New(nil)
	tsAll, err := devicestate.PopulateStateFromSeedImpl(s.state, &opts, perftimings)
	c.Assert(err, IsNil)
	chg := s.state.NewChange("seed", "mocked seeding")
	for _, ts := range tsAll {
		chg.AddAll(ts)
	}
	s.state.Unlock()

	devicestate.SetSystemMode(s.mgr, "run")

	// we can only go to install mode of other system when one is currently
	// being seeded
	err = s.bootloader.SetBootVars(map[string]string{
		"snapd_recovery_mode":   "",
		"snapd_recovery_system": label,
	})
	c.Assert(err, IsNil)
	err = s.mgr.RequestSystemAction(otherLabel, devicestate.SystemAction{Mode: "install"})
	c.Assert(err, IsNil)
	m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"snapd_recovery_system": otherLabel,
		"snapd_recovery_mode":   "install",
	})
}

func (s *deviceMgrSystemsSuite) TestRequestModeRunInstallForRecover(c *C) {
	// we are in recover mode here
	devicestate.SetSystemMode(s.mgr, "recover")
	// non run modes use modeenv
	modeenv := boot.Modeenv{
		Mode:           "recover",
		RecoverySystem: s.mockedSystemSeeds[0].label,
	}
	err := modeenv.WriteTo("")
	c.Assert(err, IsNil)

	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	for _, mode := range []string{"install", "run"} {
		c.Logf("checking mode: %q", mode)
		err := s.mgr.RequestSystemAction(s.mockedSystemSeeds[0].label,
			devicestate.SystemAction{Mode: mode})
		c.Assert(err, IsNil)
		m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
		c.Assert(err, IsNil)
		c.Check(m, DeepEquals, map[string]string{
			"snapd_recovery_system": s.mockedSystemSeeds[0].label,
			"snapd_recovery_mode":   mode,
		})
		c.Check(s.restartRequests, DeepEquals, []state.RestartType{state.RestartSystemNow})
		s.restartRequests = nil
		s.bootloader.BootVars = map[string]string{}
	}
}

func (s *deviceMgrSystemsSuite) TestRequestModeInstallRecoverForCurrent(c *C) {
	devicestate.SetSystemMode(s.mgr, "run")
	// non run modes use modeenv
	modeenv := boot.Modeenv{
		Mode: "run",
	}
	err := modeenv.WriteTo("")
	c.Assert(err, IsNil)

	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	for _, mode := range []string{"install", "recover"} {
		c.Logf("checking mode: %q", mode)
		err := s.mgr.RequestSystemAction(s.mockedSystemSeeds[0].label,
			devicestate.SystemAction{Mode: mode})
		c.Assert(err, IsNil)
		m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
		c.Assert(err, IsNil)
		c.Check(m, DeepEquals, map[string]string{
			"snapd_recovery_system": s.mockedSystemSeeds[0].label,
			"snapd_recovery_mode":   mode,
		})
		c.Check(s.restartRequests, DeepEquals, []state.RestartType{state.RestartSystemNow})
		s.restartRequests = nil
		s.bootloader.BootVars = map[string]string{}
	}
}

func (s *deviceMgrSystemsSuite) TestRequestModeErrInBoot(c *C) {
	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Unlock()

	s.bootloader.SetErr = errors.New("no can do")
	err := s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, `cannot set device to boot into system "20191119" in mode "install": no can do`)
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrSystemsSuite) TestRequestModeNotFound(c *C) {
	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Unlock()

	err := s.mgr.RequestSystemAction("not-found", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, NotNil)
	c.Assert(os.IsNotExist(err), Equals, true)
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrSystemsSuite) TestRequestModeBadMode(c *C) {
	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Unlock()

	err := s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "unknown-mode"})
	c.Assert(err, Equals, devicestate.ErrUnsupportedAction)
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrSystemsSuite) TestRequestModeBroken(c *C) {
	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Unlock()

	// break the first seed
	err := os.Remove(filepath.Join(dirs.SnapSeedDir, "systems", s.mockedSystemSeeds[0].label, "model"))
	c.Assert(err, IsNil)

	err = s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, "cannot load seed system: cannot load assertions: .*")
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrSystemsSuite) TestRequestModeNonUC20(c *C) {
	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Unlock()

	s.setPCModelInState(c)
	err := s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, `cannot set device to boot into system "20191119" in mode "install": system mode is unsupported`)
	c.Check(s.restartRequests, HasLen, 0)
}

func (s *deviceMgrSystemsSuite) TestRequestModeForNonCurrent(c *C) {
	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})

	s.state.Unlock()
	s.setPCModelInState(c)
	// request mode reserved for current system
	err := s.mgr.RequestSystemAction(s.mockedSystemSeeds[1].label, devicestate.SystemAction{Mode: "run"})
	c.Assert(err, Equals, devicestate.ErrUnsupportedAction)
	err = s.mgr.RequestSystemAction(s.mockedSystemSeeds[1].label, devicestate.SystemAction{Mode: "recover"})
	c.Assert(err, Equals, devicestate.ErrUnsupportedAction)
	c.Check(s.restartRequests, HasLen, 0)
}
