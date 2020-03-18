// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2019 Canonical Ltd
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

package seed

/* ATTN this should *not* use:

* dirs package: it is passed an explicit directory to work on

* release.OnClassic: it assumes classic based on the model classic
  option; consistency between system and model can/must be enforced
  elsewhere

*/

import (
	"fmt"
	"path/filepath"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/snapasserts"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/seed/internal"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/channel"
	"github.com/snapcore/snapd/snap/naming"
	"github.com/snapcore/snapd/timings"
)

type seed16 struct {
	seedDir string

	db asserts.RODatabase

	model *asserts.Model
	brand *asserts.Account

	snaps             []*Snap
	essentialSnapsNum int

	usesSnapdSnap bool
}

func (s *seed16) LoadAssertions(db asserts.RODatabase, commitTo func(*asserts.Batch) error) error {
	if db == nil {
		// a db was not provided, create an internal temporary one
		var err error
		db, commitTo, err = newMemAssertionsDB()
		if err != nil {
			return err
		}
	}

	assertSeedDir := filepath.Join(s.seedDir, "assertions")
	// collect assertions and find model assertion
	var modelRef *asserts.Ref
	var acctRefs []*asserts.Ref
	checkForModel := func(ref *asserts.Ref) error {
		switch ref.Type {
		case asserts.ModelType:
			if modelRef != nil && modelRef.Unique() != ref.Unique() {
				return fmt.Errorf("cannot have multiple model assertions in seed")
			}
			modelRef = ref
		case asserts.AccountType:
			acctRefs = append(acctRefs, ref)
		}
		return nil
	}

	batch, err := loadAssertions(assertSeedDir, checkForModel)
	if err != nil {
		return err
	}

	// verify we have one model assertion
	if modelRef == nil {
		return fmt.Errorf("seed must have a model assertion")
	}

	if err := commitTo(batch); err != nil {
		return err
	}

	a, err := modelRef.Resolve(db.Find)
	if err != nil {
		return fmt.Errorf("internal error: cannot find just added assertion %v: %v", modelRef, err)
	}
	modelAssertion := a.(*asserts.Model)

	var brandAssertion *asserts.Account
	for _, acctRef := range acctRefs {
		a, err := acctRef.Resolve(db.Find)
		if err != nil {
			return fmt.Errorf("internal error: cannot find just added assertion %v: %v", modelRef, err)
		}
		acctAssertion := a.(*asserts.Account)
		if acctAssertion.AccountID() == modelAssertion.BrandID() {
			brandAssertion = acctAssertion
			break
		}
	}
	// remember db for later use
	s.db = db
	s.model = modelAssertion
	s.brand = brandAssertion

	return nil
}

func (s *seed16) Model() (*asserts.Model, error) {
	if s.model == nil {
		return nil, fmt.Errorf("internal error: model assertion unset")
	}
	return s.model, nil
}

func (s *seed16) Brand() (*asserts.Account, error) {
	if s.brand == nil {
		return nil, fmt.Errorf("internal error: brand account assertion unset")
	}
	return s.brand, nil
}

func (s *seed16) addSnap(sn *internal.Snap16, pinnedTrack string, tm timings.Measurer) (*Snap, error) {
	path := filepath.Join(s.seedDir, "snaps", sn.File)
	snapChannel := sn.Channel
	if pinnedTrack != "" {
		var err error
		snapChannel, err = channel.ResolvePinned(pinnedTrack, snapChannel)
		if err != nil {
			// fallback to using the pinned track directly
			snapChannel = pinnedTrack
		}
	}
	seedSnap := &Snap{
		Path:    path,
		Channel: snapChannel,
		Classic: sn.Classic,
		DevMode: sn.DevMode,
	}

	var sideInfo snap.SideInfo
	if sn.Unasserted {
		sideInfo.RealName = sn.Name
	} else {
		var si *snap.SideInfo
		var err error
		timings.Run(tm, "derive-side-info", fmt.Sprintf("hash and derive side info for snap %q", sn.Name), func(nested timings.Measurer) {
			si, err = snapasserts.DeriveSideInfo(path, s.db)
		})
		if asserts.IsNotFound(err) {
			return nil, fmt.Errorf("cannot find signatures with metadata for snap %q (%q)", sn.Name, path)
		}
		if err != nil {
			return nil, err
		}
		sideInfo = *si
		sideInfo.Private = sn.Private
		sideInfo.Contact = sn.Contact
	}

	seedSnap.SideInfo = &sideInfo

	s.snaps = append(s.snaps, seedSnap)

	return seedSnap, nil
}

func (s *seed16) LoadMeta(tm timings.Measurer) error {
	model, err := s.Model()
	if err != nil {
		return err
	}

	seedYamlFile := filepath.Join(s.seedDir, "seed.yaml")
	if !osutil.FileExists(seedYamlFile) {
		return ErrNoMeta
	}

	seedYaml, err := internal.ReadSeedYaml(seedYamlFile)
	if err != nil {
		return err
	}
	yamlSnaps := seedYaml.Snaps

	required := naming.NewSnapSet(model.RequiredWithEssentialSnaps())
	seeding := make(map[string]*internal.Snap16, len(yamlSnaps))
	for _, sn := range yamlSnaps {
		seeding[sn.Name] = sn
	}
	added := make(map[string]bool, 3)
	classic := model.Classic()
	_, s.usesSnapdSnap = seeding["snapd"]

	baseSnap := "core"
	classicWithSnapd := false
	if model.Base() != "" {
		baseSnap = model.Base()
	}
	if classic && s.usesSnapdSnap {
		classicWithSnapd = true
		// there is no system-wide base as such
		// if there is a gadget we will install its base first though
		baseSnap = ""
	}

	// add the essential snaps
	addEssential := func(snapName string, pinnedTrack string, essType snap.Type) (*Snap, error) {
		// be idempotent
		if added[snapName] {
			return nil, nil
		}
		yamlSnap := seeding[snapName]
		if yamlSnap == nil {
			return nil, fmt.Errorf("essential snap %q required by the model is missing in the seed", snapName)
		}

		seedSnap, err := s.addSnap(yamlSnap, pinnedTrack, tm)
		if err != nil {
			return nil, err
		}

		if essType == snap.TypeBase && snapName == "core" {
			essType = snap.TypeOS
		}

		seedSnap.EssentialType = essType
		seedSnap.Essential = true
		seedSnap.Required = true
		added[snapName] = true

		return seedSnap, nil
	}

	// if there are snaps to seed, core/base needs to be seeded too
	if len(yamlSnaps) != 0 {
		// ensure "snapd" snap is installed first
		if model.Base() != "" || classicWithSnapd {
			if _, err := addEssential("snapd", "", snap.TypeSnapd); err != nil {
				return err
			}
		}
		if !classicWithSnapd {
			if _, err := addEssential(baseSnap, "", snap.TypeBase); err != nil {
				return err
			}
		}
	}

	if kernelName := model.Kernel(); kernelName != "" {
		if _, err := addEssential(kernelName, model.KernelTrack(), snap.TypeKernel); err != nil {
			return err
		}
	}

	if gadgetName := model.Gadget(); gadgetName != "" {
		gadget, err := addEssential(gadgetName, model.GadgetTrack(), snap.TypeGadget)
		if err != nil {
			return err
		}

		// always make sure the base of gadget is installed first
		info, err := readInfo(gadget.Path, gadget.SideInfo)
		if err != nil {
			return err
		}
		gadgetBase := info.Base
		if gadgetBase == "" {
			gadgetBase = "core"
		}
		// Sanity check
		// TODO: do we want to relax this? the new logic would allow
		// but it might just be confusing for now
		if baseSnap != "" && gadgetBase != baseSnap {
			return fmt.Errorf("cannot use gadget snap because its base %q is different from model base %q", gadgetBase, model.Base())
		}
		if _, err = addEssential(gadgetBase, "", snap.TypeBase); err != nil {
			return err
		}
	}

	s.essentialSnapsNum = len(s.snaps)

	// the rest of the snaps
	for _, sn := range yamlSnaps {
		if added[sn.Name] {
			continue
		}
		seedSnap, err := s.addSnap(sn, "", tm)
		if err != nil {
			return err
		}
		if required.Contains(seedSnap) {
			seedSnap.Required = true
		}
	}

	return nil
}

func (s *seed16) UsesSnapdSnap() bool {
	return s.usesSnapdSnap
}

func (s *seed16) EssentialSnaps() []*Snap {
	return s.snaps[:s.essentialSnapsNum]
}

func (s *seed16) ModeSnaps(mode string) ([]*Snap, error) {
	if mode != "run" {
		return nil, fmt.Errorf("internal error: Core 16/18 have only run mode, got: %s", mode)
	}
	return s.snaps[s.essentialSnapsNum:], nil
}
