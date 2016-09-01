// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2016 Canonical Ltd
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

package snap

import (
	"fmt"
	"io/ioutil"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/snapcore/snapd/osutil"
)

type SeedSnap struct {
	// yaml needs to be in sync with SideInfo
	Name    string `yaml:"name" json:"name"`
	Channel string `yaml:"channel,omitempty" json:"channel,omitempty"`

	// XXX: these come from assertions now
	SnapID      string   `yaml:"snap-id,omitempty" json:"snap-id"`
	Revision    Revision `yaml:"revision" json:"revision"`
	DeveloperID string   `yaml:"developer-id,omitempty" json:"developer-id,omitempty"`
	Developer   string   `yaml:"developer,omitempty" json:"developer,omitempty"` // XXX: obsolete, will be retired after full backfilling of DeveloperID

	Private bool `yaml:"private,omitempty" json:"private,omitempty"`
	// not in side-info
	File    string `yaml:"file"`
	DevMode bool   `yaml:"devmode,omitempty"`

	Sideloaded bool `yaml:"sideloaded,omitempty"`
}

type Seed struct {
	Snaps []*SeedSnap `yaml:"snaps"`
}

func ReadSeedYaml(fn string) (*Seed, error) {
	yamlData, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("cannot read seed yaml: %s", fn)
	}

	var seed Seed
	if err := yaml.Unmarshal(yamlData, &seed); err != nil {
		return nil, fmt.Errorf("cannot unmarshal %q: %s", yamlData, err)
	}

	// validate
	for _, sn := range seed.Snaps {
		if strings.Contains(sn.File, "/") {
			return nil, fmt.Errorf("%q must be a filename, not a path", sn.File)
		}
	}

	return &seed, nil
}

func (seed *Seed) Write(seedFn string) error {
	data, err := yaml.Marshal(&seed)
	if err != nil {
		return err
	}
	if err := osutil.AtomicWriteFile(seedFn, data, 0644, 0); err != nil {
		return err
	}
	return nil
}
