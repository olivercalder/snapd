// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016 Canonical Ltd
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

// Package legacygadget defines the legacy yaml specific to gadget snaps.
package legacygadget

// Gadget represents the structure inside the snap.yaml for the gadget component
// of a gadget package type.
type Gadget struct {
	Hardware             Hardware `yaml:"hardware,omitempty"`
	SkipIfupProvisioning bool     `yaml:"skip-ifup-provisioning"`
}

// Hardware describes the hardware provided by the gadget snap
type Hardware struct {
	BootAssets *BootAssets `yaml:"boot-assets,omitempty"`
	Bootloader string      `yaml:"bootloader,omitempty"`
}

// BootAssets represent all the artifacts required for booting a system
// that are particular to the board.
type BootAssets struct {
	Files    []BootAssetFiles    `yaml:"files,omitempty"`
	RawFiles []BootAssetRawFiles `yaml:"raw-files,omitempty"`
}

// BootAssetRawFiles represent all the artifacts required for booting a system
// that are particular to the board and require copying to specific sectors of
// the disk
type BootAssetRawFiles struct {
	Path   string `yaml:"path"`
	Offset string `yaml:"offset"`
}

// BootAssetFiles represent all the files required for booting a system
// that are particular to the board
type BootAssetFiles struct {
	Path   string `yaml:"path"`
	Target string `yaml:"target,omitempty"`
}
