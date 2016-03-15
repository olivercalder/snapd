// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2015 Canonical Ltd
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

// Package removed implements Removed packages, that are packages that
// have been installed, removed, but not purged: there is no
// application, but there might be data.
package removed

import (
	"errors"
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/ubuntu-core/snappy/snap"
	"github.com/ubuntu-core/snappy/snap/remote"
	"github.com/ubuntu-core/snappy/snappy"
)

// ErrRemoved is returned when you ask to operate on a removed package.
var ErrRemoved = errors.New("package is removed")

// Removed represents a removed package.
type Removed struct {
	name      string
	developer string
	version   string
	pkgType   snap.Type
	remote    *remote.Snap
}

// New removed package.
func New(name, developer, version string, pkgType snap.Type) snappy.BaseSnap {
	part := &Removed{
		name:      name,
		developer: developer,
		version:   version,
		pkgType:   pkgType,
	}

	// try to load the remote manifest, that would've been kept
	// around when installing from the store.
	content, _ := ioutil.ReadFile(snappy.RemoteManifestPath(part))
	yaml.Unmarshal(content, &(part.remote))

	return part
}

// Name from the snappy.Part interface
func (r *Removed) Name() string { return r.name }

// Version from the snappy.Part interface
func (r *Removed) Version() string { return r.version }

// Channel from the snappy.Part interface
func (r *Removed) Channel() string { return "" }

// Description from the snappy.Part interface
func (r *Removed) Description() string {
	if r.remote != nil {
		return r.remote.Description
	}

	return ""
}

// Developer from the snappy.Part interface
func (r *Removed) Developer() string {
	if r.remote != nil {
		return r.remote.Developer
	}

	return r.developer
}

// Type from the snappy.Part interface
func (r *Removed) Type() snap.Type { return r.pkgType }
