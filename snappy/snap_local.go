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

package snappy

import (
	//"fmt"

	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/ubuntu-core/snappy/osutil"
	"github.com/ubuntu-core/snappy/progress"
	"github.com/ubuntu-core/snappy/snap"
)

// Snap represents a generic snap type
type Snap struct {
	info *snap.Info

	// XXX: this should go away, and actually snappy.Snap itself
	m *snapYaml

	hash     string
	isActive bool

	basedir string
}

// NewInstalledSnap returns a new Snap from the given yamlPath
func NewInstalledSnap(yamlPath string) (*Snap, error) {
	m, err := parseSnapYamlFile(yamlPath)
	if err != nil {
		return nil, err
	}

	snap, err := newSnapFromYaml(yamlPath, m)
	if err != nil {
		return nil, err
	}

	return snap, nil
}

// newSnapFromYaml returns a new Snap from the given *snapYaml at yamlPath
func newSnapFromYaml(yamlPath string, m *snapYaml) (*Snap, error) {
	s := &Snap{
		basedir: filepath.Dir(filepath.Dir(yamlPath)),
		m:       m,
	}

	// check if the snap is active
	allVersionsDir := filepath.Dir(s.basedir)
	p, err := filepath.EvalSymlinks(filepath.Join(allVersionsDir, "current"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	if p == s.basedir {
		s.isActive = true
	}

	// XXX: temp ugly hack for now
	var yamlBits []byte
	if osutil.FileExists(yamlPath) {
		yamlBits, err = ioutil.ReadFile(yamlPath)
		if err != nil {
			return nil, err
		}
	} else {
		// XXX: ugly serialize and reparse
		yamlBits, err = yaml.Marshal(m)
		if err != nil {
			return nil, err
		}
	}

	info, err := snap.InfoFromSnapYaml(yamlBits)
	if err != nil {
		return nil, err
	}

	s.info = info

	manifestPath := ManifestPath(info)
	if osutil.FileExists(manifestPath) {
		content, err := ioutil.ReadFile(manifestPath)
		if err != nil {
			return nil, err
		}

		var manifest snap.SideInfo
		if err := yaml.Unmarshal(content, &manifest); err != nil {
			return nil, &ErrInvalidYaml{File: manifestPath, Err: err, Yaml: content}
		}
		info.SideInfo = manifest
	}

	if info.Developer == "" {
		info.Developer = SideloadedDeveloper
	}
	if info.Channel == "" {
		// default for compat with older installs
		info.Channel = "stable"
	}

	// XXX: FIXME: just some tests need this atm
	// override the package's idea of its version
	// because that could have been rewritten on sideload
	// and developer is empty sideloaded ones.
	m.Version = filepath.Base(s.basedir)
	info.Version = m.Version

	return s, nil
}

// Type returns the type of the Snap (app, gadget, ...)
func (s *Snap) Type() snap.Type {
	return s.info.Type
}

// Name returns the name
func (s *Snap) Name() string {
	return s.info.ZName()
}

// Version returns the version
func (s *Snap) Version() string {
	return s.info.Version
}

// Revision returns the revision
func (s *Snap) Revision() int {
	return s.info.Revision

}

// Developer returns the developer
func (s *Snap) Developer() string {
	return s.info.Developer

}

// Hash returns the hash
func (s *Snap) Hash() string {
	return s.hash
}

// Channel returns the channel used
func (s *Snap) Channel() string {
	return s.info.Channel
}

// Icon returns the path to the icon
func (s *Snap) Icon() string {
	found, _ := filepath.Glob(filepath.Join(s.basedir, "meta", "gui", "icon.*"))
	if len(found) == 0 {
		return ""
	}

	return found[0]
}

// IsActive returns true if the snap is active
func (s *Snap) IsActive() bool {
	return s.isActive
}

// IsInstalled returns true if the snap is installed
func (s *Snap) IsInstalled() bool {
	return true
}

// InstalledSize returns the size of the installed snap
func (s *Snap) InstalledSize() int64 {
	// FIXME: cache this at install time maybe?
	totalSize := int64(0)
	f := func(_ string, info os.FileInfo, err error) error {
		totalSize += info.Size()
		return err
	}
	filepath.Walk(s.basedir, f)
	return totalSize
}

// Info returns the snap.Info data.
func (s *Snap) Info() *snap.Info {
	return s.info
}

// DownloadSize returns the dowload size
func (s *Snap) DownloadSize() int64 {
	return s.info.Size
}

// Date returns the last update date
func (s *Snap) Date() time.Time {
	st, err := os.Stat(s.basedir)
	if err != nil {
		return time.Time{}
	}

	return st.ModTime()
}

// Apps return a list of AppsYamls the package declares
func (s *Snap) Apps() map[string]*AppYaml {
	return s.m.Apps
}

// GadgetConfig return a list of packages to configure
func (s *Snap) GadgetConfig() SystemConfig {
	return s.m.Config
}

// Install installs the snap (which does not make sense for an already
// installed snap
func (s *Snap) Install(inter progress.Meter, flags InstallFlags) (name string, err error) {
	return "", ErrAlreadyInstalled
}

// NeedsReboot returns true if the snap becomes active on the next reboot
func (s *Snap) NeedsReboot() bool {
	return kernelOrOsRebootRequired(s)
}
