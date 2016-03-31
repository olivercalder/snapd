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

// Package dbus implements interaction between snappy and dbus.
//
// Snappy creates dbus configuration files that describe how various
// services on the system bus can communicate with other peers.
//
// Each configuration is an XML file containing <busconfig>...</busconfig>.
// Particular security snippets define whole <policy>...</policy> entires.
// This is explained in detail in https://dbus.freedesktop.org/doc/dbus-daemon.1.html
package dbus

import (
	"bytes"
	"fmt"

	"github.com/ubuntu-core/snappy/dirs"
	"github.com/ubuntu-core/snappy/interfaces"
	"github.com/ubuntu-core/snappy/osutil"
	"github.com/ubuntu-core/snappy/snap"
)

// Backend is responsible for maintaining DBus policy files.
type Backend struct{}

// Configure creates dbus configuration files specific to a given snap.
//
// DBus has no concept of a complain mode, developerMode is ignored.
func (b *Backend) Configure(snapInfo *snap.Info, developerMode bool, repo *interfaces.Repository) error {
	// Get the snippets that apply to this snap
	snippets, err := repo.SecuritySnippetsForSnap(snapInfo.Name, interfaces.SecurityDBus)
	if err != nil {
		return fmt.Errorf("cannot obtain DBus security snippets for snap %q: %s", snapInfo.Name, err)
	}
	// Get the files that this snap should have
	content, err := b.combineSnippets(snapInfo, developerMode, snippets)
	if err != nil {
		return fmt.Errorf("cannot obtain expected DBus configuration files for snap %q: %s", snapInfo.Name, err)
	}
	glob := fmt.Sprintf("%s.conf", interfaces.SecurityTagGlob(snapInfo))
	_, _, err = osutil.EnsureDirState(dirs.SnapBusPolicyDir, glob, content)
	if err != nil {
		return fmt.Errorf("cannot synchronize DBus configuration files for snap %q: %s", snapInfo.Name, err)
	}
	return nil
}

// Deconfigure removes security artefacts of a given snap.
//
// This method should be called after removing a snap.
func (b *Backend) Deconfigure(snapInfo *snap.Info) error {
	glob := fmt.Sprintf("%s.conf", interfaces.SecurityTagGlob(snapInfo))
	_, _, err := osutil.EnsureDirState(dirs.SnapBusPolicyDir, glob, nil)
	if err != nil {
		return fmt.Errorf("cannot synchronize DBus configuration files for snap %q: %s", snapInfo.Name, err)
	}
	return nil
}

// combineSnippets combines security snippets collected from all the interfaces
// affecting a given snap into a content map applicable to EnsureDirState.
func (b *Backend) combineSnippets(snapInfo *snap.Info, developerMode bool, snippets map[string][][]byte) (content map[string]*osutil.FileState, err error) {
	for _, appInfo := range snapInfo.Apps {
		if len(snippets[appInfo.Name]) > 0 {
			var buf bytes.Buffer
			buf.Write(xmlHeader)
			for _, snippet := range snippets[appInfo.Name] {
				buf.Write(snippet)
				buf.WriteRune('\n')
			}
			buf.Write(xmlFooter)
			if content == nil {
				content = make(map[string]*osutil.FileState)
			}
			fname := fmt.Sprintf("%s.conf", interfaces.SecurityTag(appInfo))
			content[fname] = &osutil.FileState{Content: buf.Bytes(), Mode: 0644}
		}
	}
	return content, nil
}
