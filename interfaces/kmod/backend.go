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

// Package kmod implements a backend which loads kernel modules on behalf of
// interfaces.
//
// Interfaces may request kernel modules to be loaded by providing snippets via
// their respective "*Snippet" methods for interfaces.SecurityKMod security
// system. The snippet should contain a newline-separated list of requested
// kernel modules. The KMod backend stores all the modules needed by given
// snap in /etc/modules-load.d/snap.<snapname>.conf file ensuring they are
// loaded when the system boots and also loads these modules via modprobe.
// If a snap is uninstalled or respective interface gets disconnected, the
// corresponding /etc/modules-load.d/ config file gets removed, however no
// kernel modules are unloaded. This is by design.
//
// Note: this mechanism should not be confused with kernel-module-interface;
// kmod only loads a well-defined list of modules provided by interface definition
// and doesn't grant any special permissions related to kernel modules to snaps,
// in contrast to kernel-module-interface.
package kmod

import (
	"bytes"
	"fmt"
	"os"
	"sort"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/timings"
)

// Backend is responsible for maintaining kernel modules
type Backend struct{}

// Initialize does nothing.
func (b *Backend) Initialize() error {
	return nil
}

// Name returns the name of the backend.
func (b *Backend) Name() interfaces.SecuritySystem {
	return "kmod"
}

// Setup creates a conf file with list of kernel modules required by given snap,
// writes it in /etc/modules-load.d/ directory and immediately loads the modules
// using /sbin/modprobe. The devMode is ignored.
//
// If the method fails it should be re-tried (with a sensible strategy) by the caller.
func (b *Backend) Setup(snapInfo *snap.Info, confinement interfaces.ConfinementOptions, repo *interfaces.Repository, tm timings.Measurer) error {
	snapName := snapInfo.InstanceName()
	// Get the snippets that apply to this snap
	spec, err := repo.SnapSpecification(b.Name(), snapName)
	if err != nil {
		return fmt.Errorf("cannot obtain kmod specification for snap %q: %s", snapName, err)
	}

	content, modules := deriveContent(spec.(*Specification), snapInfo)
	// synchronize the content with the filesystem
	glob := interfaces.SecurityTagGlob(snapName)
	dir := dirs.SnapKModModulesDir
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create directory for kmod files %q: %s", dir, err)
	}

	changed, _, err := osutil.EnsureDirState(dirs.SnapKModModulesDir, glob, content)
	if err != nil {
		return err
	}

	if len(changed) > 0 {
		loadModules(modules)
	}
	return nil
}

// Remove removes modules config file specific to a given snap.
//
// This method should be called after removing a snap.
//
// If the method fails it should be re-tried (with a sensible strategy) by the caller.
func (b *Backend) Remove(snapName string) error {
	glob := interfaces.SecurityTagGlob(snapName)
	_, _, err := osutil.EnsureDirState(dirs.SnapKModModulesDir, glob, nil)
	return err
}

func deriveContent(spec *Specification, snapInfo *snap.Info) (map[string]osutil.FileState, []string) {
	if len(spec.modules) == 0 {
		return nil, nil
	}
	content := make(map[string]osutil.FileState)
	var modules []string
	for k := range spec.modules {
		modules = append(modules, k)
	}
	sort.Strings(modules)

	var buffer bytes.Buffer
	buffer.WriteString("# This file is automatically generated.\n")
	for _, module := range modules {
		buffer.WriteString(module)
		buffer.WriteRune('\n')
	}
	content[fmt.Sprintf("%s.conf", snap.SecurityTag(snapInfo.InstanceName()))] = &osutil.MemoryFileState{
		Content: buffer.Bytes(),
		Mode:    0644,
	}
	return content, modules
}

func (b *Backend) NewSpecification() interfaces.Specification {
	return &Specification{}
}

// SandboxFeatures returns the list of features supported by snapd for loading kernel modules.
func (b *Backend) SandboxFeatures() []string {
	return []string{"mediated-modprobe"}
}
