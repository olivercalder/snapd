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

package release

import (
	"bufio"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Series holds the Ubuntu Core series for snapd to use.
var Series = "16"

// OS contains information about the system extracted from /etc/os-release.
type OS struct {
	ID        string `json:"id"`
	VersionID string `json:"version-id,omitempty"`
}

var (
	apparmorFeaturesSysPath  = "/sys/kernel/security/apparmor/features"
	requiredApparmorFeatures = []string{
		"caps",
		"dbus",
		"domain",
		"file",
		"mount",
		"namespaces",
		"network",
		"ptrace",
		"signal",
	}
)

// ForceDevMode returns true if the distribution doesn't implement required
// security features for confinement and devmode is forced.
func (o *OS) ForceDevMode() bool {
	for _, req := range requiredApparmorFeatures {
		// Also ensure appamor is enabled (cannot use
		// osutil.FileExists() here because of cyclic imports)
		p := filepath.Join(apparmorFeaturesSysPath, req)
		if _, err := os.Stat(p); err != nil {
			return true
		}
	}

	return false
}

func (o *OS) SupportsClassicSnaps() bool {
	switch o.ID {
	case "fedora", "rhel", "centos":
		return false
	}
	return true
}

var (
	osReleasePath         = "/etc/os-release"
	fallbackOsReleasePath = "/usr/lib/os-release"
)

// readOSRelease returns the os-release information of the current system.
func readOSRelease() OS {
	// TODO: separate this out into its own thing maybe (if made more general)
	osRelease := OS{
		VersionID: "unknown",
		// from os-release(5): If not set, defaults to "ID=linux".
		ID: "linux",
	}

	f, err := os.Open(osReleasePath)
	if err != nil {
		// this fallback is as per os-release(5)
		f, err = os.Open(fallbackOsReleasePath)
		if err != nil {
			return osRelease
		}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ws := strings.SplitN(scanner.Text(), "=", 2)
		if len(ws) < 2 {
			continue
		}

		k := strings.TrimSpace(ws[0])
		v := strings.TrimFunc(ws[1], func(r rune) bool { return r == '"' || r == '\'' || unicode.IsSpace(r) })
		// XXX: should also unquote things as per os-release(5) but not needed yet in practice
		switch k {
		case "ID":
			// ID should be “A lower-case string (no spaces or
			// other characters outside of 0–9, a–z, ".", "_" and
			// "-") identifying the operating system, excluding any
			// version information and suitable for processing by
			// scripts or usage in generated filenames.”
			//
			// So we mangle it a little bit to account for people
			// not being too good at reading comprehension.
			// Works around e.g. lp:1602317
			osRelease.ID = strings.Fields(strings.ToLower(v))[0]
		case "VERSION_ID":
			osRelease.VersionID = v
		}
	}

	return osRelease
}

// OnClassic states whether the process is running inside a
// classic Ubuntu system or a native Ubuntu Core image.
var OnClassic bool

// ReleaseInfo contains data loaded from /etc/os-release on startup.
var ReleaseInfo OS

func init() {
	ReleaseInfo = readOSRelease()

	OnClassic = (ReleaseInfo.ID != "ubuntu-core")
}

// MockOnClassic forces the process to appear inside a classic
// Ubuntu system or a native image for testing purposes.
func MockOnClassic(onClassic bool) (restore func()) {
	old := OnClassic
	OnClassic = onClassic
	return func() { OnClassic = old }
}

// MockReleaseInfo fakes a given information to appear in ReleaseInfo,
// as if it was read /etc/os-release on startup.
func MockReleaseInfo(osRelease *OS) (restore func()) {
	old := ReleaseInfo
	ReleaseInfo = *osRelease
	return func() { ReleaseInfo = old }
}

// MockForcedDevmode fake the system to believe its in a distro
// that is in ForcedDevmode
func MockForcedDevmode(isDevmode bool) (restore func()) {
	oldApparmorFeaturesSysPath := apparmorFeaturesSysPath

	temp, err := ioutil.TempDir("", "mock-forced-devmode")
	if err != nil {
		panic(err)
	}
	fakeApparmorFeaturesSysPath := filepath.Join(temp, "apparmor")
	if !isDevmode {
		for _, req := range requiredApparmorFeatures {
			if err := os.MkdirAll(filepath.Join(fakeApparmorFeaturesSysPath, req), 0755); err != nil {
				panic(err)
			}
		}
	}
	apparmorFeaturesSysPath = fakeApparmorFeaturesSysPath

	return func() {
		if err := os.RemoveAll(temp); err != nil {
			panic(err)
		}
		apparmorFeaturesSysPath = oldApparmorFeaturesSysPath
	}
}
