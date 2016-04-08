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

package snappy

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "gopkg.in/check.v1"
	"gopkg.in/yaml.v2"

	"github.com/ubuntu-core/snappy/dirs"
	"github.com/ubuntu-core/snappy/osutil"
	"github.com/ubuntu-core/snappy/snap"
)

const (
	testDeveloper         = "testspacethename"
	fooComposedName       = "foo"
	helloSnapComposedName = "hello-snap"
)

// Hook up check.v1 into the "go test" runner
func Test(t *testing.T) { TestingT(t) }

// here to make it easy to switch in tests to "BuildSquashfsSnap"
var snapBuilderFunc = BuildSquashfsSnap

func init() {
	os.Setenv("SNAPPY_SQUASHFS_UNPACK_FOR_TESTS", "1")
}

// makeInstalledMockSnap creates a installed mock snap without any
// content other than the meta data
func makeInstalledMockSnap(snapYamlContent string) (yamlFile string, err error) {
	const packageHello = `name: hello-snap
version: 1.10
summary: hello
description: Hello...
apps:
 hello:
  command: bin/hello
 svc1:
   command: bin/hello
   stop-command: bin/goodbye
   post-stop-command: bin/missya
   daemon: forking
`
	if snapYamlContent == "" {
		snapYamlContent = packageHello
	}

	var m snapYaml
	if err := yaml.Unmarshal([]byte(snapYamlContent), &m); err != nil {
		return "", err
	}

	metaDir := filepath.Join(dirs.GlobalRootDir, "snaps", m.Name, m.Version, "meta")
	if err := os.MkdirAll(metaDir, 0775); err != nil {
		return "", err
	}
	yamlFile = filepath.Join(metaDir, "snap.yaml")
	if err := ioutil.WriteFile(yamlFile, []byte(snapYamlContent), 0644); err != nil {
		return "", err
	}

	if err := addMockDefaultApparmorProfile("hello-snap_hello_1.10"); err != nil {
		return "", err
	}

	if err := addMockDefaultApparmorProfile("hello-snap_svc1_1.10"); err != nil {
		return "", err
	}

	if err := addMockDefaultSeccompProfile("hello-snap_hello_1.10"); err != nil {
		return "", err
	}

	if err := addMockDefaultSeccompProfile("hello-snap_svc1_1.10"); err != nil {
		return "", err
	}

	hashFile := filepath.Join(metaDir, "hashes.yaml")
	if err := ioutil.WriteFile(hashFile, []byte("{}"), 0644); err != nil {
		return "", err
	}

	if err := storeMinimalRemoteManifest(m.Name, testDeveloper, m.Version, "hello in summary", "Hello...", "remote-channel"); err != nil {
		return "", err
	}

	return yamlFile, nil
}

func storeMinimalRemoteManifest(name, developer, version, summary, desc, channel string) error {
	if developer == SideloadedDeveloper {
		panic("store remote manifest for sideloaded package")
	}
	sideInfo := snap.SideInfo{
		OfficialName:      name,
		Developer:         developer,
		EditedSummary:     summary,
		EditedDescription: desc,
		Channel:           channel,
	}
	return SaveManifest(&snap.Info{Version: version, SideInfo: sideInfo})
}

func addMockDefaultApparmorProfile(appid string) error {
	appArmorDir := dirs.SnapAppArmorDir

	if err := os.MkdirAll(appArmorDir, 0775); err != nil {
		return err
	}

	const securityProfile = `
#include <tunables/global>
profile "foo" (attach_disconnected) {
	#include <abstractions/base>
}`

	apparmorFile := filepath.Join(appArmorDir, appid)
	return ioutil.WriteFile(apparmorFile, []byte(securityProfile), 0644)
}

func addMockDefaultSeccompProfile(appid string) error {
	seccompDir := dirs.SnapSeccompDir

	if err := os.MkdirAll(seccompDir, 0775); err != nil {
		return err
	}

	const securityProfile = `
open
write
connect
`

	seccompFile := filepath.Join(seccompDir, appid)
	return ioutil.WriteFile(seccompFile, []byte(securityProfile), 0644)
}

// makeTestSnapPackage creates a real snap package that can be installed on
// disk using snapYamlContent as its meta/snap.yaml
func makeTestSnapPackage(c *C, snapYamlContent string) (snapPath string) {
	return makeTestSnapPackageFull(c, snapYamlContent, true)
}

func makeTestSnapPackageWithFiles(c *C, snapYamlContent string, files [][]string) (snapPath string) {
	return makeTestSnapPackageFullWithFiles(c, snapYamlContent, true, files)
}

func makeTestSnapPackageFull(c *C, snapYamlContent string, makeLicense bool) (snapPath string) {
	return makeTestSnapPackageFullWithFiles(c, snapYamlContent, makeLicense, [][]string{})
}

func makeTestSnapPackageFullWithFiles(c *C, snapYamlContent string, makeLicense bool, files [][]string) (snapPath string) {
	tmpdir := c.MkDir()
	// content
	os.MkdirAll(filepath.Join(tmpdir, "bin"), 0755)
	content := `#!/bin/sh
echo "hello"`
	exampleBinary := filepath.Join(tmpdir, "bin", "foo")
	ioutil.WriteFile(exampleBinary, []byte(content), 0755)
	// meta
	os.MkdirAll(filepath.Join(tmpdir, "meta"), 0755)
	if snapYamlContent == "" {
		snapYamlContent = `
name: foo
version: 1.0
`
	}
	snapYamlFn := filepath.Join(tmpdir, "meta", "snap.yaml")
	ioutil.WriteFile(snapYamlFn, []byte(snapYamlContent), 0644)
	if makeLicense {
		license := filepath.Join(tmpdir, "meta", "license.txt")
		content = "WTFPL"
		ioutil.WriteFile(license, []byte(content), 0644)
	}

	for _, filenameAndContent := range files {
		filename := filenameAndContent[0]
		content := filenameAndContent[1]
		basedir := filepath.Dir(filepath.Join(tmpdir, filename))
		err := os.MkdirAll(basedir, 0755)
		c.Assert(err, IsNil)
		err = ioutil.WriteFile(filepath.Join(tmpdir, filename), []byte(content), 0644)
		c.Assert(err, IsNil)
	}

	// build it
	err := osutil.ChDir(tmpdir, func() error {
		var err error
		snapPath, err = snapBuilderFunc(tmpdir, "")
		c.Assert(err, IsNil)
		return err
	})
	c.Assert(err, IsNil)
	return filepath.Join(tmpdir, snapPath)
}

// makeTwoTestSnaps creates two real snaps of snap.Type of name
// "foo", with version "1.0" and "2.0", "2.0" being marked as the
// active snap.
func makeTwoTestSnaps(c *C, snapType snap.Type, extra ...string) {
	inter := &MockProgressMeter{}

	snapYamlContent := `name: foo
`
	if len(extra) > 0 {
		snapYamlContent += strings.Join(extra, "\n") + "\n"
	}

	if snapType != snap.TypeApp {
		snapYamlContent += fmt.Sprintf("type: %s\n", snapType)
	}

	snapPath := makeTestSnapPackage(c, snapYamlContent+"version: 1.0")
	_, err := (&Overlord{}).Install(snapPath, AllowUnauthenticated|AllowGadget, inter)
	c.Assert(err, IsNil)
	c.Assert(storeMinimalRemoteManifest("foo", testDeveloper, "1.0", "", "", "remote-channel"), IsNil)

	snapPath = makeTestSnapPackage(c, snapYamlContent+"version: 2.0")
	_, err = (&Overlord{}).Install(snapPath, AllowUnauthenticated|AllowGadget, inter)
	c.Assert(err, IsNil)
	c.Assert(storeMinimalRemoteManifest("foo", testDeveloper, "2.0", "", "", "remote-channel"), IsNil)

	installed, err := (&Overlord{}).Installed()
	c.Assert(err, IsNil)
	c.Assert(installed, HasLen, 2)
}

type MockProgressMeter struct {
	total    float64
	progress []float64
	finished bool
	spin     bool
	spinMsg  string
	written  int
	// Notifier:
	notified []string
	// Agreer:
	intro   string
	license string
	y       bool
}

func (m *MockProgressMeter) Start(pkg string, total float64) {
	m.total = total
}
func (m *MockProgressMeter) Set(current float64) {
	m.progress = append(m.progress, current)
}
func (m *MockProgressMeter) SetTotal(total float64) {
	m.total = total
}
func (m *MockProgressMeter) Spin(msg string) {
	m.spin = true
	m.spinMsg = msg
}
func (m *MockProgressMeter) Write(buf []byte) (n int, err error) {
	m.written += len(buf)
	return len(buf), err
}
func (m *MockProgressMeter) Finished() {
	m.finished = true
}
func (m *MockProgressMeter) Agreed(intro, license string) bool {
	m.intro = intro
	m.license = license
	return m.y
}
func (m *MockProgressMeter) Notify(msg string) {
	m.notified = append(m.notified, msg)
}

// apparmor_parser mocks
func mockRunAppArmorParser(argv ...string) ([]byte, error) {
	return nil, nil
}
