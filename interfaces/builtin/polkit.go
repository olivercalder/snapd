// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package builtin

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/polkit"
	"github.com/snapcore/snapd/snap"
)

const polkitSummary = `allows access to polkitd to check authorisation`

const polkitBaseDeclarationPlugs = `
  polkit:
    allow-installation: false
    deny-auto-connection: true
`

const polkitBaseDeclarationSlots = `
  polkit:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const polkitConnectedPlugAppArmor = `
# Description: Can talk to polkitd's CheckAuthorization API

#include <abstractions/dbus-strict>

dbus (send)
    bus=system
    path="/org/freedesktop/PolicyKit1/Authority"
    interface="org.freedesktop.PolicyKit1.Authority"
    member="{,Cancel}CheckAuthorization"
    peer=(name="org.freedesktop.PolicyKit1", label=unconfined),
dbus (send)
    bus=system
    path="/org/freedesktop/PolicyKit1/Authority"
    interface="org.freedesktop.DBus.Properties"
    peer=(name="org.freedesktop.PolicyKit1", label=unconfined),
dbus (send)
    bus=system
    path="/org/freedesktop/PolicyKit1/Authority"
    interface="org.freedesktop.DBus.Introspectable"
    member="Introspect"
    peer=(name="org.freedesktop.PolicyKit1", label=unconfined),
`

type polkitInterface struct {
	commonInterface
}

func (iface *polkitInterface) getActionPrefix(attribs interfaces.Attrer) (string, error) {
	var prefix string
	if err := attribs.Attr("action-prefix", &prefix); err != nil {
		return "", err
	}
	if err := interfaces.ValidateDBusBusName(prefix); err != nil {
		return "", fmt.Errorf("plug has invalid action-prefix: %q", prefix)
	}
	return prefix, nil
}

func (iface *polkitInterface) PolkitConnectedPlug(spec *polkit.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	_, err := iface.getActionPrefix(plug)
	if err != nil {
		return err
	}

	mountDir := plug.Snap().MountDir()
	policyFiles, err := filepath.Glob(filepath.Join(mountDir, "meta", plug.Name()+".*.policy"))
	if err != nil {
		return err
	}
	if len(policyFiles) == 0 {
		return fmt.Errorf("could not find any policy files for plug %q", plug.Name())
	}
	for _, filename := range policyFiles {
		suffix := strings.TrimSuffix(filepath.Base(filename), ".policy")
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			return fmt.Errorf(`could not read file %q: %v`, filename, err)
		}
		if err := spec.AddPolicy(suffix, polkit.Policy(content)); err != nil {
			return err
		}
	}
	return nil
}

func (iface *polkitInterface) BeforePreparePlug(plug *snap.PlugInfo) error {
	_, err := iface.getActionPrefix(plug)
	return err
}

func init() {
	registerIface(&polkitInterface{
		commonInterface{
			name:                  "polkit",
			summary:               polkitSummary,
			implicitOnCore:        false,
			implicitOnClassic:     true,
			baseDeclarationPlugs:  polkitBaseDeclarationPlugs,
			baseDeclarationSlots:  polkitBaseDeclarationSlots,
			connectedPlugAppArmor: polkitConnectedPlugAppArmor,
		},
	})
}
