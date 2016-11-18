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

package builtin

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/release"
)

const dbusPermanentSlotAppArmor = `
# Description: Allow owning a name on DBus public bus

#include <abstractions/###DBUS_ABSTRACTION###>

# register on DBus
dbus (send)
    bus=system
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member="{Request,Release}Name"
    peer=(name=org.freedesktop.DBus, label=unconfined),

dbus (send)
    bus=system
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member="GetConnectionUnix{ProcessID,User}"
    peer=(name=org.freedesktop.DBus, label=unconfined),

# bind to a well-known DBus name: ###DBUS_NAME###
dbus (bind)
    bus=###DBUS_BUS###
    name=###DBUS_NAME###,

# Allow us to talk to dbus-daemon
dbus (receive)
    bus=###DBUS_BUS###
    path=###DBUS_PATH###
    peer=(name=org.freedesktop.DBus, label=unconfined),
dbus (send)
    bus=###DBUS_BUS###
    path=###DBUS_PATH###
    interface=org.freedesktop.DBus.Properties
    peer=(name=org.freedesktop.DBus, label=unconfined),
`

const dbusPermanentSlotAppArmorClassic = `
# allow unconfined clients talk to ###DBUS_NAME### on classic
dbus (receive, send)
    bus=###DBUS_BUS###
    path=###DBUS_PATH###
    interface=###DBUS_INTERFACE###
    peer=(label=unconfined),
`

const dbusPermanentSlotSecComp = `
# Description: Allow owning a name on DBus public bus
getsockname
recvmsg
sendmsg
sendto
`

const dbusConnectedSlotAppArmor = `
# allow snaps to introspect us. This allows clients to see all the interfaces
# supported by the service, but only use the specified interface.
dbus (receive)
    bus=###DBUS_BUS###
    interface=org.freedesktop.DBus.Introspectable
    peer=(label=###PLUG_SECURITY_TAGS###),

# allow snaps to ###DBUS_NAME###
dbus (receive, send)
    bus=###DBUS_BUS###
    path=###DBUS_PATH###
    interface=###DBUS_INTERFACE###
    peer=(label=###PLUG_SECURITY_TAGS###),
`

const dbusConnectedPlugAppArmor = `
# allow snaps to introspect us. This allows clients to see all the interfaces
# supported by the service, but only use the specified interface.
dbus (send)
    bus=###DBUS_BUS###
    interface=org.freedesktop.DBus.Introspectable
    peer=(label=###SLOT_SECURITY_TAGS###),

# allow snaps to ###DBUS_NAME###
dbus (receive, send)
    bus=###DBUS_BUS###
    path=###DBUS_PATH###
    interface=###DBUS_INTERFACE###
    peer=(label=###SLOT_SECURITY_TAGS###),
`

const dbusConnectedPlugSecComp = `
getsockname
recvmsg
sendmsg
sendto
`

type DbusInterface struct{}

func (iface *DbusInterface) Name() string {
	return "dbus"
}

// Obtain yaml-specified bus well-known name
func (iface *DbusInterface) getAttribs(attribs map[string]interface{}) (string, string, error) {
	bus := ""
	name := ""
	for attr := range attribs {
		if attr != "bus" && attr != "name" {
			return "", "", fmt.Errorf("unknown attribute '%s'", attr)
		}

		raw, ok := attribs[attr]
		if !ok {
			return "", "", fmt.Errorf("cannot find attribute %q", attr)
		}
		val, ok := raw.(string)
		if !ok {
			return "", "", fmt.Errorf("element %v for '%s' is not a string", raw, attr)
		}

		if attr == "bus" {
			if val != "session" && val != "system" {
				return "", "", fmt.Errorf("bus '%s' must be one of 'session' or 'system'", val)
			}
			bus = val
		} else if attr == "name" {
			err := interfaces.ValidateDBusBusName(val)
			if err != nil {
				return "", "", err
			}
			name = val
		}
	}

	if bus == "" {
		return "", "", fmt.Errorf("required attribute 'bus' not specified")
	} else if name == "" {
		return "", "", fmt.Errorf("required attribute 'name' not specified")
	}

	return bus, name, nil
}

// Determine AppArmor dbus abstraction to use based on bus
func getAppArmorAbstraction(bus string) (string, error) {
	var abstraction string
	if bus == "system" {
		abstraction = "dbus-strict"
	} else if bus == "session" {
		abstraction = "dbus-session-strict"
	} else {
		return "", fmt.Errorf("unknown abstraction for specified bus '%q'", bus)
	}
	return abstraction, nil
}

// Calculate individual snippet policy based on bus and name
func getAppArmorSnippet(policy []byte, bus string, name string) []byte {
	old := []byte("###DBUS_BUS###")
	new := []byte(bus)
	snippet := bytes.Replace(policy, old, new, -1)

	old = []byte("###DBUS_NAME###")
	new = []byte(name)
	snippet = bytes.Replace(snippet, old, new, -1)

	// convert name to AppArmor dbus path (eg 'org.foo' to '/org/foo{,/**}')
	dot_re := regexp.MustCompile("\\.")
	var pathBuf bytes.Buffer
	pathBuf.WriteString(`"/`)
	pathBuf.WriteString(dot_re.ReplaceAllString(name, "/"))
	pathBuf.WriteString(`{,/**}"`)

	old = []byte("###DBUS_PATH###")
	new = pathBuf.Bytes()
	snippet = bytes.Replace(snippet, old, new, -1)

	// convert name to AppArmor dbus interface (eg, 'org.foo' to 'org.foo{,.*}')
	var ifaceBuf bytes.Buffer
	ifaceBuf.WriteString(`"`)
	ifaceBuf.WriteString(name)
	ifaceBuf.WriteString(`{,.*}"`)

	old = []byte("###DBUS_INTERFACE###")
	new = ifaceBuf.Bytes()
	snippet = bytes.Replace(snippet, old, new, -1)

	return snippet
}

func (iface *DbusInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	return nil, nil
}

func (iface *DbusInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		bus, name, err := iface.getAttribs(plug.Attrs)
		if err != nil {
			return nil, err
		}

		// well-known DBus name-specific connected plug policy
		snippet := getAppArmorSnippet([]byte(dbusConnectedPlugAppArmor), bus, name)

		old := []byte("###SLOT_SECURITY_TAGS###")
		new := slotAppLabelExpr(slot)
		snippet = bytes.Replace(snippet, old, new, -1)

		//fmt.Printf("DEBUG - CONNECTED PLUG:\n %s\n", snippet)
		return snippet, nil
	case interfaces.SecuritySecComp:
		return []byte(dbusConnectedPlugSecComp), nil
	}
	return nil, nil
}

func (iface *DbusInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		bus, name, err := iface.getAttribs(slot.Attrs)
		if err != nil {
			return nil, err
		}

		snippets := bytes.NewBufferString("")

		// common permanent slot policy
		abstraction, err := getAppArmorAbstraction(bus)
		if err != nil {
			return nil, err
		}

		// well-known DBus name-specific permanent slot policy
		snippet := getAppArmorSnippet([]byte(dbusPermanentSlotAppArmor), bus, name)

		old := []byte("###DBUS_ABSTRACTION###")
		new := []byte(abstraction)
		snippet = bytes.Replace(snippet, old, new, -1)

		snippets.Write(snippet)

		if release.OnClassic {
			// classic-only policy
			snippets.Write(getAppArmorSnippet([]byte(dbusPermanentSlotAppArmorClassic), bus, name))
		}
		//fmt.Printf("DEBUG - PERMANENT SLOT:\n %s\n", snippets.Bytes())
		return snippets.Bytes(), nil
	case interfaces.SecuritySecComp:
		return []byte(dbusPermanentSlotSecComp), nil
	}
	return nil, nil
}

func (iface *DbusInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		bus, name, err := iface.getAttribs(slot.Attrs)
		if err != nil {
			return nil, err
		}

		// well-known DBus name-specific connected slot policy
		snippet := getAppArmorSnippet([]byte(dbusConnectedSlotAppArmor), bus, name)

		old := []byte("###PLUG_SECURITY_TAGS###")
		new := plugAppLabelExpr(plug)
		snippet = bytes.Replace(snippet, old, new, -1)

		//fmt.Printf("DEBUG - CONNECTED SLOT:\n %s\n", snippet)
		return snippet, nil
	}
	return nil, nil
}

func (iface *DbusInterface) SanitizePlug(plug *interfaces.Plug) error {
	if iface.Name() != plug.Interface {
		panic(fmt.Sprintf("plug is not of interface %q", iface))
	}

	_, _, err := iface.getAttribs(plug.Attrs)
	return err
}

func (iface *DbusInterface) SanitizeSlot(slot *interfaces.Slot) error {
	if iface.Name() != slot.Interface {
		panic(fmt.Sprintf("slot is not of interface %q", iface))
	}

	_, _, err := iface.getAttribs(slot.Attrs)
	return err
}

// Since we only implement the permanent slot side, this is meaningless but
// we have to supply the method, so set it to something safe.
func (iface *DbusInterface) AutoConnect(*interfaces.Plug, *interfaces.Slot) bool {
	// allow what declarations allowed
	return true
}
