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
)

var dbusBindPermanentSlotAppArmor = []byte(`
# Description: Allow owning a name on DBus public bus
# Usage: common

# DBus accesses
# FIXME
#include <abstractions/dbus-session-strict>

# register and bind to a well-known DBus name
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

dbus (bind)
    bus=###DBUS_BIND_BUS###
    name=###DBUS_BIND_NAME###,

# Allow us to talk to dbus-daemon
dbus (receive)
    bus=###DBUS_BIND_BUS###
    path=###DBUS_BIND_PATH###
    peer=(name=org.freedesktop.DBus, label=unconfined),
dbus (send)
    bus=###DBUS_BIND_BUS###
    path=###DBUS_BIND_PATH###
    interface=org.freedesktop.DBus.Properties
    peer=(name=org.freedesktop.DBus, label=unconfined),

# TODO: allow unconfined clients talk to us
`)

var dbusBindPermanentSlotSecComp = []byte(`
# Description: Allow owning a name on DBus public bus
# Usage: common

getsockname
recvmsg
sendmsg
sendto
`)

var dbusBindConnectedSlotAppArmor = []byte(`
# Description: Allow DBus consumer to connect to us
# FIXME
#include <abstractions/dbus-session-strict>

# Communicate with the well-known named DBus service
dbus (receive, send)
    bus=###DBUS_BIND_BUS###
    path=###DBUS_BIND_PATH###
    peer=(label=###PLUG_SECURITY_TAGS###),
`)


var dbusBindConnectedPlugAppArmor = []byte(`
# Description: Allow connecting to DBus service on well-known name
# Usage: common

# DBus accesses
#include <abstractions/dbus-session-strict>

# Communicate with the well-known named DBus service
dbus (receive, send)
    bus=###DBUS_BIND_BUS###
    path=###DBUS_BIND_PATH###
    peer=(label=###SLOT_SECURITY_TAGS###),
`)

var dbusBindConnectedPlugSecComp = []byte(`
getsockname
recvmsg
sendmsg
sendto
`)

type DbusBindInterface struct{}

func (iface *DbusBindInterface) Name() string {
	return "dbus-bind"
}

func (iface *DbusBindInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *DbusBindInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		old := []byte("###DBUS_BIND_BUS###")
		new := []byte(slot.Attrs["bus"].(string))
		snippet := bytes.Replace(dbusBindConnectedPlugAppArmor, old, new, -1)

		old = []byte("###DBUS_BIND_NAME###")
		new = []byte(slot.Attrs["name"].(string))
		snippet = bytes.Replace(snippet, old, new, -1)

		// convert name to AppArmor dbus path
		dot_re := regexp.MustCompile("\\.")
		var path_buf bytes.Buffer
		path_buf.WriteString(`"/`)
		path_buf.WriteString(dot_re.ReplaceAllString(slot.Attrs["name"].(string), "/"))
		path_buf.WriteString(`{,/**}"`)

		old = []byte("###DBUS_BIND_PATH###")
		new = path_buf.Bytes()
		snippet = bytes.Replace(snippet, old, new, -1)

		old = []byte("###SLOT_SECURITY_TAGS###")
		new = slotAppLabelExpr(slot)
		snippet = bytes.Replace(snippet, old, new, -1)

		//fmt.Printf("CONNECTED PLUG:\n %s\n", snippet)
		return snippet, nil
	case interfaces.SecuritySecComp:
		return dbusBindPermanentSlotSecComp, nil
	case interfaces.SecurityDBus, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *DbusBindInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	dbusBindBusNames, err := getBusNames(slot)
	if err != nil {
		return nil, err
	}
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		var snippets bytes.Buffer
		snippets.WriteString(``)
		for bus, names := range dbusBindBusNames {
			fmt.Printf("DEBUG1: %s\n", bus)
			for _, name := range names {
				fmt.Printf("DEBUG2: %s\n", name)
				old := []byte("###DBUS_BIND_BUS###")
				new := []byte(bus)
				snippet := bytes.Replace(dbusBindPermanentSlotAppArmor, old, new, -1)

				old = []byte("###DBUS_BIND_NAME###")
				new = []byte(name)
				snippet = bytes.Replace(snippet, old, new, -1)

				// convert name to AppArmor dbus path
				dot_re := regexp.MustCompile("\\.")
				var path_buf bytes.Buffer
				path_buf.WriteString(`"/`)
				path_buf.WriteString(dot_re.ReplaceAllString(name, "/"))
				path_buf.WriteString(`{,/**}"`)

				old = []byte("###DBUS_BIND_PATH###")
				new = path_buf.Bytes()
				snippet = bytes.Replace(snippet, old, new, -1)

				snippets.Write(snippet)
			}
		}
		fmt.Printf("PERMANENT SLOT:\n %s\n", snippets.Bytes())
		return snippets.Bytes(), nil
	case interfaces.SecuritySecComp:
		return dbusBindPermanentSlotSecComp, nil
	case interfaces.SecurityDBus, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *DbusBindInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		old := []byte("###DBUS_BIND_BUS###")
		new := []byte(slot.Attrs["bus"].(string))
		snippet := bytes.Replace(dbusBindConnectedSlotAppArmor, old, new, -1)

		// TODO: break this out
		// convert name to AppArmor dbus path
		dot_re := regexp.MustCompile("\\.")
		var path_buf bytes.Buffer
		path_buf.WriteString(`"/`)
		path_buf.WriteString(dot_re.ReplaceAllString(slot.Attrs["name"].(string), "/"))
		path_buf.WriteString(`{,/**}"`)

		old = []byte("###DBUS_BIND_PATH###")
		new = path_buf.Bytes()
		snippet = bytes.Replace(snippet, old, new, -1)

		old = []byte("###PLUG_SECURITY_TAGS###")
		new = plugAppLabelExpr(plug)
		snippet = bytes.Replace(snippet, old, new, -1)

		//fmt.Printf("CONNECTED SLOT:\n %s\n", snippet)
		return snippet, nil
	case interfaces.SecurityDBus, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func getBusNames(slot *interfaces.Slot) (map[string][]string, error) {
	busNames := make(map[string][]string)
	for attr := range slot.Attrs {
		bus := attr
		if bus != "session" && bus != "system" {
			return nil, fmt.Errorf("bus must be one of 'session' or 'system'")
		}
		busNamesList, ok := slot.Attrs[bus].([]interface{})
		if !ok {
			return nil, fmt.Errorf("bus attribute is not a list")
		}

		for _, item := range busNamesList {
			busName, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("session element is not a string")
			}

			// https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-names
			if !ok || len(busName) == 0 {
				return nil, fmt.Errorf("bus name must be set")
			} else if len(busName) > 255 {
				return nil, fmt.Errorf("bus name is too long (must be <= 255)")
			}

			validBusName := regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9_-]*(\\.[a-zA-Z0-9_-]+)+$")
			if !validBusName.MatchString(busName) {
				return nil, fmt.Errorf("invalid bus name: %q", busName)
			}

			busNames[bus] = append(busNames[bus], busName)
		}
	}

	return busNames, nil
}

func (iface *DbusBindInterface) SanitizePlug(slot *interfaces.Plug) error {
	return nil
}

func (iface *DbusBindInterface) SanitizeSlot(slot *interfaces.Slot) error {
	if iface.Name() != slot.Interface {
		panic(fmt.Sprintf("slot is not of interface %q", iface))
	}

	_, err := getBusNames(slot)
	return err
}

func (iface *DbusBindInterface) AutoConnect() bool {
	return true
}
