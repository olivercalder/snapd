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
	"github.com/snapcore/snapd/interfaces"
	"path/filepath"
	"regexp"
	"strings"
)

// The type for i2c control interface
type I2cControlInterface struct{}

// Getter for the name of the i2c-control interface
func (iface *I2cControlInterface) Name() string {
	return "i2c-control"
}

func (iface *I2cControlInterface) String() string {
	return iface.Name()
}

// Pattern to match allowed i2c device nodes. It is gonna be used to check the
// validity of the path attributes in case the udev is not used for
// identification
var i2cControlDeviceNodePattern = regexp.MustCompile("^/dev/i2c-[0-9]+$")

// Check validity of the defined slot
func (iface *I2cControlInterface) SanitizeSlot(slot *interfaces.Slot) error {

	// Does it have right type?
	if iface.Name() != slot.Interface {
		panic(fmt.Sprintf("slot is not of interface %q", iface))
	}

	// Creation of the slot of this type
	// is allowed only by a gadget snap
	if slot.Snap.Type != "gadget" {
		return fmt.Errorf("%s slots only allowed on gadget snaps", iface.Name())
	}

	// Validate the path
	path, ok := slot.Attrs["path"].(string)
	if !ok || path == "" {
		return fmt.Errorf("%s slot must have a path attribute", iface.Name())
	}

	path = filepath.Clean(path)

	if !i2cControlDeviceNodePattern.MatchString(path) {
		return fmt.Errorf("%s path attribute must be a valid device node", iface.Name())
	}

	return nil
}

// Checks and possibly modifies a plug
func (iface *I2cControlInterface) SanitizePlug(plug *interfaces.Plug) error {
	if iface.Name() != plug.Interface {
		panic(fmt.Sprintf("plug is not of interface %q", iface))
	}
	// Currently nothing is checked on the plug side
	return nil
}

// Returns snippet granted on install
func (iface *I2cControlInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	return nil, nil
}

// Getter for the security snippet specific to the plug
func (iface *I2cControlInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	path, pathOk := slot.Attrs["path"].(string)
	if !pathOk {
		return nil, nil
	}
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		cleanedPath := filepath.Clean(path)
		return []byte(fmt.Sprintf("%s rw,\n", cleanedPath)), nil

	case interfaces.SecurityUDev:
		const udevRule string = `KERNEL="%s", TAG+="snap_%s_%s"`
		var udevSnippet bytes.Buffer
		for appName := range plug.Apps {
			rule := fmt.Sprintf(udevRule, strings.TrimPrefix(path, "/dev/"), plug.Snap.Name(), appName)
			udevSnippet.WriteString(fmt.Sprintf("%s\n", rule))
		}
		return udevSnippet.Bytes(), nil
	}
	return nil, nil
}

// No extra permissions granted on connection
func (iface *I2cControlInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	return nil, nil
}

// No permissions granted to plug permanently
func (iface *I2cControlInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	return nil, nil
}

func (iface *I2cControlInterface) LegacyAutoConnect() bool {
	return false
}

func (iface *I2cControlInterface) AutoConnect(*interfaces.Plug, *interfaces.Slot) bool {
	// Allow what is allowed in the declarations
	return true
}
