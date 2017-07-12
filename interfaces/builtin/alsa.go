// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017 Canonical Ltd
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

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/udev"
)

const alsaSummary = `allows access to raw ALSA devices`

const alsaDescription = `
The alsa interface allows connected plugs to access raw ALSA devices.

The core snap provides the slot that is shared by all the snaps.
`

const alsaBaseDeclarationSlots = `
  alsa:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const alsaConnectedPlugAppArmor = `
# Description: Allow access to raw ALSA devices.

/dev/snd/  r,
/dev/snd/* rw,

/run/udev/data/c116:[0-9]* r, # alsa

# Allow access to the alsa state dir
/var/lib/alsa/{,*}         r,
`

const alsaConnectedPlugUdev = `
# This file contains udev rules for alsa devices.
#
# Do not edit this file, it will be overwritten on updates

KERNEL=="controlC[0-9]*", NAME="snd/%%k", TAG+="%[1]s"
KERNEL=="hw[CD0-9]*",     NAME="snd/%%k", TAG+="%[1]s"
KERNEL=="pcm[CD0-9cp]*",  NAME="snd/%%k", TAG+="%[1]s"
KERNEL=="midiC[D0-9]*",   NAME="snd/%%k", TAG+="%[1]s"
KERNEL=="timer",          NAME="snd/%%k", TAG+="%[1]s"
KERNEL=="seq",            NAME="snd/%%k", TAG+="%[1]s"
`

// The type for alsa interface
type alsaInterface struct{}

// Getter for the name of the alsa interface
func (iface *alsaInterface) Name() string {
	return "alsa"
}

func (iface *alsaInterface) MetaData() interfaces.MetaData {
	return interfaces.MetaData{
		Summary:              alsaSummary,
		Description:          alsaDescription,
		ImplicitOnCore:       true,
		ImplicitOnClassic:    true,
		BaseDeclarationSlots: alsaBaseDeclarationSlots,
	}
}

func (iface *alsaInterface) String() string {
	return iface.Name()
}

// Check validity of the defined slot
func (iface *alsaInterface) SanitizeSlot(slot *interfaces.Slot) error {
	// Does it have right type?
	if iface.Name() != slot.Interface {
		panic(fmt.Sprintf("slot is not of interface %q", iface))
	}

	// Creation of the slot of this type
	// is allowed only by a gadget or os snap
	if !(slot.Snap.Type == "os") {
		return fmt.Errorf("%s slots are reserved for the operating system snap", iface.Name())
	}
	return nil
}

// Checks and possibly modifies a plug
func (iface *alsaInterface) SanitizePlug(plug *interfaces.Plug) error {
	if iface.Name() != plug.Interface {
		panic(fmt.Sprintf("plug is not of interface %q", iface))
	}
	// Currently nothing is checked on the plug side
	return nil
}

func (iface *alsaInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	spec.AddSnippet(alsaConnectedPlugAppArmor)
	return nil
}

func (iface *alsaInterface) UDevConnectedPlug(spec *udev.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	for appName := range plug.Apps {
		tag := udevSnapSecurityName(plug.Snap.Name(), appName)
		spec.AddSnippet(fmt.Sprintf(alsaConnectedPlugUdev, tag))
	}
	return nil
}

func (iface *alsaInterface) AutoConnect(*interfaces.Plug, *interfaces.Slot) bool {
	// Allow what is allowed in the declarations
	return true
}

func init() {
	registerIface(&alsaInterface{})
}
