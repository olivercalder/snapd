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
	"github.com/snapcore/snapd/snap"
)

const hardwareRandomObserveConnectedPlugAppArmor = `
# Description: allow direct access to the hardware random number generator device. Usually,
# the default access to /dev/random is sufficient, but this allows applications such as rng-tools
# to use /dev/hwrng directly or change the hwrng via sysfs. For details, see
# https://www.kernel.org/doc/Documentation/hw_random.txt

/dev/hwrng r,
/sys/devices/virtual/misc/ r,
/sys/devices/virtual/misc/hw_random/rng_{available,current} r,
/run/udev/data/c10:183 r,
`

// The type for physical-memory-control interface
type HardwareRandomObserveInterface struct{}

// Getter for the name of the physical-memory-control interface
func (iface *HardwareRandomObserveInterface) Name() string {
	return "hardware-random-observe"
}

// Check validity of the defined slot
func (iface *HardwareRandomObserveInterface) SanitizeSlot(slot *interfaces.Slot) error {
	if iface.Name() != slot.Interface {
		panic(fmt.Sprintf("slot is not of interface %q", iface.Name()))
	}
	if slot.Snap.Type != snap.TypeOS {
		return fmt.Errorf("%s slots are reserved for the operating system snap", iface.Name())
	}
	return nil
}

// Checks and possibly modifies a plug
func (iface *HardwareRandomObserveInterface) SanitizePlug(plug *interfaces.Plug) error {
	if iface.Name() != plug.Interface {
		panic(fmt.Sprintf("plug is not of interface %q", iface.Name()))
	}
	// Currently nothing is checked on the plug side
	return nil
}

func (iface *HardwareRandomObserveInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.Plug, slot *interfaces.Slot) error {
	spec.AddSnippet(hardwareRandomObserveConnectedPlugAppArmor)
	return nil
}

func (iface *HardwareRandomObserveInterface) UdevConnectedPlug(spec *udev.Specification, plug *interfaces.Plug, slot *interfaces.Slot) error {
	const udevRule = `KERNEL=="hwrng", TAG+="%s"`
	for appName := range plug.Apps {
		tag := udevSnapSecurityName(plug.Snap.Name(), appName)
		spec.AddSnippet(fmt.Sprintf(udevRule, tag))
	}
	return nil
}

func (iface *HardwareRandomObserveInterface) AutoConnect(*interfaces.Plug, *interfaces.Slot) bool {
	return true
}
