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
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/interfaces/udev"
)

const kernelModuleControlSummary = `allows insertion, removal and querying of kernel modules`

const kernelModuleControlBaseDeclarationPlugs = `
  kernel-module-control:
    allow-installation: false
    deny-auto-connection: true
`

const kernelModuleControlBaseDeclarationSlots = `
  kernel-module-control:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const kernelModuleControlConnectedPlugAppArmor = `
# Description: Allow insertion, removal and querying of modules.

  capability sys_module,
  @{PROC}/modules r,

  # FIXME: moved to physical-memory-observe (remove this in series 18)
  /dev/mem r,

  # Required to use SYSLOG_ACTION_READ_ALL and SYSLOG_ACTION_SIZE_BUFFER when
  # /proc/sys/kernel/dmesg_restrict is '1' (syslog(2)). These operations are
  # required to verify kernel modules that are loaded.
  capability syslog,

  # Allow plug side to read information about loaded kernel modules
  /sys/module/{,**} r,
`

const kernelModuleControlConnectedPlugSecComp = `
# Description: Allow insertion, removal and querying of modules.

init_module
finit_module
delete_module
`
const kernelModuleControlConnectedPlugUdev = `
# This file contains udev rules for kernel module control.
#
# Do not edit this file, it will be overwritten on updates

KERNEL=="mem", TAG+="%s"
`

// The type for kernel module control interface
type kernelModuleControlInterface struct{}

// Getter for the name of the kernel module control interface
func (iface *kernelModuleControlInterface) Name() string {
	return "kernel-module-control"
}

func (iface *kernelModuleControlInterface) MetaData() interfaces.MetaData {
	return interfaces.MetaData{
		Summary:              kernelModuleControlSummary,
		ImplicitOnCore:       true,
		ImplicitOnClassic:    true,
		BaseDeclarationSlots: kernelModuleControlBaseDeclarationSlots,
	}
}

func (iface *kernelModuleControlInterface) String() string {
	return iface.Name()
}

// Check validity of the defined slot
func (iface *kernelModuleControlInterface) SanitizeSlot(slot *interfaces.Slot) error {
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
func (iface *kernelModuleControlInterface) SanitizePlug(plug *interfaces.Plug) error {
	if iface.Name() != plug.Interface {
		panic(fmt.Sprintf("plug is not of interface %q", iface))
	}
	// Currently nothing is checked on the plug side
	return nil
}

func (iface *kernelModuleControlInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	spec.AddSnippet(kernelModuleControlConnectedPlugAppArmor)
	return nil
}

func (iface *kernelModuleControlInterface) SecCompConnectedPlug(spec *seccomp.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	spec.AddSnippet(kernelModuleControlConnectedPlugSecComp)
	return nil
}

func (iface *kernelModuleControlInterface) UDevConnectedPlug(spec *udev.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	for appName := range plug.Apps {
		tag := udevSnapSecurityName(plug.Snap.Name(), appName)
		spec.AddSnippet(fmt.Sprintf(kernelModuleControlConnectedPlugUdev, tag))
	}
	return nil
}

func (iface *kernelModuleControlInterface) AutoConnect(*interfaces.Plug, *interfaces.Slot) bool {
	// Allow what is allowed in the declarations
	return true
}

func init() {
	registerIface(&kernelModuleControlInterface{})
}
