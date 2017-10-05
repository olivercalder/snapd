// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (c) 2016-2017 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more dtails.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.
 *
 */

package builtin

import (
	"fmt"
	"strings"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/interfaces/udev"
)

const mirSummary = `allows operating as the Mir server`

const mirBaseDeclarationSlots = `
  mir:
    allow-installation:
      slot-snap-type:
        - app
    deny-connection: true
`

const mirPermanentSlotAppArmor = `
# Description: Allow operating as the Mir server. This gives privileged access
# to the system.

# needed since Mir is the display server, to configure tty devices
capability sys_tty_config,
/dev/tty[0-9]* rw,

/{dev,run}/shm/\#* mrw,
/run/mir_socket rw,

# Needed for mode setting via drmSetMaster() and drmDropMaster()
capability sys_admin,

# NOTE: this allows reading and inserting all input events
/dev/input/* rw,

# For using udev
network netlink raw,
/run/udev/data/c13:[0-9]* r,
/run/udev/data/+input:input[0-9]* r,
/run/udev/data/+platform:* r,
`

const mirPermanentSlotSecComp = `
# Description: Allow operating as the mir server. This gives privileged access
# to the system.
# Needed for server launch
bind
listen
# Needed by server upon client connect
accept
accept4
shmctl
# for udev
socket AF_NETLINK - NETLINK_KOBJECT_UEVENT
`

const mirConnectedSlotAppArmor = `
# Description: Permit clients to use Mir
unix (receive, send) type=seqpacket addr=none peer=(label=###PLUG_SECURITY_TAGS###),
`

const mirConnectedPlugAppArmor = `
# Description: Permit clients to use Mir
unix (receive, send) type=seqpacket addr=none peer=(label=###SLOT_SECURITY_TAGS###),
/run/mir_socket rw,
/run/user/[0-9]*/mir_socket rw,
`

const mirPermanentSlotUdev = `
KERNEL=="tty[0-9]*", TAG+="%[1]s"

# input devices
KERNEL=="mice",   TAG+="%[1]s"
KERNEL=="mouse[0-9]*", TAG+="%[1]s"
KERNEL=="event[0-9]*", TAG+="%[1]s"
KERNEL=="ts[0-9]*",    TAG+="%[1]s"
`

type mirInterface struct{}

func (iface *mirInterface) Name() string {
	return "mir"
}

func (iface *mirInterface) StaticInfo() interfaces.StaticInfo {
	return interfaces.StaticInfo{
		Summary:              mirSummary,
		BaseDeclarationSlots: mirBaseDeclarationSlots,
	}
}

func (iface *mirInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	old := "###SLOT_SECURITY_TAGS###"
	new := slotAppLabelExpr(slot)
	snippet := strings.Replace(mirConnectedPlugAppArmor, old, new, -1)
	spec.AddSnippet(snippet)
	return nil
}

func (iface *mirInterface) AppArmorConnectedSlot(spec *apparmor.Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	old := "###PLUG_SECURITY_TAGS###"
	new := plugAppLabelExpr(plug)
	snippet := strings.Replace(mirConnectedSlotAppArmor, old, new, -1)
	spec.AddSnippet(snippet)
	return nil
}

func (iface *mirInterface) AppArmorPermanentSlot(spec *apparmor.Specification, slot *interfaces.Slot) error {
	spec.AddSnippet(mirPermanentSlotAppArmor)
	return nil
}

func (iface *mirInterface) SecCompPermanentSlot(spec *seccomp.Specification, slot *interfaces.Slot) error {
	spec.AddSnippet(mirPermanentSlotSecComp)
	return nil
}

func (iface *mirInterface) UDevPermanentSlot(spec *udev.Specification, slot *interfaces.Slot) error {
	for appName := range slot.Apps {
		tag := udevSnapSecurityName(slot.Snap.Name(), appName)
		spec.AddSnippet(fmt.Sprintf(mirPermanentSlotUdev, tag))
	}
	return nil
}

func (iface *mirInterface) AutoConnect(*interfaces.Plug, *interfaces.Slot) bool {
	return true
}

func init() {
	registerIface(&mirInterface{})
}
