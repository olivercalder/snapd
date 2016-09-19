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

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/release"
)

const pulseaudioConnectedPlugAppArmor = `
/{run,dev}/shm/pulse-shm-* rwkm,

owner /{,var/}run/pulse/ r,
owner /{,var/}run/pulse/native rwk,
`

const pulseaudioConnectedPlugAppArmorDesktop = `
# Only on desktop do we need access to /etc/pulse for any PulseAudio client
# to read available client side configuration settings. On an Ubuntu Core
# device those things will be stored inside the snap directory.
/etc/pulse/ r,
/etc/pulse/* r,
owner @{HOME}/.pulse-cookie rk,
owner @{HOME}/.config/pulse/cookie rk,
owner /{,var/}run/user/*/pulse/ rwk,
owner /{,var/}run/user/*/pulse/native rwk,
`

const pulseaudioConnectedPlugSecComp = `
getsockopt
setsockopt
connect
sendto
shmctl
getsockname
getpeername
sendmsg
recvmsg
`

const pulseaudioPermanentSlotAppArmor = `
# When running PulseAudio in system mode it will switch to the at
# build time configured user/group on startup.
capability setuid,
capability setgid,

capability sys_nice,
capability sys_resource,

owner @{PROC}/@{pid}/exe r,
/etc/machine-id r,

# Audio related
@{PROC}/asound/devices r,
@{PROC}/asound/card** r,
/dev/snd/pcm* rw,
/dev/snd/control* rw,
/dev/snd/timer r,
/sys/**/sound/** r,

# For udev
network netlink raw,
/sys/devices/virtual/dmi/id/sys_vendor r,
/sys/devices/virtual/dmi/id/bios_vendor r,
# FIXME: use udev queries to make this more specific
/run/udev/data/** r,

owner /{,var/}run/pulse/ rw,
owner /{,var/}run/pulse/** rwk,

# Shared memory based communication with clients
/{run,dev}/shm/pulse-shm-* rwk,
`

const pulseaudioPermanentSlotSecComp = `
# The following are needed for UNIX sockets
personality
setpriority
setsockopt
getsockname
bind
listen
sendto
recvfrom
accept4
shmctl
getsockname
getpeername
sendmsg
recvmsg
# Needed to set root as group for different state dirs
# pulseaudio creates on startup.
setgroups
`

type PulseAudioInterface struct{}

func (iface *PulseAudioInterface) Name() string {
	return "pulseaudio"
}

func (iface *PulseAudioInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount, interfaces.SecurityKMod:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *PulseAudioInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		if release.OnClassic {
			b := bytes.NewBuffer([]byte(pulseaudioConnectedPlugAppArmor))
			b.Write([]byte(pulseaudioConnectedPlugAppArmorDesktop))
			return b.Bytes(), nil
		} else {
			return []byte(pulseaudioConnectedPlugAppArmor), nil
		}
	case interfaces.SecuritySecComp:
		return []byte(pulseaudioConnectedPlugSecComp), nil
	case interfaces.SecurityDBus, interfaces.SecurityUDev, interfaces.SecurityMount, interfaces.SecurityKMod:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *PulseAudioInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		return []byte(pulseaudioPermanentSlotAppArmor), nil
	case interfaces.SecuritySecComp:
		return []byte(pulseaudioPermanentSlotSecComp), nil
	case interfaces.SecurityDBus, interfaces.SecurityUDev, interfaces.SecurityMount, interfaces.SecurityKMod:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *PulseAudioInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount, interfaces.SecurityKMod:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *PulseAudioInterface) SanitizePlug(slot *interfaces.Plug) error {
	return nil
}

func (iface *PulseAudioInterface) SanitizeSlot(slot *interfaces.Slot) error {
	return nil
}

func (iface *PulseAudioInterface) AutoConnect() bool {
	return true
}
