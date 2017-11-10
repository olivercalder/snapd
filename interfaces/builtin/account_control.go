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
	"strconv"
	"strings"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/osutil"
)

const accountControlSummary = `allows managing non-system user accounts`

const accountControlBaseDeclarationSlots = `
  account-control:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const accountControlConnectedPlugAppArmor = `
/{,usr/}sbin/chpasswd ixr,
/{,usr/}sbin/user{add,del} ixr,

# Only allow modifying the non-system extrausers database
/var/lib/extrausers/ r,
/var/lib/extrausers/** rwkl,

# Needed by useradd
/etc/login.defs r,
/etc/default/useradd r,
/etc/default/nss r,
/etc/pam.d/{,*} r,

# Useradd needs netlink
network netlink raw,

# Capabilities needed by useradd
capability audit_write,
capability chown,
capability fsetid,

# useradd writes the result in the log
#include <abstractions/wutmp>
/var/log/faillog rwk,
`

// Needed because useradd uses a netlink socket, {{group}} is used as a
// placeholder argument for the actual ID of a group owning /etc/shadow
const accountControlConnectedPlugSecCompTemplate = `
# useradd requires chowning to 0:'{{group}}'
fchown - u:root {{group}}
fchown32 - u:root {{group}}

# from libaudit1
bind
socket AF_NETLINK - NETLINK_AUDIT
`

type accountControlInterface struct {
	commonInterface
	secCompSnippet string
}

func makeAccountControlSecCompSnippet() (string, error) {
	gid, err := osutil.FindGidOwning("/etc/shadow")
	if err != nil {
		return "", err
	}

	snippet := strings.Replace(accountControlConnectedPlugSecCompTemplate,
		"{{group}}", strconv.FormatUint(gid, 10), -1)

	return snippet, nil
}

func (iface *accountControlInterface) SecCompConnectedPlug(spec *seccomp.Specification, plug *interfaces.Plug, Attrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	if iface.secCompSnippet == "" {
		snippet, err := makeAccountControlSecCompSnippet()
		if err != nil {
			return err
		}
		iface.secCompSnippet = snippet
	}
	spec.AddSnippet(iface.secCompSnippet)
	return nil
}

func init() {
	registerIface(&accountControlInterface{
		commonInterface: commonInterface{
			name:                  "account-control",
			summary:               accountControlSummary,
			implicitOnCore:        true,
			implicitOnClassic:     true,
			baseDeclarationSlots:  accountControlBaseDeclarationSlots,
			connectedPlugAppArmor: accountControlConnectedPlugAppArmor,
			// handled by SecCompConnectedPlug
			connectedPlugSecComp: "",
			reservedForOS:        true,
		},
	})
}
