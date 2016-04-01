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
	"github.com/ubuntu-core/snappy/interfaces"
)

// http://bazaar.launchpad.net/~ubuntu-security/ubuntu-core-security/trunk/view/head:/data/apparmor/policygroups/ubuntu-core/16.04/x
const xConnectedPlugAppArmor = `
# Description: Can access the X server. Restricted because X does not prevent
# eavesdropping or apps interfering with one another.
# Usage: reserved

#include <abstractions/X>
`

// http://bazaar.launchpad.net/~ubuntu-security/ubuntu-core-security/trunk/view/head:/data/seccomp/policygroups/ubuntu-core/16.04/x
const xConnectedPlugSecComp = `
# Description: Can access the X server. Restricted because X does not prevent
# eavesdropping or apps interfering with one another.
# Usage: reserved

getpeername
recvfrom
recvmsg
shutdown
`

// NewXInterface returns a new "x" interface.
func NewXInterface() interfaces.Interface {
	return &commonInterface{
		name: "x",
		connectedPlugAppArmor: xConnectedPlugAppArmor,
		connectedPlugSecComp:  xConnectedPlugSecComp,
		reservedForOS:         true,
	}
}
