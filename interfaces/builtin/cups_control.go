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

import "github.com/snapcore/snapd/interfaces"

const cupsConnectedPlugAppArmor = `
# Description: Can access cups daemon.
# Usage: reserved
#include <abstractions/cups-client>
`

const cupsConnectedPlugSecComp = `
setsockopt
`

// NewCupsControlInterface returns a new "cups" interface.
func NewCupsControlInterface() interfaces.Interface {
	return &commonInterface{
		name: "cups-control",
		connectedPlugAppArmor: cupsConnectedPlugAppArmor,
		connectedPlugSecComp:  cupsConnectedPlugSecComp,
		reservedForOS:         true,
		autoConnect:           false,
	}
}
