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

const opticalDriveSummary = `allows read access to optical drives`

const opticalDriveConnectedPlugAppArmor = `
/dev/sr[0-9]* r,
/dev/scd[0-9]* r,
@{PROC}/sys/dev/cdrom/info r,
`

func init() {
	registerIface(&commonInterface{
		name:                  "optical-drive",
		summary:               opticalDriveSummary,
		implicitOnClassic:     true,
		connectedPlugAppArmor: opticalDriveConnectedPlugAppArmor,
		reservedForOS:         true,
	})
}
