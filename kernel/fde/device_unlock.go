// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package fde

import (
	"encoding/json"
	"fmt"

	"github.com/snapcore/snapd/osutil"
)

type DeviceUnlockRequest struct {
	Op string `json:"op"`

	Key    []byte `json:"key,omitempty"`
	Device string `json:"device,omitempty"`
}

// runFDEDeviceUnlockCommand returns the output of
// fde-device-unlock run with systemd.
//
// Note that systemd-run in the initrd can only talk to the private
// systemd bus so this cannot use "--pipe" or "--wait", see
// https://github.com/snapcore/core-initrd/issues/13
func runFDEDeviceUnlockCommand(req *DeviceUnlockRequest) (output []byte, err error) {
	stdin, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf(`cannot build request %q for fde-device-unlock: %v`, req, err)
	}

	return runFDEinitramfsHelper("fde-device-unlock", stdin)
}

// DeviceUnlockParams contains the parameters for fde-device-unlock
// "device-unlock" operation.
type DeviceUnlockParams struct {
	Key    []byte
	Device string
}

// DeviceUnlock invokes the "fde-device-unlock" helper with the
// "device-unlock" operation.
func DeviceUnlock(params *DeviceUnlockParams) (err error) {
	req := &DeviceUnlockRequest{
		Op:     "device-unlock",
		Key:    params.Key,
		Device: params.Device,
	}
	output, err := runFDEDeviceUnlockCommand(req)
	if err != nil {
		return fmt.Errorf(`cannot run fde-device-unlock "device-unlock": %v`, osutil.OutputErr(output, err))
	}
	return nil
}
