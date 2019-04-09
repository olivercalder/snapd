// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package configcore

import (
	"fmt"
	"time"

	"github.com/snapcore/snapd/overlord/configstate/config"
)

func init() {
	// add supported configuration of this module
	supportedConfigurations["core.automatic-snapshots.expiration"] = true
}

func validateAutomaticSnapshotsExpiration(tr config.Conf) error {
	expirationStr, err := coreCfg(tr, "automatic-snapshots.expiration")
	if err != nil {
		return err
	}
	if expirationStr != "" {
		dur, err := time.ParseDuration(expirationStr)
		if err != nil {
			return fmt.Errorf("automatic-snapshots.expiration cannot be parsed: %v", err)
		}
		if dur > 0 && dur < time.Hour*24 {
			return fmt.Errorf("automatic-snapshots.expiration must be 0 to disable automatic snapshots, or a value greater than 24 hours")
		}
		// special-case "0" (with no unit): it's a valid duration (any other number with unit omitted isn't), but when left as is it would
		// be stored as int64 instead of a string representing duration, causing issue when reading from the state.
		if expirationStr == "0" {
			tr.Set("core", "automatic-snapshots.expiration", "0s")
		}
	}
	return nil
}
