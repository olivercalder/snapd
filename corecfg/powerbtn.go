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

package corecfg

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/snapcore/snapd/osutil"
)

// can be overriden in tests
var powerBtnCfg = "/etc/systemd/logind.conf.d/00-snap-core.conf"

// switchHandlePowerKey change the behavor when the power key is pressed
func switchHandlePowerKey(action string) error {
	validActions := map[string]bool{
		"ignore":       true,
		"poweroff":     true,
		"reboot":       true,
		"halt":         true,
		"kexec":        true,
		"suspend":      true,
		"hibernate":    true,
		"hybrid-sleep": true,
		"lock":         true,
	}

	cfgDir := filepath.Dir(powerBtnCfg)
	if !osutil.IsDirectory(cfgDir) {
		if err := os.MkdirAll(cfgDir, 0755); err != nil {
			return err
		}
	}
	if !validActions[action] {
		return fmt.Errorf("invalid action %q supplied for system.power-key-action option", action)
	}

	content := fmt.Sprintf(`[Login]
HandlePowerKey=%s
`, action)
	return osutil.AtomicWriteFile(powerBtnCfg, []byte(content), 0644, 0)
}
