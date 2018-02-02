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

package configcore

import (
	"fmt"
	"os"

	"github.com/snapcore/snapd/overlord/configstate/config"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/release"
)

var (
	Stdout = os.Stdout
	Stderr = os.Stderr
)

type Conf interface {
	Get(snapName, key string, result interface{}) error
	Changes() []string
	State() *state.State
}

func coreCfg(tr Conf, key string) (result string, err error) {
	var v interface{} = ""
	if err := tr.Get("core", key, &v); err != nil && !config.IsNoOption(err) {
		return "", err
	}
	// TODO: we could have a fully typed approach but at the
	// moment we also always use "" to mean unset as well, this is
	// the smallest change
	return fmt.Sprintf("%v", v), nil
}

var supportedConfigurations = map[string]bool{
	// FIMXE: duplicated with picfg.go fix by building piConfigKeys
	//        dynamically from this array and check config prefix
	//        and s/-/_/ in the option names.
	"core.pi-config.disable-overscan":         true,
	"core.pi-config.framebuffer-width":        true,
	"core.pi-config.framebuffer-height":       true,
	"core.pi-config.framebuffer-depth":        true,
	"core.pi-config.framebuffer-ignore-alpha": true,
	"core.pi-config.overscan-left":            true,
	"core.pi-config.overscan-right":           true,
	"core.pi-config.overscan-top":             true,
	"core.pi-config.overscan-bottom":          true,
	"core.pi-config.overscan-scale":           true,
	"core.pi-config.display-rotate":           true,
	"core.pi-config.hdmi-group":               true,
	"core.pi-config.hdmi-mode":                true,
	"core.pi-config.hdmi-drive":               true,
	"core.pi-config.avoid-warnings":           true,
	"core.pi-config.gpu-mem-256":              true,
	"core.pi-config.gpu-mem-512":              true,
	"core.pi-config.gpu-mem":                  true,
	"core.pi-config.sdtv-aspect":              true,
	"core.pi-config.config-hdmi-boost":        true,
	"core.pi-config.hdmi-force-hotplug":       true,
	// proxy
	"core.proxy.http":     true,
	"core.proxy.https":    true,
	"core.proxy.ftp":      true,
	"core.proxy.no-proxy": true,
	"core.proxy.store":    true,
	// refresh
	"core.refresh.timer":    true,
	"core.refresh.schedule": true,
	// services
	"core.service.rsyslog.disable": true,
	"core.service.ssh.disable":     true,
	// powerbtn
	"core.system.power-key-action": true,
}

func Run(tr Conf) error {
	if err := validateProxyStore(tr); err != nil {
		return err
	}
	if err := validateRefreshSchedule(tr); err != nil {
		return err
	}

	// check if the changes
	for _, k := range tr.Changes() {
		if !supportedConfigurations[k] {
			return fmt.Errorf("cannot set %q: unsupported core config option", k)
		}
	}

	// see if it makes sense to run at all
	if release.OnClassic {
		// nothing to do
		return nil
	}
	// TODO: consider allowing some of these on classic too?
	// consider erroring on core-only options on classic?

	// handle the various core config options:
	// service.*.disable
	if err := handleServiceDisableConfiguration(tr); err != nil {
		return err
	}
	// system.power-key-action
	if err := handlePowerButtonConfiguration(tr); err != nil {
		return err
	}
	// pi-config.*
	if err := handlePiConfiguration(tr); err != nil {
		return err
	}
	// proxy.{http,https,ftp}
	if err := handleProxyConfiguration(tr); err != nil {
		return err
	}

	return nil
}
