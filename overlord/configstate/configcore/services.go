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
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/configstate/config"
	"github.com/snapcore/snapd/systemd"
)

var services = []struct{ configName, systemdName string }{
	{"ssh", "ssh.service"},
	{"rsyslog", "rsyslog.service"},
}

func init() {
	for _, service := range services {
		s := fmt.Sprintf("core.service.%s.disable", service.configName)
		supportedConfigurations[s] = true
	}
}

type sysdLogger struct{}

func (l *sysdLogger) Notify(status string) {
	fmt.Fprintf(Stderr, "sysd: %s\n", status)
}

// switchDisableSSHService handles the special case of disabling/enabling ssh
// service on core devices.
func switchDisableSSHService(sysd systemd.Systemd, serviceName, value string, opts *config.ApplyOptions) error {
	rootDir := dirs.GlobalRootDir
	if opts != nil && opts.RootDir != "" {
		rootDir = opts.RootDir
	}
	sshCanary := filepath.Join(rootDir, "/etc/ssh/sshd_not_to_be_run")

	switch value {
	case "true":
		if err := ioutil.WriteFile(sshCanary, []byte("SSH has been disabled by snapd system configuration\n"), 0644); err != nil {
			return err
		}
		if opts == nil || !opts.Preseeding {
			return sysd.Stop(serviceName, 5*time.Minute)
		}
		return nil
	case "false":
		err := os.Remove(sshCanary)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		// Unmask both sshd.service and ssh.service and ignore the
		// errors, if any. This undoes the damage done by earlier
		// versions of snapd.
		sysd.Unmask("sshd.service")
		sysd.Unmask("ssh.service")
		if opts == nil || !opts.Preseeding {
			return sysd.Start(serviceName)
		}
		return nil
	default:
		return fmt.Errorf("option %q has invalid value %q", serviceName, value)
	}
}

// switchDisableTypicalService switches a service in/out of disabled state
// where "true" means disabled and "false" means enabled.
func switchDisableService(serviceName, value string, opts *config.ApplyOptions) error {
	var sysd systemd.Systemd
	if opts != nil && opts.Preseeding {
		sysd = systemd.NewEmulationMode(opts.RootDir)
	} else {
		sysd = systemd.New(dirs.GlobalRootDir, systemd.SystemMode, &sysdLogger{})
	}

	if serviceName == "ssh.service" {
		return switchDisableSSHService(sysd, serviceName, value, opts)
	}

	switch value {
	case "true":
		if err := sysd.Disable(serviceName); err != nil {
			return err
		}
		if err := sysd.Mask(serviceName); err != nil {
			return err
		}
		if opts == nil || !opts.Preseeding {
			return sysd.Stop(serviceName, 5*time.Minute)
		}
		return nil
	case "false":
		if err := sysd.Unmask(serviceName); err != nil {
			return err
		}
		if err := sysd.Enable(serviceName); err != nil {
			return err
		}
		if opts == nil || !opts.Preseeding {
			return sysd.Start(serviceName)
		}
		return nil
	default:
		return fmt.Errorf("option %q has invalid value %q", serviceName, value)
	}
}

// services that can be disabled
func handleServiceDisableConfiguration(tr config.ConfReader, opts *config.ApplyOptions) error {
	for _, service := range services {
		output, err := coreCfg(tr, fmt.Sprintf("service.%s.disable", service.configName))
		if err != nil {
			return err
		}
		if output != "" {
			if err := switchDisableService(service.systemdName, output, opts); err != nil {
				return err
			}
		}
	}

	return nil
}
