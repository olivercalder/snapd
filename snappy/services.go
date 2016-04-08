// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2016 Canonical Ltd
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

package snappy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ubuntu-core/snappy/dirs"
	"github.com/ubuntu-core/snappy/logger"
	"github.com/ubuntu-core/snappy/osutil"
	"github.com/ubuntu-core/snappy/snap"
	"github.com/ubuntu-core/snappy/systemd"
	"github.com/ubuntu-core/snappy/timeout"
)

type agreer interface {
	Agreed(intro, license string) bool
}

type interacter interface {
	agreer
	Notify(status string)
}

// wait this time between TERM and KILL
var killWait = 5 * time.Second

// servicesBinariesStringsWhitelist is the whitelist of legal chars
// in the "binaries" and "services" section of the snap.yaml
var servicesBinariesStringsWhitelist = regexp.MustCompile(`^[A-Za-z0-9/. _#:-]*$`)

func serviceStopTimeout(app *snap.AppInfo) time.Duration {
	tout := app.StopTimeout
	if tout == 0 {
		tout = timeout.DefaultTimeout
	}
	return time.Duration(tout)
}

func generateSnapServicesFile(app *snap.AppInfo, baseDir string) (string, error) {
	if err := snap.ValidateApp(app); err != nil {
		return "", err
	}

	desc := fmt.Sprintf("service %s for snap %s - autogenerated DO NO EDIT", app.Name, app.Snap.Name())

	socketFileName := ""
	if app.Socket {
		socketFileName = filepath.Base(app.ServiceSocketFile())
	}

	return systemd.New(dirs.GlobalRootDir, nil).GenServiceFile(
		&systemd.ServiceDescription{
			SnapName:       app.Snap.Name(),
			AppName:        app.Name,
			Version:        app.Snap.Version,
			Description:    desc,
			SnapPath:       baseDir,
			Start:          app.Command,
			Stop:           app.Stop,
			PostStop:       app.PostStop,
			StopTimeout:    serviceStopTimeout(app),
			AaProfile:      app.SecurityTag(),
			BusName:        app.BusName,
			Type:           app.Daemon,
			UdevAppName:    app.SecurityTag(),
			Socket:         app.Socket,
			SocketFileName: socketFileName,
			Restart:        app.RestartCond,
		}), nil
}

func generateSnapSocketFile(app *snap.AppInfo, baseDir string) (string, error) {
	if err := snap.ValidateApp(app); err != nil {
		return "", err
	}

	// lp: #1515709, systemd will default to 0666 if no socket mode
	// is specified
	if app.SocketMode == "" {
		app.SocketMode = "0660"
	}

	serviceFileName := filepath.Base(app.ServiceFile())

	return systemd.New(dirs.GlobalRootDir, nil).GenSocketFile(
		&systemd.ServiceDescription{
			ServiceFileName: serviceFileName,
			ListenStream:    app.ListenStream,
			SocketMode:      app.SocketMode,
		}), nil
}

func oldGenerateServiceFileName(m *snapYaml, app *AppYaml) string {
	return filepath.Join(dirs.SnapServicesDir, fmt.Sprintf("%s_%s_%s.service", m.Name, app.Name, m.Version))
}

func addPackageServices(s *snap.Info, inter interacter) error {
	baseDir := s.MountDir()

	for _, app := range s.Apps {
		if app.Daemon == "" {
			continue
		}

		// this will remove the global base dir when generating the
		// service file, this ensures that /snaps/foo/1.0/bin/start
		// is in the service file when the SetRoot() option
		// is used
		realBaseDir := stripGlobalRootDir(baseDir)
		// Generate service file
		content, err := generateSnapServicesFile(app, realBaseDir)
		if err != nil {
			return err
		}
		svcFilePath := app.ServiceFile()
		os.MkdirAll(filepath.Dir(svcFilePath), 0755)
		if err := osutil.AtomicWriteFile(svcFilePath, []byte(content), 0644, 0); err != nil {
			return err
		}
		// Generate systemd socket file if needed
		if app.Socket {
			content, err := generateSnapSocketFile(app, realBaseDir)
			if err != nil {
				return err
			}
			svcSocketFilePath := app.ServiceSocketFile()
			os.MkdirAll(filepath.Dir(svcSocketFilePath), 0755)
			if err := osutil.AtomicWriteFile(svcSocketFilePath, []byte(content), 0644, 0); err != nil {
				return err
			}
		}
		// daemon-reload and enable plus start
		serviceName := filepath.Base(app.ServiceFile())
		sysd := systemd.New(dirs.GlobalRootDir, inter)

		if err := sysd.DaemonReload(); err != nil {
			return err
		}

		// enable the service
		if err := sysd.Enable(serviceName); err != nil {
			return err
		}

		if err := sysd.Start(serviceName); err != nil {
			return err
		}

		if app.Socket {
			socketName := filepath.Base(app.ServiceSocketFile())
			// enable the socket
			if err := sysd.Enable(socketName); err != nil {
				return err
			}

			if err := sysd.Start(socketName); err != nil {
				return err
			}
		}
	}

	return nil
}

func removePackageServices(s *snap.Info, inter interacter) error {
	sysd := systemd.New(dirs.GlobalRootDir, inter)

	nservices := 0

	for _, app := range s.Apps {
		if app.Daemon == "" {
			continue
		}
		nservices++

		serviceName := filepath.Base(app.ServiceFile())
		if err := sysd.Disable(serviceName); err != nil {
			return err
		}
		if err := sysd.Stop(serviceName, serviceStopTimeout(app)); err != nil {
			if !systemd.IsTimeout(err) {
				return err
			}
			inter.Notify(fmt.Sprintf("%s refused to stop, killing.", serviceName))
			// ignore errors for kill; nothing we'd do differently at this point
			sysd.Kill(serviceName, "TERM")
			time.Sleep(killWait)
			sysd.Kill(serviceName, "KILL")
		}

		if err := os.Remove(app.ServiceFile()); err != nil && !os.IsNotExist(err) {
			logger.Noticef("Failed to remove service file for %q: %v", serviceName, err)
		}

		if err := os.Remove(app.ServiceSocketFile()); err != nil && !os.IsNotExist(err) {
			logger.Noticef("Failed to remove socket file for %q: %v", serviceName, err)
		}
	}

	// only reload if we actually had services
	if nservices > 0 {
		if err := sysd.DaemonReload(); err != nil {
			return err
		}
	}

	return nil
}
