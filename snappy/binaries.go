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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/ubuntu-core/snappy/arch"
	"github.com/ubuntu-core/snappy/dirs"
	"github.com/ubuntu-core/snappy/osutil"
	"github.com/ubuntu-core/snappy/snap"
	"github.com/ubuntu-core/snappy/snap/snapenv"
)

// XXX: this needs to change in the new interfaces world!
// it will need to be a SecurityTag value
func getSecurityProfileFromApp(app *snap.AppInfo) string {
	cleanedName := strings.Replace(app.Name, "/", "-", -1)

	return fmt.Sprintf("%s_%s_%s", app.Snap.Name, cleanedName, app.Snap.Version)
}

// generate the name
// TODO: => AppInfo.WrapperPath
func generateBinaryName(app *snap.AppInfo) string {
	var binName string
	if app.Name == app.Snap.Name {
		binName = filepath.Base(app.Name)
	} else {
		binName = fmt.Sprintf("%s.%s", app.Snap.Name, filepath.Base(app.Name))
	}

	return filepath.Join(dirs.SnapBinariesDir, binName)
}

// TODO: => AppInfo.CommandLine
func binPathForBinary(pkgPath string, app *snap.AppInfo) string {
	return filepath.Join(pkgPath, app.Command)
}

// Doesn't need to handle complications like internal quotes, just needs to
// wrap right side of an env variable declaration with quotes for the shell.
func quoteEnvVar(envVar string) string {
	return "export " + strings.Replace(envVar, "=", "=\"", 1) + "\""
}

func generateSnapBinaryWrapper(app *snap.AppInfo, pkgPath string) (string, error) {
	wrapperTemplate := `#!/bin/sh
set -e

# snap info (deprecated)
{{.OldAppVars}}

# snap info
{{.NewAppVars}}

if [ ! -d "$SNAP_USER_DATA" ]; then
   mkdir -p "$SNAP_USER_DATA"
fi
export HOME="$SNAP_USER_DATA"

# Snap name is: {{.SnapName}}
# App name is: {{.AppName}}

ubuntu-core-launcher {{.UdevAppName}} {{.AaProfile}} {{.Target}} "$@"
`

	if err := snap.ValidateApp(app); err != nil {
		return "", err
	}

	actualBinPath := binPathForBinary(pkgPath, app)
	aaProfile := getSecurityProfileFromApp(app)

	var templateOut bytes.Buffer
	t := template.Must(template.New("wrapper").Parse(wrapperTemplate))
	wrapperData := struct {
		SnapName    string
		AppName     string
		SnapArch    string
		SnapPath    string
		Version     string
		UdevAppName string
		Home        string
		Target      string
		AaProfile   string
		OldAppVars  string
		NewAppVars  string
	}{
		SnapName:    app.Snap.Name,
		AppName:     app.Name,
		SnapArch:    arch.UbuntuArchitecture(),
		SnapPath:    pkgPath,
		Version:     app.Snap.Version,
		UdevAppName: fmt.Sprintf("%s.%s", app.Snap.Name, app.Name),
		Home:        "$HOME",
		Target:      actualBinPath,
		AaProfile:   aaProfile,
	}

	oldVars := []string{}
	for _, envVar := range append(
		snapenv.GetDeprecatedBasicSnapEnvVars(wrapperData),
		snapenv.GetDeprecatedUserSnapEnvVars(wrapperData)...) {
		oldVars = append(oldVars, quoteEnvVar(envVar))
	}
	wrapperData.OldAppVars = strings.Join(oldVars, "\n")

	newVars := []string{}
	for _, envVar := range append(
		snapenv.GetBasicSnapEnvVars(wrapperData),
		snapenv.GetUserSnapEnvVars(wrapperData)...) {
		newVars = append(newVars, quoteEnvVar(envVar))
	}
	wrapperData.NewAppVars = strings.Join(newVars, "\n")

	t.Execute(&templateOut, wrapperData)

	return templateOut.String(), nil
}

func addPackageBinaries(s *snap.Info) error {
	if err := os.MkdirAll(dirs.SnapBinariesDir, 0755); err != nil {
		return err
	}

	baseDir := s.BaseDir()

	for _, app := range s.Apps {
		if app.Daemon != "" {
			continue
		}

		// this will remove the global base dir when generating the
		// service file, this ensures that /snaps/foo/1.0/bin/start
		// is in the service file when the SetRoot() option
		// is used
		realBaseDir := stripGlobalRootDir(baseDir)
		content, err := generateSnapBinaryWrapper(app, realBaseDir)
		if err != nil {
			return err
		}

		if err := osutil.AtomicWriteFile(generateBinaryName(app), []byte(content), 0755, 0); err != nil {
			return err
		}
	}

	return nil
}

func removePackageBinaries(s *snap.Info) error {
	for _, app := range s.Apps {
		os.Remove(generateBinaryName(app))
	}

	return nil
}
