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

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/jessevdk/go-flags"

	"github.com/snapcore/snapd/arch"
	"github.com/snapcore/snapd/i18n"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snapenv"
)

type cmdRun struct {
	Positional struct {
		SnapApp string `positional-arg-name:"<snapApp>" description:"the application to run, e.g. hello-world.env"`
	} `positional-args:"yes" required:"yes"`

	Command string `long:"command" description:"use a different command like {stop,post-stop} from the app"`
}

func init() {
	addCommand("run",
		i18n.G("Run the given snap command"),
		i18n.G("Run the given snap command with the right confinement and environment"),
		func() flags.Commander {
			return &cmdRun{}
		})
}

// FIXME: copied code :/
func splitSnapApp(snapApp string) (snap, app string) {
	l := strings.SplitN(snapApp, ".", 2)
	if len(l) < 2 {
		return l[0], l[0]
	}
	return l[0], l[1]
}

// --- end copied code

func (x *cmdRun) Execute(args []string) error {
	return snapRun(x.Positional.SnapApp, x.Command, args)
}

var GetSnapInfo = getSnapInfoImpl

func getSnapInfoImpl(snapName string) (*snap.Info, error) {
	// we need to get the revision here because once we are inside
	// the confinement its not available anymore
	snaps, err := Client().ListSnaps([]string{snapName})
	if err != nil {
		return nil, err
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("cannot find snap %q", snapName)
	}
	if len(snaps) > 1 {
		return nil, fmt.Errorf("multiple snaps for %q: %d", snapName, len(snaps))
	}
	sn := snaps[0]
	info, err := snap.ReadInfo(snapName, &snap.SideInfo{
		Revision: snap.R(sn.Revision.N),
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// returns phase1 env (same vars for all apps)
func getPhase1AppEnv(app *snap.AppInfo) []string {
	env := []string{}
	wrapperData := struct {
		App     *snap.AppInfo
		EnvVars string
		// XXX: needed by snapenv
		SnapName string
		SnapArch string
		SnapPath string
		Version  string
		Revision snap.Revision
		Home     string
	}{
		App: app,
		// XXX: needed by snapenv
		SnapName: app.Snap.Name(),
		SnapArch: arch.UbuntuArchitecture(),
		SnapPath: app.Snap.MountDir(),
		Version:  app.Snap.Version,
		Revision: app.Snap.Revision,
		// must be an absolute path for
		//   ubuntu-core-launcher/snap-confine
		// which will mkdir() SNAP_USER_DATA for us
		Home: os.Getenv("$HOME"),
	}
	for _, envVar := range append(
		snapenv.GetBasicSnapEnvVars(wrapperData),
		snapenv.GetUserSnapEnvVars(wrapperData)...) {
		env = append(env, envVar)
	}
	return env
}

var SyscallExec = syscall.Exec

func snapRun(snapApp, command string, args []string) error {
	snapName, appName := splitSnapApp(snapApp)
	info, err := GetSnapInfo(snapName)
	if err != nil {
		return err
	}

	app := info.Apps[appName]
	if app == nil {
		return fmt.Errorf("cannot find app %q in %q", appName, snapName)
	}

	// build command to run
	cmd := []string{
		"/usr/bin/ubuntu-core-launcher",
		app.SecurityTag(),
		app.SecurityTag(),
		"/usr/lib/snapd/snap-exec",
		snapApp,
	}
	if command != "" {
		cmd = append(cmd, "--command="+command)
	}
	cmd = append(cmd, args...)

	// build env
	env := append(os.Environ(), getPhase1AppEnv(app)...)

	// launch!
	return SyscallExec(cmd[0], cmd, env)
}
