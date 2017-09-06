// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016-2017 Canonical Ltd
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

package ctlcmd

import (
	"fmt"
	"time"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/i18n"
	"github.com/snapcore/snapd/overlord/configstate"
	"github.com/snapcore/snapd/overlord/hookstate"
	"github.com/snapcore/snapd/overlord/servicectl"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
)

type stopCommand struct {
	baseCommand
	Positional struct {
		ServiceNames []string `positional-arg-name:"<service>" required:"1"`
	} `positional-args:"yes" required:"yes"`
	Disable bool `long:"disable"`
}

var (
	shortStopHelp = i18n.G("Stop services")
)

func init() {
	addCommand("stop", shortStopHelp, "", func() command { return &stopCommand{} })
}

func getServiceInfos(st *state.State, snapName string, serviceNames []string) ([]*snap.AppInfo, error) {
	st.Lock()
	defer st.Unlock()

	var snapst snapstate.SnapState
	if err := snapstate.Get(st, snapName, &snapst); err != nil {
		return nil, err
	}

	info, err := snapst.CurrentInfo()
	if err != nil {
		return nil, err
	}

	requested := make(map[string]bool)
	for _, svc := range serviceNames {
		requested[svc] = true
	}

	var svcs []*snap.AppInfo
	for _, app := range info.Apps {
		svcName := snapName + "." + app.Name
		if _, ok := requested[svcName]; ok && app.IsService() {
			svcs = append(svcs, app)
			delete(requested, svcName)
		}
	}

	if len(requested) > 0 {
		for k := range requested {
			return nil, fmt.Errorf(i18n.G("unknown service: %q"), k)
		}
	}

	return svcs, nil
}

type ServiceControlFunc func(st *state.State, appInfos []*snap.AppInfo, inst *servicectl.AppInstruction) (*state.Change, error)

var runService ServiceControlFunc = servicectl.ServiceControl

func runServiceCommand(context *hookstate.Context, inst *servicectl.AppInstruction, serviceNames []string) error {
	if context == nil {
		return fmt.Errorf(i18n.G("cannot %s without a context"), inst.Action)
	}

	st := context.State()
	appInfos, err := getServiceInfos(st, context.SnapName(), serviceNames)
	if err != nil {
		return err
	}

	chg, err := runService(st, appInfos, inst)
	if err != nil {
		return err
	}

	st.Lock()
	st.EnsureBefore(0)
	st.Unlock()

	select {
	case <-chg.Ready():
		st.Lock()
		defer st.Unlock()
		return chg.Err()
	case <-time.After(configstate.ConfigureHookTimeout() / 2):
		return fmt.Errorf("%s command timed out", inst.Action)
	}
}

func (c *stopCommand) Execute(args []string) error {
	inst := servicectl.AppInstruction{
		Action: "stop",
		Names:  c.Positional.ServiceNames,
		StopOptions: client.StopOptions{
			Disable: c.Disable,
		},
	}
	return runServiceCommand(c.context(), &inst, c.Positional.ServiceNames)
}
