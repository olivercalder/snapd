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

package main

import (
	"github.com/snapcore/snapd/i18n"

	"github.com/jessevdk/go-flags"
)

type cmdWait struct {
	Positional struct {
		ChangeID string `positional-arg-name:"<change-id>"`
	} `positional-args:"yes" required:"yes"`
}

var shortWaitHelp = i18n.G("Wait for a change in progress")
var longWaitHelp = i18n.G(`
The wait command waits for the given change-id to finish and show progress
(if available).
`)

func init() {
	addCommand("wait", shortWaitHelp, longWaitHelp, func() flags.Commander {
		return &cmdWait{}
	}, nil, []argDesc{{
		name: i18n.G("<change-id>"),
		desc: i18n.G("Change ID"),
	}})
}

func (x *cmdWait) Execute(args []string) error {
	if len(args) > 0 {
		return ErrExtraArgs
	}
	cli := Client()
	_, err := wait(cli, x.Positional.ChangeID)

	return err
}
