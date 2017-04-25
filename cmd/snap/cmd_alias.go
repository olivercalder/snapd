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
	"github.com/jessevdk/go-flags"

	"github.com/snapcore/snapd/i18n"
	"github.com/snapcore/snapd/snap"
)

type cmdAlias struct {
	Positionals struct {
		SnapApp string `required:"yes"`
		Alias   string `required:"yes"`
	} `positional-args:"true"`
}

// TODO: implement a completer for snapApp

var shortAliasHelp = i18n.G("Sets up a manual alias")
var longAliasHelp = i18n.G(`
The alias command aliases the given snap application to the given alias.

Once this manual alias is setup the respective application command can be invoked just using the alias.
`)

func init() {
	addCommand("alias", shortAliasHelp, longAliasHelp, func() flags.Commander {
		return &cmdAlias{}
	}, nil, []argDesc{
		{name: "<snap.app>"},
		{name: i18n.G("<alias>")},
	})
}

func (x *cmdAlias) Execute(args []string) error {
	if len(args) > 0 {
		return ErrExtraArgs
	}

	snapName, appName := snap.SplitSnapApp(x.Positionals.SnapApp)
	alias := x.Positionals.Alias

	cli := Client()
	id, err := cli.Alias(snapName, appName, alias)
	if err != nil {
		return err
	}

	_, err = wait(cli, id)
	return err
}
