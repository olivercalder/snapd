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

package main

import (
	"fmt"
	"io/ioutil"

	"github.com/jessevdk/go-flags"

	"github.com/snapcore/snapd/i18n"
)

type cmdRemodel struct {
	waitMixin
	RemodelOptions struct {
		NewModelFile flags.Filename
	} `positional-args:"true" required:"true"`
}

func init() {
	cmd := addCommand("remodel",
		"Remodel the given device",
		"Remodel the given device",
		func() flags.Commander {
			return &cmdRemodel{}
		}, nil, []argDesc{{
			// TRANSLATORS: This needs to begin with < and end with >
			name: i18n.G("<new model file>"),
			// TRANSLATORS: This should not start with a lowercase letter.
			desc: i18n.G("New model file"),
		}})
	cmd.hidden = true
}

func (x *cmdRemodel) Execute(args []string) error {
	if len(args) > 0 {
		return ErrExtraArgs
	}
	newModelFile := x.RemodelOptions.NewModelFile
	modelData, err := ioutil.ReadFile(string(newModelFile))
	if err != nil {
		return err
	}
	changeID, err := x.client.Remodel(modelData)
	if err != nil {
		return fmt.Errorf("cannot remodel: %v", err)
	}

	if _, err := x.wait(changeID); err != nil {
		if err == noWait {
			return nil
		}
		return err
	}
	fmt.Fprintf(Stdout, i18n.G("New model %s set"), newModelFile)
	return nil
}
