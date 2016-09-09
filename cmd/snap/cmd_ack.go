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
	"io/ioutil"

	"github.com/snapcore/snapd/i18n"

	"github.com/jessevdk/go-flags"
)

type cmdAck struct {
	AckOptions struct {
		AssertionFile string
	} `positional-args:"true" required:"true"`
}

var shortAckHelp = i18n.G("Adds an assertion to the system")
var longAckHelp = i18n.G(`
The ack command tries to add an assertion to the system assertion database.

The assertion may also be a newer revision of a preexisting assertion that it
will replace.

To succeed the assertion must be valid, its signature verified with a known
public key and the assertion consistent with and its prerequisite in the
database.
`)

func init() {
	addCommand("ack", shortAckHelp, longAckHelp, func() flags.Commander {
		return &cmdAck{}
	}, nil, [][2]string{{i18n.G("<assertion file>"), i18n.G("assertion file")}})
}

func (x *cmdAck) Execute(args []string) error {
	if len(args) > 0 {
		return ErrExtraArgs
	}

	assertFile := x.AckOptions.AssertionFile

	assertData, err := ioutil.ReadFile(assertFile)
	if err != nil {
		return err
	}

	return Client().Ack(assertData)
}
