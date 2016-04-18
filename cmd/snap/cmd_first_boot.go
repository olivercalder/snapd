// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2015 Canonical Ltd
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

	"github.com/jessevdk/go-flags"

	"github.com/ubuntu-core/snappy/i18n"
	"github.com/ubuntu-core/snappy/overlord"
	"github.com/ubuntu-core/snappy/snappy"
)

type cmdInternalFirstBoot struct{}

func init() {
	cmd := addCommand("firstboot",
		"internal",
		"internal", func() flags.Commander {
			return &cmdInternalFirstBoot{}
		})
	cmd.hidden = true
}

func (x *cmdInternalFirstBoot) Execute(args []string) error {
	err := overlord.FirstBoot()
	if err == snappy.ErrNotFirstBoot {
		fmt.Println(i18n.G("First boot has already run"))
		return nil
	}

	return err
}
