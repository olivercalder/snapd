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
	"fmt"
	"text/tabwriter"

	"github.com/ubuntu-core/snappy/i18n"

	"github.com/jessevdk/go-flags"
)

type cmdInterfaces struct {
	Interface   string `short:"i" description:"constrain listing to specific interfaces"`
	Positionals struct {
		Query SnapAndName `positional-arg-name:"<snap>:<slot or plug>" description:"snap or snap:name" skip-help:"true"`
	} `positional-args:"true"`
}

var shortInterfacesHelp = i18n.G("Lists interfaces in the system")
var longInterfacesHelp = i18n.G(`
The interfaces command lists interfaces available in the system.

By default all slots and plugs, used and offered by all snaps, are displayed.
 
$ snap interfaces <snap>:<slot or plug>

Lists only the specified slot or plug.

$ snap interfaces <snap>

Lists the slots offered and plugs used by the specified snap.

$ snap interfaces --i=<interface> [<snap>]

Filters the complete output so only plugs and/or slots matching the provided details are listed.
`)

func init() {
	addCommand("interfaces", shortInterfacesHelp, longInterfacesHelp, func() flags.Commander {
		return &cmdInterfaces{}
	})
}

func (x *cmdInterfaces) Execute(args []string) error {
	ifaces, err := Client().Interfaces()
	if err == nil {
		w := tabwriter.NewWriter(Stdout, 0, 4, 1, ' ', 0)
		fmt.Fprintln(w, i18n.G("slot\tplug"))
		defer w.Flush()
		for _, slot := range ifaces.Slots {
			if x.Positionals.Query.Snap != "" && x.Positionals.Query.Snap != slot.Snap {
				continue
			}
			if x.Positionals.Query.Name != "" && x.Positionals.Query.Name != slot.Name {
				continue
			}
			if x.Interface != "" && slot.Interface != x.Interface {
				continue
			}
			// The OS snap (always ubuntu-core) is special and enable abbreviated
			// display syntax on the slot-side of the connection.
			if slot.Snap == "ubuntu-core" {
				fmt.Fprintf(w, ":%s\t", slot.Name)
			} else {
				fmt.Fprintf(w, "%s:%s\t", slot.Snap, slot.Name)
			}
			for i := 0; i < len(slot.Connections); i++ {
				if i > 0 {
					fmt.Fprint(w, ",")
				}
				if slot.Connections[i].Name != slot.Name {
					fmt.Fprintf(w, "%s:%s", slot.Connections[i].Snap, slot.Connections[i].Name)
				} else {
					fmt.Fprintf(w, "%s", slot.Connections[i].Snap)
				}
			}
			// Display visual indicator for disconnected slots
			if len(slot.Connections) == 0 {
				fmt.Fprint(w, "--")
			}
			fmt.Fprintf(w, "\n")
		}
		// Plugs are treated differently. Since the loop above already printed each connected
		// plug, the loop below focuses on printing just the disconnected plugs.
		for _, plug := range ifaces.Plugs {
			if x.Positionals.Query.Snap != "" && x.Positionals.Query.Snap != plug.Snap {
				continue
			}
			if x.Positionals.Query.Name != "" && x.Positionals.Query.Name != plug.Name {
				continue
			}
			if x.Interface != "" && plug.Interface != x.Interface {
				continue
			}
			// Display visual indicator for disconnected plugs.
			if len(plug.Connections) == 0 {
				fmt.Fprintf(w, "--\t%s:%s\n", plug.Snap, plug.Name)
			}
		}
	}
	return err
}
