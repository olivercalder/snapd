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
package partition

import (
	"fmt"

	"github.com/snapcore/snapd/gadget"
)

// makeFilesystem will create a filesystem on the given node with
// the given label and filesystem type. Optionally a directory with
// filesystem content can be specified and the newly created filesystem
// will be populated with that.
func makeFilesystem(node, label, filesystem, content string) error {
	switch filesystem {
	case "vfat":
		return gadget.MkfsVfat(node, label, content)
	case "ext4":
		return gadget.MkfsExt4(node, label, content)
	default:
		return fmt.Errorf("cannot create unsupported filesystem %q", filesystem)
	}
}
