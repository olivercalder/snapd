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
package gadget

import (
	"encoding/binary"
	"fmt"
	"io"
)

// OffsetWriter implements support for writing the start offsets of structure
// and its content at locations defined by offset-write property. structures and
// their content.
type OffsetWriter struct {
	ps         *PositionedStructure
	sectorSize Size
}

func asLBA(value, sectorSize Size) uint32 {
	return uint32(value / sectorSize)
}

func deployOffsetWrite(out io.WriteSeeker, offset Size, value uint32) error {
	if _, err := out.Seek(int64(offset), io.SeekStart); err != nil {
		return fmt.Errorf("cannot seek to offset %v: %v", offset, err)
	}
	if err := binary.Write(out, binary.LittleEndian, value); err != nil {
		return fmt.Errorf("cannot write LBA value %#x at offset %v: %v", value, offset, err)
	}
	return nil
}

// NewOffsetWriter returns a writer for given structure.
func NewOffsetWriter(ps *PositionedStructure, sectorSize Size) *OffsetWriter {
	return &OffsetWriter{
		ps:         ps,
		sectorSize: sectorSize,
	}
}

// Write writes the start offset of the structure and the raw content of the
// structure, at the locations defined by offset-writer property of respective
// element, in the format of LBA pointer.
func (w *OffsetWriter) Write(out io.WriteSeeker) error {
	// positioning guarantees that start offset is aligned to sector size

	if w.ps.PositionedOffsetWrite != nil {
		if err := deployOffsetWrite(out, *w.ps.PositionedOffsetWrite, asLBA(w.ps.StartOffset, w.sectorSize)); err != nil {
			return err
		}
	}

	if !w.ps.IsBare() {
		// only raw content uses offset-writes
		return nil
	}

	for _, pc := range w.ps.PositionedContent {
		if pc.PositionedOffsetWrite == nil {
			continue
		}
		if err := deployOffsetWrite(out, *pc.PositionedOffsetWrite, asLBA(pc.StartOffset, w.sectorSize)); err != nil {
			return err
		}
	}
	return nil
}
