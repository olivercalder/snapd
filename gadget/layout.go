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
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type LayoutConstraints struct {
	NonMBRStartOffset Size
	SectorSize        Size
}

type PositionedVolume struct {
	// Size is the total size of the volume
	Size Size
	// Structures are sorted in order of 'appearance' in the volume
	Structures []PositionedStructure
}

// PositionedStructure describes a VolumeStructure that has been positioned
// within the volume
type PositionedStructure struct {
	*VolumeStructure
	// StartOffset defines the start offset of the structure within the
	// enclosing volume
	StartOffset Size
	// Index of the structure definition in gadget YAML
	Index int

	// PositionedContent is a list of raw content included in this structure
	PositionedContent []PositionedContent
}

func (p PositionedStructure) String() string {
	return fmtIndexAndName(p.Index, p.Name)
}

type byStartOffset []PositionedStructure

func (b byStartOffset) Len() int           { return len(b) }
func (b byStartOffset) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }
func (b byStartOffset) Less(i, j int) bool { return b[i].StartOffset < b[j].StartOffset }

// PositionedContent describes raw content that has been positioned within the
// encompassing structure
type PositionedContent struct {
	*VolumeContent

	// StartOffset defines the start offset of this content image
	StartOffset Size
	// Size is the maximum size occupied by this image
	Size Size
}

// LayOutVolume attempts to lay out the volume using constraints and returns a
// fully positioned description of the resulting volume
func LayOutVolume(gadgetRootDir string, volume *Volume, constraints LayoutConstraints) (*PositionedVolume, error) {
	previousEnd := Size(0)
	farthestEnd := Size(0)
	structures := make([]PositionedStructure, len(volume.Structure))

	if constraints.SectorSize == 0 {
		return nil, fmt.Errorf("cannot lay out volume, invalid constraints: sector size cannot be 0")
	}

	for idx, s := range volume.Structure {
		var start Size
		if s.Offset == nil {
			if previousEnd < constraints.NonMBRStartOffset {
				start = constraints.NonMBRStartOffset
			} else {
				start = previousEnd
			}
		} else {
			start = *s.Offset
		}

		end := start + s.Size
		ps := PositionedStructure{
			VolumeStructure: &volume.Structure[idx],
			StartOffset:     start,
			Index:           idx,
		}

		if ps.EffectiveRole() != "mbr" {
			if s.Size%constraints.SectorSize != 0 {
				return nil, fmt.Errorf("cannot lay out volume, structure %v size is not a multiple of sector size %v",
					ps, constraints.SectorSize)
			}
		}

		structures[idx] = ps

		if end > farthestEnd {
			farthestEnd = end
		}
		previousEnd = end
	}

	// sort by starting offset
	sort.Sort(byStartOffset(structures))

	previousEnd = Size(0)
	for idx, ps := range structures {
		if ps.StartOffset < previousEnd {
			return nil, fmt.Errorf("cannot lay out volume, structure %v overlaps with preceding structure %v", ps, structures[idx-1])
		}
		previousEnd = ps.StartOffset + ps.Size

		content, err := layOutStructureContent(gadgetRootDir, &structures[idx])
		if err != nil {
			return nil, err
		}
		structures[idx].PositionedContent = content
	}

	vol := &PositionedVolume{
		Size:       farthestEnd,
		Structures: structures,
	}
	return vol, nil
}

type byContentStartOffset []PositionedContent

func (b byContentStartOffset) Len() int           { return len(b) }
func (b byContentStartOffset) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }
func (b byContentStartOffset) Less(i, j int) bool { return b[i].StartOffset < b[j].StartOffset }

func getImageSize(path string) (Size, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return Size(stat.Size()), nil
}

func layOutStructureContent(gadgetRootDir string, ps *PositionedStructure) ([]PositionedContent, error) {
	if !ps.IsBare() {
		// structures with a filesystem do not need any extra layout
		return nil, nil
	}
	if len(ps.Content) == 0 {
		return nil, nil
	}

	content := make([]PositionedContent, len(ps.Content))
	previousEnd := Size(0)

	for idx, c := range ps.Content {
		imageSize, err := getImageSize(filepath.Join(gadgetRootDir, c.Image))
		if err != nil {
			return nil, fmt.Errorf("cannot lay out structure %v: content %q: %v", ps, c.Image, err)
		}

		var start Size
		if c.Offset != nil {
			start = *c.Offset
		} else {
			start = previousEnd
		}

		actualSize := imageSize

		if c.Size != 0 {
			if c.Size < imageSize {
				return nil, fmt.Errorf("cannot lay out structure %v: content %q size %v is larger than declared %v", ps, c.Image, actualSize, c.Size)
			}
			actualSize = c.Size
		}

		content[idx] = PositionedContent{
			VolumeContent: &ps.Content[idx],
			StartOffset:   ps.StartOffset + start,
			Size:          actualSize,
		}
		previousEnd = start + actualSize
		if previousEnd > ps.Size {
			return nil, fmt.Errorf("cannot lay out structure %v: content %q does not fit in the structure", ps, c.Image)
		}
	}

	sort.Sort(byContentStartOffset(content))

	previousEnd = ps.StartOffset
	for idx, pc := range content {
		if pc.StartOffset < previousEnd {
			return nil, fmt.Errorf("cannot lay out structure %v: content %q overlaps with preceding image %q", ps, pc.Image, content[idx-1].Image)
		}
		previousEnd = pc.StartOffset + pc.Size
	}

	return content, nil
}
