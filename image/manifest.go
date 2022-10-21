// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2022 Canonical Ltd
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

package image

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"regexp"
	"sort"
	"strconv"

	"github.com/snapcore/snapd/snap"
)

// The seed.manifest generated by ubuntu-image contains entries in the following
// format:
// <snap-name> <snap-revision>
// The goal in a future iteration of this will be to move the generation of the
// seed.manifest to this package, out of ubuntu-image.
// TODO: Move generation of seed.manifest from ubuntu-image to here
var revisionEntryRegex = regexp.MustCompile(`([^\s]+) (-?[0-9]+)`)

// ReadSeedManifest reads a seed.manifest generated by ubuntu-image, and returns
// an map containing the snap names and their revisions.
func ReadSeedManifest(manifestFile string) (map[string]int, error) {
	contents, err := ioutil.ReadFile(manifestFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read seed manifest: %v", err)
	}

	matches := revisionEntryRegex.FindAllStringSubmatch(string(contents), -1)
	revisions := make(map[string]int, len(matches))
	for _, c := range matches {
		if err := snap.ValidateName(c[1]); err != nil {
			return nil, err
		}

		value, err := strconv.Atoi(c[2])
		if err != nil {
			return nil, fmt.Errorf("cannot read seed manifest file: %v", err)
		}

		// Values that are higher than 0 indicate the revision comes from the store, and values
		// lower than 0 indicate the snap was sourced locally. We allow both in the seed.manifest as
		// long as the user can provide us with the correct snaps. The only number we won't accept is
		// 0.
		if value == 0 {
			return nil, fmt.Errorf("cannot use revision %d for snap %q: revision must not be 0", value, c[1])
		}
		revisions[c[1]] = value
	}
	return revisions, nil
}

// WriteSeedManifest generates the seed.manifest contents from the provided map of
// snaps and their revisions, and stores in the the file path provided
func WriteSeedManifest(filePath string, revisions map[string]int) error {
	if len(revisions) == 0 {
		return nil
	}

	keys := make([]string, 0, len(revisions))
	for k := range revisions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := bytes.NewBuffer(nil)
	for _, key := range keys {
		rev := revisions[key]
		if rev == 0 {
			return fmt.Errorf("invalid revision %d for snap %q, revision must not be 0", rev, key)
		}
		fmt.Fprintf(buf, "%s %d.snap\n", key, rev)
	}
	return ioutil.WriteFile(filePath, buf.Bytes(), 0755)
}
