// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016-2020 Canonical Ltd
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

// Package snapdenv presents common environment (and related) options
// for snapd components.
package snapdenv

import (
	"os"

	"github.com/snapcore/snapd/osutil"
)

var mockTesting *bool

// is this a testing binary? (see withtestkeys.go)
var testingBinary = false

// Testing returns whether snapd compontents are under testing.
func Testing() bool {
	if mockTesting != nil {
		return *mockTesting
	}
	ok := osutil.GetenvBool("SNAPPY_TESTING")
	if !ok {
		// assume testing if we are a testing binary and the
		// env is not set explicitly to the contrary
		if testingBinary && os.Getenv("SNAPPY_TESTING") == "" {
			return true
		}
	}
	return ok
}

func MockTesting(testing bool) (restore func()) {
	old := mockTesting
	mockTesting = &testing
	return func() {
		mockTesting = old
	}
}
