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
package seccomp

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"

	"github.com/snapcore/snapd/osutil"
)

var (
	// The format of version-info: <build-id> <libseccomp-version> <hash>
	// Where, the hash is calculated over all syscall names supported by the
	// libseccomp library.
	// Ex: 7ac348ac9c934269214b00d1692dfa50d5d4a157 2.3.3 03e996919907bc7163bc83b95bca0ecab31300f20dfa365ea14047c698340e7c
	validVersionInfo = regexp.MustCompile(`^[0-9a-f]+ [0-9]+\.[0-9]+\.[0-9]+ [0-9a-f]+$`)
)

type Compiler struct {
	snapSeccomp string
}

func NewAtPath(path string) *Compiler {
	return &Compiler{snapSeccomp: path}
}

// VersionInfo returns the version information of the compiler. The format of
// version information is: <build-id> <libseccomp-version> <hash>. Where, the
// hash is calculated over all syscall names supported by the libseccomp
// library.
func (c *Compiler) VersionInfo() (string, error) {
	cmd := exec.Command(c.snapSeccomp, "version-info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", osutil.OutputErr(output, err)
	}
	raw := bytes.TrimSpace(output)
	if len(raw) > 120 {
		return "", fmt.Errorf("invalid version-info length: %q", raw)
	}
	if match := validVersionInfo.Match(raw); !match {
		return "", fmt.Errorf("invalid format of version-info: %q", raw)
	}

	return string(raw), nil
}

// Compile compiles given source profile and saves the result to the out
// location.
func (c *Compiler) Compile(in, out string) error {
	cmd := exec.Command(c.snapSeccomp, "compile", in, out)
	if output, err := cmd.CombinedOutput(); err != nil {
		return osutil.OutputErr(output, err)
	}
	return nil
}
