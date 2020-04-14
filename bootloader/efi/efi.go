// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

// Package efi supports reading EFI variables.
package efi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/osutil"
)

var ErrNoEFISystem = errors.New("not a supported EFI system")

type VariableAttr uint32

const (
	VariableNonVolatile       VariableAttr = 0x00000001
	VariableBootServiceAccess VariableAttr = 0x00000002
	VariableRuntimeAccess     VariableAttr = 0x00000004
)

var (
	isSnapdTest = len(os.Args) > 0 && strings.HasSuffix(os.Args[0], ".test")
	openEFIVar  = openEFIVarImpl
)

const expectedEFIvarfsDir = "/sys/firmware/efi/efivars"

func openEFIVarImpl(name string) (r io.ReadCloser, attr VariableAttr, size int64, err error) {
	mounts, err := osutil.LoadMountInfo()
	if err != nil {
		return nil, 0, 0, err
	}
	found := false
	for _, mnt := range mounts {
		if mnt.MountDir == expectedEFIvarfsDir {
			if mnt.FsType == "efivarfs" {
				found = true
				break
			}
		}
	}
	if !found {
		return nil, 0, 0, ErrNoEFISystem
	}
	varf, err := os.Open(filepath.Join(dirs.GlobalRootDir, expectedEFIvarfsDir, name))
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() {
		if err != nil {
			varf.Close()
		}
	}()
	fi, err := varf.Stat()
	if err != nil {
		return nil, 0, 0, err
	}
	sz := fi.Size()
	if sz < 4 {
		return nil, 0, 0, fmt.Errorf("unexpected size: %d", sz)
	}

	var abuf [4]byte
	if _, err = varf.Read(abuf[:]); err != nil {
		return nil, 0, 0, err
	}
	return varf, VariableAttr(binary.LittleEndian.Uint32(abuf[:])), sz - 4, nil
}

func cannotReadError(name string, err error) error {
	return fmt.Errorf("cannot read EFI var %q: %v", name, err)
}

// ReadVarBytes will attempt to read the bytes of the value of the
// specified EFI variable, specified by it's full name of the variable
// and vendor ID. It also returns the attribute value attached to it.
// It expects to use the efivars filesystem at /sys/firmware/efivars.
// https://www.kernel.org/doc/Documentation/filesystems/efivarfs.txt
// for more details.
func ReadVarBytes(name string) ([]byte, VariableAttr, error) {
	varf, attr, _, err := openEFIVar(name)
	if err != nil {
		if err == ErrNoEFISystem {
			return nil, 0, err
		}
		return nil, 0, cannotReadError(name, err)
	}
	defer varf.Close()
	b, err := ioutil.ReadAll(varf)
	if err != nil {
		return nil, 0, cannotReadError(name, err)
	}
	return b, attr, nil
}

// ReadVarStringwill attempt to read the string value of the specified
// EFI variable, specified by it's full name of the variable and
// vendor ID. The string value is expected to be encoded as UTF16. It
// also returns the attribute value attached to it. It expects to use
// the efivars filesystem at /sys/firmware/efivars.
// https://www.kernel.org/doc/Documentation/filesystems/efivarfs.txt
// for more details.
func ReadVarString(name string) (string, VariableAttr, error) {
	varf, attr, sz, err := openEFIVar(name)
	if err != nil {
		if err == ErrNoEFISystem {
			return "", 0, err
		}
		return "", 0, cannotReadError(name, err)
	}
	defer varf.Close()
	if sz%2 != 0 {
		return "", 0, fmt.Errorf("EFI var %q has an extra byte to be an UTF16 string", name)
	}
	n := int(sz / 2)
	if n == 0 {
		return "", attr, nil
	}
	r16 := make([]uint16, n)
	for i := range r16 {
		var b [2]byte
		_, err := io.ReadFull(varf, b[:])
		if err != nil {
			return "", 0, cannotReadError(name, err)
		}
		r16[i] = binary.LittleEndian.Uint16(b[:])
	}
	if r16[n-1] == 0 {
		n--
	}
	b := &bytes.Buffer{}
	for _, r := range utf16.Decode(r16[:n]) {
		b.WriteRune(r)
	}
	return b.String(), attr, nil
}

// MockVars mocks EFI variables as read by ReadVar*, only to be used
// from tests. Set vars to nil to mock a non-EFI system.
func MockVars(vars map[string][]byte, attrs map[string]VariableAttr) (restore func()) {
	if !isSnapdTest {
		panic("MockVars only to be used from tests")
	}
	old := openEFIVar
	openEFIVar = func(name string) (io.ReadCloser, VariableAttr, int64, error) {
		if vars == nil {
			return nil, 0, 0, ErrNoEFISystem
		}
		if val, ok := vars[name]; ok {
			attr, ok := attrs[name]
			if !ok {
				attr = VariableRuntimeAccess | VariableBootServiceAccess
			}
			return ioutil.NopCloser(bytes.NewBuffer(val)), attr, int64(len(val)), nil
		}
		return nil, 0, 0, fmt.Errorf("EFI variable %s not mocked", name)
	}

	return func() {
		openEFIVar = old
	}
}
