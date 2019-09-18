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

package osutil_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/testutil"
)

type EnsureDirStateSuite struct {
	dir  string
	glob string
}

var _ = Suite(&EnsureDirStateSuite{glob: "*.snap"})

func (s *EnsureDirStateSuite) SetUpTest(c *C) {
	s.dir = c.MkDir()
}

func (s *EnsureDirStateSuite) TestVerifiesExpectedFiles(c *C) {
	name := filepath.Join(s.dir, "expected.snap")
	err := ioutil.WriteFile(name, []byte("expected"), 0600)
	c.Assert(err, IsNil)
	changed, removed, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{
		"expected.snap": &osutil.MemoryBlob{Content: []byte("expected"), Mode: 0600},
	})
	c.Assert(err, IsNil)
	// Report says that nothing has changed
	c.Assert(changed, HasLen, 0)
	c.Assert(removed, HasLen, 0)
	// The content is correct
	c.Assert(path.Join(s.dir, "expected.snap"), testutil.FileEquals, "expected")
	// The permissions are correct
	stat, err := os.Stat(name)
	c.Assert(err, IsNil)
	c.Assert(stat.Mode().Perm(), Equals, os.FileMode(0600))
}

func (s *EnsureDirStateSuite) TestTwoPatterns(c *C) {
	name1 := filepath.Join(s.dir, "expected.snap")
	err := ioutil.WriteFile(name1, []byte("expected-1"), 0600)
	c.Assert(err, IsNil)

	name2 := filepath.Join(s.dir, "expected.snap-update-ns")
	err = ioutil.WriteFile(name2, []byte("expected-2"), 0600)
	c.Assert(err, IsNil)

	changed, removed, err := osutil.EnsureDirStateGlobs(s.dir, []string{"*.snap", "*.snap-update-ns"}, map[string]osutil.FileState{
		"expected.snap":           &osutil.MemoryBlob{Content: []byte("expected-1"), Mode: 0600},
		"expected.snap-update-ns": &osutil.MemoryBlob{Content: []byte("expected-2"), Mode: 0600},
	})
	c.Assert(err, IsNil)
	// Report says that nothing has changed
	c.Assert(changed, HasLen, 0)
	c.Assert(removed, HasLen, 0)
	// The content is correct
	c.Assert(name1, testutil.FileEquals, "expected-1")
	c.Assert(name2, testutil.FileEquals, "expected-2")
	// The permissions are correct
	stat, err := os.Stat(name1)
	c.Assert(err, IsNil)
	c.Assert(stat.Mode().Perm(), Equals, os.FileMode(0600))
	stat, err = os.Stat(name2)
	c.Assert(err, IsNil)
	c.Assert(stat.Mode().Perm(), Equals, os.FileMode(0600))
}

func (s *EnsureDirStateSuite) TestMultipleMatches(c *C) {
	name := filepath.Join(s.dir, "foo")
	err := ioutil.WriteFile(name, []byte("content"), 0600)
	c.Assert(err, IsNil)
	// When a file is matched by multiple globs it removed correctly.
	changed, removed, err := osutil.EnsureDirStateGlobs(s.dir, []string{"foo", "f*"}, nil)
	c.Assert(err, IsNil)
	c.Assert(changed, HasLen, 0)
	c.Assert(removed, DeepEquals, []string{"foo"})
}

func (s *EnsureDirStateSuite) TestCreatesMissingFiles(c *C) {
	name := filepath.Join(s.dir, "missing.snap")
	changed, removed, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{
		"missing.snap": &osutil.MemoryBlob{Content: []byte(`content`), Mode: 0600},
	})
	c.Assert(err, IsNil)
	// Created file is reported
	c.Assert(changed, DeepEquals, []string{"missing.snap"})
	c.Assert(removed, HasLen, 0)
	// The content is correct
	c.Assert(name, testutil.FileEquals, "content")
	// The permissions are correct
	stat, err := os.Stat(name)
	c.Assert(err, IsNil)
	c.Assert(stat.Mode().Perm(), Equals, os.FileMode(0600))
}

func (s *EnsureDirStateSuite) TestRemovesUnexpectedFiless(c *C) {
	name := filepath.Join(s.dir, "evil.snap")
	err := ioutil.WriteFile(name, []byte(`evil text`), 0600)
	c.Assert(err, IsNil)
	changed, removed, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{})
	c.Assert(err, IsNil)
	// Removed file is reported
	c.Assert(changed, HasLen, 0)
	c.Assert(removed, DeepEquals, []string{"evil.snap"})
	// The file is removed
	_, err = os.Stat(name)
	c.Assert(os.IsNotExist(err), Equals, true)
}

func (s *EnsureDirStateSuite) TestIgnoresUnrelatedFiles(c *C) {
	name := filepath.Join(s.dir, "unrelated")
	err := ioutil.WriteFile(name, []byte(`text`), 0600)
	c.Assert(err, IsNil)
	changed, removed, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{})
	c.Assert(err, IsNil)
	// Report says that nothing has changed
	c.Assert(changed, HasLen, 0)
	c.Assert(removed, HasLen, 0)
	// The file is still there
	_, err = os.Stat(name)
	c.Assert(err, IsNil)
}

func (s *EnsureDirStateSuite) TestCorrectsFilesWithDifferentSize(c *C) {
	name := filepath.Join(s.dir, "differing.snap")
	err := ioutil.WriteFile(name, []byte(``), 0600)
	c.Assert(err, IsNil)
	changed, removed, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{
		"differing.snap": &osutil.MemoryBlob{Content: []byte(`Hello World`), Mode: 0600},
	})
	c.Assert(err, IsNil)
	// changed file is reported
	c.Assert(changed, DeepEquals, []string{"differing.snap"})
	c.Assert(removed, HasLen, 0)
	// The content is changed
	c.Assert(name, testutil.FileEquals, "Hello World")
	// The permissions are what we expect
	stat, err := os.Stat(name)
	c.Assert(err, IsNil)
	c.Assert(stat.Mode().Perm(), Equals, os.FileMode(0600))
}

func (s *EnsureDirStateSuite) TestCorrectsFilesWithSameSize(c *C) {
	name := filepath.Join(s.dir, "differing.snap")
	err := ioutil.WriteFile(name, []byte("evil"), 0600)
	c.Assert(err, IsNil)
	changed, removed, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{
		"differing.snap": &osutil.MemoryBlob{Content: []byte("good"), Mode: 0600},
	})
	c.Assert(err, IsNil)
	// changed file is reported
	c.Assert(changed, DeepEquals, []string{"differing.snap"})
	c.Assert(removed, HasLen, 0)
	// The content is changed
	c.Assert(name, testutil.FileEquals, "good")
	// The permissions are what we expect
	stat, err := os.Stat(name)
	c.Assert(err, IsNil)
	c.Assert(stat.Mode().Perm(), Equals, os.FileMode(0600))
}

func (s *EnsureDirStateSuite) TestFixesFilesWithBadPermissions(c *C) {
	name := filepath.Join(s.dir, "sensitive.snap")
	// NOTE: the existing file is currently wide-open for everyone"
	err := ioutil.WriteFile(name, []byte("password"), 0666)
	c.Assert(err, IsNil)
	changed, removed, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{
		// NOTE: we want the file to be private
		"sensitive.snap": &osutil.MemoryBlob{Content: []byte("password"), Mode: 0600},
	})
	c.Assert(err, IsNil)
	// changed file is reported
	c.Assert(changed, DeepEquals, []string{"sensitive.snap"})
	c.Assert(removed, HasLen, 0)
	// The content is still the same
	c.Assert(name, testutil.FileEquals, "password")
	// The permissions are changed
	stat, err := os.Stat(name)
	c.Assert(err, IsNil)
	c.Assert(stat.Mode().Perm(), Equals, os.FileMode(0600))
}

func (s *EnsureDirStateSuite) TestReportsAbnormalFileLocation(c *C) {
	_, _, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{"subdir/file.snap": &osutil.MemoryBlob{}})
	c.Assert(err, ErrorMatches, `internal error: EnsureDirState got filename "subdir/file.snap" which has a path component`)
}

func (s *EnsureDirStateSuite) TestReportsAbnormalFileName(c *C) {
	_, _, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{"without-namespace": &osutil.MemoryBlob{}})
	c.Assert(err, ErrorMatches, `internal error: EnsureDirState got filename "without-namespace" which doesn't match the glob pattern "\*\.snap"`)
}

func (s *EnsureDirStateSuite) TestReportsAbnormalPatterns(c *C) {
	_, _, err := osutil.EnsureDirState(s.dir, "[", nil)
	c.Assert(err, ErrorMatches, `internal error: EnsureDirState got invalid pattern "\[": syntax error in pattern`)
}

func (s *EnsureDirStateSuite) TestRemovesAllManagedFilesOnError(c *C) {
	// Create a "prior.snap" file
	prior := filepath.Join(s.dir, "prior.snap")
	err := ioutil.WriteFile(prior, []byte("data"), 0600)
	c.Assert(err, IsNil)
	// Create a "clash.snap" directory to simulate failure
	clash := filepath.Join(s.dir, "clash.snap")
	err = os.Mkdir(clash, 0000)
	c.Assert(err, IsNil)
	// Try to ensure directory state
	changed, removed, err := osutil.EnsureDirState(s.dir, s.glob, map[string]osutil.FileState{
		"prior.snap": &osutil.MemoryBlob{Content: []byte("data"), Mode: 0600},
		"clash.snap": &osutil.MemoryBlob{Content: []byte("data"), Mode: 0600},
	})
	c.Assert(changed, HasLen, 0)
	c.Assert(removed, DeepEquals, []string{"clash.snap", "prior.snap"})
	c.Assert(err, ErrorMatches, "open .*/clash.snap: permission denied")
	// The clashing file is removed
	_, err = os.Stat(clash)
	c.Assert(os.IsNotExist(err), Equals, true)
}

func (s *EnsureDirStateSuite) TestStreamEqual(c *C) {
	text := "marry had a little lamb"

	// Passing the same stream twice is not mishandled.
	readerA := bytes.NewReader(nil)
	readerB := readerA
	eq, err := osutil.StreamEqual(readerA, readerB, 0)
	c.Assert(err, IsNil)
	c.Check(eq, Equals, true)

	// Passing two streams with the same content works as expected. Note that
	// we are using different block sizes to check for additional edge cases.
	for _, chunkSize := range []int{0, 1, len(text) / 2, len(text), len(text) + 1} {
		readerA = bytes.NewReader([]byte(text))
		readerB = bytes.NewReader([]byte(text))
		eq, err = osutil.StreamEqual(readerA, readerB, chunkSize)
		c.Assert(err, IsNil)
		c.Check(eq, Equals, true, Commentf("chunk size %d", chunkSize))
	}

	// Passing two streams with unequal contents but equal length works as
	// expected.
	for _, chunkSize := range []int{0, 1, len(text) / 2, len(text), len(text) + 1} {
		comment := Commentf("chunk size %d", chunkSize)
		readerA = bytes.NewReader([]byte(strings.ToLower(text)))
		readerB = bytes.NewReader([]byte(strings.ToUpper(text)))
		eq, err = osutil.StreamEqual(readerA, readerB, chunkSize)
		c.Assert(err, IsNil, comment)
		c.Check(eq, Equals, false, comment)
	}

	// Passing two streams with different length works as expected.
	// Note that this is not used by EnsureDirState in practice.
	for _, chunkSize := range []int{0, 1, len(text) / 2, len(text), len(text) + 1} {
		comment := Commentf("A: %q, B: %q, chunk size %d", text, text[:len(text)/2], chunkSize)
		readerA = bytes.NewReader([]byte(text))
		readerB = bytes.NewReader([]byte(text[:len(text)/2]))
		eq, err = osutil.StreamEqual(readerA, readerB, chunkSize)
		c.Assert(err, IsNil, comment)
		c.Check(eq, Equals, false, comment)

		// Readers passed the other way around.
		readerA = bytes.NewReader([]byte(text))
		readerB = bytes.NewReader([]byte(text[:len(text)/2]))
		eq, err = osutil.StreamEqual(readerB, readerA, chunkSize)
		c.Assert(err, IsNil, comment)
		c.Check(eq, Equals, false, comment)
	}
}

func (s *EnsureDirStateSuite) TestStreamEqualWAT(c *C) {
	text := "marry had a little lamb"
	chunkSize := 1
	comment := Commentf("A: %q, B: %q, chunk size %d", text, text[:len(text)/2], chunkSize)
	readerA := bytes.NewReader([]byte(text))
	readerB := bytes.NewReader([]byte(text[:len(text)/2]))

	eq, err := osutil.StreamEqual(readerB, readerA, chunkSize)
	c.Assert(err, IsNil, comment)
	c.Check(eq, Equals, false, comment)
}
