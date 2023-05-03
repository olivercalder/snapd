// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package dmverity_test

import (
	"fmt"
	"strings"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/snap/integrity/dmverity"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/testutil"
)

func Test(t *testing.T) { TestingT(t) }

type VerityTestSuite struct {
	testutil.BaseTest
}

var _ = Suite(&VerityTestSuite{})

func (s *VerityTestSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
}

func (s *VerityTestSuite) TearDownTest(c *C) {
	s.BaseTest.TearDownTest(c)
}

func (vs *VerityTestSuite) makeValidVeritySetupOutput() string {
	return `
VERITY header information for my-snap-name_0.1_all.snap.veritynosb
UUID:
Hash type:       	1
Data blocks:     	7
Data block size: 	4096
Hash blocks:     	1
Hash block size: 	4096
Hash algorithm:  	sha256
Salt:            	595c3d19c4d8d56727332eba16ef6900faeb4fde0c6625fefcd178b8dfdff48a
Root hash:      	cf9a379613c0dc10301fe3eba4665c38b849b7aad311471faa4d2392ee4ede49
Hash device size: 	4096 [bytes]
	`
}

func (s *VerityTestSuite) TestGetRootHashFromOutput(c *C) {
	testinput := s.makeValidVeritySetupOutput()
	testroothash := "cf9a379613c0dc10301fe3eba4665c38b849b7aad311471faa4d2392ee4ede49"

	roothash, err := dmverity.GetRootHashFromOutput([]byte(testinput))
	c.Assert(err, IsNil)
	c.Check(roothash, Equals, testroothash)
}

func (s *VerityTestSuite) TestGetRootHashFromOutputInvalid(c *C) {
	validVeritySetupOutput := s.makeValidVeritySetupOutput()

	rootHashLine := "Root hash:      	cf9a379613c0dc10301fe3eba4665c38b849b7aad311471faa4d2392ee4ede49"
	invalidTests := []struct{ original, invalid, expectedErr string }{
		{rootHashLine, "", "internal error: unexpected root hash length"},
		{rootHashLine, "Root hash      	", "internal error: unexpected veritysetup output format"},
		{"Hash algorithm:  	sha256", "Hash algorithm:  	sha25", "internal error: unexpected hash algorithm"},
	}

	for _, test := range invalidTests {
		invalid := strings.Replace(validVeritySetupOutput, test.original, test.invalid, 1)
		_, err := dmverity.GetRootHashFromOutput([]byte(invalid))
		c.Check(err, ErrorMatches, test.expectedErr)
	}
}

func (s *VerityTestSuite) TestFormatSuccess(c *C) {
	snapPath, _ := snaptest.MakeTestSnapInfoWithFiles(c, "name: foo\nversion: 1.0", nil, nil)

	// mock the verity-setup command, what it does is make of a copy of the snap
	// and then returns pre-calculated output
	vscmd := testutil.MockCommand(c, "veritysetup", fmt.Sprintf(`
cp %[1]s %[1]s.verity
echo VERITY header information for %[1]s.verity
echo "UUID:            	97d80536-aad9-4f25-a528-5319c038c0c4"
echo "Hash type:       	1"
echo "Data blocks:     	1"
echo "Data block size: 	4096"
echo "Hash block size: 	4096"
echo "Hash algorithm:  	sha256"
echo "Salt:            	c0234a906cfde0d5ffcba25038c240a98199cbc1d8fbd388a41e8faa02239c08"
echo "Root hash:      	e48cfc4df6df0f323bcf67f17b659a5074bec3afffe28f0b3b4db981d78d2e3e"
`, snapPath))
	defer vscmd.Restore()

	_, err := dmverity.Format(snapPath, snapPath+".verity")
	c.Assert(err, IsNil)
	c.Assert(vscmd.Calls(), HasLen, 1)
	c.Check(vscmd.Calls()[0], DeepEquals, []string{"veritysetup", "format", snapPath, snapPath + ".verity"})
}

func (s *VerityTestSuite) TestFormatFail(c *C) {
	snapPath, _ := snaptest.MakeTestSnapInfoWithFiles(c, "name: foo\nversion: 1.0", nil, nil)

	_, err := dmverity.Format(snapPath, "")
	c.Check(err, ErrorMatches, "Cannot create hash image  for writing.")
}
