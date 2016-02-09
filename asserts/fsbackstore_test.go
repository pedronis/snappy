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

package asserts_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	. "gopkg.in/check.v1"

	"github.com/ubuntu-core/snappy/asserts"
)

type fsBackstoreSuite struct{}

var _ = Suite(&fsBackstoreSuite{})

func (fsbss *fsBackstoreSuite) TestOpenOK(c *C) {
	// ensure umask is clean when creating the DB dir
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	topDir := filepath.Join(c.MkDir(), "asserts-db")

	bs, err := asserts.OpenFSBackstore(topDir)
	c.Check(err, IsNil)
	c.Check(bs, NotNil)

	info, err := os.Stat(filepath.Join(topDir, "asserts-v0"))
	c.Assert(err, IsNil)
	c.Assert(info.IsDir(), Equals, true)
	c.Check(info.Mode().Perm(), Equals, os.FileMode(0775))
}

func (fsbss *fsBackstoreSuite) TestOpenCreateFail(c *C) {
	parent := filepath.Join(c.MkDir(), "var")
	topDir := filepath.Join(parent, "asserts-db")
	// make it not writable
	err := os.Mkdir(parent, 0555)
	c.Assert(err, IsNil)

	bs, err := asserts.OpenFSBackstore(topDir)
	c.Assert(err, ErrorMatches, "failed to create assert storage root: .*")
	c.Check(bs, IsNil)
}

func (fsbss *fsBackstoreSuite) TestOpenWorldWritableFail(c *C) {
	topDir := filepath.Join(c.MkDir(), "asserts-db")
	// make it world-writable
	oldUmask := syscall.Umask(0)
	os.MkdirAll(filepath.Join(topDir, "asserts-v0"), 0777)
	syscall.Umask(oldUmask)

	bs, err := asserts.OpenFSBackstore(topDir)
	c.Assert(err, ErrorMatches, "assert storage root unexpectedly world-writable: .*")
	c.Check(bs, IsNil)
}

type scanner interface {
	Scan(assertType *asserts.AssertionType, scanCb func(asserts.Assertion, error)) error
}

func (fsbss *fsBackstoreSuite) TestScanNothing(c *C) {
	topDir := filepath.Join(c.MkDir(), "asserts-db")

	bs, err := asserts.OpenFSBackstore(topDir)
	c.Assert(err, IsNil)

	scanner, ok := bs.(scanner)
	c.Assert(ok, Equals, true)

	invoked := 0
	scanCb := func(asserts.Assertion, error) {
		invoked++
	}

	err = scanner.Scan(asserts.TestOnly2Type, scanCb)
	c.Check(err, IsNil)
	c.Check(invoked, Equals, 0)
}

const (
	exampleTestOnly2_1 = `type: test-only-2
authority-id: auth-id1
pk1: a
pk2: x
body-length: 0

openpgp c2ln
`
	exampleTestOnly2_2 = `type: test-only-2
authority-id: auth-id1
pk1: b
pk2: y%
body-length: 0

openpgp c2ln
`
)

func (fsbss *fsBackstoreSuite) TestScanTwo(c *C) {
	topDir := filepath.Join(c.MkDir(), "asserts-db")

	bs, err := asserts.OpenFSBackstore(topDir)
	c.Assert(err, IsNil)

	a1, err := asserts.Decode([]byte(exampleTestOnly2_1))
	c.Assert(err, IsNil)
	a2, err := asserts.Decode([]byte(exampleTestOnly2_2))
	c.Assert(err, IsNil)

	err = bs.Put(asserts.TestOnly2Type, a1)
	c.Assert(err, IsNil)
	err = bs.Put(asserts.TestOnly2Type, a2)
	c.Assert(err, IsNil)

	scanner, ok := bs.(scanner)
	c.Assert(ok, Equals, true)

	var seen []asserts.Assertion
	scanCb := func(a asserts.Assertion, err error) {
		c.Assert(err, IsNil)
		seen = append(seen, a)
	}

	err = scanner.Scan(asserts.TestOnly2Type, scanCb)
	c.Assert(err, IsNil)

	c.Check(seen, HasLen, 2)
	c.Check(seen[0].Header("pk1"), Equals, "a")
	c.Check(seen[1].Header("pk1"), Equals, "b")
}

func setupBackstore(c *C) (topDir string, bs asserts.Backstore) {
	topDir = filepath.Join(c.MkDir(), "asserts-db")

	bs, err := asserts.OpenFSBackstore(topDir)
	c.Assert(err, IsNil)

	a1, err := asserts.Decode([]byte(exampleTestOnly2_1))
	c.Assert(err, IsNil)
	a2, err := asserts.Decode([]byte(exampleTestOnly2_2))
	c.Assert(err, IsNil)

	err = bs.Put(asserts.TestOnly2Type, a1)
	c.Assert(err, IsNil)
	err = bs.Put(asserts.TestOnly2Type, a2)
	c.Assert(err, IsNil)

	return
}

func (fsbss *fsBackstoreSuite) TestScanKeyMismatch(c *C) {
	topDir, bs := setupBackstore(c)

	// confuse path to content mapping
	err := os.Rename(filepath.Join(topDir, "asserts-v0", "test-only-2", "a", "x"), filepath.Join(topDir, "asserts-v0", "test-only-2", "a", "z"))
	c.Assert(err, IsNil)
	err = os.Rename(filepath.Join(topDir, "asserts-v0", "test-only-2", "a"), filepath.Join(topDir, "asserts-v0", "test-only-2", "e"))
	c.Assert(err, IsNil)
	affected := filepath.Join(topDir, "asserts-v0", "test-only-2", "e", "z", "active")

	scanner, ok := bs.(scanner)
	c.Assert(ok, Equals, true)

	var errors []error
	var seen []asserts.Assertion
	scanCb := func(a asserts.Assertion, err error) {
		if err != nil {
			errors = append(errors, err)
			return
		}
		seen = append(seen, a)
	}

	err = scanner.Scan(asserts.TestOnly2Type, scanCb)
	c.Assert(err, IsNil)

	c.Check(seen, HasLen, 1)
	c.Check(seen[0].Header("pk1"), Equals, "b")

	c.Check(errors, HasLen, 2)
	c.Check(errors[0], ErrorMatches, fmt.Sprintf(`scan test-only-2 %q: disk path key value "e" for "pk1" does not match assertion content: "a"`, affected))
	c.Check(errors[1], ErrorMatches, fmt.Sprintf(`scan test-only-2 %q: disk path key value "z" for "pk2" does not match assertion content: "x"`, affected))
}

func (fsbss *fsBackstoreSuite) TestScanUnexpectedFname(c *C) {
	topDir, bs := setupBackstore(c)

	// confuse path to content mapping
	affected := filepath.Join(topDir, "asserts-v0", "test-only-2", "a", "x", "foo")
	err := os.Rename(filepath.Join(topDir, "asserts-v0", "test-only-2", "a", "x", "active"), affected)
	c.Assert(err, IsNil)

	scanner, ok := bs.(scanner)
	c.Assert(ok, Equals, true)

	var errors []error
	seen := 0
	scanCb := func(a asserts.Assertion, err error) {
		if err != nil {
			errors = append(errors, err)
			return
		}
		seen++
	}

	err = scanner.Scan(asserts.TestOnly2Type, scanCb)
	c.Assert(err, IsNil)

	c.Check(seen, Equals, 1)

	c.Check(errors, HasLen, 1)
	c.Check(errors[0], ErrorMatches, fmt.Sprintf(`scan test-only-2 %q: assertion file unexpectedly not named "active"`, affected))
}

func (fsbss *fsBackstoreSuite) TestScanReadFail(c *C) {
	topDir, bs := setupBackstore(c)

	// confuse path to content mapping
	affected := filepath.Join(topDir, "asserts-v0", "test-only-2", "a", "x", "active")
	err := os.Truncate(affected, 0)
	c.Assert(err, IsNil)

	scanner, ok := bs.(scanner)
	c.Assert(ok, Equals, true)

	var errors []error
	seen := 0
	scanCb := func(a asserts.Assertion, err error) {
		if err != nil {
			errors = append(errors, err)
			return
		}
		seen++
	}

	err = scanner.Scan(asserts.TestOnly2Type, scanCb)
	c.Assert(err, IsNil)

	c.Check(seen, Equals, 1)

	c.Check(errors, HasLen, 1)
	c.Check(errors[0], ErrorMatches, fmt.Sprintf(`scan test-only-2 %q: broken assertion storage, failed to decode assertion: .*`, affected))
}

func (fsbss *fsBackstoreSuite) TestScanExpectingRegularFile(c *C) {
	topDir, bs := setupBackstore(c)

	// confuse path to content mapping
	affected := filepath.Join(topDir, "asserts-v0", "test-only-2", "a", "x", "baz")
	err := os.Mkdir(affected, 0770)
	c.Assert(err, IsNil)
	// ignored file
	err = ioutil.WriteFile(filepath.Join(affected, "ignored"), nil, 0770)
	c.Assert(err, IsNil)

	scanner, ok := bs.(scanner)
	c.Assert(ok, Equals, true)

	var errors []error
	seen := 0
	scanCb := func(a asserts.Assertion, err error) {
		if err != nil {
			errors = append(errors, err)
			return
		}
		seen++
	}

	err = scanner.Scan(asserts.TestOnly2Type, scanCb)
	c.Assert(err, IsNil)

	c.Check(seen, Equals, 2)

	c.Check(errors, HasLen, 1)
	c.Check(errors[0], ErrorMatches, fmt.Sprintf(`scan test-only-2 %q: expected regular file`, affected))
}

func (fsbss *fsBackstoreSuite) TestScanExpectingDirectory(c *C) {
	topDir, bs := setupBackstore(c)

	// confuse path to content mapping
	affected := filepath.Join(topDir, "asserts-v0", "test-only-2", "a", "baz")
	err := ioutil.WriteFile(affected, nil, 0770)
	c.Assert(err, IsNil)

	scanner, ok := bs.(scanner)
	c.Assert(ok, Equals, true)

	var errors []error
	seen := 0
	scanCb := func(a asserts.Assertion, err error) {
		if err != nil {
			errors = append(errors, err)
			return
		}
		seen++
	}

	err = scanner.Scan(asserts.TestOnly2Type, scanCb)
	c.Assert(err, IsNil)

	c.Check(seen, Equals, 2)

	c.Check(errors, HasLen, 1)
	c.Check(errors[0], ErrorMatches, fmt.Sprintf(`scan test-only-2 %q: expected directory`, affected))
}

func (fsbss *fsBackstoreSuite) TestScanUnreadable(c *C) {
	topDir, bs := setupBackstore(c)

	// confuse path to content mapping
	affected := filepath.Join(topDir, "asserts-v0", "test-only-2", "a")
	err := os.Chmod(affected, 000)
	c.Assert(err, IsNil)
	defer os.Chmod(affected, 0770)

	scanner, ok := bs.(scanner)
	c.Assert(ok, Equals, true)

	var errors []error
	seen := 0
	scanCb := func(a asserts.Assertion, err error) {
		if err != nil {
			errors = append(errors, err)
			return
		}
		seen++
	}

	err = scanner.Scan(asserts.TestOnly2Type, scanCb)
	c.Assert(err, IsNil)

	c.Check(seen, Equals, 1)

	c.Check(errors, HasLen, 1)
	c.Check(errors[0], ErrorMatches, fmt.Sprintf(`scan test-only-2 %q: .* permission denied`, affected))
}
