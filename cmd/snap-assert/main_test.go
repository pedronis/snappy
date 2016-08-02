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

package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"

	snapassert "github.com/snapcore/snapd/cmd/snap-assert"
)

func Test(t *testing.T) { TestingT(t) }

type snapassertSuite struct {
	tempdir string
	homedir string

	savedArgs []string

	stdin  *bytes.Buffer
	stdout *bytes.Buffer
}

var _ = Suite(&snapassertSuite{})

func (s *snapassertSuite) SetUpSuite(c *C) {
	s.tempdir = c.MkDir()
	s.homedir = filepath.Join(s.tempdir, "gpg")
	err := os.Mkdir(s.homedir, 0700)
	c.Assert(err, IsNil)

	assertstest.GPGImportKey(s.homedir, assertstest.DevKey)
}

func (s *snapassertSuite) SetUpTest(c *C) {
	s.savedArgs = os.Args
	s.stdin = new(bytes.Buffer)
	s.stdout = new(bytes.Buffer)
	snapassert.Stdout = s.stdout
	snapassert.Stdin = s.stdin
}

func (s *snapassertSuite) TearDownTest(c *C) {
	snapassert.Stdin = os.Stdin
	snapassert.Stdout = os.Stdout
	os.Args = s.savedArgs
}

func (s *snapassertSuite) TestHappy(c *C) {
	os.Args = []string{"", "--gpg-homedir", s.homedir, "--key-hash", assertstest.DevKeyHash, "--authority-id", "devel1", "snap-build"}

	s.stdin.Write([]byte(fmt.Sprintf(`series: "16"
snap-id: snapidsnapidsnapidsnapidsnapidsn
snap-sha3-384: QlqR0uAWEAWF5Nwnzj5kqmmwFslYPu1IL16MKtLKhwhv0kpBv5wKZ_axf_nf_2cL
snap-size: "1"
grade: devel
timestamp: %s
`, time.Now().Format(time.RFC3339))))

	err := snapassert.Run()
	c.Assert(err, IsNil)

	a, err := asserts.Decode(s.stdout.Bytes())
	c.Assert(err, IsNil)
	c.Check(a.Type(), Equals, asserts.SnapBuildType)
}

func (s *snapassertSuite) TestHappyKeyID(c *C) {
	os.Args = []string{"", "--gpg-homedir", s.homedir, "--key-id", assertstest.DevKeyPGPFingerprint, "--authority-id", "devel1", "snap-build"}

	s.stdin.Write([]byte(fmt.Sprintf(`series: "16"
snap-id: snapidsnapidsnapidsnapidsnapidsn
snap-sha3-384: QlqR0uAWEAWF5Nwnzj5kqmmwFslYPu1IL16MKtLKhwhv0kpBv5wKZ_axf_nf_2cL
snap-size: "1"
grade: devel
timestamp: %s
`, time.Now().Format(time.RFC3339))))

	err := snapassert.Run()
	c.Assert(err, IsNil)

	a, err := asserts.Decode(s.stdout.Bytes())
	c.Assert(err, IsNil)
	c.Check(a.Type(), Equals, asserts.SnapBuildType)
}

func (s *snapassertSuite) TestHappyJSONAccountKeyStatementFile(c *C) {
	accKeyFile := filepath.Join(s.tempdir, "devel1.account-key")
	statementFile := filepath.Join(s.tempdir, "snap-build")

	devKey, _ := assertstest.ReadPrivKey(assertstest.DevKey)
	pubKeyEncoded, err := asserts.EncodePublicKey(devKey.PublicKey())
	c.Assert(err, IsNil)

	now := time.Now()
	// good enough as a handle as is used by Sign
	mockAccKey := "type: account-key\n" +
		"authority-id: canonical\n" +
		"account-id: user-id1\n" +
		"public-key-sha3-384: " + assertstest.DevKeyHash + "\n" +
		"since: " + now.Format(time.RFC3339) + "\n" +
		"until: " + now.AddDate(1, 0, 0).Format(time.RFC3339) + "\n" +
		fmt.Sprintf("body-length: %v", len(pubKeyEncoded)) + "\n" +
		"sign-key-sha3-384: Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij" + "\n\n" +
		string(pubKeyEncoded) + "\n\n" +
		"openpgp c2ln"

	err = ioutil.WriteFile(accKeyFile, []byte(mockAccKey), 0655)
	c.Assert(err, IsNil)

	headers := map[string]interface{}{
		"series":        "16",
		"snap-id":       "snapidsnapidsnapidsnapidsnapidsn",
		"snap-sha3-384": "QlqR0uAWEAWF5Nwnzj5kqmmwFslYPu1IL16MKtLKhwhv0kpBv5wKZ_axf_nf_2cL",
		"snap-size":     "1",
		"grade":         "devel",
		"timestamp":     now.Format(time.RFC3339),
	}

	b, err := json.Marshal(headers)
	c.Assert(err, IsNil)

	err = ioutil.WriteFile(statementFile, b, 0655)
	c.Assert(err, IsNil)

	os.Args = []string{"", "--gpg-homedir", s.homedir, "--format", "json", "--account-key", accKeyFile, "snap-build", statementFile}

	err = snapassert.Run()
	c.Assert(err, IsNil)

	a, err := asserts.Decode(s.stdout.Bytes())
	c.Assert(err, IsNil)
	c.Check(a.Type(), Equals, asserts.SnapBuildType)
}

func (s *snapassertSuite) TestHappyAccountKeyKeyIDs(c *C) {
	os.Args = []string{"", "--gpg-homedir", s.homedir, "--key-id", assertstest.DevKeyPGPFingerprint, "--public-key-id", assertstest.DevKeyPGPFingerprint, "--authority-id", "devel1", "account-key"}

	now := time.Now()
	until := now.AddDate(5, 0, 0) // XXX: we don't to be forced to set until actully

	s.stdin.Write([]byte(fmt.Sprintf(`
account-id: devel1
since: %s
until: %s
`, now.Format(time.RFC3339), until.Format(time.RFC3339))))

	err := snapassert.Run()
	c.Assert(err, IsNil)

	a, err := asserts.Decode(s.stdout.Bytes())
	c.Assert(err, IsNil)
	c.Check(a.Type(), Equals, asserts.AccountKeyType)
	ak := a.(*asserts.AccountKey)
	c.Check(ak.AuthorityID(), Equals, "devel1")
	c.Check(ak.AccountID(), Equals, "devel1")
	c.Check(ak.PublicKeySHA3_384(), Equals, assertstest.DevKeyHash)
}

func (s *snapassertSuite) TestHappyAccountKeyKeyHashes(c *C) {
	os.Args = []string{"", "--gpg-homedir", s.homedir, "--key-hash", assertstest.DevKeyHash, "--public-key-hash", assertstest.DevKeyHash, "--authority-id", "devel1", "account-key"}

	now := time.Now()
	until := now.AddDate(5, 0, 0) // XXX: we don't to be forced to set until actully

	s.stdin.Write([]byte(fmt.Sprintf(`
account-id: devel1
since: %s
until: %s
`, now.Format(time.RFC3339), until.Format(time.RFC3339))))

	err := snapassert.Run()
	c.Assert(err, IsNil)

	a, err := asserts.Decode(s.stdout.Bytes())
	c.Assert(err, IsNil)
	c.Check(a.Type(), Equals, asserts.AccountKeyType)
	ak := a.(*asserts.AccountKey)
	c.Check(ak.AuthorityID(), Equals, "devel1")
	c.Check(ak.AccountID(), Equals, "devel1")
	c.Check(ak.PublicKeySHA3_384(), Equals, assertstest.DevKeyHash)
}
