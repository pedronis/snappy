// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2015 Canonical Ltd
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

package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/jessevdk/go-flags"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/tool"
)

func main() {
	if err := Run(); err != nil {
		fmt.Fprintf(os.Stderr, "snap-assert: %s\n", err)
		os.Exit(1)
	}
}

// Standard streams, redirected for testing.
var (
	Stdout io.Writer = os.Stdout
	Stdin  io.Reader = os.Stdin
)

func findByKeyPGPID(mgr *asserts.GPGKeypairManager, keyID string) (asserts.PublicKey, error) {
	found := errors.New("found")
	var pubKey asserts.PublicKey
	idSfx := strings.ToUpper(keyID)
	match := func(privk asserts.PrivateKey, fpr string) error {
		if strings.HasSuffix(fpr, idSfx) {
			pubKey = privk.PublicKey()
			return found
		}
		return nil
	}
	err := mgr.Walk(match)
	if err == found {
		return pubKey, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot find key by key id %q: %v", keyID, err)
	}
	return nil, nil
}

func findByKeyID(mgr *asserts.GPGKeypairManager, keyID string) (asserts.PublicKey, error) {
	pk, err := mgr.Get("", keyID)
	if err != nil {
		return nil, err
	}
	return pk.PublicKey(), nil
}

func Run() error {
	var opts struct {
		Positional struct {
			AssertionType string `positional-arg-name:"<assert-type>" required:"yes" description:"type of the assertion to sign (mandatory)"`
			Statement     string `positional-arg-name:"<statement>" description:"input file with the statement to sign as YAML or JSON (optional, left out or - means use stdin)"`
		} `positional-args:"yes"`

		Format string `long:"format" default:"yaml" description:"the format of the input statement (json|yaml)"`

		AuthorityID string `long:"authority-id" description:"identifier of the signer (otherwise taken from the account-key or the statement)"`
		KeyID       string `long:"key-id" description:"snappy sha3-384 key id of the GnuPG key to use (otherwise taken from account-key)"`
		KeyPGPID    string `long:"key-pgp-id" description:"PGP key id of the GnuPG key to use (otherwise taken from account-key)"`

		AccountKey string `long:"account-key" description:"file with the account-key assertion of the key to use"`

		Revision int `long:"revision" description:"revision to set for the assertion (starts and defaults to 0)"`

		PublicKeyPGPID string `long:"public-key-pgp-id" description:"PGP key id of the GnuPG key to embed into the signed account-key"`

		PublicKeyID string `long:"public-key-id" description:"snappy sha3-384 key id of the GnuPG key to embed into the signed account-key"`

		GPGHomedir string `long:"gpg-homedir" description:"alternative GPG homedir, otherwise the default ~/.gnupg is used (or GNUPGHOME env var can be set instead)"`
	}

	parser := flags.NewParser(&opts, flags.HelpFlag)

	_, err := parser.Parse()
	if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
		parser.WriteHelp(Stdout)
		return nil
	} else if err != nil {
		return err
	}

	var mediaType string
	switch opts.Format {
	case "yaml":
		mediaType = tool.YAMLInput
	case "json":
		mediaType = tool.JSONInput
	default:
		return fmt.Errorf("input format can only be yaml or json")
	}

	var accountKey []byte
	if opts.AccountKey != "" {
		var err error
		accountKey, err = ioutil.ReadFile(opts.AccountKey)
		if err != nil {
			return fmt.Errorf("cannot read account-key: %v", err)
		}
	}

	statement, err := readStatement(opts.Positional.Statement)
	if err != nil {
		return fmt.Errorf("cannot read statement: %v", err)
	}

	keypairMgr := asserts.NewGPGKeypairManager(opts.GPGHomedir)

	keyID := opts.KeyID

	if keyID == "" && opts.KeyPGPID != "" {
		pubKey, err := findByKeyPGPID(keypairMgr, opts.KeyPGPID)
		if err != nil {
			return err
		}
		if pubKey != nil {
			keyID = pubKey.ID()
		}
	}

	var overrides map[string]interface{}

	assertType := opts.Positional.AssertionType

	if opts.PublicKeyPGPID != "" || opts.PublicKeyID != "" {
		if assertType != "account-key" {
			return fmt.Errorf("does not make sense to specify --public-key-(pgp-)id when the type is not account-key")
		}

		overrides = make(map[string]interface{})
		var pubKey asserts.PublicKey
		var err error
		if opts.PublicKeyID != "" {
			pubKey, err = findByKeyID(keypairMgr, opts.PublicKeyID)
		} else {
			pubKey, err = findByKeyPGPID(keypairMgr, opts.PublicKeyPGPID)
		}
		if err != nil {
			return err
		}
		err = fillInKeyDetails(overrides, pubKey)
		if err != nil {
			return fmt.Errorf("cannot fill in key details: %v", err)
		}
	}

	signReq := tool.SignRequest{
		AccountKey:         accountKey,
		KeyID:              keyID,
		AuthorityID:        opts.AuthorityID,
		AssertionType:      assertType,
		StatementMediaType: mediaType,
		Statement:          statement,
		Overrides:          overrides,
		Revision:           opts.Revision,
	}

	encodedAssert, err := tool.Sign(&signReq, keypairMgr)
	if err != nil {
		return err
	}

	_, err = Stdout.Write(encodedAssert)
	if err != nil {
		return err
	}
	return nil
}

func readStatement(statementFile string) ([]byte, error) {
	if statementFile == "" || statementFile == "-" {
		return ioutil.ReadAll(Stdin)
	}
	return ioutil.ReadFile(statementFile)
}

func fillInKeyDetails(m map[string]interface{}, pubKey asserts.PublicKey) error {
	encodedPubKey, err := asserts.EncodePublicKey(pubKey)
	if err != nil {
		return err
	}
	m["body"] = string(encodedPubKey)
	m["public-key-sha3-384"] = pubKey.ID()
	return nil
}
