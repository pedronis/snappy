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

// Package tool offers tooling to sign assertions.
package tool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"gopkg.in/yaml.v2"

	"github.com/snapcore/snapd/asserts"
)

// The supported media types for the input of assertion signing.
const (
	JSONInput = "application/json"
	YAMLInput = "application/x-yaml"
)

// SignRequest specifies the complete input for signing an assertion.
type SignRequest struct {
	// The key to use can be speficied either passing the text of
	// an account-key assertion in AccountKey
	AccountKey []byte
	// or passing the key hash in KeyHash
	KeyHash string
	// and an optional account-id of the signer (if left out headers value are consulted) in AuthorityID
	AuthorityID string

	// The assertion type (as a string)
	AssertionType string
	// StatementMediaType specifies the media type of the input
	StatementMediaType string
	// Statement is used as input to construct the assertion
	// it's a mapping encoded as either JSON or YAML
	// (specified in StatementMediaType)
	// either of just the header fields of the assertion
	// or containting exactly two entries
	// "headers": mapping with the header fields
	// "body": used as the body of the assertion
	Statement []byte

	// Overrides let specify further header values overriding Statement,
	// the special key "body" can be used to override the body
	Overrides map[string]interface{}

	// The revision of the new assertion
	Revision int
}

func parseStatement(req *SignRequest, dest interface{}) error {
	switch req.StatementMediaType {
	case YAMLInput:
		err := yaml.Unmarshal(req.Statement, dest)
		if err != nil {
			return fmt.Errorf("cannot parse the assertion input as YAML: %v", err)
		}
	case JSONInput:
		dec := json.NewDecoder(bytes.NewBuffer(req.Statement))
		// we want control over supporting only integers
		dec.UseNumber()
		err := dec.Decode(dest)
		if err != nil {
			return fmt.Errorf("cannot parse the assertion input as JSON: %v", err)
		}
	default:
		return fmt.Errorf("unsupported media type for assertion input: %q", req.StatementMediaType)
	}
	return nil
}

type nestedStatement struct {
	Headers map[string]interface{} `yaml:"headers" json:"headers"`
	Body    string                 `yaml:"body" json:"body"`
}

// Sign produces the text of a signed assertion as specified by req.
func Sign(req *SignRequest, keypairMgr asserts.KeypairManager) ([]byte, error) {
	typ := asserts.Type(req.AssertionType)
	if typ == nil {
		return nil, fmt.Errorf("invalid assertion type: %q", req.AssertionType)
	}
	if req.Revision < 0 {
		return nil, fmt.Errorf("assertion revision cannot be negative")
	}
	if req.AccountKey == nil && req.KeyHash == "" {
		return nil, fmt.Errorf("both account-key and key hash were not specified")
	}

	var nestedStatement nestedStatement
	err := parseStatement(req, &nestedStatement)
	if err != nil {
		return nil, err
	}
	if nestedStatement.Headers == nil {
		// flat headers, reparse
		err := parseStatement(req, &nestedStatement.Headers)
		if err != nil {
			return nil, err
		}
	}

	headers := nestedStatement.Headers
	body := []byte(nestedStatement.Body)

	keyHash := req.KeyHash
	authorityID := req.AuthorityID

	if req.AccountKey != nil {
		if keyHash != "" || authorityID != "" {
			return nil, fmt.Errorf("cannot mix specifying an account-key together with key hash and/or authority-id")
		}

		// use the account-key as a handle to get the information about
		// signer and key hash
		a, err := asserts.Decode(req.AccountKey)
		if err != nil {
			return nil, fmt.Errorf("cannot parse handle account-key: %v", err)
		}
		accKey, ok := a.(*asserts.AccountKey)
		if !ok {
			return nil, fmt.Errorf("cannot use handle account-key, not actually an account-key, got: %s", a.Type().Name)
		}

		keyHash = accKey.PublicKeySHA3_384()
		authorityID = accKey.AccountID()
	}

	if authorityID != "" {
		headers["authority-id"] = authorityID
	}

	if headers["authority-id"] == nil {
		return nil, fmt.Errorf("cannot sign assertion with unspecified signer identifier (aka authority-id)")
	}

	if req.Revision != 0 {
		headers["revision"] = strconv.Itoa(req.Revision)
	}

	if req.Overrides != nil {
		for k, v := range req.Overrides {
			if k == "body" {
				bodyStr, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("body overrid must be a string: %v", v)
				}
				body = []byte(bodyStr)
				continue
			}
			headers[k] = v
		}
	}

	adb, err := asserts.OpenDatabase(&asserts.DatabaseConfig{
		KeypairManager: keypairMgr,
	})
	if err != nil {
		return nil, err
	}

	a, err := adb.Sign(typ, headers, body, keyHash)
	if err != nil {
		return nil, err
	}

	return asserts.Encode(a), nil
}
