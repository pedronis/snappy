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

package tool_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/asserts/tool"
)

func TestTool(t *testing.T) { TestingT(t) }

type signSuite struct {
	keypairMgr  asserts.KeypairManager
	testKeyHash string

	accKey      []byte
	otherAssert []byte
}

var _ = Suite(&signSuite{})

func (s *signSuite) SetUpSuite(c *C) {
	testKey, _ := assertstest.GenerateKey(752)

	s.keypairMgr = asserts.NewMemoryKeypairManager()
	s.keypairMgr.Put("user-id1", testKey)
	s.testKeyHash = testKey.PublicKey().SHA3_384()

	pubKeyEncoded, err := asserts.EncodePublicKey(testKey.PublicKey())
	c.Assert(err, IsNil)

	now := time.Now()
	// good enough as a handle as is used by Sign
	mockAccKey := "type: account-key\n" +
		"authority-id: canonical\n" +
		"account-id: user-id1\n" +
		"public-key-sha3-384: " + s.testKeyHash + "\n" +
		"since: " + now.Format(time.RFC3339) + "\n" +
		"until: " + now.AddDate(1, 0, 0).Format(time.RFC3339) + "\n" +
		fmt.Sprintf("body-length: %v", len(pubKeyEncoded)) + "\n" +
		"sign-key-sha3-384: Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij" + "\n\n" +
		string(pubKeyEncoded) + "\n\n" +
		"openpgp c2ln"

	s.accKey = []byte(mockAccKey)

	s.otherAssert = []byte("type: account\n" +
		"authority-id: canonical\n" +
		"account-id: user-id1\n" +
		"display-name: User One\n" +
		"username: userone\n" +
		"validation: unproven\n" +
		"timestamp: " + now.Format(time.RFC3339) + "\n" +
		"sign-key-sha3-384: Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij" + "\n\n" +
		"openpgp c2ln")
}

const (
	flatModelYaml = `series: "16"
brand-id: user-id1
model: baz-3000
core: core
architecture: amd64
gadget: brand-gadget
kernel: baz-linux
store: brand-store
allowed-modes: []
required-snaps: [foo,bar]
class: fixed
timestamp: 2015-11-25T20:00:00Z
`
	nestedModelYaml = `headers:
  series: "16"
  brand-id: user-id1
  model: baz-3000
  core: core
  architecture: amd64
  gadget: brand-gadget
  kernel: baz-linux
  store: brand-store
  allowed-modes: []
  required-snaps: [foo,bar]
  class: fixed
  timestamp: 2015-11-25T20:00:00Z
`
)

func expectedModelHeaders(a asserts.Assertion) map[string]interface{} {
	return map[string]interface{}{
		"type":              "model",
		"authority-id":      "user-id1",
		"series":            "16",
		"brand-id":          "user-id1",
		"model":             "baz-3000",
		"architecture":      "amd64",
		"class":             "fixed",
		"gadget":            "brand-gadget",
		"kernel":            "baz-linux",
		"core":              "core",
		"store":             "brand-store",
		"required-snaps":    []interface{}{"foo", "bar"},
		"timestamp":         "2015-11-25T20:00:00Z",
		"sign-key-sha3-384": a.SigningKey(),
	}
}

func (s *signSuite) TestSignKeyHashFlatYAML(c *C) {
	req := tool.SignRequest{
		KeyHash:     s.testKeyHash,
		AuthorityID: "user-id1",

		AssertionType:      "model",
		StatementMediaType: "application/x-yaml",
		Statement:          []byte(flatModelYaml),
	}

	assertText, err := tool.Sign(&req, s.keypairMgr)
	c.Assert(err, IsNil)

	a, err := asserts.Decode(assertText)
	c.Assert(err, IsNil)

	c.Check(a.Type(), Equals, asserts.ModelType)
	c.Check(a.Revision(), Equals, 0)
	c.Check(a.Headers(), DeepEquals, expectedModelHeaders(a))
	c.Check(a.Body(), IsNil)
}

func (s *signSuite) TestSignKeyHashNestedYAML(c *C) {
	req := tool.SignRequest{
		KeyHash:     s.testKeyHash,
		AuthorityID: "user-id1",

		AssertionType:      "model",
		StatementMediaType: "application/x-yaml",
		Statement:          []byte(nestedModelYaml),
	}

	assertText, err := tool.Sign(&req, s.keypairMgr)
	c.Assert(err, IsNil)

	a, err := asserts.Decode(assertText)
	c.Assert(err, IsNil)

	c.Check(a.Type(), Equals, asserts.ModelType)
	c.Check(a.Revision(), Equals, 0)
	c.Check(a.Headers(), DeepEquals, expectedModelHeaders(a))
	c.Check(a.Body(), IsNil)
}

func (s *signSuite) TestSignKeyHashNestedYAMLWithBodyAndRevision(c *C) {
	req := tool.SignRequest{
		KeyHash:     s.testKeyHash,
		AuthorityID: "user-id1",

		AssertionType:      "model",
		StatementMediaType: "application/x-yaml",
		Statement:          []byte(nestedModelYaml + `body: "BODY"`),

		Revision: 11,
	}

	assertText, err := tool.Sign(&req, s.keypairMgr)
	c.Assert(err, IsNil)

	a, err := asserts.Decode(assertText)
	c.Assert(err, IsNil)

	c.Check(a.Type(), Equals, asserts.ModelType)
	c.Check(a.Revision(), Equals, 11)

	expectedHeaders := expectedModelHeaders(a)
	expectedHeaders["revision"] = "11"
	expectedHeaders["body-length"] = "4"

	c.Check(a.Headers(), DeepEquals, expectedHeaders)

	c.Check(a.Body(), DeepEquals, []byte("BODY"))
}

func (s *signSuite) TestSignKeyHashFlatYAMLRevisionWithinHeaders(c *C) {
	req := tool.SignRequest{
		KeyHash:     s.testKeyHash,
		AuthorityID: "user-id1",

		AssertionType:      "model",
		StatementMediaType: "application/x-yaml",
		Statement:          []byte(flatModelYaml + `revision: "12"`),
	}

	assertText, err := tool.Sign(&req, s.keypairMgr)
	c.Assert(err, IsNil)

	a, err := asserts.Decode(assertText)
	c.Assert(err, IsNil)

	c.Check(a.Type(), Equals, asserts.ModelType)
	c.Check(a.Revision(), Equals, 12)

	expectedHeaders := expectedModelHeaders(a)
	expectedHeaders["revision"] = "12"

	c.Check(a.Headers(), DeepEquals, expectedHeaders)

	c.Check(a.Body(), IsNil)
}

func headersForJSON() map[string]interface{} {
	return map[string]interface{}{
		"series":         "16",
		"brand-id":       "user-id1",
		"model":          "baz-3000",
		"core":           "core",
		"architecture":   "amd64",
		"gadget":         "brand-gadget",
		"kernel":         "baz-linux",
		"store":          "brand-store",
		"allowed-modes":  []string{},
		"required-snaps": []string{"foo", "bar"},
		"class":          "fixed",
		"timestamp":      "2015-11-25T20:00:00Z",
	}
}

func (s *signSuite) TestSignKeyHashFlatJSONRevisionWithinHeaders(c *C) {
	hdrs := headersForJSON()
	hdrs["revision"] = "12"
	statement, err := json.Marshal(hdrs)
	c.Assert(err, IsNil)

	req := tool.SignRequest{
		KeyHash:     s.testKeyHash,
		AuthorityID: "user-id1",

		AssertionType:      "model",
		StatementMediaType: "application/json",
		Statement:          statement,
	}

	assertText, err := tool.Sign(&req, s.keypairMgr)
	c.Assert(err, IsNil)

	a, err := asserts.Decode(assertText)
	c.Assert(err, IsNil)

	c.Check(a.Type(), Equals, asserts.ModelType)
	c.Check(a.Revision(), Equals, 12)

	expectedHeaders := expectedModelHeaders(a)
	expectedHeaders["revision"] = "12"

	c.Check(a.Headers(), DeepEquals, expectedHeaders)

	c.Check(a.Body(), IsNil)
}

func (s *signSuite) TestSignKeyHashNestedJSONWithBodyAndRevision(c *C) {
	hdrs := headersForJSON()
	statement, err := json.Marshal(map[string]interface{}{
		"headers": hdrs,
		"body":    "BODY",
	})
	c.Assert(err, IsNil)

	req := tool.SignRequest{
		KeyHash:     s.testKeyHash,
		AuthorityID: "user-id1",

		AssertionType:      "model",
		StatementMediaType: "application/json",
		Statement:          statement,

		Revision: 11,
	}

	assertText, err := tool.Sign(&req, s.keypairMgr)
	c.Assert(err, IsNil)

	a, err := asserts.Decode(assertText)
	c.Assert(err, IsNil)

	c.Check(a.Type(), Equals, asserts.ModelType)
	c.Check(a.Revision(), Equals, 11)

	expectedHeaders := expectedModelHeaders(a)
	expectedHeaders["revision"] = "11"
	expectedHeaders["body-length"] = "4"

	c.Check(a.Headers(), DeepEquals, expectedHeaders)

	c.Check(a.Body(), DeepEquals, []byte("BODY"))
}

func (s *signSuite) TestSignAccountKeyHandle(c *C) {
	req := tool.SignRequest{
		AccountKey: s.accKey,

		AssertionType:      "model",
		StatementMediaType: "application/x-yaml",
		Statement:          []byte(nestedModelYaml),
	}

	assertText, err := tool.Sign(&req, s.keypairMgr)
	c.Assert(err, IsNil)

	a, err := asserts.Decode(assertText)
	c.Assert(err, IsNil)

	c.Check(a.Type(), Equals, asserts.ModelType)
	c.Check(a.Revision(), Equals, 0)
	c.Check(a.Headers(), DeepEquals, expectedModelHeaders(a))
	c.Check(a.Body(), IsNil)
}

func (s *signSuite) TestSignRequestOverridesHeaders(c *C) {
	hdrs := headersForJSON()
	hdrs["revision"] = 12
	hdrs["authority-id"] = "whatever"
	statement, err := json.Marshal(hdrs)
	c.Assert(err, IsNil)

	req := tool.SignRequest{
		KeyHash:     s.testKeyHash,
		AuthorityID: "user-id1",

		AssertionType:      "model",
		StatementMediaType: "application/json",
		Statement:          statement,

		Revision: 13,
	}

	assertText, err := tool.Sign(&req, s.keypairMgr)
	c.Assert(err, IsNil)

	a, err := asserts.Decode(assertText)
	c.Assert(err, IsNil)

	c.Check(a.Type(), Equals, asserts.ModelType)
	c.Check(a.AuthorityID(), Equals, "user-id1")
	c.Check(a.Revision(), Equals, 13)

	expectedHeaders := expectedModelHeaders(a)
	expectedHeaders["revision"] = "13"

	c.Check(a.Headers(), DeepEquals, expectedHeaders)

	c.Check(a.Body(), IsNil)
}

func (s *signSuite) TestSignErrors(c *C) {
	req := tool.SignRequest{
		KeyHash:     s.testKeyHash,
		AuthorityID: "user-id1",

		AssertionType:      "model",
		StatementMediaType: tool.YAMLInput,
		Statement:          []byte(flatModelYaml),
	}

	tests := []struct {
		expError string
		breakReq func(*tool.SignRequest)
	}{
		{`unsupported media type for assertion input: "yyy"`,
			func(req *tool.SignRequest) {
				req.StatementMediaType = "yyy"
			},
		},
		{`cannot parse the assertion input as YAML:.*`,
			func(req *tool.SignRequest) {
				req.Statement = []byte("\x00")
			},
		},
		{`cannot parse the assertion input as JSON:.*`,
			func(req *tool.SignRequest) {
				req.StatementMediaType = tool.JSONInput
				req.Statement = []byte("{")
			},
		},
		{`invalid assertion type: "what"`,
			func(req *tool.SignRequest) {
				req.AssertionType = "what"
			},
		},
		{"assertion revision cannot be negative",
			func(req *tool.SignRequest) {
				req.Revision = -10
			},
		},
		{"both account-key and key hash were not specified",
			func(req *tool.SignRequest) {
				req.KeyHash = ""
				req.AccountKey = nil
			},
		},
		{"cannot mix specifying an account-key together with key hash and/or authority-id",
			func(req *tool.SignRequest) {
				req.AccountKey = []byte("ak")
			},
		},
		{"cannot parse handle account-key:.*",
			func(req *tool.SignRequest) {
				req.KeyHash = ""
				req.AuthorityID = ""
				req.AccountKey = []byte("ak")
			},
		},
		{"cannot use handle account-key, not actually an account-key, got: account",
			func(req *tool.SignRequest) {
				req.KeyHash = ""
				req.AuthorityID = ""
				req.AccountKey = s.otherAssert
			},
		},
		{`cannot sign assertion with unspecified signer identifier \(aka authority-id\)`,
			func(req *tool.SignRequest) {
				req.AuthorityID = ""
			},
		},
		{`header "foo": header values must be strings or nested lists with strings as the only scalars:.*`,
			func(req *tool.SignRequest) {
				req.Statement = []byte("foo: [1]")
			},
		},
	}

	for _, t := range tests {
		fresh := req

		t.breakReq(&fresh)

		_, err := tool.Sign(&fresh, s.keypairMgr)
		c.Check(err, ErrorMatches, t.expError)
	}
}
