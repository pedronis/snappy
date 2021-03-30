// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package netonboard_test

import (
	"fmt"

	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"testing"

	. "gopkg.in/check.v1"
	jose "gopkg.in/square/go-jose.v2"
)

func Test(t *testing.T) { TestingT(t) }

type netonboardSuite struct{}

var _ = Suite(&netonboardSuite{})

func dump(msg string) {
	fmt.Printf("%03d %s\n", len(msg), msg)
}

type msg struct {
	M string `json:"m"`
	V string `json:"v,omitempty"`
	N []byte `json:"n,omitempty"`
	K []byte `json:"k,omitempty"`
}

const encALG = jose.A256GCM

func (m *msg) JSON() []byte {
	x, err := json.Marshal(m)
	if err != nil {
		panic("can't serialize")
	}
	return x
}

func (s *netonboardSuite) TestKEX(c *C) {
	onbs := make([]byte, 32)
	_, err := jose.RandReader.Read(onbs)
	c.Assert(err, IsNil)

	devOnbKey, err := ecdsa.GenerateKey(elliptic.P256(), jose.RandReader)
	c.Assert(err, IsNil)

	wk := &jose.JSONWebKey{
		Key: &devOnbKey.PublicKey,
	}
	c.Assert(wk.Valid(), Equals, true)
	wirek, err := wk.MarshalJSON()
	dump(string(wirek))
	nonce2 := make([]byte, 16)
	_, err = jose.RandReader.Read(nonce2)
	c.Assert(err, IsNil)

	// kex
	sek := make([]byte, 32)
	_, err = jose.RandReader.Read(sek)
	c.Assert(err, IsNil)

	devKEXRcpt := jose.Recipient{
		Algorithm: jose.ECDH_ES,
		Key:       wk,
	}
	appKEXEnc, err := jose.NewEncrypter(encALG, devKEXRcpt, nil)
	c.Assert(err, IsNil)
	kex := &msg{
		M: "kex",
		K: sek,
		N: nonce2,
	}

	sopts := &jose.SignerOptions{}
	kexSign, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       onbs,
	}, sopts.WithBase64(true))
	c.Assert(err, IsNil)
	kexSigned, err := kexSign.Sign(kex.JSON())
	c.Assert(err, IsNil)
	kexJSON := kexSigned.FullSerialize()
	dump(kexJSON)

	encrypted, err := appKEXEnc.Encrypt([]byte(kexJSON))
	c.Assert(err, IsNil)
	serialized := encrypted.FullSerialize()
	dump(serialized)

	unserialized, err := jose.ParseEncrypted(serialized)
	c.Assert(err, IsNil)
	dkexJSON, err := unserialized.Decrypt(devOnbKey)
	c.Assert(err, IsNil)
	parsed, err := jose.ParseSigned(string(dkexJSON))
	c.Assert(err, IsNil)
	dkex, err := parsed.Verify(onbs)
	c.Assert(err, IsNil)
	dump(string(dkex))
}

func (s *netonboardSuite) TestSessionMsgReply(c *C) {
	sek := make([]byte, 32)
	_, err := jose.RandReader.Read(sek)
	c.Assert(err, IsNil)

	devSRcpt := jose.Recipient{
		Algorithm: jose.DIRECT,
		Key:       sek,
	}
	appSEnc, err := jose.NewEncrypter(encALG, devSRcpt, nil)
	c.Assert(err, IsNil)

	// m1
	m1 := &msg{
		M: "a to d",
		V: "cfg1",
	}
	encrypted, err := appSEnc.Encrypt(m1.JSON())
	c.Assert(err, IsNil)
	serialized := encrypted.FullSerialize()
	dump(serialized)

	unserialized, err := jose.ParseEncrypted(serialized)
	c.Assert(err, IsNil)
	dm1, err := unserialized.Decrypt(sek)
	c.Assert(err, IsNil)
	dump(string(dm1))

	// r1
	appSRcpt := jose.Recipient{
		Algorithm: jose.DIRECT,
		Key:       sek,
	}
	devSEnc, err := jose.NewEncrypter(encALG, appSRcpt, nil)
	c.Assert(err, IsNil)

	r1 := &msg{
		M: "d to a",
		V: "repl1",
	}
	encrypted, err = devSEnc.Encrypt(r1.JSON())
	c.Assert(err, IsNil)
	serialized = encrypted.FullSerialize()
	dump(serialized)
	unserialized, err = jose.ParseEncrypted(serialized)
	c.Assert(err, IsNil)
	dr1, err := unserialized.Decrypt(sek)
	c.Assert(err, IsNil)
	dump(string(dr1))

	// m2
	m2 := &msg{
		M: "a to d",
		V: "cfg2",
	}
	encrypted, err = appSEnc.Encrypt(m2.JSON())
	c.Assert(err, IsNil)
	serialized = encrypted.FullSerialize()
	dump(serialized)

	unserialized, err = jose.ParseEncrypted(serialized)
	c.Assert(err, IsNil)
	dm2, err := unserialized.Decrypt(sek)
	c.Assert(err, IsNil)
	dump(string(dm2))
}
