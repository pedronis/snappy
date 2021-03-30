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

package netonboard

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
)

// Device implements the device protocol side that is getting
// configured and network onboarded.
type Device struct {
	onbSecret []byte
	onbKey    *ecdsa.PrivateKey
	nonce1    []byte
	nonce2    []byte
	sek       []byte

	ready    bool
	replyEnc jose.Encrypter
}

// XXX SetOnboardingSecretFromKey, generate the secret by using a KDF

func (d *Device) SetOnboardingSecret(s []byte) error {
	if len(s) != secretSize {
		return fmt.Errorf("onboarding secret has the wrong size")
	}
	d.onbSecret = s
	return nil
}

func (d *Device) SetOnboardingDeviceKey(k *ecdsa.PrivateKey) error {
	if k.Curve != elliptic.P256() {
		return fmt.Errorf("expected P256 key")
	}
	d.onbKey = k
	return nil
}

func (d *Device) RcvHello(b []byte) error {
	var hello hello
	if err := json.Unmarshal(b, &hello); err != nil {
		return fmt.Errorf("can deserialize hello: %v", err)
	}
	if hello.M != "hello" {
		return fmt.Errorf("expected hello")
	}
	if len(hello.Nonce1) != nonceSize {
		return fmt.Errorf("nonce1 has the wrong size")
	}
	d.nonce1 = hello.Nonce1
	return nil
}

func (d *Device) Device() ([]byte, error) {
	if d.onbKey == nil {
		return nil, fmt.Errorf("onboarding device key must be set")
	}
	if d.nonce1 == nil {
		return nil, fmt.Errorf("nonce1 must have been received")
	}
	nonce2, err := genNonce()
	if err != nil {
		return nil, err
	}
	d.nonce2 = nonce2

	sopts := &jose.SignerOptions{}
	devSign, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       d.onbKey,
	}, sopts.WithBase64(true).WithHeader("m", "device"))
	if err != nil {
		return nil, fmt.Errorf("can't prepare for signing device")
	}
	b, err := json.Marshal(&device{
		Key: &jose.JSONWebKey{
			Key: &d.onbKey.PublicKey,
		},
		Nonce1: d.nonce1,
		Nonce2: nonce2,
	})
	if err != nil {
		return nil, fmt.Errorf("can't serialize device: %v", err)
	}
	signed, err := devSign.Sign(b)
	if err != nil {
		return nil, fmt.Errorf("can't sign device")
	}
	return []byte(signed.FullSerialize()), nil
}

func (d *Device) RcvSessionSetup(b []byte) error {
	if d.onbSecret == nil {
		return fmt.Errorf("onboarding secret must be set")
	}
	if d.onbKey == nil {
		return fmt.Errorf("onboarding device key must be set")
	}
	if d.nonce2 == nil {
		return fmt.Errorf("nonce2 must have been sent")
	}
	encrypted, err := jose.ParseEncrypted(string(b))
	if err != nil {
		// XXX maybe fatal instead
		return fmt.Errorf("can't parse session")
	}
	if encrypted.Header.ExtraHeaders["m"] != "session" {
		return fmt.Errorf("expected session")
	}
	b, err = encrypted.Decrypt(d.onbKey)
	if err != nil {
		return fmt.Errorf("can't decrypt session")
	}
	hashed, err := jose.ParseSigned(string(b))
	if err != nil {
		return fmt.Errorf("can't parse session hashing")
	}
	b, err = hashed.Verify(d.onbSecret)
	if err != nil {
		return fmt.Errorf("can't verify session against onboarding secret")
	}
	var sessionSetup sessionSetup
	if err := json.Unmarshal(b, &sessionSetup); err != nil {
		return fmt.Errorf("can't deserialize session")
	}
	if !bytes.Equal(d.nonce2, sessionSetup.Nonce2) {
		return fmt.Errorf("configurator didn't sign correct nonce")
	}
	d.sek = sessionSetup.SessionKey
	return nil
}

func (d *Device) sessEnc(m string) (jose.Encrypter, error) {
	if d.sek == nil {
		return nil, fmt.Errorf("session key must have been received")
	}
	rcpt := jose.Recipient{
		Algorithm: jose.DIRECT,
		Key:       d.sek,
	}
	eopts := &jose.EncrypterOptions{}
	enc, err := jose.NewEncrypter(contEnc, rcpt, eopts.WithHeader("m", m))
	if err != nil {
		return nil, fmt.Errorf("can't prepare session key encryption")
	}
	return enc, nil
}

func (d *Device) Ready(data map[string]interface{}) ([]byte, error) {
	enc, err := d.sessEnc("ready")
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(&deviceReady{
		Nonce1: d.nonce1,
		D:      data,
	})
	if err != nil {
		return nil, fmt.Errorf("can't serialize ready")
	}
	encrypted, err := enc.Encrypt(b)
	if err != nil {
		return nil, fmt.Errorf("can't encrypt ready")
	}
	return []byte(encrypted.FullSerialize()), nil
}

func (d *Device) sessDecrypt(b []byte, m string) ([]byte, error) {
	if d.sek == nil {
		return nil, fmt.Errorf("session key must have been received")
	}
	encrypted, err := jose.ParseEncrypted(string(b))
	if err != nil {
		// XXX maybe fatal instead
		return nil, fmt.Errorf("can't parse %s", m)
	}
	if encrypted.Header.ExtraHeaders["m"] != m {
		// XXX maybe fatal instead
		return nil, fmt.Errorf("expected %s", m)
	}
	b, err = encrypted.Decrypt(d.sek)
	if err != nil {
		return nil, fmt.Errorf("can't decrypt %s", m)
	}
	return b, nil
}

func (d *Device) RcvCfg(b []byte) (map[string]interface{}, error) {
	b, err := d.sessDecrypt(b, "cfg")
	if err != nil {
		return nil, err
	}
	var exchg exchg
	if err := json.Unmarshal(b, &exchg); err != nil {
		return nil, fmt.Errorf("can't deserialize cfg")
	}
	d.ready = true
	return exchg.D, nil
}

func (d *Device) Reply(data map[string]interface{}) ([]byte, error) {
	if !d.ready {
		return nil, fmt.Errorf("must have received cfg")
	}
	if d.replyEnc == nil {
		enc, err := d.sessEnc("reply")
		if err != nil {
			return nil, err
		}
		d.replyEnc = enc
	}
	b, err := json.Marshal(&exchg{
		D: data,
	})
	if err != nil {
		return nil, fmt.Errorf("can't serialize reply")
	}
	encrypted, err := d.replyEnc.Encrypt(b)
	if err != nil {
		return nil, fmt.Errorf("can't encrypt reply")
	}
	return []byte(encrypted.FullSerialize()), nil
}
