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
	jose "gopkg.in/square/go-jose.v2"
)

const (
	nonceSize   = 16
	secretSize  = 32
	contEnc     = jose.A256GCM
	sessKeySize = 32
)

type hello struct {
	// M is hello
	M      string `json:"m"`
	Nonce1 []byte `json:"n1"`

	// XXX: list of protocols/versions
}

// for JOSE messages the message type m goes into the protected headers

type device struct {
	// M is device
	// this message is wrapped in a JWS object signed by the device
	// onboarding key

	Key    *jose.JSONWebKey `json:"k"`
	Nonce1 []byte           `json:"n1"`
	Nonce2 []byte           `json:"n2"`

	// XXX: list of protocols/versions
	// XXX: minimal device info
	// XXX max sizes?
}

type sessionSetup struct {
	// M is session
	// this goes from the configurator to the device as JWS object
	// "signed" with the onboarding secret and then itself
	// encrypted usign ECDH-ES against the device onboarding key

	SessionKey []byte `json:"sek"`
	Nonce2     []byte `json:"n2"`
}

type deviceReady struct {
	// M is ready
	// from device, this and messages after this are encrypted
	// with the session key
	// Good point just before replying with this to start
	// signaling visually that the device is fully engaged being configured

	Nonce1 []byte `json:"n1"`

	// D can be set optionally to give upfront device information
	// relevant to configuration
	D map[string]interface{} `json:"d,omitempty"`

	// XXX include in D or separately a list of supported
	// configuration facets, they could look like:
	// wifi, onboard, subiquity? or brand-foo
}

type exchg struct {
	// M is cfg if from configurator to device
	// M is reply if from device to configurator
	// XXX need a way to split these into multiple messages if they
	// are too big

	// D is for directives or data
	D map[string]interface{} `json:"d"`
}

type notification struct {
}

// type answer

type fatal struct {
	// M is fatal
	Code string `json:"code"`
	Msg  string `json:"msg"`
}
