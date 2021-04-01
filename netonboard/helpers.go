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
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
)

func genNonce() ([]byte, error) {
	n := make([]byte, nonceSize)
	_, err := jose.RandReader.Read(n)
	if err != nil {
		return nil, fmt.Errorf("can't generate nonce: %v", err)
	}
	return n, nil
}

func GenSecret() ([]byte, error) {
	s := make([]byte, secretSize)
	_, err := jose.RandReader.Read(s)
	if err != nil {
		return nil, fmt.Errorf("can't generate secret: %v", err)
	}
	return s, nil
}

func GenDeviceKey() (*ecdsa.PrivateKey, error) {
	dk, err := ecdsa.GenerateKey(elliptic.P256(), jose.RandReader)
	if err != nil {
		return nil, fmt.Errorf("can't generate device key: %v", err)
	}
	return dk, nil
}
